# Technical details
The exploit takes advantage of three issues. Taken together, the issues present us with a buffer overflow vulnerability. All issues are present in `drivers/tty/n_gsm.c`.

## Issues
The first issue is that the `gsm->state` field of the muxer is not reset when the muxing method is changed from `BASIC` to `ADVANCED` mode:
```C
static int gsm_activate_mux(struct gsm_mux *gsm) {
    // ...
    // gsm->state is not reset when we change the demux method
    if (gsm->encoding == GSM_BASIC_OPT)
        gsm->receive = gsm0_receive;
    else
        gsm->receive = gsm1_receive;
    // ...
}
```

The second issue is that the `BASIC` mux mode checks the length of the buffer with an equality check:
```C
    case GSM_DATA:    /* Data */
        gsm->buf[gsm->count++] = c;
        // notice the check is ==, not >=
        if (gsm->count == gsm->len) {
            // ...
            gsm->state = GSM_FCS;
        }
        break;
```

The third issue, when considered with the above, is that the `ADVANCED` mux mode performs a different length check than the `BASIC` mux mode:
```C
    case GSM_DATA:    /* Data */
        // We check if count > gsm->mru here; compare to above
        if (gsm->count > gsm->mru) {    /* Allow one for the FCS */
            gsm->state = GSM_OVERRUN;
            gsm->bad_size++;
        } else
            gsm->buf[gsm->count++] = c;
        break;
```

## Exploit flow
Using the above primitives, we can construct the following flow:

0. We open a pseudoterminal and attach the `N_GSM` line discipline to open a mux
1. Switch the MUX to the `BASIC` mode
2. Send a message to progress to the `DATA` state and set `gsm->len` to `8`
3. Switch the MUX to the `ADVANCED` mode
4. Send `16` bytes to push `gsm->count` above `gsm->len`
5. Switch back to `BASIC` mode

At this point, we can now overflow as much as we want, because `gsm->count == gsm->len` will never be true.

In this exploit, we overflow into a netlink socket and corrupt some fields, then call some `getsockopt()` calls to leak memory and gain a read/write primitive. We then use this to overwrite our task's credentials and spawn a root shell.

## Overflow
The buffer we overflow is `gsm->buf`, of size `1501`, which is allocated in `gsm_alloc_mux`:
```C
#define MAX_MRU 1500
// ...
static struct gsm_mux *gsm_alloc_mux(void) {
    // ...
    gsm->buf = kmalloc(MAX_MRU + 1, GFP_KERNEL);
    // ...
}
```

The buffer will be allocated in the `kmalloc-2k` bucket. `gsm_alloc_mux` is called when we attach the `N_GSM` line discipline to a terminal, so we can control when this allocation happens.

To exploit the overflow, we will overflow into a `struct netlink_sock` object. This object fits into the `kmalloc-2k` bucket, it has a number of function pointers, variables which lead to read primitives, and is easily allocated by a normal unprivileged user.

In order to exploit successfully, we need the `gsm->buf` buffer to be allocated in a bucket before a `netlink_sock` bucket:
```txt
kmalloc-2k:
+------------+------------+------------+------------+
|            |            |            |            |
|    junk    |  gsm->buf  |netlink_sock|    junk    |
|            |            |            |            |
+------------+------------+------------+------------+
```

To do this, we try and shape the heap by allocating a number of `netlink_sock` objects and `free()`-ing some of them. After the `free()`s, we allocate the `gsm->buf` and hope that the allocation lands in the hole we created.

In order to test if we have allocated successfully, we overflow a small amount into the next bucket to overwrite `netlink_sock.sk.sk_family`.

This overwrite is done blind, because we do not yet have a read primitive. This is what can cause instability -- if the allocation did not land correctly, we will overwrite something unexpected, which could crash the system.

If the allocation _did_ land correctly, then we can check which socket is corrupted by calling `getsockopt(SO_DOMAIN)` to check the `skc_family` field on all of the sockets we have allocated. The socket which does not return `AF_NETLINK` is the one we corrupted.

## Infoleak
We can call `poll` on the corrupted socket to call into `skb_queue_empty_lockless`:
```C
skb_queue_empty_lockless(const struct sk_buff_head *list) {
    return READ_ONCE(list->next) == (const struct sk_buff *) list;
}
```

Calling this normally will return TRUE for the above, signalling that the error queue is empty, so `poll` will not return the `EPOLLERR` flag. If we overwrite the first byte of `sk.sk_buff_head`, we will change the first byte of `list->next`. This causes the condition to return `FALSE`, which causes poll to return the `EPOLLERR` flag.

We use this primitive to guess the address of `sk_buff_head` incrementally, by overwriting the address one byte at a time, and checking for `EPOLLERR` on every change.

Once we have the address of `sk_buff_head`, we can calculate the address of `netlink_sock`, and of `gsm->buf`.

## Arbitrary read and KASLR bypass
With the address of `netlink_sock`, we can now use `getsockopt` to read arbitrary memory. We do this by overwriting the `sk.skc_net` pointer on the corrupted socket and calling `getsockopt(SO_NETNS_COOKIE)` to read the value at `sk.skc_net->cookie`. As we control the `skc_net` pointer, we can change this to read the `sk.sk_prot_creator` field, which gives us the address for the global `netlink_proto` symbol.

Given the `netlink_proto` offset from kernel base, we can then calculate the kernel base to bypass KASLR.

We also use this read primitive to read `sk->socket`, then `sk->socket->file`, then `sk->sk_socket->file->f_cred` to retrieve the address of the credentials struct for the current task.

## Memory write
Knowing the address of the kernel base, we can now setup `gsm->buf` as a fake `proto` object. We can then call a function pointer in this object by calling `getsockopt(SO_KEEPALIVE)` on our corrupted socket.

The target function (keepalive) is called with `sk` as it's first argument. We will use this to call `bpf_prog_free_id`, and use a crafted `sock` object to write zeroes to fields in our `cred` struct:
```C
void bpf_prog_free_id(struct bpf_prog *prog) {
    // ...

    // id == &current_cred().uid
    prog->aux->id = 0; 

    // ...
}
```

## Payload
After the credential overwrites, we have `cred.uid == 0` etc for our task, so we call `setuid(0)` and spawn a shell.