#include <stdint.h>        // u/intN_t types

#define ptr uintptr_t
#define u64 uint64_t
#define i64  int64_t
#define u32 uint32_t
#define i32  int32_t
#define u16 uint16_t
#define  u8  uint8_t

#define KMALLOC_2K 2048

#define SKC_FAMILY_OFFSET 0x10 // hasn't changed since at least 4.11-rc1
#define SKC_PROT_OFFSET   0x28 // hasn't changed since at least 4.11-rc1
#define SKC_NET_OFFSET    0x30 // hasn't changed since at least 4.11-rc1

struct kernel_offsets {
    char kernel_tag[144];      // version string for the kernel
    u32 SKC_REFCNT;            // offset of skc_refcnt       in struct sock_common
    u32 SK_ERROR_QUEUE;        // offset of sk_error_queue   in struct sock
    u32 SK_LOCK;               // offset of sk_lock          in struct sock
    u32 SK_PROT_CREATOR;       // offset of sk_prot_creator  in struct sock
    u32 SK_SOCKET;             // offset of sk_socket        in struct sock

    u32 NET_COOKIE;            // offset of net_cookie field in struct net
    u32 FILE_SK;               // offset of file             in struct socket
    u32 FCRED_FILE;            // offset of f_cred           in struct file
    u32 CRED_UID;              // offset of uid              in struct cred

    u32 AUX_IN_BPF;            // offset of AUX field        in struct bpf_prog
    u32 ID_IN_AUX;             // offset of ID field         in struct bpf_prog_aux
    
    u32 NETLINK_PROTO;         // offset of netlink_proto    from kernel base
    u32 BPF_WRITER;            // offset of bpf_prog_free_id from kernel base
} offset_table[] = {

/*                                          UBUNTU                                                */
{ "6.5.0-34-generic#34~22.04.2-Ubuntu",
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000008, 0x00000038, 0x00000020, 0x02595dc0, 0x002f88f0, 
},
{ "6.5.0-34-generic#34-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000008, 0x00000038, 0x00000020, 0x02596a40, 0x002fa6a0, 
},
{ "6.5.0-33-generic#33-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000008, 0x00000038, 0x00000020, 0x02596a40, 0x002f66a0, 
},
{ "6.5.0-28-generic#29~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000008, 0x00000038, 0x00000020, 0x02595680, 0x002f32a0, 
},
{ "6.5.0-28-generic#29-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000008, 0x00000038, 0x00000020, 0x02596300, 0x002f6070, 
},
{ "6.5.0-27-generic#28~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000008, 0x00000038, 0x00000020, 0x02595680, 0x002f32a0, 
},
{ "6.5.0-27-generic#28-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000008, 0x00000038, 0x00000020, 0x02596300, 0x002f6070, 
},
{ "6.5.0-26-generic#26~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02595380, 0x002f29f0, 
},
{ "6.5.0-26-generic#26-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02596000, 0x002f47a0, 
},
{ "6.5.0-25-generic#25~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02595380, 0x002f29f0, 
},
{ "6.5.0-25-generic#25-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02596000, 0x002f47a0, 
},
{ "6.5.0-21-generic#21~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02594e00, 0x002f1f00, 
},
{ "6.5.0-21-generic#21-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02595b00, 0x002f3b10, 
},
{ "6.5.0-18-generic#18~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02594e00, 0x002f1f00, 
},
{ "6.5.0-17-generic#17~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02594e00, 0x002f1f00, 
},
{ "6.5.0-17-generic#17-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02595b00, 0x002f3b10, 
},
{ "6.5.0-16-generic#16-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02595b00, 0x002f3b10, 
},
{ "6.5.0-15-generic#15~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02594f00, 0x002f1870, 
},
{ "6.5.0-15-generic#15-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02595a40, 0x002f3500, 
},
{ "6.5.0-14-generic#14~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02594f00, 0x002f1870, 
},
{ "6.5.0-14-generic#14-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02595a40, 0x002f3500, 
},
{ "6.5.0-13-generic#13-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02595ac0, 0x002f3500, 
},
{ "6.5.0-12-generic#12-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02595a40, 0x002f3500, 
},
{ "6.5.0-10-generic#10-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02595ac0, 0x002f3500, 
},
{ "6.5.0-9-generic#9-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x02595ac0, 0x002f3500, 
},
{ "6.2.0-39-generic#40~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x0257f3e0, 0x002ce590, 
},
{ "6.2.0-37-generic#38~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x02581120, 0x002ce520, 
},
{ "6.2.0-36-generic#37~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x02581120, 0x002ce520, 
},
{ "6.2.0-35-generic#35~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x02580b40, 0x002ce000, 
},
{ "6.2.0-34-generic#34~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x02580b40, 0x002ce000, 
},
{ "6.2.0-33-generic#33~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x02580980, 0x002ccf50, 
},
{ "6.2.0-32-generic#32~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x02580940, 0x002ccf50, 
},
{ "6.2.0-31-generic#31~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x02580940, 0x002ccd10, 
},
{ "6.2.0-26-generic#26~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x02580300, 0x002cca10, 
},
{ "6.2.0-25-generic#25~22.04.2-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x02580300, 0x002ccb30, 
},
{ "5.19.0-50-generic#50-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x02377040, 0x00275e70, 
},
{ "5.19.0-46-generic#47~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x02377040, 0x00275e70, 
},
{ "5.19.0-45-generic#46~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x02377040, 0x00275e70, 
},
{ "5.19.0-43-generic#44~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x02376c80, 0x00274e60, 
},
{ "5.19.0-42-generic#43~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x02376c80, 0x00274e60, 
},
{ "5.19.0-41-generic#42~22.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x0236ec40, 0x00273820, 
},
{ "5.15.0-106-generic#116~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000008, 0x00000038, 0x00000020, 0x021c6fa0, 0x0024a100, 
},
{ "5.15.0-106-generic#116-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000008, 0x00000038, 0x00000020, 0x021c8320, 0x00252ad0, 
},
{ "5.15.0-105-generic#115~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000008, 0x00000038, 0x00000020, 0x021c6d20, 0x00243cf0, 
},
{ "5.15.0-105-generic#115-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000008, 0x00000038, 0x00000020, 0x021c80a0, 0x0024c6b0, 
},
{ "5.15.0-104-generic#114~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000008, 0x00000038, 0x00000020, 0x021c6fa0, 0x00244100, 
},
{ "5.15.0-104-generic#114-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000008, 0x00000038, 0x00000020, 0x021c8320, 0x0024cad0, 
},
{ "5.15.0-102-generic#112~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000008, 0x00000038, 0x00000020, 0x021c6d20, 0x00243cf0, 
},
{ "5.15.0-102-generic#112-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000008, 0x00000038, 0x00000020, 0x021c80a0, 0x0024c6b0, 
},
{ "5.15.0-101-generic#111~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c6ca0, 0x002439b0, 
},
{ "5.15.0-101-generic#111-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c8060, 0x0024c3b0, 
},
{ "5.15.0-100-generic#110~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c6ca0, 0x002439b0, 
},
{ "5.15.0-100-generic#110-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c8060, 0x0024c3b0, 
},
{ "5.15.0-97-generic#107~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c68a0, 0x002439b0, 
},
{ "5.15.0-97-generic#107-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c7c60, 0x0024c310, 
},
{ "5.15.0-94-generic#104~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c68a0, 0x002439b0, 
},
{ "5.15.0-94-generic#104-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c7c60, 0x0024c310, 
},
{ "5.15.0-93-generic#103-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c7b60, 0x0024c310, 
},
{ "5.15.0-92-generic#102~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c6660, 0x002433d0, 
},
{ "5.15.0-92-generic#102-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c79e0, 0x0024bce0, 
},
{ "5.15.0-91-generic#101~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c65e0, 0x002433d0, 
},
{ "5.15.0-91-generic#101-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c7960, 0x0024bce0, 
},
{ "5.15.0-90-generic#100-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c7920, 0x0024bce0, 
},
{ "5.15.0-89-generic#99~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c66a0, 0x00242fc0, 
},
{ "5.15.0-89-generic#99-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c7a20, 0x0024b8d0, 
},
{ "5.15.0-88-generic#98~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c66a0, 0x00242fc0, 
},
{ "5.15.0-88-generic#98-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c7a20, 0x0024b8d0, 
},
{ "5.15.0-87-generic#97~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c64e0, 0x00242b00, 
},
{ "5.15.0-87-generic#97-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c7860, 0x0024b4c0, 
},
{ "5.15.0-86-generic#96~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c64e0, 0x00242b00, 
},
{ "5.15.0-86-generic#96-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c7860, 0x0024b4c0, 
},
{ "5.15.0-85-generic#95~20.04.2-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c64e0, 0x00242b00, 
},
{ "5.15.0-85-generic#95-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f00, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c7860, 0x0024b4c0, 
},
{ "5.15.0-84-generic#93~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c5f40, 0x00242500, 
},
{ "5.15.0-84-generic#93-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c7200, 0x0024afd0, 
},
{ "5.15.0-83-generic#92~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c5f00, 0x00241500, 
},
{ "5.15.0-83-generic#92-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000230, 0x00000298, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c71c0, 0x0024afd0, 
},
{ "5.15.0-82-generic#91~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c5f40, 0x00241360, 
},
{ "5.15.0-82-generic#91-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c71c0, 0x0024ae20, 
},
{ "5.15.0-79-generic#86~20.04.2-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c5e40, 0x002413c0, 
},
{ "5.15.0-79-generic#86-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c70c0, 0x00249e20, 
},
{ "5.15.0-78-generic#85~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c4340, 0x0023d480, 
},
{ "5.15.0-78-generic#85-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c5800, 0x00245dc0, 
},
{ "5.15.0-77-generic#84-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c6a00, 0x00248f10, 
},
{ "5.15.0-76-generic#83~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c4340, 0x0023d480, 
},
{ "5.15.0-75-generic#82~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c4340, 0x0023d480, 
},
{ "5.15.0-75-generic#82-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c5800, 0x00245dc0, 
},
{ "5.15.0-74-generic#81~20.04.2-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c4340, 0x0023d480, 
},
{ "5.15.0-73-generic#80~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c4200, 0x0023d570, 
},
{ "5.15.0-73-generic#80-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c55c0, 0x00245e30, 
},
{ "5.15.0-72-generic#79~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c4200, 0x0023d570, 
},
{ "5.15.0-72-generic#79-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c55c0, 0x00245e30, 
},
{ "5.15.0-71-generic#78~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c4140, 0x0023d430, 
},
{ "5.15.0-70-generic#77~20.04.1-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c4140, 0x0023d430, 
},
{ "5.15.0-25-generic#25-Ubuntu", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000b0, 0x00000088, 0x00000228, 0x00000290, 0x00000f40, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x021c5b40, 0x00231710, 
},



/*                                          DEBIAN                                                */
{ "6.5.0-0.deb12.4-amd64#1", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000070, 0x00000004, 0x00000038, 0x00000020, 0x01bebe20, 0x0025d150, 
},
{ "6.1.0-20-amd64#1", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000008, 0x00000038, 0x00000020, 0x01bec720, 0x002081e0, 
},
{ "6.1.0-19-amd64#1", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000008, 0x00000038, 0x00000020, 0x01bec720, 0x002040a0, 
},
{ "6.1.0-18-amd64#1", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000008, 0x00000038, 0x00000020, 0x01bec6a0, 0x00203df0, 
},
{ "6.1.0-16-amd64#1", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x01bec620, 0x00204200, 
},
{ "6.1.0-15-amd64#1", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x01bec620, 0x00204200, 
},
{ "6.1.0-0.deb11.18-amd64#1", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000008, 0x00000038, 0x00000020, 0x01bec6e0, 0x001ff2f0, 
},
{ "6.1.0-0.deb11.17-amd64#1", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000008, 0x00000038, 0x00000020, 0x01bec660, 0x001ff600, 
},
{ "6.1.0-0.deb11.13-amd64#1", 
//  SKC_REFCNT  ERR_QUEUE   SK_LOCK     PROT_CRE8R  SK_SOCKET   NET_COOKIE  FILE_SK     FCRED_FILE  CRED_UID    AUX_IN_BPF  ID_IN_AUX   NLK_PROTO   BPF_WRITER
    0x00000080, 0x000000c0, 0x00000098, 0x00000210, 0x00000270, 0x00001000, 0x00000010, 0x00000090, 0x00000004, 0x00000038, 0x00000020, 0x01bec220, 0x00203710, 
},


};

#define NUM_KERNELS sizeof(offset_table)/sizeof(struct kernel_offsets)