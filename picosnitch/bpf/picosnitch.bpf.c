// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2020 Eric Lesiuta
// BPF CO-RE program for picosnitch

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16
#define AF_INET 2
#define AF_INET6 10

// DNS structures
struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    __u32 ai_addrlen;
    void *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};

struct dns_val_t {
    char host[80];
    struct addrinfo **res;
};

struct dns_event_t {
    char host[80];
    __u32 daddr;
    unsigned __int128 daddr6;
} __attribute__((packed));

struct exec_event_t {
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    __u64 ino;
    __u64 pino;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 dev;
    __u32 pdev;
} __attribute__((packed));

struct sendrecv_event_t {
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    __u64 ino;
    __u64 pino;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 dev;
    __u32 pdev;
    __u32 bytes;
    __u32 daddr;
    __u32 saddr;
    __u16 dport;
    __u16 lport;
} __attribute__((packed));

struct sendrecv6_event_t {
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    unsigned __int128 daddr;
    unsigned __int128 saddr;
    __u64 ino;
    __u64 pino;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 dev;
    __u32 pdev;
    __u32 bytes;
    __u16 dport;
    __u16 lport;
} __attribute__((packed));

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct dns_val_t);
} dns_hash SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} dns_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} exec_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} sendmsg_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} recvmsg_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} sendmsg6_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} recvmsg6_events SEC(".maps");

// Convert kernel dev_t format (major << 20 | minor) to glibc format
// that Python's os.stat() returns
static __always_inline __u32 kernel_to_glibc_dev(__u32 dev)
{
    __u32 major = (dev >> 20) & 0xfff;
    __u32 minor = dev & 0xfffff;
    return (minor & 0xff) | (major << 8) | ((minor & 0xfff00) << 12);
}

// DNS entry probe
SEC("uprobe")
int BPF_UPROBE(dns_entry, const char *node, const char *service,
               const struct addrinfo *hints, struct addrinfo **res)
{
    if (!node)
        return 0;

    struct dns_val_t val = {};
    val.res = res;

    if (bpf_probe_read_user(&val.host, sizeof(val.host), node) == 0) {
        __u32 tid = (__u32)bpf_get_current_pid_tgid();
        bpf_map_update_elem(&dns_hash, &tid, &val, BPF_ANY);
    }

    return 0;
}

// DNS return probe
SEC("uretprobe")
int BPF_URETPROBE(dns_return)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct dns_val_t *valp = bpf_map_lookup_elem(&dns_hash, &tid);

    if (!valp)
        return 0;

    struct dns_event_t data = {};
    bpf_probe_read_kernel(&data.host, sizeof(data.host), (void *)valp->host);

    struct addrinfo *address = NULL;
    bpf_probe_read(&address, sizeof(address), valp->res);

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (!address)
            break;

        __u32 address_family;
        bpf_probe_read(&address_family, sizeof(address_family), &address->ai_family);

        if (address_family == AF_INET) {
            struct sockaddr_in *daddr;
            bpf_probe_read(&daddr, sizeof(daddr), &address->ai_addr);
            bpf_probe_read(&data.daddr, sizeof(data.daddr), &daddr->sin_addr.s_addr);
            bpf_perf_event_output(ctx, &dns_events, BPF_F_CURRENT_CPU, &data, sizeof(data));
        }
        else if (address_family == AF_INET6) {
            struct sockaddr_in6 *daddr6;
            bpf_probe_read(&daddr6, sizeof(daddr6), &address->ai_addr);
            bpf_probe_read(&data.daddr6, sizeof(data.daddr6), &daddr6->sin6_addr.in6_u.u6_addr32);
            bpf_perf_event_output(ctx, &dns_events, BPF_F_CURRENT_CPU, &data, sizeof(data));
        }

        if (bpf_probe_read(&address, sizeof(address), &address->ai_next) != 0)
            break;

        __builtin_memset(&data, 0, sizeof(data));
        bpf_probe_read_kernel(&data.host, sizeof(data.host), (void *)valp->host);
    }

    bpf_map_delete_elem(&dns_hash, &tid);
    return 0;
}

// Exec probe
SEC("kretprobe")
int BPF_KRETPROBE(exec_entry, long ret)
{
    if (ret != 0)
        return 0;

    struct exec_event_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();

    // Read task fields using CO-RE with null checks
    struct task_struct *parent = BPF_CORE_READ(task, parent);
    if (!parent)
        return 0;
    data.ppid = BPF_CORE_READ(parent, tgid);

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return 0;
    struct file *exe_file = BPF_CORE_READ(mm, exe_file);
    if (!exe_file)
        return 0;
    struct path exe_path = BPF_CORE_READ(exe_file, f_path);
    struct dentry *exe_dentry = BPF_CORE_READ(&exe_path, dentry);
    if (!exe_dentry)
        return 0;
    struct inode *exe_inode = BPF_CORE_READ(exe_dentry, d_inode);
    if (!exe_inode)
        return 0;
    data.ino = BPF_CORE_READ(exe_inode, i_ino);
    struct super_block *exe_sb = BPF_CORE_READ(exe_inode, i_sb);
    if (!exe_sb)
        return 0;
    data.dev = kernel_to_glibc_dev(BPF_CORE_READ(exe_sb, s_dev));

    // Parent info (default to 0 if unavailable)
    mm = BPF_CORE_READ(parent, mm);
    if (mm) {
        exe_file = BPF_CORE_READ(mm, exe_file);
        if (exe_file) {
            exe_path = BPF_CORE_READ(exe_file, f_path);
            exe_dentry = BPF_CORE_READ(&exe_path, dentry);
            if (exe_dentry) {
                exe_inode = BPF_CORE_READ(exe_dentry, d_inode);
                if (exe_inode) {
                    data.pino = BPF_CORE_READ(exe_inode, i_ino);
                    exe_sb = BPF_CORE_READ(exe_inode, i_sb);
                    if (exe_sb) {
                        data.pdev = kernel_to_glibc_dev(BPF_CORE_READ(exe_sb, s_dev));
                    }
                }
            }
        }
    }

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_kernel_str(&data.pcomm, sizeof(data.pcomm), BPF_CORE_READ(parent, comm));

    bpf_perf_event_output(ctx, &exec_events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

// Network bandwidth probes
static __always_inline int trace_sendrecv(void *ctx, struct socket *sock, int retval, int is_send)
{
    // Skip if error (negative) or invalid
    if (retval <= 0 || !sock)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    struct task_struct *parent = BPF_CORE_READ(task, parent);
    if (!parent)
        return 0;

    __u32 ppid = BPF_CORE_READ(parent, tgid);

    // Get task exe info with null checks
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return 0;
    struct file *exe_file = BPF_CORE_READ(mm, exe_file);
    if (!exe_file)
        return 0;
    struct path exe_path = BPF_CORE_READ(exe_file, f_path);
    struct dentry *exe_dentry = BPF_CORE_READ(&exe_path, dentry);
    if (!exe_dentry)
        return 0;
    struct inode *exe_inode = BPF_CORE_READ(exe_dentry, d_inode);
    if (!exe_inode)
        return 0;
    __u64 ino = BPF_CORE_READ(exe_inode, i_ino);
    struct super_block *exe_sb = BPF_CORE_READ(exe_inode, i_sb);
    if (!exe_sb)
        return 0;
    __u32 dev = kernel_to_glibc_dev(BPF_CORE_READ(exe_sb, s_dev));

    // Get parent exe info with null checks (default to 0 if unavailable)
    __u64 pino = 0;
    __u32 pdev = 0;
    mm = BPF_CORE_READ(parent, mm);
    if (mm) {
        exe_file = BPF_CORE_READ(mm, exe_file);
        if (exe_file) {
            exe_path = BPF_CORE_READ(exe_file, f_path);
            exe_dentry = BPF_CORE_READ(&exe_path, dentry);
            if (exe_dentry) {
                exe_inode = BPF_CORE_READ(exe_dentry, d_inode);
                if (exe_inode) {
                    pino = BPF_CORE_READ(exe_inode, i_ino);
                    exe_sb = BPF_CORE_READ(exe_inode, i_sb);
                    if (exe_sb) {
                        pdev = kernel_to_glibc_dev(BPF_CORE_READ(exe_sb, s_dev));
                    }
                }
            }
        }
    }

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    __u16 address_family = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (address_family == AF_INET) {
        struct sendrecv_event_t data = {};
        data.pid = pid;
        data.ppid = ppid;
        data.uid = uid;
        data.dev = dev;
        data.pdev = pdev;
        data.ino = ino;
        data.pino = pino;
        data.bytes = retval;

        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        bpf_probe_read_kernel_str(&data.pcomm, sizeof(data.pcomm), BPF_CORE_READ(parent, comm));
        data.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        data.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        data.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        data.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
        data.dport = __builtin_bswap16(data.dport);

        if (is_send)
            bpf_perf_event_output(ctx, &sendmsg_events, BPF_F_CURRENT_CPU, &data, sizeof(data));
        else
            bpf_perf_event_output(ctx, &recvmsg_events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }
    else if (address_family == AF_INET6) {
        struct sendrecv6_event_t data = {};
        data.pid = pid;
        data.ppid = ppid;
        data.uid = uid;
        data.dev = dev;
        data.pdev = pdev;
        data.ino = ino;
        data.pino = pino;
        data.bytes = retval;

        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        bpf_probe_read_kernel_str(&data.pcomm, sizeof(data.pcomm), BPF_CORE_READ(parent, comm));
        // Read IPv6 addresses using CO-RE with temporary variables to avoid packed alignment issues
        struct in6_addr temp_daddr = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
        struct in6_addr temp_saddr = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);
        __builtin_memcpy(&data.daddr, &temp_daddr, sizeof(data.daddr));
        __builtin_memcpy(&data.saddr, &temp_saddr, sizeof(data.saddr));
        data.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        data.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
        data.dport = __builtin_bswap16(data.dport);

        if (is_send)
            bpf_perf_event_output(ctx, &sendmsg6_events, BPF_F_CURRENT_CPU, &data, sizeof(data));
        else
            bpf_perf_event_output(ctx, &recvmsg6_events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }

    return 0;
}

SEC("fexit/sock_sendmsg")
int BPF_PROG(sock_sendmsg_ret, struct socket *sock, struct msghdr *msg, int ret)
{
    return trace_sendrecv(ctx, sock, ret, 1);
}

SEC("fexit/sock_recvmsg")
int BPF_PROG(sock_recvmsg_ret, struct socket *sock, struct msghdr *msg, int flags, int ret)
{
    return trace_sendrecv(ctx, sock, ret, 0);
}

char LICENSE[] SEC("license") = "GPL";
