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
#define MSG_PEEK 2         // recv flag: data left in queue, recounted on the real recv
#define MSG_ERRQUEUE 0x2000  // recv flag: reads the error queue, not received data

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
    __u16 family;  // AF_INET/AF_INET6: distinguishes a v4 0.0.0.0 from a v6 ::
} __attribute__((packed));

struct exec_event_t {
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    char gpcomm[TASK_COMM_LEN];
    __u64 ino;
    __u64 pino;
    __u64 gpino;
    __u32 pid;
    __u32 ppid;
    __u32 gppid;
    __u32 uid;
    __u32 dev;
    __u32 pdev;
    __u32 gpdev;
} __attribute__((packed));

// Per-connection aggregation: instead of one perf event per sendmsg/recvmsg,
// sum send/recv bytes and packets in a BPF hash map keyed by connection.
// userspace drains the map on a fixed interval with bpf_map_lookup_and_delete_elem
// (atomic per entry, no in-flight loss) and emits one event per connection, so
// the per-packet event rate and ancestry walk collapse to once per connection.
// v4 and v6 use separate maps to keep keys compact; the value layout is shared.
struct conn_key4_t {
    __u32 pid;
    __u32 netns;
    __u32 saddr;
    __u32 daddr;
    __u16 lport;
    __u16 dport;
    __u16 protocol;
    __u16 _pad;
} __attribute__((packed));

struct conn_key6_t {
    __u32 pid;
    __u32 netns;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    __u16 lport;
    __u16 dport;
    __u16 protocol;
    __u16 _pad;
} __attribute__((packed));

// conn_val_t is deliberately NOT packed: the 64-bit counters are updated with
// atomic adds, which require natural 8-byte alignment. Field order (char
// arrays, then u64s, then u32s) yields a 128-byte struct with no internal
// padding, so userspace can mirror it without packing either.
struct conn_val_t {
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    char gpcomm[TASK_COMM_LEN];
    __u64 ino;
    __u64 pino;
    __u64 gpino;
    __u64 send_bytes;
    __u64 recv_bytes;
    __u64 send_pkts;
    __u64 recv_pkts;
    __u32 ppid;
    __u32 gppid;
    __u32 uid;
    __u32 dev;
    __u32 pdev;
    __u32 gpdev;
};


// CO-RE compat for possible_net_t: on kernels built with CONFIG_NET_NS=n
// (or when BTF deduplication drops the field) `possible_net_t` has no
// `.net` member, which breaks direct field access at compile time.
// Define local "flavor" types (libbpf ___suffix convention) so the BPF
// source always compiles; `bpf_core_field_exists` guards the read at load.
struct possible_net_t___compat {
    struct net *net;
};

struct sock_common___compat {
    struct possible_net_t___compat skc_net;
};

struct sock___compat {
    struct sock_common___compat __sk_common;
};

static __always_inline __u32 read_netns(struct sock *sk) {
    struct sock___compat *s = (struct sock___compat *)sk;
    if (!bpf_core_field_exists(s->__sk_common.skc_net.net))
        return 0;
    struct net *n = BPF_CORE_READ(s, __sk_common.skc_net.net);
    if (!n)
        return 0;
    return BPF_CORE_READ(n, ns.inum);
}

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

// Per-connection byte accumulators, drained periodically by userspace.
// LRU so the map self-bounds under pathological connection churn; with a
// sub-second drain interval eviction should never trigger in practice.
// max_entries is resized at load from [monitoring].conn_map_max_entries.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conn_key4_t);
    __type(value, struct conn_val_t);
} conn_stats4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conn_key6_t);
    __type(value, struct conn_val_t);
} conn_stats6 SEC(".maps");

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

    // _str stops at the NUL: a fixed-size read faults (dropping the mapping)
    // when a short hostname sits within sizeof(host) of an unmapped page
    if (bpf_probe_read_user_str(&val.host, sizeof(val.host), node) > 0) {
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
            data.family = AF_INET;
            bpf_perf_event_output(ctx, &dns_events, BPF_F_CURRENT_CPU, &data, sizeof(data));
        }
        else if (address_family == AF_INET6) {
            struct sockaddr_in6 *daddr6;
            bpf_probe_read(&daddr6, sizeof(daddr6), &address->ai_addr);
            bpf_probe_read(&data.daddr6, sizeof(data.daddr6), &daddr6->sin6_addr.in6_u.u6_addr32);
            data.family = AF_INET6;
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

    // Read task fields using CO-RE with null checks.
    // real_parent (the creator), not parent (SIGCHLD recipient = the tracer
    // when ptraced) -- so a debugger/strace can't masquerade as the ancestry.
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
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

    // Grandparent info (default to 0 if unavailable)
    struct task_struct *grandparent = BPF_CORE_READ(parent, real_parent);
    if (grandparent) {
        data.gppid = BPF_CORE_READ(grandparent, tgid);
        bpf_probe_read_kernel_str(&data.gpcomm, sizeof(data.gpcomm), BPF_CORE_READ(grandparent, comm));
        mm = BPF_CORE_READ(grandparent, mm);
        if (mm) {
            exe_file = BPF_CORE_READ(mm, exe_file);
            if (exe_file) {
                exe_path = BPF_CORE_READ(exe_file, f_path);
                exe_dentry = BPF_CORE_READ(&exe_path, dentry);
                if (exe_dentry) {
                    exe_inode = BPF_CORE_READ(exe_dentry, d_inode);
                    if (exe_inode) {
                        data.gpino = BPF_CORE_READ(exe_inode, i_ino);
                        exe_sb = BPF_CORE_READ(exe_inode, i_sb);
                        if (exe_sb) {
                            data.gpdev = kernel_to_glibc_dev(BPF_CORE_READ(exe_sb, s_dev));
                        }
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

// Resolve process ancestry (exe inode/dev + comm for self, parent,
// grandparent) into a conn_val_t. Returns 0 on success, -1 if the calling
// task's own exe cannot be resolved (matching the original per-event
// behaviour of skipping such events). Runs only when a connection is first
// inserted into the stats map, not on every packet.
static __always_inline int fill_conn_ancestry(struct conn_val_t *val, __u32 uid)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return -1;
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (!parent)
        return -1;

    val->uid = uid;
    val->ppid = BPF_CORE_READ(parent, tgid);

    // Self exe info (required)
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return -1;
    struct file *exe_file = BPF_CORE_READ(mm, exe_file);
    if (!exe_file)
        return -1;
    struct path exe_path = BPF_CORE_READ(exe_file, f_path);
    struct dentry *exe_dentry = BPF_CORE_READ(&exe_path, dentry);
    if (!exe_dentry)
        return -1;
    struct inode *exe_inode = BPF_CORE_READ(exe_dentry, d_inode);
    if (!exe_inode)
        return -1;
    val->ino = BPF_CORE_READ(exe_inode, i_ino);
    struct super_block *exe_sb = BPF_CORE_READ(exe_inode, i_sb);
    if (!exe_sb)
        return -1;
    val->dev = kernel_to_glibc_dev(BPF_CORE_READ(exe_sb, s_dev));

    // Parent exe info (default to 0 if unavailable)
    mm = BPF_CORE_READ(parent, mm);
    if (mm) {
        exe_file = BPF_CORE_READ(mm, exe_file);
        if (exe_file) {
            exe_path = BPF_CORE_READ(exe_file, f_path);
            exe_dentry = BPF_CORE_READ(&exe_path, dentry);
            if (exe_dentry) {
                exe_inode = BPF_CORE_READ(exe_dentry, d_inode);
                if (exe_inode) {
                    val->pino = BPF_CORE_READ(exe_inode, i_ino);
                    exe_sb = BPF_CORE_READ(exe_inode, i_sb);
                    if (exe_sb) {
                        val->pdev = kernel_to_glibc_dev(BPF_CORE_READ(exe_sb, s_dev));
                    }
                }
            }
        }
    }

    // Grandparent info (default to 0 if unavailable)
    struct task_struct *grandparent = BPF_CORE_READ(parent, real_parent);
    if (grandparent) {
        val->gppid = BPF_CORE_READ(grandparent, tgid);
        bpf_probe_read_kernel_str(&val->gpcomm, sizeof(val->gpcomm), BPF_CORE_READ(grandparent, comm));
        mm = BPF_CORE_READ(grandparent, mm);
        if (mm) {
            exe_file = BPF_CORE_READ(mm, exe_file);
            if (exe_file) {
                exe_path = BPF_CORE_READ(exe_file, f_path);
                exe_dentry = BPF_CORE_READ(&exe_path, dentry);
                if (exe_dentry) {
                    exe_inode = BPF_CORE_READ(exe_dentry, d_inode);
                    if (exe_inode) {
                        val->gpino = BPF_CORE_READ(exe_inode, i_ino);
                        exe_sb = BPF_CORE_READ(exe_inode, i_sb);
                        if (exe_sb) {
                            val->gpdev = kernel_to_glibc_dev(BPF_CORE_READ(exe_sb, s_dev));
                        }
                    }
                }
            }
        }
    }

    bpf_get_current_comm(&val->comm, sizeof(val->comm));
    bpf_probe_read_kernel_str(&val->pcomm, sizeof(val->pcomm), BPF_CORE_READ(parent, comm));
    return 0;
}

// Network bandwidth probes. Bytes are accumulated per connection in the
// conn_stats4/6 maps (see the map definitions for the design rationale).
// The expensive ancestry walk runs only when a connection is first seen;
// subsequent packets are a lookup plus two atomic adds.
// msg is the sendmsg/recvmsg header; for unconnected udp the peer is in
// msg_name rather than the sock, so dport/daddr fall back to it.
static __always_inline int trace_sendrecv(void *ctx, struct sock *sk, struct msghdr *msg, int retval, int is_send)
{
    // Skip if error (negative) or invalid
    if (retval <= 0 || !sk)
        return 0;

    __u16 address_family = BPF_CORE_READ(sk, __sk_common.skc_family);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid();
    __u32 netns = read_netns(sk);
    __u16 dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
    __u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 protocol = BPF_CORE_READ(sk, sk_protocol);

    if (address_family == AF_INET) {
        struct conn_key4_t key = {};
        key.pid = pid;
        key.netns = netns;
        key.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        key.lport = lport;
        key.dport = dport;
        key.protocol = protocol;

        // unconnected udp: peer is in msg_name, not the sock
        if (key.dport == 0 && msg) {
            void *name = BPF_CORE_READ(msg, msg_name);
            int namelen = BPF_CORE_READ(msg, msg_namelen);
            if (name && namelen >= (int)sizeof(struct sockaddr_in)) {
                struct sockaddr_in sin = {};
                bpf_probe_read_kernel(&sin, sizeof(sin), name);
                if (sin.sin_family == AF_INET) {
                    key.daddr = sin.sin_addr.s_addr;
                    key.dport = __builtin_bswap16(sin.sin_port);
                }
            }
        }

        struct conn_val_t *val = bpf_map_lookup_elem(&conn_stats4, &key);
        if (!val) {
            struct conn_val_t newval = {};
            if (fill_conn_ancestry(&newval, uid) != 0)
                return 0;
            bpf_map_update_elem(&conn_stats4, &key, &newval, BPF_NOEXIST);
            val = bpf_map_lookup_elem(&conn_stats4, &key);
            if (!val)
                return 0;
        }
        if (is_send) {
            __sync_fetch_and_add(&val->send_bytes, (__u64)retval);
            __sync_fetch_and_add(&val->send_pkts, 1);
        } else {
            __sync_fetch_and_add(&val->recv_bytes, (__u64)retval);
            __sync_fetch_and_add(&val->recv_pkts, 1);
        }
    }
    else if (address_family == AF_INET6) {
        struct conn_key6_t key = {};
        key.pid = pid;
        key.netns = netns;
        struct in6_addr temp_saddr = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);
        struct in6_addr temp_daddr = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
        __builtin_memcpy(&key.saddr, &temp_saddr, sizeof(key.saddr));
        __builtin_memcpy(&key.daddr, &temp_daddr, sizeof(key.daddr));
        key.lport = lport;
        key.dport = dport;
        key.protocol = protocol;

        // unconnected udp: peer is in msg_name, not the sock
        if (key.dport == 0 && msg) {
            void *name = BPF_CORE_READ(msg, msg_name);
            int namelen = BPF_CORE_READ(msg, msg_namelen);
            if (name && namelen >= (int)sizeof(struct sockaddr_in6)) {
                struct sockaddr_in6 sin6 = {};
                bpf_probe_read_kernel(&sin6, sizeof(sin6), name);
                if (sin6.sin6_family == AF_INET6) {
                    __builtin_memcpy(&key.daddr, &sin6.sin6_addr, sizeof(key.daddr));
                    key.dport = __builtin_bswap16(sin6.sin6_port);
                }
            }
        }

        struct conn_val_t *val = bpf_map_lookup_elem(&conn_stats6, &key);
        if (!val) {
            struct conn_val_t newval = {};
            if (fill_conn_ancestry(&newval, uid) != 0)
                return 0;
            bpf_map_update_elem(&conn_stats6, &key, &newval, BPF_NOEXIST);
            val = bpf_map_lookup_elem(&conn_stats6, &key);
            if (!val)
                return 0;
        }
        if (is_send) {
            __sync_fetch_and_add(&val->send_bytes, (__u64)retval);
            __sync_fetch_and_add(&val->send_pkts, 1);
        } else {
            __sync_fetch_and_add(&val->recv_bytes, (__u64)retval);
            __sync_fetch_and_add(&val->recv_pkts, 1);
        }
    }

    return 0;
}

// send: hook inet_sendmsg / inet6_sendmsg, the per-family sendmsg dispatch.
// one hook per family covers tcp, udp, raw and icmp sends plus write()/writev()
// without double counting. takes a struct socket *, so sk is derived like recv.
SEC("fexit/inet_sendmsg")
int BPF_PROG(inet_sendmsg_ret, struct socket *sock, struct msghdr *msg, size_t size, int ret)
{
    struct sock *sk = BPF_CORE_READ(sock, sk);
    return trace_sendrecv(ctx, sk, msg, ret, 1);
}

SEC("fexit/inet6_sendmsg")
int BPF_PROG(inet6_sendmsg_ret, struct socket *sock, struct msghdr *msg, size_t size, int ret)
{
    struct sock *sk = BPF_CORE_READ(sock, sk);
    return trace_sendrecv(ctx, sk, msg, ret, 1);
}

// recv: hook inet_recvmsg / inet6_recvmsg, the per-family recvmsg dispatch.
SEC("fexit/inet_recvmsg")
int BPF_PROG(inet_recvmsg_ret, struct socket *sock, struct msghdr *msg, size_t size, int flags, int ret) {
    if (flags & (MSG_PEEK | MSG_ERRQUEUE))  // don't double count peeks or count errqueue reads
        return 0;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    return trace_sendrecv(ctx, sk, msg, ret, 0);
}

SEC("fexit/inet6_recvmsg")
int BPF_PROG(inet6_recvmsg_ret, struct socket *sock, struct msghdr *msg, size_t size, int flags, int ret) {
    if (flags & (MSG_PEEK | MSG_ERRQUEUE))
        return 0;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    return trace_sendrecv(ctx, sk, msg, ret, 0);
}

// recv: also hook sock_common_recvmsg -- the recvmsg proto_ops slot for af_inet6
// raw sockets (and l2tp-over-ip, dccp), which skip inet6_recvmsg. disjoint from
// the inet hooks (tcp/udp/icmp/raw-v4/mptcp use inet_recvmsg) so no double
// counting; non-inet families that share this slot hit the family filter.
SEC("fexit/sock_common_recvmsg")
int BPF_PROG(sock_common_recvmsg_ret, struct socket *sock, struct msghdr *msg, size_t size, int flags, int ret) {
    if (flags & (MSG_PEEK | MSG_ERRQUEUE))
        return 0;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    return trace_sendrecv(ctx, sk, msg, ret, 0);
}

// recv via splice()/sendfile() from a tcp socket: tcp_splice_read moves bytes to a
// pipe without a recvmsg, so the recvmsg hooks never fire. ret is bytes moved;
// disjoint from those hooks (normal recv never calls it) so no double counting.
SEC("fexit/tcp_splice_read")
int BPF_PROG(tcp_splice_read_ret, struct socket *sock, void *ppos, void *pipe, size_t len, unsigned int flags, long ret) {
    struct sock *sk = BPF_CORE_READ(sock, sk);
    return trace_sendrecv(ctx, sk, 0, ret, 0);
}

SEC("fexit/mptcp_splice_read")
int BPF_PROG(mptcp_splice_read_ret, struct socket *sock, void *ppos, void *pipe, size_t len, unsigned int flags, long ret) {
    struct sock *sk = BPF_CORE_READ(sock, sk);
    return trace_sendrecv(ctx, sk, 0, ret, 0);
}

// recv via io_uring zero-copy (IORING_OP_RECV_ZC): io_zcrx_recv -> tcp_read_sock, bypassing
// recvmsg and the splice hooks. tcp_read_sock is the exported 3-arg wrapper (sk is the low-level
// sock); ret is bytes read. tcp_read_sock is also every proto_ops->read_sock: in-kernel readers
// (kTLS copy-mode ciphertext -- recounted as plaintext at inet_recvmsg -- strparser/kcm/espintcp
// in softirq with a borrowed current, nvme-tcp/iscsi kworkers) reach it too, so count only calls
// whose recv_actor is io_uring's io_zcrx_recv_skb. Userspace writes its kallsyms address after
// load, before attach (0 = count nothing); if the symbol is absent the program stays disabled.
volatile __u64 io_zcrx_actor SEC(".data.io_zcrx") = 0;

SEC("fexit/tcp_read_sock")
int BPF_PROG(tcp_read_sock_ret, struct sock *sk, void *desc, void *recv_actor, int ret) {
    // recv_actor is a function pointer (FUNC_PROTO), which BTF ctx access refuses to
    // load directly; bpf_get_func_arg reads the raw argument value instead
    __u64 actor;
    if (bpf_get_func_arg(ctx, 2, &actor) || actor != io_zcrx_actor)
        return 0;
    return trace_sendrecv(ctx, sk, 0, ret, 0);
}

char LICENSE[] SEC("license") = "GPL";
