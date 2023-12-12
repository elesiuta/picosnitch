#!/usr/bin/env python3
# picosnitch
# Copyright (C) 2020-2023 Eric Lesiuta

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# https://github.com/elesiuta/picosnitch

import collections
import ctypes
import ctypes.util
import functools
import ipaddress
import multiprocessing
import os
import pickle
import signal
import site
import socket
import struct
import sys
import time
import typing

# add site dirs for system and user installed packages (to import bcc with picosnitch installed via pipx/venv, or dependencies installed via user)
site.addsitedir("/usr/lib/python3/dist-packages")
site.addsitedir(os.path.expandvars("$PYTHON_USER_SITE"))
import psutil

from .constants import FD_CACHE, PID_CACHE, ST_DEV_MASK


def monitor_subprocess_initial_poll() -> list:
    """poll initial processes and connections using psutil"""
    initial_processes = []
    for pid in psutil.pids():
        try:
            proc = psutil.Process(pid).as_dict(attrs=["name", "exe", "pid", "ppid", "uids"], ad_value="")
            proc["uid"] = proc["uids"][0]
            proc["pname"] = psutil.Process(proc["ppid"]).name()
            proc["raddr"] = ""
            proc["rport"] = -1
            proc["laddr"] = ""
            proc["lport"] = -1
            initial_processes.append(proc)
        except Exception:
            pass
    for conn in psutil.net_connections(kind="all"):
        try:
            proc = psutil.Process(conn.pid).as_dict(attrs=["name", "exe", "pid", "ppid", "uids"], ad_value="")
            proc["uid"] = proc["uids"][0]
            proc["pname"] = psutil.Process(proc["ppid"]).name()
            proc["raddr"] = conn.raddr.ip
            proc["rport"] = conn.raddr.port
            proc["laddr"] = conn.laddr.ip
            proc["lport"] = conn.laddr.port
            initial_processes.append(proc)
        except Exception:
            pass
    return initial_processes


def monitor_subprocess(config: dict, fan_fd, snitch_pipes, q_error, q_in, _q_out):
    """runs a bpf program to monitor the system for new connections and puts info into a pipe for primary_subprocess"""
    # initialization of subprocess
    try:
        os.nice(-20)
    except Exception:
        pass
    import bcc
    from bcc import BPF
    parent_process = multiprocessing.parent_process()
    signal.signal(signal.SIGTERM, lambda *args: sys.exit(0))
    snitch_pipe_0, snitch_pipe_1, snitch_pipe_2, snitch_pipe_3, snitch_pipe_4 = snitch_pipes
    EVERY_EXE: typing.Final[bool] = config["Every exe (not just conns)"]
    PAGE_CNT: typing.Final[int] = config["Perf ring buffer (pages)"]
    # fanotify (for watching executables for modification)
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    _FAN_MARK_ADD = 0x1
    _FAN_MARK_REMOVE = 0x2
    _FAN_MARK_FLUSH = 0x80
    _FAN_MODIFY = 0x2
    libc.fanotify_mark(fan_fd, _FAN_MARK_FLUSH, _FAN_MODIFY, -1, None)
    # domain and file descriptor cache, domains are cached for the life of the program, fd has a fixed size, populate with dummy values
    domain_dict = collections.defaultdict(str)
    fd_dict = collections.OrderedDict()
    for x in range(FD_CACHE):
        fd_dict[f"tmp{x}"] = (0,)
    self_pid = os.getpid()
    # function for getting an existing or opening a new file descriptor based on st_dev and st_ino
    def get_fd(st_dev: int, st_ino: int, pid: int, port: int) -> typing.Tuple[int, int, int, str, str]:
        st_dev = st_dev & ST_DEV_MASK
        sig = f"{st_dev} {st_ino}"
        try:
            # check if it is in the cache and move it to the most recent position
            fd_dict.move_to_end(sig)
            fd, fd_path, exe = fd_dict[sig]
            if not fd:
                # sig is in cache but fd is 0, try again to open it
                # add a dummy value to the oldest postition to be popped off on retry so cache size is maintained
                # since sig is already in cache, value will just be updated without increasing cache size
                fd_dict[f"tmp{sig}"] = (0,)
                fd_dict.move_to_end(f"tmp{sig}", last=False)
                raise Exception("previous attempt failed, probably due to process terminating too quickly, try again")
        except Exception:
            # open a new file descriptor and pop off the oldest one
            # watch it with fanotify, and also cache the apparent executable path with it
            try:
                fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY)
                libc.fanotify_mark(fan_fd, _FAN_MARK_ADD, _FAN_MODIFY, fd, None)
                fd_path = f"/proc/{self_pid}/fd/{fd}"
            except Exception:
                fd, fd_path = 0, ""
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except Exception:
                exe = ""
            if fd and (st_dev, st_ino) != get_fstat(fd):
                if EVERY_EXE or port != -1:
                    q_error.put(f"Exe inode changed for (pid: {pid} fd: {fd} dev: {st_dev} ino: {st_ino}) before FD could be opened, using port: {port}")
                st_dev, st_ino = get_fstat(fd)
                sig = f"{st_dev} {st_ino}"
                if EVERY_EXE or port != -1:
                    q_error.put(f"New inode for (pid: {pid} fd: {fd} dev: {st_dev} ino: {st_ino} exe: {exe})")
            fd_dict[sig] = (fd, fd_path, exe)
            try:
                if fd_old := fd_dict.popitem(last=False)[1][0]:
                    libc.fanotify_mark(fan_fd, _FAN_MARK_REMOVE, _FAN_MODIFY, fd_old, None)
                    os.close(fd_old)
            except Exception:
                pass
        return (st_dev, st_ino, pid, fd_path, exe)
    # function for getting or looking up the cmdline for a pid
    @functools.lru_cache(maxsize=PID_CACHE)
    def get_cmdline(pid: int) -> str:
        try:
            with open(f"/proc/{pid}/cmdline", "r") as f:
                return f.read()
        except Exception:
            return ""
    # get current connections
    for proc in monitor_subprocess_initial_poll():
        try:
            stat = os.stat(f"/proc/{proc['pid']}/exe")
            pstat = os.stat(f"/proc/{proc['ppid']}/exe")
            cmd = get_cmdline(proc["pid"])
            pcmd = get_cmdline(proc["ppid"])
            st_dev, st_ino, pid, fd, exe = get_fd(stat.st_dev, stat.st_ino, proc["pid"], proc["rport"])
            pst_dev, pst_ino, ppid, pfd, pexe = get_fd(pstat.st_dev, pstat.st_ino, proc["ppid"], -1)
            if EVERY_EXE or proc["rport"] != -1:
                snitch_pipe_0.send_bytes(pickle.dumps({"pid": pid, "name": proc["name"], "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd,
                                                     "ppid": ppid, "pname": proc["pname"], "pfd": pfd, "pdev": pst_dev, "pino": pst_ino, "pexe": pexe, "pcmdline": pcmd,
                                                     "uid": proc["uid"], "send": 0, "recv": 0, "lport": proc["lport"], "rport": proc["rport"], "laddr": proc["laddr"], "raddr": proc["raddr"], "domain": domain_dict[proc["raddr"]]}))
        except Exception:
            pass
    # initialize bpf program
    bpf_text = bpf_text_base + bpf_text_bandwidth_structs + bpf_text_bandwidth_probe.replace("int flags, ", "") + bpf_text_bandwidth_probe.replace("sendmsg", "recvmsg")
    try:
        assert BPF.support_kfunc(), "BPF.support_kfunc() was not True, check BCC version or Kernel Configuration"
        b = BPF(text=bpf_text)
        b.attach_kretprobe(event=b.get_syscall_fnname("execve"), fn_name="exec_entry")
    except Exception as e:
        q_error.put("Init BPF %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))
        time.sleep(5)
        os.kill(parent_process.pid, signal.SIGTERM)
        raise e
    use_getaddrinfo_uprobe = False
    if bcc.__version__ == "EAD-HASH-NOTFOUND+GITDIR-N" or tuple(map(int, bcc.__version__.split(".")[0:2])) >= (0, 23):
        try:
            b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="dns_entry")
            b.attach_uretprobe(name="c", sym="getaddrinfo", fn_name="dns_return")
            use_getaddrinfo_uprobe = True
        except Exception:
            q_error.put("BPF.attach_uprobe() failed for getaddrinfo, falling back to only using reverse DNS lookup")
    # callbacks for bpf events, read event and put into a pipe for primary_subprocess
    def queue_lost(event, *args):
        q_error.put(f"BPF callbacks not processing fast enough, missed {event} event, try increasing 'Perf ring buffer (pages)' (power of two) if this continues")
    def queue_sendv4_event(cpu, data, size):
        event = b["sendmsg_events"].event(data)
        st_dev, st_ino, pid, fd, exe = get_fd(event.dev, event.ino, event.pid, event.dport)
        pst_dev, pst_ino, ppid, pfd, pexe = get_fd(event.pdev, event.pino, event.ppid, -1)
        cmd = get_cmdline(event.pid)
        pcmd = get_cmdline(event.ppid)
        laddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.saddr))
        raddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))
        snitch_pipe_0.send_bytes(pickle.dumps({"pid": pid, "name": event.comm.decode(), "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd,
                                             "ppid": ppid, "pname": event.pcomm.decode(), "pfd": pfd, "pdev": pst_dev, "pino": pst_ino, "pexe": pexe, "pcmdline": pcmd,
                                             "uid": event.uid, "send": event.bytes, "recv": 0, "lport": event.lport, "rport": event.dport, "laddr": laddr, "raddr": raddr, "domain": domain_dict[raddr]}))
    def queue_sendv6_event(cpu, data, size):
        event = b["sendmsg6_events"].event(data)
        st_dev, st_ino, pid, fd, exe = get_fd(event.dev, event.ino, event.pid, event.dport)
        pst_dev, pst_ino, ppid, pfd, pexe = get_fd(event.pdev, event.pino, event.ppid, -1)
        cmd = get_cmdline(event.pid)
        pcmd = get_cmdline(event.ppid)
        laddr = socket.inet_ntop(socket.AF_INET6, event.saddr)
        raddr = socket.inet_ntop(socket.AF_INET6, event.daddr)
        snitch_pipe_1.send_bytes(pickle.dumps({"pid": pid, "name": event.comm.decode(), "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd,
                                             "ppid": ppid, "pname": event.pcomm.decode(), "pfd": pfd, "pdev": pst_dev, "pino": pst_ino, "pexe": pexe, "pcmdline": pcmd,
                                             "uid": event.uid, "send": event.bytes, "recv": 0, "lport": event.lport, "rport": event.dport, "laddr": laddr, "raddr": raddr, "domain": domain_dict[raddr]}))
    def queue_recvv4_event(cpu, data, size):
        event = b["recvmsg_events"].event(data)
        st_dev, st_ino, pid, fd, exe = get_fd(event.dev, event.ino, event.pid, event.dport)
        pst_dev, pst_ino, ppid, pfd, pexe = get_fd(event.pdev, event.pino, event.ppid, -1)
        cmd = get_cmdline(event.pid)
        pcmd = get_cmdline(event.ppid)
        laddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.saddr))
        raddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))
        snitch_pipe_2.send_bytes(pickle.dumps({"pid": pid, "name": event.comm.decode(), "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd,
                                             "ppid": ppid, "pname": event.pcomm.decode(), "pfd": pfd, "pdev": pst_dev, "pino": pst_ino, "pexe": pexe, "pcmdline": pcmd,
                                             "uid": event.uid, "send": 0, "recv": event.bytes, "lport": event.lport, "rport": event.dport, "laddr": laddr, "raddr": raddr, "domain": domain_dict[raddr]}))
    def queue_recvv6_event(cpu, data, size):
        event = b["recvmsg6_events"].event(data)
        st_dev, st_ino, pid, fd, exe = get_fd(event.dev, event.ino, event.pid, event.dport)
        pst_dev, pst_ino, ppid, pfd, pexe = get_fd(event.pdev, event.pino, event.ppid, -1)
        cmd = get_cmdline(event.pid)
        pcmd = get_cmdline(event.ppid)
        laddr = socket.inet_ntop(socket.AF_INET6, event.saddr)
        raddr = socket.inet_ntop(socket.AF_INET6, event.daddr)
        snitch_pipe_3.send_bytes(pickle.dumps({"pid": pid, "name": event.comm.decode(), "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd,
                                             "ppid": ppid, "pname": event.pcomm.decode(), "pfd": pfd, "pdev": pst_dev, "pino": pst_ino, "pexe": pexe, "pcmdline": pcmd,
                                             "uid": event.uid, "send": 0, "recv": event.bytes, "lport": event.lport, "rport": event.dport, "laddr": laddr, "raddr": raddr, "domain": domain_dict[raddr]}))
    def queue_exec_event(cpu, data, size):
        event = b["exec_events"].event(data)
        st_dev, st_ino, pid, fd, exe = get_fd(event.dev, event.ino, event.pid, -1)
        pst_dev, pst_ino, ppid, pfd, pexe = get_fd(event.pdev, event.pino, event.ppid, -1)
        cmd = get_cmdline(event.pid)
        pcmd = get_cmdline(event.ppid)
        if EVERY_EXE:
            snitch_pipe_4.send_bytes(pickle.dumps({"pid": pid, "name": event.comm.decode(), "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd,
                                                 "ppid": ppid, "pname": event.pcomm.decode(), "pfd": pfd, "pdev": pst_dev, "pino": pst_ino, "pexe": pexe, "pcmdline": pcmd,
                                                 "uid": event.uid, "send": 0, "recv": 0, "lport": -1, "rport": -1, "laddr": "", "raddr": "", "domain": ""}))
    def queue_dns_event(cpu, data, size):
        event = b["dns_events"].event(data)
        if event.daddr:
            ip = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))
        else:
            ip = socket.inet_ntop(socket.AF_INET6, event.daddr6)
        domain = event.host.decode("utf-8", "replace")
        try:
            _ = ipaddress.ip_address(domain)
        except ValueError:
            domain_dict[ip] = ".".join(reversed(domain.split(".")))
    b["exec_events"].open_perf_buffer(queue_exec_event, page_cnt=PAGE_CNT, lost_cb=lambda *args: queue_lost("exec", *args))
    if use_getaddrinfo_uprobe:
        b["dns_events"].open_perf_buffer(queue_dns_event, page_cnt=PAGE_CNT, lost_cb=lambda *args: queue_lost("dns", *args))
    b["sendmsg_events"].open_perf_buffer(queue_sendv4_event, page_cnt=PAGE_CNT*4, lost_cb=lambda *args: queue_lost("sendv4", *args))
    b["sendmsg6_events"].open_perf_buffer(queue_sendv6_event, page_cnt=PAGE_CNT*4, lost_cb=lambda *args: queue_lost("sendv6", *args))
    b["recvmsg_events"].open_perf_buffer(queue_recvv4_event, page_cnt=PAGE_CNT*4, lost_cb=lambda *args: queue_lost("recvv4", *args))
    b["recvmsg6_events"].open_perf_buffer(queue_recvv6_event, page_cnt=PAGE_CNT*4, lost_cb=lambda *args: queue_lost("recvv6", *args))
    # main loop
    while True:
        if not parent_process.is_alive() or not q_in.empty():
            return 0
        try:
            b.perf_buffer_poll(timeout=-1)
        except Exception as e:
            q_error.put("BPF %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))


bpf_text_base = """
// This eBPF program was based on the following sources
// https://github.com/p-/socket-connect-bpf/blob/7f386e368759e53868a078570254348e73e73e22/securitySocketConnectSrc.bpf
// https://github.com/iovisor/bcc/blob/master/tools/execsnoop.py
// https://github.com/iovisor/bcc/blob/master/tools/gethostlatency.py
// https://github.com/iovisor/bcc/blob/master/tools/tcpconnect.py
// https://www.gcardone.net/2020-07-31-per-process-bandwidth-monitoring-on-Linux-with-bpftrace/

#include <uapi/linux/ptrace.h>
#include <linux/socket.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <net/sock.h>

struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    u32 ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};

struct dns_val_t {
    char host[80];
    struct addrinfo **res;
};
BPF_HASH(dns_hash, u32, struct dns_val_t);

struct dns_event_t {
    char host[80];
    u32 daddr;
    unsigned __int128 daddr6;
} __attribute__((packed));
BPF_PERF_OUTPUT(dns_events);

struct exec_event_t {
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    u64 ino;
    u64 pino;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 dev;
    u32 pdev;
} __attribute__((packed));
BPF_PERF_OUTPUT(exec_events);

int dns_entry(struct pt_regs *ctx, const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    if (PT_REGS_PARM1(ctx)) {
        struct dns_val_t val = {.res = res};
        if (bpf_probe_read_user(&val.host, sizeof(val.host), (void *)PT_REGS_PARM1(ctx)) == 0) {
            u32 tid = (u32)bpf_get_current_pid_tgid();
            dns_hash.update(&tid, &val);
        }
    }
    return 0;
}

int dns_return(struct pt_regs *ctx) {
    struct dns_val_t *valp;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    valp = dns_hash.lookup(&tid);
    if (valp) {
        struct dns_event_t data = {};
        bpf_probe_read_kernel(&data.host, sizeof(data.host), (void *)valp->host);
        struct addrinfo *address;
        bpf_probe_read(&address, sizeof(address), valp->res);
        for (int i = 0; i < 8; i++) {
            u32 address_family;
            bpf_probe_read(&address_family, sizeof(address_family), &address->ai_family);
            if (address_family == AF_INET) {
                struct sockaddr_in *daddr;
                bpf_probe_read(&daddr, sizeof(daddr), &address->ai_addr);
                bpf_probe_read(&data.daddr, sizeof(data.daddr), &daddr->sin_addr.s_addr);
                dns_events.perf_submit(ctx, &data, sizeof(data));
            }
            else if (address_family == AF_INET6) {
                struct sockaddr_in6 *daddr6;
                bpf_probe_read(&daddr6, sizeof(daddr6), &address->ai_addr);
                bpf_probe_read(&data.daddr6, sizeof(data.daddr6), &daddr6->sin6_addr.in6_u.u6_addr32);
                dns_events.perf_submit(ctx, &data, sizeof(data));
            }
            if (bpf_probe_read(&address, sizeof(address), &address->ai_next) != 0) break;
            struct dns_event_t data = {};
            bpf_probe_read_kernel(&data.host, sizeof(data.host), (void *)valp->host);
        }
        dns_hash.delete(&tid);
    }
    return 0;
}

int exec_entry(struct pt_regs *ctx) {
    if (PT_REGS_RC(ctx) == 0) {
        struct exec_event_t data = {};
        data.pid = bpf_get_current_pid_tgid() >> 32;
        data.uid = bpf_get_current_uid_gid();
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        data.ppid = task->real_parent->tgid;
        data.ino = task->mm->exe_file->f_path.dentry->d_inode->i_ino;
        data.dev = task->mm->exe_file->f_path.dentry->d_inode->i_sb->s_dev;
        data.dev = new_encode_dev(data.dev);
        data.pino = task->real_parent->mm->exe_file->f_path.dentry->d_inode->i_ino;
        data.pdev = task->real_parent->mm->exe_file->f_path.dentry->d_inode->i_sb->s_dev;
        data.pdev = new_encode_dev(data.pdev);
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        bpf_probe_read_kernel_str(&data.pcomm, sizeof(data.pcomm), &task->real_parent->comm);
        exec_events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}
"""


bpf_text_bandwidth_structs = """
struct sendrecv_event_t {
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    u64 ino;
    u64 pino;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 dev;
    u32 pdev;
    u32 bytes;
    u32 daddr;
    u32 saddr;
    u16 dport;
    u16 lport;
} __attribute__((packed));
BPF_PERF_OUTPUT(sendmsg_events);
BPF_PERF_OUTPUT(recvmsg_events);

struct sendrecv6_event_t {
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    unsigned __int128 daddr;
    unsigned __int128 saddr;
    u64 ino;
    u64 pino;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 dev;
    u32 pdev;
    u32 bytes;
    u16 dport;
    u16 lport;
} __attribute__((packed));
BPF_PERF_OUTPUT(sendmsg6_events);
BPF_PERF_OUTPUT(recvmsg6_events);
"""


bpf_text_bandwidth_probe = """
KRETFUNC_PROBE(sock_sendmsg, struct socket *sock, struct msghdr *msg, int flags, u32 retval) {
    if (retval >= 0 && retval < 0x7fffffff) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u32 uid = bpf_get_current_uid_gid();
        struct task_struct *task, *parent;
        struct mm_struct *mm;
        struct file *exe_file;
        struct dentry *exe_dentry;
        struct inode *exe_inode;
        struct super_block *exe_sb;
        u64 ino, pino;
        u32 ppid, dev, pdev;
        task = (struct task_struct *)bpf_get_current_task();
        // u32 ppid = task->real_parent->tgid;
        // u64 ino = task->mm->exe_file->f_path.dentry->d_inode->i_ino;
        // u32 dev = task->mm->exe_file->f_path.dentry->d_inode->i_sb->s_dev;
        if (bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent)) return 0;
        if (bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent->tgid)) return 0;
        if (bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm)) return 0;
        if (bpf_probe_read_kernel(&exe_file, sizeof(exe_file), &mm->exe_file)) return 0;
        if (bpf_probe_read_kernel(&exe_dentry, sizeof(exe_dentry), &exe_file->f_path.dentry)) return 0;
        if (bpf_probe_read_kernel(&exe_inode, sizeof(exe_inode), &exe_dentry->d_inode)) return 0;
        if (bpf_probe_read_kernel(&ino, sizeof(ino), &exe_inode->i_ino)) return 0;
        if (bpf_probe_read_kernel(&exe_sb, sizeof(exe_sb), &exe_inode->i_sb)) return 0;
        if (bpf_probe_read_kernel(&dev, sizeof(dev), &exe_sb->s_dev)) return 0;
        dev = new_encode_dev(dev);
        // u64 pino = task->real_parent->mm->exe_file->f_path.dentry->d_inode->i_ino;
        // u32 pdev = task->real_parent->mm->exe_file->f_path.dentry->d_inode->i_sb->s_dev;
        if (bpf_probe_read_kernel(&mm, sizeof(mm), &parent->mm)) return 0;
        if (bpf_probe_read_kernel(&exe_file, sizeof(exe_file), &mm->exe_file)) return 0;
        if (bpf_probe_read_kernel(&exe_dentry, sizeof(exe_dentry), &exe_file->f_path.dentry)) return 0;
        if (bpf_probe_read_kernel(&exe_inode, sizeof(exe_inode), &exe_dentry->d_inode)) return 0;
        if (bpf_probe_read_kernel(&pino, sizeof(pino), &exe_inode->i_ino)) return 0;
        if (bpf_probe_read_kernel(&exe_sb, sizeof(exe_sb), &exe_inode->i_sb)) return 0;
        if (bpf_probe_read_kernel(&pdev, sizeof(pdev), &exe_sb->s_dev)) return 0;
        pdev = new_encode_dev(pdev);
        u32 address_family = sock->sk->__sk_common.skc_family;
        if (address_family == AF_INET) {
            struct sendrecv_event_t data = {.pid = pid, .ppid = ppid, .uid = uid, .dev = dev, .pdev = pdev, .ino = ino, .pino = pino, .bytes = retval};
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            bpf_probe_read_kernel_str(&data.pcomm, sizeof(data.pcomm), &parent->comm);
            bpf_probe_read(&data.daddr, sizeof(data.daddr), &sock->sk->__sk_common.skc_daddr);
            bpf_probe_read(&data.saddr, sizeof(data.saddr), &sock->sk->__sk_common.skc_rcv_saddr);
            bpf_probe_read(&data.dport, sizeof(data.dport), &sock->sk->__sk_common.skc_dport);
            bpf_probe_read(&data.lport, sizeof(data.lport), &sock->sk->__sk_common.skc_num);
            data.dport = ntohs(data.dport);
            sendmsg_events.perf_submit(ctx, &data, sizeof(data));
        }
        else if (address_family == AF_INET6) {
            struct sendrecv6_event_t data = {.pid = pid, .ppid = ppid, .uid = uid, .dev = dev, .pdev = pdev, .ino = ino, .pino = pino, .bytes = retval};
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            bpf_probe_read_kernel_str(&data.pcomm, sizeof(data.pcomm), &parent->comm);
            bpf_probe_read(&data.daddr, sizeof(data.daddr), &sock->sk->__sk_common.skc_v6_daddr);
            bpf_probe_read(&data.saddr, sizeof(data.saddr), &sock->sk->__sk_common.skc_v6_rcv_saddr);
            bpf_probe_read(&data.dport, sizeof(data.dport), &sock->sk->__sk_common.skc_dport);
            bpf_probe_read(&data.lport, sizeof(data.lport), &sock->sk->__sk_common.skc_num);
            data.dport = ntohs(data.dport);
            sendmsg6_events.perf_submit(ctx, &data, sizeof(data));
        }
    }
    return 0;
}
"""

