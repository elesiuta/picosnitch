# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

import collections
import ctypes
import ctypes.util
import functools
import ipaddress
import multiprocessing
import os
import pickle
import shutil
import signal
import socket
import struct
import sys
import time
import typing

import psutil

from ..bpf_wrapper import BPF, check_bpf_requirements, find_bpf_object
from ..config import Config
from ..constants import FD_CACHE, PID_CACHE, ST_DEV_MASK
from ..utils import get_fstat


def initial_poll() -> list:
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


def run_monitor(config: Config, fan_fd, event_pipes, q_error, q_in, _q_out):
    """runs a bpf program to monitor the system for new connections and puts info into a pipe for run_primary"""
    # initialization of subprocess
    try:
        os.nice(-20)
    except Exception:
        pass
    parent_process = multiprocessing.parent_process()
    signal.signal(signal.SIGTERM, lambda *args: sys.exit(0))
    event_pipe_0, event_pipe_1, event_pipe_2, event_pipe_3, event_pipe_4 = event_pipes
    EVERY_EXE: typing.Final[bool] = config.monitoring.every_exe
    PAGE_CNT: typing.Final[int] = config.monitoring.perf_ring_buffer_pages
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
    # cache of resolved inode -> exe path, for when /proc/PID/exe is gone
    ino_path_cache = {}

    # helper to find executable by comm name and inode when /proc/PID/exe is unavailable
    def _find_exe_by_inode(comm: str, st_dev: int, st_ino: int) -> str:
        """Try to find the executable file on disk by comm name and inode match."""
        if not comm:
            return ""
        # Try shutil.which first (uses PATH)
        candidate = shutil.which(comm)
        if candidate:
            try:
                stat = os.stat(candidate)
                if (stat.st_dev & ST_DEV_MASK) == st_dev and stat.st_ino == st_ino:
                    return os.path.realpath(candidate)
            except Exception:
                pass
        # Try common system directories
        for prefix in ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"):
            candidate = os.path.join(prefix, comm)
            try:
                stat = os.stat(candidate)
                if (stat.st_dev & ST_DEV_MASK) == st_dev and stat.st_ino == st_ino:
                    return os.path.realpath(candidate)
            except Exception:
                continue
        return ""

    # function for getting an existing or opening a new file descriptor based on st_dev and st_ino
    def get_fd(st_dev: int, st_ino: int, pid: int, port: int, comm: str = "") -> typing.Tuple[int, int, int, str, str]:
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
            # fallback: if /proc/PID/exe is gone, resolve exe from inode cache or by comm name
            if not exe:
                if sig in ino_path_cache:
                    exe = ino_path_cache[sig]
                elif comm:
                    exe = _find_exe_by_inode(comm, st_dev, st_ino)
            if not fd and exe:
                try:
                    fd = os.open(exe, os.O_RDONLY)
                    # verify the inode still matches before caching
                    if (st_dev, st_ino) == get_fstat(fd):
                        libc.fanotify_mark(fan_fd, _FAN_MARK_ADD, _FAN_MODIFY, fd, None)
                        fd_path = f"/proc/{self_pid}/fd/{fd}"
                    else:
                        os.close(fd)
                        fd, fd_path = 0, ""
                except Exception:
                    fd, fd_path = 0, ""
            # cache resolved exe path by inode for future lookups
            if exe:
                ino_path_cache[sig] = exe
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
    for proc in initial_poll():
        try:
            stat = os.stat(f"/proc/{proc['pid']}/exe")
            pstat = os.stat(f"/proc/{proc['ppid']}/exe")
            cmd = get_cmdline(proc["pid"])
            pcmd = get_cmdline(proc["ppid"])
            st_dev, st_ino, pid, fd, exe = get_fd(stat.st_dev, stat.st_ino, proc["pid"], proc["rport"], proc["name"])
            pst_dev, pst_ino, ppid, pfd, pexe = get_fd(pstat.st_dev, pstat.st_ino, proc["ppid"], -1, proc["pname"])
            if EVERY_EXE or proc["rport"] != -1:
                event_pipe_0.send_bytes(
                    pickle.dumps(
                        {
                            "pid": pid,
                            "name": proc["name"],
                            "fd": fd,
                            "dev": st_dev,
                            "ino": st_ino,
                            "exe": exe,
                            "cmdline": cmd,
                            "ppid": ppid,
                            "pname": proc["pname"],
                            "pfd": pfd,
                            "pdev": pst_dev,
                            "pino": pst_ino,
                            "pexe": pexe,
                            "pcmdline": pcmd,
                            "uid": proc["uid"],
                            "send": 0,
                            "recv": 0,
                            "lport": proc["lport"],
                            "rport": proc["rport"],
                            "laddr": proc["laddr"],
                            "raddr": proc["raddr"],
                            "domain": domain_dict[proc["raddr"]],
                        }
                    )
                )
        except Exception:
            pass
    # pre-flight checks and BPF program init
    try:
        check_bpf_requirements()
    except (RuntimeError, FileNotFoundError) as e:
        q_error.put(f"BPF requirements check failed: {e}")
        raise
    try:
        bpf_obj_path = find_bpf_object()
        b = BPF(obj_file=bpf_obj_path)
        b.attach_kretprobe(event=b.get_syscall_fnname("execve"), fn_name="exec_entry")
    except Exception as e:
        q_error.put("Init BPF %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))
        time.sleep(5)
        os.kill(parent_process.pid, signal.SIGTERM)
        raise e
    use_getaddrinfo_uprobe = False
    try:
        b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="dns_entry")
        b.attach_uretprobe(name="c", sym="getaddrinfo", fn_name="dns_return")
        use_getaddrinfo_uprobe = True
    except Exception as e:
        q_error.put(f"BPF.attach_uprobe() failed for getaddrinfo: {e}, falling back to only using reverse DNS lookup")
    # Attach fexit programs for network monitoring
    try:
        b.bpf_obj.attach_trace("sock_sendmsg_ret")
        b.bpf_obj.attach_trace("sock_recvmsg_ret")
    except Exception as e:
        q_error.put(f"Failed to attach network monitoring programs: {e}")
        raise

    # callbacks for bpf events, read event and put into a pipe for run_primary
    def queue_lost(event, *args):
        q_error.put(f"BPF callbacks not processing fast enough, missed {event} event, try increasing 'Perf ring buffer (pages)' (power of two) if this continues")

    def queue_sendv4_event(cpu, data, size):
        event = b["sendmsg_events"].event(data)
        st_dev, st_ino, pid, fd, exe = get_fd(event.dev, event.ino, event.pid, event.dport, event.comm.decode())
        pst_dev, pst_ino, ppid, pfd, pexe = get_fd(event.pdev, event.pino, event.ppid, -1, event.pcomm.decode())
        cmd = get_cmdline(event.pid)
        pcmd = get_cmdline(event.ppid)
        laddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.saddr))
        raddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))
        event_pipe_0.send_bytes(
            pickle.dumps(
                {
                    "pid": pid,
                    "name": event.comm.decode(),
                    "fd": fd,
                    "dev": st_dev,
                    "ino": st_ino,
                    "exe": exe,
                    "cmdline": cmd,
                    "ppid": ppid,
                    "pname": event.pcomm.decode(),
                    "pfd": pfd,
                    "pdev": pst_dev,
                    "pino": pst_ino,
                    "pexe": pexe,
                    "pcmdline": pcmd,
                    "uid": event.uid,
                    "send": event.bytes,
                    "recv": 0,
                    "lport": event.lport,
                    "rport": event.dport,
                    "laddr": laddr,
                    "raddr": raddr,
                    "domain": domain_dict[raddr],
                }
            )
        )

    def queue_sendv6_event(cpu, data, size):
        event = b["sendmsg6_events"].event(data)
        st_dev, st_ino, pid, fd, exe = get_fd(event.dev, event.ino, event.pid, event.dport, event.comm.decode())
        pst_dev, pst_ino, ppid, pfd, pexe = get_fd(event.pdev, event.pino, event.ppid, -1, event.pcomm.decode())
        cmd = get_cmdline(event.pid)
        pcmd = get_cmdline(event.ppid)
        laddr = socket.inet_ntop(socket.AF_INET6, bytes(event.saddr)[:16])
        raddr = socket.inet_ntop(socket.AF_INET6, bytes(event.daddr)[:16])
        event_pipe_1.send_bytes(
            pickle.dumps(
                {
                    "pid": pid,
                    "name": event.comm.decode(),
                    "fd": fd,
                    "dev": st_dev,
                    "ino": st_ino,
                    "exe": exe,
                    "cmdline": cmd,
                    "ppid": ppid,
                    "pname": event.pcomm.decode(),
                    "pfd": pfd,
                    "pdev": pst_dev,
                    "pino": pst_ino,
                    "pexe": pexe,
                    "pcmdline": pcmd,
                    "uid": event.uid,
                    "send": event.bytes,
                    "recv": 0,
                    "lport": event.lport,
                    "rport": event.dport,
                    "laddr": laddr,
                    "raddr": raddr,
                    "domain": domain_dict[raddr],
                }
            )
        )

    def queue_recvv4_event(cpu, data, size):
        event = b["recvmsg_events"].event(data)
        st_dev, st_ino, pid, fd, exe = get_fd(event.dev, event.ino, event.pid, event.dport, event.comm.decode())
        pst_dev, pst_ino, ppid, pfd, pexe = get_fd(event.pdev, event.pino, event.ppid, -1, event.pcomm.decode())
        cmd = get_cmdline(event.pid)
        pcmd = get_cmdline(event.ppid)
        laddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.saddr))
        raddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))
        event_pipe_2.send_bytes(
            pickle.dumps(
                {
                    "pid": pid,
                    "name": event.comm.decode(),
                    "fd": fd,
                    "dev": st_dev,
                    "ino": st_ino,
                    "exe": exe,
                    "cmdline": cmd,
                    "ppid": ppid,
                    "pname": event.pcomm.decode(),
                    "pfd": pfd,
                    "pdev": pst_dev,
                    "pino": pst_ino,
                    "pexe": pexe,
                    "pcmdline": pcmd,
                    "uid": event.uid,
                    "send": 0,
                    "recv": event.bytes,
                    "lport": event.lport,
                    "rport": event.dport,
                    "laddr": laddr,
                    "raddr": raddr,
                    "domain": domain_dict[raddr],
                }
            )
        )

    def queue_recvv6_event(cpu, data, size):
        event = b["recvmsg6_events"].event(data)
        st_dev, st_ino, pid, fd, exe = get_fd(event.dev, event.ino, event.pid, event.dport, event.comm.decode())
        pst_dev, pst_ino, ppid, pfd, pexe = get_fd(event.pdev, event.pino, event.ppid, -1, event.pcomm.decode())
        cmd = get_cmdline(event.pid)
        pcmd = get_cmdline(event.ppid)
        laddr = socket.inet_ntop(socket.AF_INET6, bytes(event.saddr)[:16])
        raddr = socket.inet_ntop(socket.AF_INET6, bytes(event.daddr)[:16])
        event_pipe_3.send_bytes(
            pickle.dumps(
                {
                    "pid": pid,
                    "name": event.comm.decode(),
                    "fd": fd,
                    "dev": st_dev,
                    "ino": st_ino,
                    "exe": exe,
                    "cmdline": cmd,
                    "ppid": ppid,
                    "pname": event.pcomm.decode(),
                    "pfd": pfd,
                    "pdev": pst_dev,
                    "pino": pst_ino,
                    "pexe": pexe,
                    "pcmdline": pcmd,
                    "uid": event.uid,
                    "send": 0,
                    "recv": event.bytes,
                    "lport": event.lport,
                    "rport": event.dport,
                    "laddr": laddr,
                    "raddr": raddr,
                    "domain": domain_dict[raddr],
                }
            )
        )

    def queue_exec_event(cpu, data, size):
        event = b["exec_events"].event(data)
        st_dev, st_ino, pid, fd, exe = get_fd(event.dev, event.ino, event.pid, -1, event.comm.decode())
        pst_dev, pst_ino, ppid, pfd, pexe = get_fd(event.pdev, event.pino, event.ppid, -1, event.pcomm.decode())
        cmd = get_cmdline(event.pid)
        pcmd = get_cmdline(event.ppid)
        if EVERY_EXE:
            event_pipe_4.send_bytes(
                pickle.dumps(
                    {
                        "pid": pid,
                        "name": event.comm.decode(),
                        "fd": fd,
                        "dev": st_dev,
                        "ino": st_ino,
                        "exe": exe,
                        "cmdline": cmd,
                        "ppid": ppid,
                        "pname": event.pcomm.decode(),
                        "pfd": pfd,
                        "pdev": pst_dev,
                        "pino": pst_ino,
                        "pexe": pexe,
                        "pcmdline": pcmd,
                        "uid": event.uid,
                        "send": 0,
                        "recv": 0,
                        "lport": -1,
                        "rport": -1,
                        "laddr": "",
                        "raddr": "",
                        "domain": "",
                    }
                )
            )

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
    b["sendmsg_events"].open_perf_buffer(queue_sendv4_event, page_cnt=PAGE_CNT * 4, lost_cb=lambda *args: queue_lost("sendv4", *args))
    b["sendmsg6_events"].open_perf_buffer(queue_sendv6_event, page_cnt=PAGE_CNT * 4, lost_cb=lambda *args: queue_lost("sendv6", *args))
    b["recvmsg_events"].open_perf_buffer(queue_recvv4_event, page_cnt=PAGE_CNT * 4, lost_cb=lambda *args: queue_lost("recvv4", *args))
    b["recvmsg6_events"].open_perf_buffer(queue_recvv6_event, page_cnt=PAGE_CNT * 4, lost_cb=lambda *args: queue_lost("recvv6", *args))
    # main loop
    while True:
        if not parent_process.is_alive() or not q_in.empty():
            return 0
        try:
            b.perf_buffer_poll(timeout=1000)
        except Exception as e:
            q_error.put("BPF %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))
