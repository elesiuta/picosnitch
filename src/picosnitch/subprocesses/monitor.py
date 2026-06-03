# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import collections
import ctypes
import ctypes.util
import functools
import ipaddress
import multiprocessing
import os
import pickle
import resource
import shutil
import signal
import socket
import struct
import sys
import time
import typing

from picosnitch.bpf_wrapper import BPF, ConnKey4, ConnKey6, ConnVal, check_bpf_requirements, find_bpf_object
from picosnitch.config import Config
from picosnitch.constants import FD_CACHE, PID_CACHE, ST_DEV_MASK
from picosnitch.utils import get_fstat


def _read_proc_comm(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except OSError:
        return ""


def _classify_inode_fallback(st_dev: int, st_ino: int, exe: str) -> str:
    """classify a resolved path before it is stored in dev_ino_fallback, which is
    keyed by (dev, ino) alone and reused for later events that have no comm.

    realpath collapses symlink aliases to one canonical file (busybox ->
    /bin/busybox, python -> python3.13) with st_nlink == 1, which is what the
    kernel reports for live procs anyway. hardlink multi-call binaries (uutils)
    have st_nlink > 1 and no canonical name, so return a '<multi-call:dev,ino>'
    sentinel rather than claim an arbitrary hardlink. inode re-verified after
    realpath so a name is never attributed unless dev+ino still match."""
    if not exe or exe.startswith("<multi-call:"):
        return exe
    try:
        canonical = os.path.realpath(exe)
        stat = os.stat(canonical)
    except OSError:
        return exe
    if (stat.st_dev & ST_DEV_MASK) != st_dev or stat.st_ino != st_ino:
        return exe
    if stat.st_nlink > 1:
        return f"<multi-call:dev={st_dev},ino={st_ino}>"
    return canonical


def _read_proc_status_uid(pid: int) -> int:
    """Return the effective UID for `pid` from /proc/[pid]/status.

    Format: 'Uid:\\treal\\teffective\\tsaved\\tfs'.  We use the effective
    UID (field 2) because BPF's bpf_get_current_uid_gid() also returns
    the effective UID -- keeping the two paths consistent."""
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("Uid:"):
                    return int(line.split()[2])
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _parse_proc_net_addr(hex_addr: str) -> str:
    """Parse 'AABBCCDD:PPPP' or IPv6 hex form into a string IP address."""
    addr_part, _, _port_part = hex_addr.partition(":")
    try:
        if len(addr_part) == 8:
            packed = bytes.fromhex(addr_part)
            return socket.inet_ntop(socket.AF_INET, packed[::-1])
        if len(addr_part) == 32:
            # /proc/net stores IPv6 as 4 little-endian u32 words
            words = [bytes.fromhex(addr_part[i : i + 8])[::-1] for i in range(0, 32, 8)]
            return socket.inet_ntop(socket.AF_INET6, b"".join(words))
    except (ValueError, OSError):
        pass
    return ""


def _parse_proc_net_port(hex_addr: str) -> int:
    _, _, port_part = hex_addr.partition(":")
    try:
        return int(port_part, 16)
    except ValueError:
        return -1


def _initial_family_for(addr: str) -> int:
    """Best-effort AF_* guess for an initial-poll address. Returns 0 when
    the address is empty/unparseable."""
    if not addr:
        return 0
    if ":" in addr:
        return socket.AF_INET6
    return socket.AF_INET


def _read_netns_inode(pid: int) -> int:
    """Return the network namespace inode for a pid, or 0 if unreadable."""
    try:
        return os.stat(f"/proc/{pid}/ns/net").st_ino
    except OSError:
        return 0


def _scan_proc_net_sockets() -> dict[int, tuple[str, int, str, int]]:
    """Return {inode: (laddr, lport, raddr, rport)} from /proc/net/{tcp,tcp6,udp,udp6}."""
    inode_to_endpoint: dict[int, tuple[str, int, str, int]] = {}
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        try:
            with open(f"/proc/net/{proto}", "r") as f:
                next(f, None)  # skip header
                for line in f:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    try:
                        inode = int(parts[9])
                    except ValueError:
                        continue
                    if inode == 0:
                        continue
                    laddr = _parse_proc_net_addr(parts[1])
                    lport = _parse_proc_net_port(parts[1])
                    raddr = _parse_proc_net_addr(parts[2])
                    rport = _parse_proc_net_port(parts[2])
                    # only keep connections that actually have a remote peer
                    if not raddr or rport <= 0 or raddr in ("0.0.0.0", "::"):
                        continue
                    inode_to_endpoint[inode] = (laddr, lport, raddr, rport)
        except OSError:
            continue
    return inode_to_endpoint


def _scan_pid_socket_inodes(pid: int) -> list[int]:
    """Return socket inode numbers owned by `pid` by reading /proc/{pid}/fd/*."""
    inodes: list[int] = []
    try:
        entries = os.listdir(f"/proc/{pid}/fd")
    except OSError:
        return inodes
    for entry in entries:
        try:
            target = os.readlink(f"/proc/{pid}/fd/{entry}")
        except OSError:
            continue
        if target.startswith("socket:["):
            try:
                inodes.append(int(target[8:-1]))
            except ValueError:
                continue
    return inodes


def _read_proc_ppid(pid: int) -> int:
    """Parse ppid (4th field) from /proc/{pid}/stat, splitting on the last
    `)` to handle commands containing spaces or parens."""
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            return int(f.read().rsplit(")", 1)[1].split()[1])
    except (OSError, ValueError, IndexError):
        return 0


def initial_poll() -> list:
    """Poll initial processes from /proc and seed any pre-existing TCP/UDP
    connections from /proc/net/{tcp,tcp6,udp,udp6} so the daemon catches
    sockets that were already open before BPF attached.

    BPF picks up every new send/recv after attach, so this only matters
    for long-running connections that pre-date the daemon."""
    initial_processes = []
    try:
        pids = [int(name) for name in os.listdir("/proc") if name.isdigit()]
    except OSError:
        return initial_processes
    inode_to_endpoint = _scan_proc_net_sockets()
    for pid in pids:
        try:
            name = _read_proc_comm(pid)
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                exe = ""
            ppid = _read_proc_ppid(pid)
            uid = _read_proc_status_uid(pid)
            pname = _read_proc_comm(ppid) if ppid else ""
            base = {
                "name": name,
                "exe": exe,
                "pid": pid,
                "ppid": ppid,
                "uid": uid,
                "pname": pname,
            }
            # find connections that this pid owns by matching socket inodes
            seeded_any = False
            if inode_to_endpoint:
                for inode in _scan_pid_socket_inodes(pid):
                    endpoint = inode_to_endpoint.get(inode)
                    if endpoint is None:
                        continue
                    laddr, lport, raddr, rport = endpoint
                    initial_processes.append(
                        {
                            **base,
                            "raddr": raddr,
                            "rport": rport,
                            "laddr": laddr,
                            "lport": lport,
                        }
                    )
                    seeded_any = True
            if not seeded_any:
                initial_processes.append(
                    {
                        **base,
                        "raddr": "",
                        "rport": -1,
                        "laddr": "",
                        "lport": -1,
                    }
                )
        except Exception:
            pass
    return initial_processes


def run_monitor(config: Config, fan_fd: int, event_pipes: tuple, q_error: multiprocessing.Queue[str], q_in: multiprocessing.Queue[str], _q_out: multiprocessing.Queue) -> int:
    """runs a bpf program to monitor the system for new connections and puts info into a pipe for run_primary"""
    # initialization of subprocess
    try:
        os.nice(-20)
    except Exception:
        pass
    # Required for libbpf to mmap the per-cpu perf event ring buffers
    # without hitting the inherited 8 MiB cap.
    try:
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    except (ValueError, OSError):
        pass
    parent_process = multiprocessing.parent_process()
    assert parent_process is not None
    signal.signal(signal.SIGTERM, lambda *args: sys.exit(0))
    event_pipe_0, event_pipe_1, event_pipe_2, event_pipe_3, event_pipe_4 = event_pipes
    EVERY_EXE: typing.Final[bool] = config.monitoring.every_exe
    PAGE_CNT: typing.Final[int] = config.monitoring.perf_ring_buffer_pages
    CONN_MAP_MAX: typing.Final[int] = config.monitoring.conn_map_max_entries
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
    for cache_idx in range(FD_CACHE):
        fd_dict[f"tmp{cache_idx}"] = (0,)
    self_pid = os.getpid()
    # cache of resolved (dev, ino, comm) -> exe path, used as a fallback for
    # when /proc/PID/exe is no longer readable (short-lived processes).
    # Keyed by comm in addition to (dev, ino) because multi-call binaries
    # (e.g. uutils-coreutils) hardlink many symlinks (head, sleep, cat, ...)
    # to a single inode; the kernel distinguishes them per-process via
    # /proc/PID/exe but the inode alone is ambiguous.
    ino_path_cache: dict[str, str] = {}
    # last-resort fallback keyed only by (dev, ino), used when the live
    # readlink and the (dev, ino, comm) lookup both miss (e.g. BPF reports a
    # worker-thread comm like `tokio-rt-worker` matching no binary). value is
    # classified once by _classify_inode_fallback(): a canonical path, or a
    # '<multi-call:dev,ino>' sentinel for hardlink multi-call binaries.
    dev_ino_fallback: dict[str, str] = {}
    multi_call_reported: set[str] = set()

    def _record_inode_fallback(sig: str, st_dev: int, st_ino: int, exe: str) -> None:
        """classify and memoize the (dev, ino) fallback name the first time an inode
        is resolved (O(1), so multi-call binaries with many names don't trigger
        rescans). emits one q_error per hardlink multi-call inode when first seen."""
        if not exe or exe.startswith("<multi-call:") or sig in dev_ino_fallback:
            return
        label = _classify_inode_fallback(st_dev, st_ino, exe)
        dev_ino_fallback[sig] = label
        if label.startswith("<multi-call:") and sig not in multi_call_reported:
            multi_call_reported.add(sig)
            q_error.put(f"monitor.get_fd: hardlink multi-call inode dev={st_dev} ino={st_ino} (e.g. {exe}), fallback reports {label!r} when /proc is gone")

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
        for prefix in ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin", "/usr/libexec"):
            candidate = os.path.join(prefix, comm)
            try:
                stat = os.stat(candidate)
                if (stat.st_dev & ST_DEV_MASK) == st_dev and stat.st_ino == st_ino:
                    return os.path.realpath(candidate)
            except Exception:
                continue
        return ""

    def _read_tgid_comm(pid: int) -> str:
        """Return the thread group leader's comm from /proc/<pid>/comm.

        BPF reports task->comm of the *current task*, which for worker
        threads is the thread name set via prctl(PR_SET_NAME) (e.g.
        `tokio-rt-worker`, `libuv-worker`, `sshd-session`) rather than
        the binary name. Reading /proc/<tgid>/comm gives us the leader's
        comm, which usually matches the binary's basename and lets
        _find_exe_by_inode() resolve it on disk."""
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                return f.read().strip()
        except OSError:
            return ""

    # function for getting an existing or opening a new file descriptor based on st_dev and st_ino
    def get_fd(st_dev: int, st_ino: int, pid: int, port: int, comm: str = "") -> tuple[int, int, int, str, str]:
        st_dev = st_dev & ST_DEV_MASK
        sig = f"{st_dev} {st_ino}"
        # Resolve the exe path for THIS process via /proc/PID/exe whenever
        # possible. The kernel records the specific symlink each process was
        # exec'd from, even when many symlinks share an inode (multi-call
        # binaries like uutils-coreutils). The fd cache is keyed only by
        # (dev, ino), so without this per-PID lookup a cached entry could
        # return the wrong exe path (e.g. report `head` as `sleep`).
        proc_exe = ""
        try:
            proc_exe = os.readlink(f"/proc/{pid}/exe")
        except Exception:
            pass
        # per-(dev, ino, comm) fallback key for when /proc is gone
        comm_sig = f"{sig} {comm}"

        def _resolve_when_proc_gone() -> str:
            """best-effort exe resolution when the /proc/PID/exe readlink failed.

            comm only locates a candidate; _find_exe_by_inode verifies its
            (dev, ino) against the event inode, so at worst comm names another
            hardlink of the same inode (same bytes, same hash).
            with no comm match, fall back to dev_ino_fallback (sentinel for
            hardlink multi-call inodes)."""
            candidate = ino_path_cache.get(comm_sig, "")
            if not candidate and comm:
                candidate = _find_exe_by_inode(comm, st_dev, st_ino)
            if not candidate:
                leader_comm = _read_tgid_comm(pid)
                if leader_comm and leader_comm != comm:
                    candidate = _find_exe_by_inode(leader_comm, st_dev, st_ino)
            # an inode-verified candidate names a hardlink of the exact event
            # inode, trust it; otherwise use the comm-less fallback
            return candidate or dev_ino_fallback.get(sig, "")

        try:
            # check if it is in the cache and move it to the most recent position
            fd_dict.move_to_end(sig)
            fd, fd_path, cached_exe = fd_dict[sig]
            if not fd:
                # sig is in cache but fd is 0, try again to open it
                # add a dummy value to the oldest postition to be popped off on retry so cache size is maintained
                # since sig is already in cache, value will just be updated without increasing cache size
                fd_dict[f"tmp{sig}"] = (0,)
                fd_dict.move_to_end(f"tmp{sig}", last=False)
                raise Exception("previous attempt failed, probably due to process terminating too quickly, try again")
            # cache hit: prefer the per-PID exe (kernel-authoritative for
            # multi-call binaries), then the staged fallback chain, finally
            # the fd_dict's last-seen exe.
            exe = proc_exe or _resolve_when_proc_gone() or cached_exe
            # only cache non-empty, non-sentinel resolutions; an empty value
            # would poison ino_path_cache for a (dev, ino, comm) tuple whose
            # first event was a dead process, masking later live lookups
            if exe and not exe.startswith("<multi-call:"):
                ino_path_cache[comm_sig] = exe
                _record_inode_fallback(sig, st_dev, st_ino, exe)
        except Exception:
            # open a new file descriptor and pop off the oldest one
            # watch it with fanotify, and also cache the apparent executable path with it
            try:
                fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY)
                libc.fanotify_mark(fan_fd, _FAN_MARK_ADD, _FAN_MODIFY, fd, None)
                fd_path = f"/proc/{self_pid}/fd/{fd}"
            except Exception:
                fd, fd_path = 0, ""
            exe = proc_exe or _resolve_when_proc_gone()
            if not fd and exe and not exe.startswith("<multi-call:"):
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
            # cache resolved exe for future lookups (skip empty and sentinel,
            # see cache-hit branch above)
            if exe and not exe.startswith("<multi-call:"):
                ino_path_cache[comm_sig] = exe
                _record_inode_fallback(sig, st_dev, st_ino, exe)
            if fd and (st_dev, st_ino) != get_fstat(fd):
                if EVERY_EXE or port != -1:
                    q_error.put(f"monitor.get_fd: exe inode changed for (pid: {pid} fd: {fd} dev: {st_dev} ino: {st_ino}) before FD could be opened, using port: {port}")
                st_dev, st_ino = get_fstat(fd)
                sig = f"{st_dev} {st_ino}"
                if EVERY_EXE or port != -1:
                    q_error.put(f"monitor.get_fd: new inode for (pid: {pid} fd: {fd} dev: {st_dev} ino: {st_ino} exe: {exe})")
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
            # grandparent: read ppid of ppid via /proc, best-effort
            gppid = 0
            gpname = ""
            gpst_dev, gpst_ino, gpfd, gpexe = 0, 0, "", ""
            gpcmd = ""
            try:
                with open(f"/proc/{proc['ppid']}/stat", "r") as f:
                    stat_fields = f.read().rsplit(")", 1)[-1].split()
                gppid = int(stat_fields[1])
                if gppid > 0:
                    gpname = _read_proc_comm(gppid)
                    gstat = os.stat(f"/proc/{gppid}/exe")
                    gpcmd = get_cmdline(gppid)
                    gpst_dev, gpst_ino, _, gpfd, gpexe = get_fd(gstat.st_dev, gstat.st_ino, gppid, -1, gpname)
            except Exception:
                pass
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
                            "gppid": gppid,
                            "gpname": gpname,
                            "gpfd": gpfd,
                            "gpdev": gpst_dev,
                            "gpino": gpst_ino,
                            "gpexe": gpexe,
                            "gpcmdline": gpcmd,
                            "uid": proc["uid"],
                            "send": 0,
                            "recv": 0,
                            "family": _initial_family_for(proc["raddr"]),
                            "protocol": 0,
                            "lport": proc["lport"],
                            "rport": proc["rport"],
                            "laddr": proc["laddr"],
                            "raddr": proc["raddr"],
                            "domain": domain_dict[proc["raddr"]],
                            "netns": _read_netns_inode(pid),
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
        b = BPF(obj_file=bpf_obj_path, map_max_entries={"conn_stats4": CONN_MAP_MAX, "conn_stats6": CONN_MAP_MAX})
        b.attach_kretprobe(event=b.get_syscall_fnname("execve"), fn_name="exec_entry")
    except Exception as e:
        q_error.put("Init BPF %s%s on line %s" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?"))
        time.sleep(5)
        if parent_process.pid is not None:
            os.kill(parent_process.pid, signal.SIGTERM)
        raise e
    use_getaddrinfo_uprobe = False
    try:
        b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="dns_entry")
        b.attach_uretprobe(name="c", sym="getaddrinfo", fn_name="dns_return")
        use_getaddrinfo_uprobe = True
    except Exception as e:
        q_error.put(f"BPF.attach_uprobe() failed for getaddrinfo: {e}, falling back to only using reverse DNS lookup")
    # attach fexit network hooks: inet_sendmsg/inet6_sendmsg for send,
    # sock_recvmsg for recv
    try:
        b.bpf_obj.attach_trace("inet_sendmsg_ret")
        b.bpf_obj.attach_trace("sock_recvmsg_ret")
    except Exception as e:
        q_error.put(f"Failed to attach network monitoring programs: {e}")
        raise
    # inet6_sendmsg is best-effort: absent on kernels built without IPv6, a
    # missing hook only drops IPv6 send bytes
    try:
        b.bpf_obj.attach_trace("inet6_sendmsg_ret")
    except Exception as e:
        q_error.put(f"BPF.attach_trace() failed for inet6_sendmsg: {e}, IPv6 send bytes will not be recorded")

    # callbacks for bpf events, read event and put into a pipe for run_primary
    def queue_lost(event, *args):
        q_error.put(f"BPF callbacks not processing fast enough, missed {event} event, try increasing [monitoring].perf_ring_buffer_pages (power of two) if this continues")

    def resolve_grandparent(event) -> tuple[int, int, int, str, str, str, str]:
        """resolve grandparent proc info, returning all-empty/zero values when
        gppid <= 0 (BPF reports tgid=0 for the kernel/swapper). this happens
        whenever the parent walk hits init or any process whose parent is the
        kernel idle task, e.g. detached daemons, kernel-thread-spawned procs,
        or systemd's direct children. without this guard get_fd() and the
        downstream resolve_hash() would emit "Read Error" toasts and store
        garbage rows in the executables table."""
        if event.gppid <= 0:
            return 0, 0, 0, "", "", "", ""
        gpcomm = event.gpcomm.decode()
        gpst_dev, gpst_ino, gppid, gpfd, gpexe = get_fd(event.gpdev, event.gpino, event.gppid, -1, gpcomm)
        gpcmd = get_cmdline(event.gppid)
        return gpst_dev, gpst_ino, gppid, gpfd, gpexe, gpcmd, gpcomm

    def drain_conn_maps():
        """drain the per-connection aggregation maps.

        bytes and packets are summed in-kernel per connection in the
        conn_stats4/conn_stats6 LRU hash maps, so process-ancestry resolution
        and pickling run once per connection per drain interval rather than per
        packet. each entry carries the send and recv totals as one event. ipv4
        goes to event_pipe_0, ipv6 to event_pipe_1."""
        for map_name, key_type, family, pipe in (
            ("conn_stats4", ConnKey4, socket.AF_INET, event_pipe_0),
            ("conn_stats6", ConnKey6, socket.AF_INET6, event_pipe_1),
        ):
            try:
                entries = b.drain_map(map_name, key_type, ConnVal)
            except Exception as e:
                q_error.put("BPF drain %s %s%s on line %s" % (map_name, type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?"))
                continue
            # an lru map evicts oldest entries silently when full, so a drain at
            # near capacity means connections may have been dropped before drain
            if len(entries) >= CONN_MAP_MAX * 9 // 10:
                q_error.put(f"{map_name} near capacity ({len(entries)}/{CONN_MAP_MAX}), connections may have been evicted, try increasing [monitoring].conn_map_max_entries")
            for key, val in entries:
                st_dev, st_ino, pid, fd, exe = get_fd(val.dev, val.ino, key.pid, key.dport, val.comm.decode())
                pst_dev, pst_ino, ppid, pfd, pexe = get_fd(val.pdev, val.pino, val.ppid, -1, val.pcomm.decode())
                gpst_dev, gpst_ino, gppid, gpfd, gpexe, gpcmd, gpcomm = resolve_grandparent(val)
                cmd = get_cmdline(key.pid)
                pcmd = get_cmdline(val.ppid)
                if family == socket.AF_INET:
                    laddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", key.saddr))
                    raddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", key.daddr))
                else:
                    laddr = socket.inet_ntop(socket.AF_INET6, bytes(key.saddr)[:16])
                    raddr = socket.inet_ntop(socket.AF_INET6, bytes(key.daddr)[:16])
                pipe.send_bytes(
                    pickle.dumps(
                        {
                            "pid": pid,
                            "name": val.comm.decode(),
                            "fd": fd,
                            "dev": st_dev,
                            "ino": st_ino,
                            "exe": exe,
                            "cmdline": cmd,
                            "ppid": ppid,
                            "pname": val.pcomm.decode(),
                            "pfd": pfd,
                            "pdev": pst_dev,
                            "pino": pst_ino,
                            "pexe": pexe,
                            "pcmdline": pcmd,
                            "gppid": gppid,
                            "gpname": gpcomm,
                            "gpfd": gpfd,
                            "gpdev": gpst_dev,
                            "gpino": gpst_ino,
                            "gpexe": gpexe,
                            "gpcmdline": gpcmd,
                            "uid": val.uid,
                            "send": int(val.send_bytes),
                            "recv": int(val.recv_bytes),
                            "pkts": int(val.send_pkts) + int(val.recv_pkts),
                            "family": family,
                            "protocol": int(key.protocol),
                            "lport": key.lport,
                            "rport": key.dport,
                            "laddr": laddr,
                            "raddr": raddr,
                            "domain": domain_dict[raddr],
                            "netns": int(key.netns),
                        }
                    )
                )

    def queue_exec_event(cpu, data, size):
        event = b["exec_events"].event(data)
        st_dev, st_ino, pid, fd, exe = get_fd(event.dev, event.ino, event.pid, -1, event.comm.decode())
        pst_dev, pst_ino, ppid, pfd, pexe = get_fd(event.pdev, event.pino, event.ppid, -1, event.pcomm.decode())
        gpst_dev, gpst_ino, gppid, gpfd, gpexe, gpcmd, gpcomm = resolve_grandparent(event)
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
                        "gppid": gppid,
                        "gpname": gpcomm,
                        "gpfd": gpfd,
                        "gpdev": gpst_dev,
                        "gpino": gpst_ino,
                        "gpexe": gpexe,
                        "gpcmdline": gpcmd,
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
            ip = socket.inet_ntop(socket.AF_INET6, bytes(event.daddr6))
        domain = event.host.decode("utf-8", "replace")
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            domain_dict[ip] = ".".join(reversed(domain.split(".")))

    b["exec_events"].open_perf_buffer(queue_exec_event, page_cnt=PAGE_CNT, lost_cb=lambda *args: queue_lost("exec", *args))
    if use_getaddrinfo_uprobe:
        b["dns_events"].open_perf_buffer(queue_dns_event, page_cnt=PAGE_CNT, lost_cb=lambda *args: queue_lost("dns", *args))
    # main loop: poll the exec/dns perf buffers on a short timeout so DNS/exec
    # context stays fresh, and drain the in-kernel connection aggregation maps
    # on a fixed interval. Bandwidth is accumulated in-kernel between drains, so
    # the userspace cost scales with the number of active connections per
    # interval rather than the packet rate.
    drain_interval = 1.0
    next_drain = time.monotonic() + drain_interval
    while True:
        if not parent_process.is_alive() or not q_in.empty():
            drain_conn_maps()
            return 0
        try:
            b.perf_buffer_poll(timeout=200)
            now = time.monotonic()
            if now >= next_drain:
                drain_conn_maps()
                next_drain = now + drain_interval
        except Exception as e:
            q_error.put("BPF %s%s on line %s" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?"))
