# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import ctypes
import fcntl
import functools
import grp
import hashlib
import ipaddress
import json
import logging
import multiprocessing
import os
import pickle
import pwd
import socket
import sqlite3
import sys
import tempfile
import termios
from pathlib import Path

from picosnitch.config import load_config
from picosnitch.constants import DATA_DIR, LOG_DIR, PID_CACHE, ST_DEV_MASK
from picosnitch.types import FanotifyEventMetadata, State


def drop_root_permanent(uid: int, gid: int) -> None:
    """Permanently drop root privileges. Cannot be reversed."""
    if os.getuid() != 0:
        return
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    if os.getuid() != uid or os.getgid() != gid:
        logging.error("Failed to drop root privileges")
        sys.exit(1)
    try:
        os.setuid(0)
    except PermissionError:
        return
    logging.error("FATAL: was able to regain root after dropping privileges")
    sys.exit(1)


def resolve_owner(owner: str) -> int:
    """Resolve a username or numeric string to a UID."""
    try:
        return int(owner)
    except ValueError:
        return pwd.getpwnam(owner).pw_uid


def resolve_group(group: str) -> int:
    """Resolve a group name or numeric string to a GID."""
    try:
        return int(group)
    except ValueError:
        return grp.getgrnam(group).gr_gid


def connect_db_readonly(db_path: Path | str, timeout: float = 5.0) -> sqlite3.Connection:
    """Open a sqlite3 connection for read-only access.

    Tries in order: read-write, then `mode=ro`, then `mode=ro&immutable=1`.
    The immutable fallback is needed when the caller cannot write to the
    -shm / -wal sidecar files of a WAL-mode database (e.g. a non-root
    user opening the picosnitch database written by the root daemon).
    Raises sqlite3.OperationalError if every attempt fails."""
    last_err: Exception | None = None
    for uri in (
        str(db_path),
        f"file:{db_path}?mode=ro",
        f"file:{db_path}?mode=ro&immutable=1",
    ):
        try:
            con = sqlite3.connect(uri, uri=uri.startswith("file:"), timeout=timeout)
            # Force the connection to actually touch the file so we
            # surface "attempt to write a readonly database" here
            # instead of at the first user query.
            con.execute("PRAGMA user_version").fetchone()
            return con
        except sqlite3.OperationalError as e:
            last_err = e
            continue
    raise sqlite3.OperationalError(f"could not open {db_path} for reading: {last_err}")


def apply_data_permissions(config_dir: Path, data_dir: Path, log_dir: Path, cache_dir: Path) -> None:
    """Apply configured ownership and permissions to data, log, and cache directories."""
    config_path = config_dir / "config.toml"
    if not config_path.exists():
        return
    config = load_config(config_dir)
    uid = resolve_owner(config.data.owner)
    gid = resolve_group(config.data.group)
    mode = int(config.data.mode, 8)
    dir_mode = mode | 0o111  # add execute bits for directories
    for d in [data_dir, log_dir, cache_dir]:
        d.chmod(dir_mode)
        os.chown(d, uid, gid)
        for entry in d.iterdir():
            if entry.is_file() and not entry.is_symlink():
                entry.chmod(mode)
                os.chown(entry, uid, gid)


def load_state() -> State:
    """read data for the state dictionary from state.json or init new if not found"""
    data: State = {
        "Error Log": [],
        "Exe Log": [],
        "Executables": {},
        "Names": {},
        "Parent Executables": {},
        "Parent Names": {},
        "Grandparent Executables": {},
        "Grandparent Names": {},
        "SHA256": {},
    }
    state_path = DATA_DIR / "state.json"
    if state_path.exists():
        with open(state_path, "r", encoding="utf-8", errors="surrogateescape") as json_file:
            state_record = json.load(json_file)
        for key in ["Executables", "Names", "Parent Executables", "Parent Names", "Grandparent Executables", "Grandparent Names", "SHA256"]:
            if key in state_record:
                data[key] = state_record[key]
            if not isinstance(data[key], dict):
                logging.error("Invalid state.json")
                sys.exit(1)
    return data


# translation table to strip control characters from log entries (keeps printable + space)
_CONTROL_CHAR_TABLE = str.maketrans("", "", "".join(chr(c) for c in range(32) if c not in (9,)) + chr(127))  # keep tab


def sanitize_log_line(line: str) -> str:
    """Remove control characters from a log line to prevent log injection."""
    return line.translate(_CONTROL_CHAR_TABLE)


def flush_logs(state: State) -> None:
    """append pending error.log and exe.log entries, then clear the lists"""
    exe_log_path = LOG_DIR / "exe.log"
    error_log_path = LOG_DIR / "error.log"
    try:
        if state["Error Log"]:
            with open(error_log_path, "a", encoding="utf-8", errors="surrogateescape") as f:
                f.write("\n".join(sanitize_log_line(line) for line in state["Error Log"]) + "\n")
            state["Error Log"] = []
    except Exception as e:
        logging.error(f"picosnitch write error (error.log): {type(e).__name__}{e.args}")
    try:
        if state["Exe Log"]:
            with open(exe_log_path, "a", encoding="utf-8", errors="surrogateescape") as f:
                f.write("\n".join(sanitize_log_line(line) for line in state["Exe Log"]) + "\n")
            state["Exe Log"] = []
    except Exception as e:
        logging.error(f"picosnitch write error (exe.log): {type(e).__name__}{e.args}")


def save_state(state: State, write_record: bool = True) -> None:
    """flush logs then atomically write state.json via tempfile + os.replace"""
    flush_logs(state)
    try:
        if write_record:
            state_path = DATA_DIR / "state.json"
            state_data = {k: state[k] for k in ("Executables", "Names", "Parent Executables", "Parent Names", "Grandparent Executables", "Grandparent Names", "SHA256")}
            # preserve the existing file mode across atomic replacement (tempfile defaults to 0o600)
            try:
                existing_mode = state_path.stat().st_mode & 0o777
            except FileNotFoundError:
                existing_mode = None
            fd = tempfile.NamedTemporaryFile(dir=DATA_DIR, mode="w", prefix=".state.", suffix=".tmp", delete=False, encoding="utf-8", errors="surrogateescape")
            try:
                json.dump(state_data, fd, indent=2, separators=(",", ": "), sort_keys=True, ensure_ascii=False)
                fd.flush()
                os.fsync(fd.fileno())
                fd.close()
                if existing_mode is not None:
                    os.chmod(fd.name, existing_mode)
                os.replace(fd.name, state_path)
            except BaseException:
                fd.close()
                try:
                    os.unlink(fd.name)
                except OSError:
                    pass
                raise
    except Exception as e:
        logging.error(f"picosnitch write error (state.json): {type(e).__name__}{e.args}")


@functools.lru_cache(maxsize=131072)
def reverse_dns_lookup(ip: str) -> str:
    """do a reverse dns lookup, return original ip if fails"""
    try:
        host = socket.getnameinfo((ip, 0), 0)[0]
        try:
            ipaddress.ip_address(host)
            return ip
        except ValueError:
            return ".".join(reversed(host.split(".")))
    except Exception:
        return ip


@functools.lru_cache(maxsize=PID_CACHE)
def get_sha256_fd(path: str, st_dev: int, st_ino: int, _mod_cnt: int) -> str:
    """get sha256 of process executable from /proc/monitor_pid/fd/proc_exe_fd"""
    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            if not st_ino:
                return "!!! FD Stat Error"
            if (st_dev, st_ino) != get_fstat(f.fileno()):
                return "!!! FD Cache Error"
            while data := f.read(1048576):
                sha256.update(data)
        return sha256.hexdigest()
    except Exception:
        return "!!! FD Read Error"


@functools.lru_cache(maxsize=PID_CACHE)
def get_sha256_pid(pid: int, st_dev: int, st_ino: int) -> str:
    """get sha256 of process executable from /proc/pid/exe"""
    try:
        sha256 = hashlib.sha256()
        with open(f"/proc/{pid}/exe", "rb") as f:
            if (st_dev, st_ino) != get_fstat(f.fileno()):
                return "!!! PID Recycled Error"
            while data := f.read(1048576):
                sha256.update(data)
        return sha256.hexdigest()
    except Exception:
        return "!!! PID Read Error"


@functools.lru_cache(maxsize=PID_CACHE)
def get_sha256_fuse(q_in: multiprocessing.Queue[bytes], q_out: multiprocessing.Queue[str], path: str, pid: int, st_dev: int, st_ino: int, _mod_cnt: int) -> str:
    """get sha256 of process executable from a fuse mount"""
    q_in.put(pickle.dumps((path, pid, st_dev, st_ino)))
    try:
        return q_out.get()
    except Exception:
        return "!!! FUSE Subprocess Error"


def get_fstat(fd: int) -> tuple[int, int]:
    """get (st_dev, st_ino) or (0, 0) if fails"""
    try:
        stat = os.fstat(fd)
        return stat.st_dev & ST_DEV_MASK, stat.st_ino
    except Exception:
        return 0, 0


def get_fanotify_events(fan_fd: int, fan_mod_cnt: dict[str, int], q_error: multiprocessing.Queue[str]) -> None:
    """check if any watched executables were modified and increase count to trigger rehash"""
    sizeof_event = ctypes.sizeof(FanotifyEventMetadata)
    bytes_avail = ctypes.c_int()
    fcntl.ioctl(fan_fd, termios.FIONREAD, bytes_avail)
    for _ in range(0, bytes_avail.value, sizeof_event):
        try:
            fanotify_event_metadata = FanotifyEventMetadata()
            buf = os.read(fan_fd, sizeof_event)
            ctypes.memmove(ctypes.addressof(fanotify_event_metadata), buf, sizeof_event)
            st_dev, st_ino = get_fstat(fanotify_event_metadata.fd)
            fan_mod_cnt[f"{st_dev} {st_ino}"] += 1
            os.close(fanotify_event_metadata.fd)
        except Exception as e:
            q_error.put("Fanotify Event %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))


def sync_vt_results(state: State, q_vt: multiprocessing.Queue[bytes], q_out: multiprocessing.Queue[bytes], check_pending: bool = False) -> None:
    """get virustotal results from subprocess and update state, q_vt = q_in if check_pending else q_out"""
    if check_pending:
        for exe in state["SHA256"]:
            for sha256 in state["SHA256"][exe]:
                if state["SHA256"][exe][sha256] in ["VT Pending", "File not analyzed (no api key)", "", None]:
                    if exe in state["Executables"] and state["Executables"][exe]:
                        name = state["Executables"][exe][0]
                    elif exe in state["Parent Executables"] and state["Parent Executables"][exe]:
                        name = state["Parent Executables"][exe][0]
                    else:
                        name = exe
                    proc = {"exe": exe, "name": name}
                    q_vt.put(pickle.dumps((proc, sha256)))
    else:
        while not q_vt.empty():
            proc, sha256, result, suspicious = pickle.loads(q_vt.get())
            q_out.put(pickle.dumps({"type": "vt_result", "name": proc["name"], "exe": proc["exe"], "sha256": sha256, "result": result, "suspicious": suspicious}))
