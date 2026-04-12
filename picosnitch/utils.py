#!/usr/bin/env python3
# picosnitch
# Copyright (C) 2020 Eric Lesiuta

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
import sys
import termios
import typing

from .constants import CONFIG_DIR, DATA_DIR, LOG_DIR, PID_CACHE, ST_DEV_MASK
from .types import FanotifyEventMetadata


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


def apply_data_permissions(config_dir: str, data_dir: str, log_dir: str, cache_dir: str) -> None:
    """Apply configured ownership and permissions to data, log, and cache directories."""
    config_path = os.path.join(config_dir, "config.json")
    if not os.path.exists(config_path):
        return
    with open(config_path, "r", encoding="utf-8", errors="surrogateescape") as f:
        config = json.load(f)
    uid = resolve_owner(config.get("Data owner", "root"))
    gid = resolve_group(config.get("Data group", "root"))
    mode = int(config.get("Data mode", "0644"), 8)
    dir_mode = mode | 0o111  # add execute bits for directories
    for d in [data_dir, log_dir, cache_dir]:
        os.chmod(d, dir_mode)
        os.chown(d, uid, gid)
        for entry in os.listdir(d):
            path = os.path.join(d, entry)
            if os.path.isfile(path) and not os.path.islink(path):
                os.chmod(path, mode)
                os.chown(path, uid, gid)


def load_state() -> dict:
    """read data for the state dictionary from config.json and state.json or init new files if not found"""
    template = {
        "Config": {
            "DB retention (days)": 30,
            "DB sql log": True,
            "DB sql server": {},
            "DB text log": False,
            "DB write limit (seconds)": 10,
            "Dash scroll zoom": True,
            "Dash theme": "",
            "Data group": "root",
            "Data mode": "0644",
            "Data owner": "root",
            "Desktop notifications": True,
            "Desktop user": "",
            "Every exe (not just conns)": False,
            "GeoIP lookup": True,
            "Log addresses": True,
            "Log commands": True,
            "Log ignore": [],
            "Log ports": True,
            "Perf ring buffer (pages)": 256,
            "Set RLIMIT_NOFILE": None,
            "Set st_dev mask": None,
            "VT API key": "",
            "VT file upload": False,
            "VT request limit (seconds)": 15,
        },
        "Error Log": [],
        "Exe Log": [],
        "Executables": {},
        "Names": {},
        "Parent Executables": {},
        "Parent Names": {},
        "SHA256": {},
    }
    data = {k: v for k, v in template.items()}
    data["Config"] = {k: v for k, v in template["Config"].items()}
    config_path = os.path.join(CONFIG_DIR, "config.json")
    state_path = os.path.join(DATA_DIR, "state.json")
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8", errors="surrogateescape") as json_file:
            data["Config"] = json.load(json_file)
        for key in template["Config"]:
            if key not in data["Config"]:
                data["Config"][key] = template["Config"][key]
    if not data["Config"]["Desktop user"] and os.environ.get("SUDO_UID"):
        data["Config"]["Desktop user"] = os.environ["SUDO_UID"]
    if os.path.exists(state_path):
        with open(state_path, "r", encoding="utf-8", errors="surrogateescape") as json_file:
            state_record = json.load(json_file)
        for key in ["Executables", "Names", "Parent Executables", "Parent Names", "SHA256"]:
            if key in state_record:
                data[key] = state_record[key]
    if not all(type(data[key]) is type(template[key]) for key in template):
        logging.error("Invalid json files")
        sys.exit(1)
    if not all(key in ["Set RLIMIT_NOFILE", "Set st_dev mask"] or type(data["Config"][key]) is type(template["Config"][key]) for key in template["Config"]):
        logging.error("Invalid config")
        sys.exit(1)
    return data


def save_state(state: dict, write_record: bool = True) -> None:
    """write the state dictionary to state.json, exe.log, and error.log (never overwrites config.json)"""
    state_path = os.path.join(DATA_DIR, "state.json")
    exe_log_path = os.path.join(LOG_DIR, "exe.log")
    error_log_path = os.path.join(LOG_DIR, "error.log")
    snitch_config = state["Config"]
    try:
        if state["Error Log"]:
            with open(error_log_path, "a", encoding="utf-8", errors="surrogateescape") as f:
                f.write("\n".join(state["Error Log"]) + "\n")
        del state["Error Log"]
        if state["Exe Log"]:
            with open(exe_log_path, "a", encoding="utf-8", errors="surrogateescape") as f:
                f.write("\n".join(state["Exe Log"]) + "\n")
        del state["Exe Log"]
        del state["Config"]
        if write_record:
            with open(state_path, "w", encoding="utf-8", errors="surrogateescape") as f:
                json.dump(state, f, indent=2, separators=(",", ": "), sort_keys=True, ensure_ascii=False)
    except Exception as e:
        logging.error(f"picosnitch write error: {type(e).__name__}{e.args}")
    state["Config"] = snitch_config
    state["Error Log"] = []
    state["Exe Log"] = []


@functools.lru_cache(maxsize=None)
def reverse_dns_lookup(ip: str) -> str:
    """do a reverse dns lookup, return original ip if fails"""
    try:
        host = socket.getnameinfo((ip, 0), 0)[0]
        try:
            _ = ipaddress.ip_address(host)
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
def get_sha256_fuse(q_in: multiprocessing.Queue, q_out: multiprocessing.Queue, path: str, pid: int, st_dev: int, st_ino: int, _mod_cnt: int) -> str:
    """get sha256 of process executable from a fuse mount"""
    q_in.put(pickle.dumps((path, pid, st_dev, st_ino)))
    try:
        return q_out.get()
    except Exception:
        return "!!! FUSE Subprocess Error"


def get_fstat(fd: int) -> typing.Tuple[int, int]:
    """get (st_dev, st_ino) or (0, 0) if fails"""
    try:
        stat = os.fstat(fd)
        return stat.st_dev & ST_DEV_MASK, stat.st_ino
    except Exception:
        return 0, 0


def get_fanotify_events(fan_fd: int, fan_mod_cnt: dict, q_error: multiprocessing.Queue) -> None:
    """check if any watched executables were modified and increase count to trigger rehash"""
    sizeof_event = ctypes.sizeof(FanotifyEventMetadata)
    bytes_avail = ctypes.c_int()
    fcntl.ioctl(fan_fd, termios.FIONREAD, bytes_avail)
    for i in range(0, bytes_avail.value, sizeof_event):
        try:
            fanotify_event_metadata = FanotifyEventMetadata()
            buf = os.read(fan_fd, sizeof_event)
            ctypes.memmove(ctypes.addressof(fanotify_event_metadata), buf, sizeof_event)
            st_dev, st_ino = get_fstat(fanotify_event_metadata.fd)
            fan_mod_cnt[f"{st_dev} {st_ino}"] += 1
            os.close(fanotify_event_metadata.fd)
        except Exception as e:
            q_error.put("Fanotify Event %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))


def sync_vt_results(state: dict, q_vt: multiprocessing.Queue, q_out: multiprocessing.Queue, check_pending: bool = False) -> None:
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
