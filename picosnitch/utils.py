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

import ctypes
import ctypes.util
import fcntl
import functools
import ipaddress
import json
import hashlib
import multiprocessing
import os
import pickle
import socket
import sys
import termios
import typing

from .constants import BASE_PATH, PID_CACHE, ST_DEV_MASK


def read_snitch() -> dict:
    """read data for the snitch dictionary from config.json and record.json or init new files if not found"""
    template = {
        "Config": {
            "DB retention (days)": 30,
            "DB sql log": True,
            "DB sql server": {},
            "DB text log": False,
            "DB write limit (seconds)": 10,
            "Dash scroll zoom": True,
            "Dash theme": "",
            "Desktop notifications": True,
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
            "VT request limit (seconds)": 15
        },
        "Error Log": [],
        "Exe Log": [],
        "Executables": {},
        "Names": {},
        "Parent Executables": {},
        "Parent Names": {},
        "SHA256": {}
    }
    data = {k: v for k, v in template.items()}
    data["Config"] = {k: v for k, v in template["Config"].items()}
    write_config = False
    config_path = os.path.join(BASE_PATH, "config.json")
    record_path = os.path.join(BASE_PATH, "record.json")
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8", errors="surrogateescape") as json_file:
            data["Config"] = json.load(json_file)
        for key in template["Config"]:
            if key not in data["Config"]:
                data["Config"][key] = template["Config"][key]
                write_config = True
    else:
        write_config = True
    if os.path.exists(record_path):
        with open(record_path, "r", encoding="utf-8", errors="surrogateescape") as json_file:
            snitch_record = json.load(json_file)
        for key in ["Executables", "Names", "Parent Executables", "Parent Names", "SHA256"]:
            if key in snitch_record:
                data[key] = snitch_record[key]
    assert all(type(data[key]) == type(template[key]) for key in template), "Invalid json files"
    assert all(key in ["Set RLIMIT_NOFILE", "Set st_dev mask"] or type(data["Config"][key]) == type(template["Config"][key]) for key in template["Config"]), "Invalid config"
    if write_config:
        write_snitch(data, write_config=True)
    return data


def write_snitch(snitch: dict, write_config: bool = False, write_record: bool = True) -> None:
    """write the snitch dictionary to config.json, record.json, exe.log, and error.log"""
    config_path = os.path.join(BASE_PATH, "config.json")
    record_path = os.path.join(BASE_PATH, "record.json")
    exe_log_path = os.path.join(BASE_PATH, "exe.log")
    error_log_path = os.path.join(BASE_PATH, "error.log")
    assert os.getuid() == 0, "Requires root privileges to write config and log files"
    if not os.path.isdir(BASE_PATH):
        os.makedirs(BASE_PATH)
    if os.stat(BASE_PATH).st_uid == 0 and os.getenv("SUDO_UID"):
        os.chown(BASE_PATH, int(os.getenv("SUDO_UID")), int(os.getenv("SUDO_UID")))
    snitch_config = snitch["Config"]
    try:
        if write_config:
            with open(config_path, "w", encoding="utf-8", errors="surrogateescape") as json_file:
                json.dump(snitch_config, json_file, indent=2, separators=(',', ': '), sort_keys=True, ensure_ascii=False)
        del snitch["Config"]
        if snitch["Error Log"]:
            with open(error_log_path, "a", encoding="utf-8", errors="surrogateescape") as text_file:
                text_file.write("\n".join(snitch["Error Log"]) + "\n")
        del snitch["Error Log"]
        if snitch["Exe Log"]:
            with open(exe_log_path, "a", encoding="utf-8", errors="surrogateescape") as text_file:
                text_file.write("\n".join(snitch["Exe Log"]) + "\n")
        del snitch["Exe Log"]
        if write_record:
            with open(record_path, "w", encoding="utf-8", errors="surrogateescape") as json_file:
                json.dump(snitch, json_file, indent=2, separators=(',', ': '), sort_keys=True, ensure_ascii=False)
    except Exception:
        NotificationManager().toast("picosnitch write error", file=sys.stderr)
    snitch["Config"] = snitch_config
    snitch["Error Log"] = []
    snitch["Exe Log"] = []


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


def get_vt_results(snitch: dict, q_vt: multiprocessing.Queue, q_out: multiprocessing.Queue, check_pending: bool = False) -> None:
    """get virustotal results from subprocess and update snitch, q_vt = q_in if check_pending else q_out"""
    if check_pending:
        for exe in snitch["SHA256"]:
            for sha256 in snitch["SHA256"][exe]:
                if snitch["SHA256"][exe][sha256] in ["VT Pending", "File not analyzed (no api key)", "", None]:
                    if exe in snitch["Executables"] and snitch["Executables"][exe]:
                        name = snitch["Executables"][exe][0]
                    elif exe in snitch["Parent Executables"] and snitch["Parent Executables"][exe]:
                        name = snitch["Parent Executables"][exe][0]
                    else:
                        name = exe
                    proc = {"exe": exe, "name": name}
                    q_vt.put(pickle.dumps((proc, sha256)))
    else:
        while not q_vt.empty():
            proc, sha256, result, suspicious = pickle.loads(q_vt.get())
            q_out.put(pickle.dumps({"type": "vt_result", "name": proc["name"], "exe": proc["exe"], "sha256": sha256, "result": result, "suspicious": suspicious}))

