#!/usr/bin/env python3
# picosnitch
# Copyright (C) 2020-2022 Eric Lesiuta

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

import atexit
import collections
import ctypes
import ctypes.util
import curses
import datetime
import fcntl
import functools
import ipaddress
import json
import hashlib
import importlib
import importlib.util
import multiprocessing
import os
import pickle
import pwd
import queue
import resource
import shlex
import signal
import site
import socket
import sqlite3
import struct
import subprocess
import sys
import termios
import textwrap
import threading
import time
import typing

# also look in user site for imports while running as root via systemd, this avoids https://xkcd.com/1987/
try:
    site.addsitedir(os.getenv("PYTHON_USER_SITE"))
except Exception:
    pass
import psutil

# picosnitch version and supported platform
VERSION: typing.Final[str] = "0.11.7"
assert sys.version_info >= (3, 8), "Python version >= 3.8 is required"
assert sys.platform.startswith("linux"), "Did not detect a supported operating system"

# set constants and RLIMIT_NOFILE if configured
if os.getuid() == 0:
    if os.getenv("SUDO_UID"):
        home_user = pwd.getpwuid(int(os.getenv("SUDO_UID"))).pw_name
    elif os.getenv("SUDO_USER"):
        home_user = os.getenv("SUDO_USER")
    else:
        for home_user in os.listdir("/home"):
            try:
                if pwd.getpwnam(home_user).pw_uid >= 1000:
                    break
            except Exception:
                pass
    home_dir = pwd.getpwnam(home_user).pw_dir
    if not os.getenv("SUDO_UID"):
        os.environ["SUDO_UID"] = str(pwd.getpwnam(home_user).pw_uid)
    if not os.getenv("DBUS_SESSION_BUS_ADDRESS"):
        os.environ["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{pwd.getpwnam(home_user).pw_uid}/bus"
else:
    home_dir = os.path.expanduser("~")
BASE_PATH: typing.Final[str] = os.path.join(home_dir, ".config", "picosnitch")
try:
    file_path = os.path.join(BASE_PATH, "config.json")
    with open(file_path, "r", encoding="utf-8", errors="surrogateescape") as json_file:
        nofile = json.load(json_file)["Set RLIMIT_NOFILE"]
    if type(nofile) == int:
        try:
            new_limit = (nofile, resource.getrlimit(resource.RLIMIT_NOFILE)[1])
            resource.setrlimit(resource.RLIMIT_NOFILE, new_limit)
            time.sleep(0.5)
        except Exception as e:
            print(type(e).__name__ + str(e.args), file=sys.stderr)
            print("Error: Set RLIMIT_NOFILE was found in config.json but it could not be set", file=sys.stderr)
except Exception:
    pass
FD_CACHE: typing.Final[int] = resource.getrlimit(resource.RLIMIT_NOFILE)[0] - 128
PID_CACHE: typing.Final[int] = max(8192, 2*FD_CACHE)
st_dev_mask = 0xffffffff
try:
    for part in psutil.disk_partitions():
        if part.fstype == "btrfs":
            st_dev_mask = 0
            print("Warning: running picosnitch on systems with btrfs is not fully supported due to dev number strangeness and non-unique inodes", file=sys.stderr)
            break
except Exception:
    pass
ST_DEV_MASK: typing.Final[int] = st_dev_mask


### classes
class Daemon:
    """A generic daemon class based on http://www.jejik.com/files/examples/daemon3x.py"""
    def __init__(self, pidfile):
        self.pidfile = pidfile

    def daemonize(self):
        """Daemonize class. UNIX double fork mechanism."""
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as err:
            sys.stderr.write('fork #1 failed: {0}\n'.format(err))
            sys.exit(1)
        # decouple from parent environment
        os.chdir('/')
        os.setsid()
        os.umask(0)
        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError as err:
            sys.stderr.write('fork #2 failed: {0}\n'.format(err))
            sys.exit(1)
        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(os.devnull, 'r')
        so = open(os.devnull, 'a+')
        se = open(os.devnull, 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        with open(self.pidfile,'w+') as f:
            f.write(pid + '\n')

    def delpid(self):
        os.remove(self.pidfile)

    def getpid(self):
        """Get the pid from the pidfile"""
        try:
            with open(self.pidfile, "r") as f:
                pid = int(f.read().strip())
        except IOError:
            pid = None
        return pid

    def start(self):
        """Start the daemon."""
        # Check for a pidfile to see if the daemon already runs
        pid = self.getpid()
        if pid:
            message = "pidfile {0} already exist. " + \
                    "picosnitch already running?\n"
            sys.stderr.write(message.format(self.pidfile))
            sys.exit(1)
        # Start the daemon
        self.daemonize()
        self.run()

    def stop(self):
        """Stop the daemon."""
        pid = self.getpid()
        if not pid:
            message = "pidfile {0} does not exist. " + \
                    "picosnitch not running?\n"
            sys.stderr.write(message.format(self.pidfile))
            return # not an error in a restart
        # Try killing the daemon process
        try:
            while 1:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
        except OSError as err:
            e = str(err.args)
            if e.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print (str(err.args))
                sys.exit(1)

    def restart(self):
        """Restart the daemon."""
        self.stop()
        self.start()

    def status(self):
        """Get daemon status."""
        pid = self.getpid()
        if pid:
            try:
                with open(f"/proc/{pid}/cmdline", "r") as f:
                    cmdline = f.read()
            except Exception:
                cmdline = ""
            if "picosnitch" in cmdline:
                print(f"picosnitch is currently running with pid {pid}.")
            else:
                print("pidfile exists however picosnitch was not detected.")
        else:
            print("picosnitch does not appear to be running.")

    def run(self):
        """Subclass Daemon and override this method"""


class ProcessManager:
    """A class for managing a subprocess"""
    def __init__(self, name: str, target: typing.Callable, init_args: tuple = ()) -> None:
        self.name, self.target, self.init_args = name, target, init_args
        self.q_in, self.q_out = multiprocessing.Queue(), multiprocessing.Queue()
        self.start()

    def start(self) -> None:
        self.p = multiprocessing.Process(name=self.name, target=self.target, daemon=True,
                                         args=(*self.init_args, self.q_in, self.q_out)
                                        )
        self.p.start()
        self.pp = psutil.Process(self.p.pid)

    def terminate(self) -> None:
        if self.p.is_alive():
            self.p.terminate()
        self.p.join(timeout=5)
        if self.p.is_alive():
            self.p.kill()
        self.p.join(timeout=5)
        self.p.close()

    def is_alive(self) -> bool:
        return self.p.is_alive()

    def is_zombie(self) -> bool:
        return self.pp.is_running() and self.pp.status() == psutil.STATUS_ZOMBIE

    def memory(self) -> int:
        return self.pp.memory_info().rss


class NotificationManager:
    """A singleton for creating system tray notifications, holds notifications in queue if fails, prints if disabled"""
    __instance = None
    dbus_notifications = False
    notifications_ready = False
    notification_queue = []
    last_notification = ""
    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            cls.__instance = super(NotificationManager, cls).__new__(cls, *args, **kwargs)
        return cls.__instance

    def enable_notifications(self):
        self.dbus_notifications = True
        try:
            import dbus
            os.seteuid(int(os.getenv("SUDO_UID")))
            dbus_session_obj = dbus.SessionBus().get_object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
            interface = dbus.Interface(dbus_session_obj, "org.freedesktop.Notifications")
            self.system_notification = lambda msg: interface.Notify("picosnitch", 0, "", "picosnitch", msg, [], [], 2000)
            self.notifications_ready = True
        except Exception:
            pass
        finally:
            os.seteuid(os.getuid())

    def toast(self, msg: str, file=sys.stdout) -> None:
        try:
            if self.notifications_ready:
                if self.last_notification != msg:
                    self.last_notification = msg
                    self.system_notification(msg)
            else:
                print(msg, file=file)
                self.notification_queue.append(msg)
                if self.dbus_notifications:
                    self.enable_notifications()
                    if self.notifications_ready:
                        for msg in self.notification_queue:
                            try:
                                if self.last_notification != msg:
                                    self.last_notification = msg
                                    self.system_notification(msg)
                            except Exception:
                                pass
                        self.notification_queue = []
        except Exception:
            self.notification_queue.append(msg)
            self.notifications_ready = False


class FanotifyEventMetadata(ctypes.Structure):
    """https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/fanotify.h"""
    _fields_ = [
        ("event_len", ctypes.c_uint32),
        ("vers", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("metadata_len", ctypes.c_uint16),
        ("mask", ctypes.c_uint64),
        ("fd", ctypes.c_int32),
        ("pid", ctypes.c_int32)
    ]


### functions
def read_snitch() -> dict:
    """read data for the snitch dictionary from config.json and record.json or init new files if not found"""
    template = {
        "Config": {
            "Bandwidth monitor": True,
            "DB retention (days)": 365,
            "DB sql log": True,
            "DB sql server": {},
            "DB text log": False,
            "DB write limit (seconds)": 10,
            "Desktop notifications": True,
            "Every exe (not just conns)": False,
            "Log addresses": True,
            "Log commands": True,
            "Log ignore": [],
            "Perf ring buffer (pages)": 64,
            "Set RLIMIT_NOFILE": None,
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
    assert all(key == "Set RLIMIT_NOFILE" or type(data["Config"][key]) == type(template["Config"][key]) for key in template["Config"]), "Invalid config"
    if write_config:
        write_snitch(data, write_config=True)
    return data


def write_snitch(snitch: dict, write_config: bool = False, write_record: bool = True) -> None:
    """write the snitch dictionary to config.json, record.json, exe.log, and error.log"""
    config_path = os.path.join(BASE_PATH, "config.json")
    record_path = os.path.join(BASE_PATH, "record.json")
    exe_log_path = os.path.join(BASE_PATH, "exe.log")
    error_log_path = os.path.join(BASE_PATH, "error.log")
    if not os.path.isdir(BASE_PATH):
        os.makedirs(BASE_PATH)
    if os.stat(BASE_PATH).st_uid == 0 and os.getuid() == 0 and os.getenv("SUDO_UID"):
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


def monitor_subprocess_initial_poll() -> list:
    """poll initial processes and connections using psutil"""
    initial_processes = []
    for pid in psutil.pids():
        try:
            proc = psutil.Process(pid).as_dict(attrs=["name", "exe", "pid", "ppid", "uids"], ad_value="")
            proc["uid"] = proc["uids"][0]
            proc["pname"] = psutil.Process(proc["ppid"]).name()
            proc["ip"] = ""
            proc["port"] = -1
            initial_processes.append(proc)
        except Exception:
            pass
    for conn in psutil.net_connections(kind="all"):
        try:
            proc = psutil.Process(conn.pid).as_dict(attrs=["name", "exe", "pid", "ppid", "uids"], ad_value="")
            proc["uid"] = proc["uids"][0]
            proc["pname"] = psutil.Process(proc["ppid"]).name()
            proc["ip"] = conn.raddr.ip
            proc["port"] = conn.raddr.port
            initial_processes.append(proc)
        except Exception:
            pass
    return initial_processes


def secondary_subprocess_sha_wrapper(snitch: dict, fan_mod_cnt: dict, proc: dict, q_vt: multiprocessing.Queue, q_out: multiprocessing.Queue, q_error: multiprocessing.Queue) -> str:
    """get sha256 of executable and submit to primary_subprocess or virustotal_subprocess if necessary"""
    sha_fd_error = ""
    sha256 = get_sha256_fd(proc["fd"], proc["dev"], proc["ino"], fan_mod_cnt["%d %d" % (proc["dev"], proc["ino"])])
    if sha256.startswith("!"):
        # fallback on trying to read directly (if still alive) if fd_cache fails, probable causes include:
        # system suspends in the middle of hashing (since cache is reset)
        # process too short lived to open fd or stat in time (then fallback will fail too)
        # too many executables on system (see Set RLIMIT_NOFILE)
        sha_fd_error = sha256
        sha256 = get_sha256_pid(proc["pid"], proc["dev"], proc["ino"])
        if sha256.startswith("!"):
            # notify user with what went wrong (may be cause for suspicion)
            sha256_error = sha_fd_error[4:] + " and " + sha256[4:]
            sha256 = sha_fd_error + " " + sha256
            q_error.put(sha256_error + " for " + str(proc))
        else:
            q_error.put(sha_fd_error[4:] + " for " + str(proc) + " (fallback pid hash successful)")
    if proc["exe"] in snitch["SHA256"]:
        if sha256 not in snitch["SHA256"][proc["exe"]]:
            snitch["SHA256"][proc["exe"]][sha256] = "SUBMITTED"
            q_vt.put(pickle.dumps((proc, sha256)))
            q_out.put(pickle.dumps({"type": "sha256", "name": proc["name"], "exe": proc["exe"], "sha256": sha256}))
        elif snitch["SHA256"][proc["exe"]][sha256] == "Failed to read process for upload":
            snitch["SHA256"][proc["exe"]][sha256] = "RETRY"
            q_vt.put(pickle.dumps((proc, sha256)))
    else:
        snitch["SHA256"][proc["exe"]] = {sha256: "SUBMITTED"}
        q_vt.put(pickle.dumps((proc, sha256)))
        q_out.put(pickle.dumps({"type": "sha256", "name": proc["name"], "exe": proc["exe"], "sha256": sha256}))
    return sha256


def secondary_subprocess_helper(snitch: dict, fan_mod_cnt: dict, new_processes: typing.List[bytes], q_vt: multiprocessing.Queue, q_out: multiprocessing.Queue, q_error: multiprocessing.Queue) -> typing.List[tuple]:
    """iterate over the list of process/connection data to generate a list of entries for the sql database"""
    datetime_now = time.strftime("%Y-%m-%d %H:%M:%S")
    event_counter = collections.defaultdict(int)
    traffic_counter = collections.defaultdict(int)
    transaction = set()
    for proc in new_processes:
        proc = pickle.loads(proc)
        if type(proc) != dict:
            q_error.put("sync error between secondary and primary, received '%s' in middle of transfer" % str(proc))
            continue
        sha256 = secondary_subprocess_sha_wrapper(snitch, fan_mod_cnt, proc, q_vt, q_out, q_error)
        pproc = {"pid": proc["ppid"], "name": proc["pname"], "exe": proc["pexe"], "fd": proc["pfd"], "dev": proc["pdev"], "ino": proc["pino"]}
        psha256 = secondary_subprocess_sha_wrapper(snitch, fan_mod_cnt, pproc, q_vt, q_out, q_error)
        # join or omit commands from logs
        if snitch["Config"]["Log commands"]:
            proc["cmdline"] = shlex.join(proc["cmdline"].encode("utf-8", "ignore").decode("utf-8", "ignore").strip("\0\t\n ").split("\0"))
            proc["pcmdline"] = shlex.join(proc["pcmdline"].encode("utf-8", "ignore").decode("utf-8", "ignore").strip("\0\t\n ").split("\0"))
        else:
            proc["cmdline"] = ""
            proc["pcmdline"] = ""
        # reverse dns lookup or omit with IP from logs
        if snitch["Config"]["Log addresses"]:
            if not proc["domain"]:
                proc["domain"] = reverse_dns_lookup(proc["ip"])
        else:
            proc["domain"], proc["ip"] = "", ""
        # omit entry from logs
        ignored = False
        for ignore in snitch["Config"]["Log ignore"]:
            if ((proc["port"] == ignore) or
                (sha256 == ignore) or
                (type(ignore) == str and proc["domain"].startswith(ignore))
               ):
                ignored = True
                break
        if ignored:
            continue
        if snitch["Config"]["Log ignore IP"] and proc["ip"]:
            daddr = ipaddress.ip_address(proc["ip"])
            if (any(daddr in network for network in snitch["Config"]["Log ignore IP"])):
                continue
        # create sql entry
        event = (proc["exe"], proc["name"], proc["cmdline"], sha256, datetime_now, proc["domain"], proc["ip"], proc["port"], proc["uid"], proc["pexe"], proc["pname"], proc["pcmdline"], psha256)
        if not (proc["send"] or proc["recv"]):
            event_counter[str(event)] += 1
        traffic_counter["send " + str(event)] += proc["send"]
        traffic_counter["recv " + str(event)] += proc["recv"]
        transaction.add(event)
    return [(*event, event_counter[str(event)], traffic_counter["send " + str(event)], traffic_counter["recv " + str(event)]) for event in transaction]


def primary_subprocess_helper(snitch: dict, new_processes: typing.List[bytes]) -> None:
    """iterate over the list of process/connection data to update the snitch dictionary and create notifications on new entries"""
    datetime_now = time.strftime("%Y-%m-%d %H:%M:%S")
    for proc in new_processes:
        proc = pickle.loads(proc)
        proc_name, proc_exe, snitch_names, snitch_executables, parent = proc["name"], proc["exe"], snitch["Names"], snitch["Executables"], ""
        for i in range(2):
            notification = []
            if proc_name in snitch_names:
                if proc_exe not in snitch_names[proc_name]:
                    snitch_names[proc_name].append(proc_exe)
            else:
                snitch_names[proc_name] = [proc_exe]
                notification.append("name")
            if proc_exe in snitch_executables:
                if proc_name not in snitch_executables[proc_exe]:
                    snitch_executables[proc_exe].append(proc_name)
            else:
                snitch_executables[proc_exe] = [proc_name]
                notification.append("exe")
                if proc_exe not in snitch["SHA256"]:
                    snitch["SHA256"][proc_exe] = {}
            if notification:
                snitch["Exe Log"].append(f"{datetime_now} {proc_name:<16.16} {proc_exe} (new {', '.join(notification)}){parent}")
                NotificationManager().toast(f"picosnitch: {proc_name} {proc_exe}")
            proc_name, proc_exe, snitch_names, snitch_executables, parent = proc["pname"], proc["pexe"], snitch["Parent Names"], snitch["Parent Executables"], " (parent)"


### processes
def primary_subprocess(snitch, snitch_pipe, secondary_pipe, q_error, q_in, _q_out):
    """first to receive connection data from monitor, more responsive than secondary, creates notifications and writes exe.log, error.log, and record.json"""
    os.nice(-20)
    # init variables for loop
    parent_process = multiprocessing.parent_process()
    snitch_record = pickle.dumps([snitch["Executables"], snitch["Names"], snitch["Parent Executables"], snitch["Parent Names"], snitch["SHA256"]])
    last_write = 0
    write_record = False
    processes_to_send = []
    # init notifications
    if snitch["Config"]["Desktop notifications"]:
        NotificationManager().enable_notifications()
    # init signal handlers
    def write_snitch_and_exit(snitch: dict, q_error: multiprocessing.Queue, snitch_pipe):
        while not q_error.empty():
            error = q_error.get()
            snitch["Error Log"].append(time.strftime("%Y-%m-%d %H:%M:%S") + " " + error)
            NotificationManager().toast(error, file=sys.stderr)
        write_snitch(snitch)
        snitch_pipe.close()
        sys.exit(0)
    signal.signal(signal.SIGTERM, lambda *args: write_snitch_and_exit(snitch, q_error, snitch_pipe))
    signal.signal(signal.SIGINT, lambda *args: write_snitch_and_exit(snitch, q_error, snitch_pipe))
    # init thread to receive new connection data over pipe
    def snitch_pipe_thread(snitch_pipe, pipe_data: list, listen: threading.Event, ready: threading.Event):
        while True:
            listen.wait()
            new_processes = pipe_data[0]
            while listen.is_set():
                snitch_pipe.poll(timeout=5)
                while snitch_pipe.poll():
                    new_processes.append(snitch_pipe.recv_bytes())
            ready.set()
    listen, ready = threading.Event(), threading.Event()
    pipe_data = [[]]
    thread = threading.Thread(target=snitch_pipe_thread, args=(snitch_pipe, pipe_data, listen, ready,), daemon=True)
    thread.start()
    listen.set()
    # main loop
    while True:
        if not parent_process.is_alive():
            q_error.put("picosnitch has stopped")
            write_snitch_and_exit(snitch, q_error, snitch_pipe)
        try:
            # check for errors
            while not q_error.empty():
                error = q_error.get()
                snitch["Error Log"].append(time.strftime("%Y-%m-%d %H:%M:%S") + " " + error)
                NotificationManager().toast(error, file=sys.stderr)
            # get list of new processes and connections since last update
            listen.clear()
            if not ready.wait(timeout=300):
                q_error.put("thread timeout error for primary subprocess")
                write_snitch_and_exit(snitch, q_error, snitch_pipe)
            new_processes = pipe_data[0]
            pipe_data[0] = []
            ready.clear()
            listen.set()
            # process the list and update snitch, send new process/connection data to secondary subprocess if ready
            primary_subprocess_helper(snitch, new_processes)
            processes_to_send += new_processes
            while not q_in.empty():
                msg: dict = pickle.loads(q_in.get())
                if msg["type"] == "ready":
                    secondary_pipe.send_bytes(pickle.dumps(len(processes_to_send)))
                    for proc in processes_to_send:
                        secondary_pipe.send_bytes(proc)
                    secondary_pipe.send_bytes(pickle.dumps("done"))
                    processes_to_send = []
                    break
                elif msg["type"] == "sha256":
                    if msg["exe"] in snitch["SHA256"]:
                        if msg["sha256"] not in snitch["SHA256"][msg["exe"]]:
                            snitch["SHA256"][msg["exe"]][msg["sha256"]] = "VT Pending"
                            snitch["Exe Log"].append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg['sha256']:<16.16} {msg['exe']} (new hash)")
                            NotificationManager().toast(f"New sha256: {msg['exe']}")
                    else:
                        snitch["SHA256"][msg["exe"]] = {msg["sha256"]: "VT Pending"}
                elif msg["type"] == "vt_result":
                    if msg["exe"] in snitch["SHA256"]:
                        if msg["sha256"] not in snitch["SHA256"][msg["exe"]]:
                            snitch["Exe Log"].append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg['sha256']:<16.16} {msg['exe']} (new hash)")
                            NotificationManager().toast(f"New sha256: {msg['exe']}")
                        snitch["SHA256"][msg["exe"]][msg["sha256"]] = msg["result"]
                    else:
                        snitch["SHA256"][msg["exe"]] = {msg["sha256"]: msg["result"]}
                    if msg["suspicious"]:
                        snitch["Exe Log"].append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg['sha256']:<16.16} {msg['exe']} (suspicious)")
                        NotificationManager().toast(f"Suspicious VT results: {msg['exe']}")
            # write the snitch dictionary to record.json, error.log, and exe.log (limit writes to reduce disk wear)
            if snitch["Error Log"] or snitch["Exe Log"] or time.time() - last_write > 30:
                new_record = pickle.dumps([snitch["Executables"], snitch["Names"], snitch["Parent Executables"], snitch["Parent Names"], snitch["SHA256"]])
                if new_record != snitch_record:
                    snitch_record = new_record
                    write_record = True
                write_snitch(snitch, write_record=write_record)
                last_write = time.time()
                write_record = False
        except Exception as e:
            q_error.put("primary subprocess %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))


def secondary_subprocess(snitch, fan_fd, p_virustotal: ProcessManager, secondary_pipe, q_primary_in, q_error, _q_in, _q_out):
    """second to receive connection data from monitor, less responsive than primary, coordinates connection data with virustotal subprocess and checks fanotify, updates connection logs and reports sha256/vt_results back to primary_subprocess if needed"""
    parent_process = multiprocessing.parent_process()
    # maintain a separate copy of the snitch dictionary here and coordinate with the primary_subprocess (sha256 and vt_results)
    get_vt_results(snitch, p_virustotal.q_in, q_primary_in, True)
    # init sql
    # (exe text, name text, cmdline text, sha256 text, contime text, domain text, ip text, port integer, uid integer, pexe text, pname text, pcmdline text, psha256 text, conns integer, send integer, recv integer)
    # (proc["exe"], proc["name"], proc["cmdline"], sha256, datetime_now, proc["domain"], proc["ip"], proc["port"], proc["uid"], proc["pexe"], proc["pname"], proc["pcmdline"], psha256, event_counter[str(event)], sent bytes, received bytes)
    sqlite_query = ''' INSERT INTO connections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) '''
    file_path = os.path.join(BASE_PATH, "snitch.db")
    text_path = os.path.join(BASE_PATH, "conn.log")
    if snitch["Config"]["DB sql log"]:
        con = sqlite3.connect(file_path)
        cur = con.cursor()
        cur.execute(''' PRAGMA user_version ''')
        assert cur.fetchone()[0] == 2, f"Incorrect database version of snitch.db for picosnitch v{VERSION}"
        cur.execute(''' DELETE FROM connections WHERE contime < datetime("now", "localtime", "-%d days") ''' % int(snitch["Config"]["DB retention (days)"]))
        con.commit()
        con.close()
    if sql_kwargs := snitch["Config"]["DB sql server"]:
        sql_client = sql_kwargs.pop("client", "no client error")
        table_name = sql_kwargs.pop("table_name", "connections")
        sql = importlib.import_module(sql_client)
        sql_query = sqlite_query.replace("?", "%s").replace("connections", table_name)
    log_destinations = int(bool(snitch["Config"]["DB sql log"])) + int(bool(sql_kwargs)) + int(bool(snitch["Config"]["DB text log"]))
    # init fanotify mod counter = {"st_dev st_ino": modify_count}, and traffic counter = {"send|recv pid socket_ino": bytes}
    fan_mod_cnt = collections.defaultdict(int)
    # get network address and mask for ignored IP subnets
    ignored_ips = []
    for ip_subnet in reversed(snitch["Config"]["Log ignore"]):
        try:
            ignored_ips.append(ipaddress.ip_network(ip_subnet))
            snitch["Config"]["Log ignore"].remove(ip_subnet)
        except Exception as e:
            pass
    snitch["Config"]["Log ignore IP"] = ignored_ips
    # main loop
    transaction = []
    new_processes = []
    last_write = 0
    while True:
        if not parent_process.is_alive():
            return 0
        try:
            # prep to receive new connections
            if secondary_pipe.poll():
                q_error.put("sync error between secondary and primary on ready (pipe not empty)")
            else:
                q_primary_in.put(pickle.dumps({"type": "ready"}))
                secondary_pipe.poll(timeout=300)
                if not secondary_pipe.poll():
                    q_error.put("sync error between secondary and primary on ready (secondary timed out waiting for first message)")
            # receive first message, should be transfer size
            transfer_size = 0
            if secondary_pipe.poll():
                first_pickle = secondary_pipe.recv_bytes()
                if type(pickle.loads(first_pickle)) == int:
                    transfer_size = pickle.loads(first_pickle)
                elif pickle.loads(first_pickle) == "done":
                    q_error.put("sync error between secondary and primary on ready (received done)")
                else:
                    q_error.put("sync error between secondary and primary on ready (did not receive transfer size)")
                    new_processes.append(first_pickle)
            # receive new connections until "done"
            timeout_counter = 0
            while True:
                while secondary_pipe.poll(timeout=1):
                    new_processes.append(secondary_pipe.recv_bytes())
                    transfer_size -= 1
                timeout_counter += 1
                if pickle.loads(new_processes[-1]) == "done":
                    _ = new_processes.pop()
                    transfer_size += 1
                    break
                elif timeout_counter > 30:
                    q_error.put("sync error between secondary and primary on receive (did not receive done)")
            if transfer_size > 0:
                q_error.put("sync error between secondary and primary on receive (did not receive all messages)")
            elif transfer_size < 0:
                q_error.put("sync error between secondary and primary on receive (received extra messages)")
            # check for other pending data (vt, fanotify)
            get_vt_results(snitch, p_virustotal.q_out, q_primary_in, False)
            get_fanotify_events(fan_fd, fan_mod_cnt, q_error)
            # process connection data
            if time.time() - last_write > snitch["Config"]["DB write limit (seconds)"] and (transaction or new_processes):
                current_write = time.time()
                transaction += secondary_subprocess_helper(snitch, fan_mod_cnt, new_processes, p_virustotal.q_in, q_primary_in, q_error)
                new_processes = []
                transaction_success = False
                try:
                    if snitch["Config"]["DB sql log"]:
                        con = sqlite3.connect(file_path)
                        with con:
                            con.executemany(sqlite_query, transaction)
                        con.close()
                        transaction_success = True
                except Exception as e:
                    q_error.put("SQLite execute %s%s on line %s, lost %s entries" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno, len(transaction)))
                try:
                    if sql_kwargs:
                        con = sql.connect(**sql_kwargs)
                        with con.cursor() as cur:
                            cur.executemany(sql_query, transaction)
                        con.commit()
                        con.close()
                        transaction_success = True
                except Exception as e:
                    q_error.put("SQL server execute %s%s on line %s, lost %s entries" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno, len(transaction)))
                try:
                    if snitch["Config"]["DB text log"]:
                        with open(text_path, "a", encoding="utf-8", errors="surrogateescape") as text_file:
                            for entry in transaction:
                                clean_entry = [str(value).replace(",", "").replace("\n", "").replace("\0", "") for value in entry]
                                text_file.write(",".join(clean_entry) + "\n")
                        transaction_success = True
                except Exception as e:
                    q_error.put("text log %s%s on line %s, lost %s entries" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno, len(transaction)))
                if transaction_success or log_destinations == 0:
                    transaction = []
                else:
                    q_error.put("secondary subprocess all log desinations failed, will retry %s entries with next write" % (len(transaction)))
                last_write = current_write
        except Exception as e:
            q_error.put("secondary subprocess %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))


def monitor_subprocess(config: dict, fan_fd, snitch_pipe, q_error, q_in, _q_out):
    """runs a bpf program to monitor the system for new connections and puts info into a pipe for primary_subprocess"""
    # initialization
    os.nice(-20)
    import bcc
    from bcc import BPF
    parent_process = multiprocessing.parent_process()
    signal.signal(signal.SIGTERM, lambda *args: sys.exit(0))
    EVERY_EXE: typing.Final[bool] = config["Every exe (not just conns)"]
    PAGE_CNT: typing.Final[int] = config["Perf ring buffer (pages)"]
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    _FAN_MARK_ADD = 0x1
    _FAN_MARK_REMOVE = 0x2
    _FAN_MARK_FLUSH = 0x80
    _FAN_MODIFY = 0x2
    libc.fanotify_mark(fan_fd, _FAN_MARK_FLUSH, _FAN_MODIFY, -1, None)
    domain_dict = collections.defaultdict(str)
    fd_dict = collections.OrderedDict()
    for x in range(FD_CACHE):
        fd_dict[f"tmp{x}"] = (0,)
    self_pid = os.getpid()
    def get_fd(st_dev: int, st_ino: int, pid: int, port: int) -> typing.Tuple[int, int, int, str, str, str]:
        st_dev = st_dev & ST_DEV_MASK
        sig = f"{st_dev} {st_ino}"
        try:
            fd_dict.move_to_end(sig)
            fd, fd_path, exe, cmd = fd_dict[sig]
            if not fd:
                fd_dict[f"tmp{sig}"] = (0,)
                fd_dict.move_to_end(f"tmp{sig}", last=False)
                raise Exception("previous attempt failed, probably due to process terminating too quickly, try again")
        except Exception:
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
            try:
                with open(f"/proc/{pid}/cmdline", "r") as f:
                    cmd = f.read()
            except Exception:
                cmd = ""
            if fd and (st_dev, st_ino) != get_fstat(fd):
                if EVERY_EXE or port != -1:
                    q_error.put(f"Exe inode changed for (pid: {pid} fd: {fd} dev: {st_dev} ino: {st_ino}) before FD could be opened, using port: {port}")
                st_dev, st_ino = get_fstat(fd)
                sig = f"{st_dev} {st_ino}"
                if EVERY_EXE or port != -1:
                    q_error.put(f"New inode for (pid: {pid} fd: {fd} dev: {st_dev} ino: {st_ino} exe: {exe})")
            fd_dict[sig] = (fd, fd_path, exe, cmd)
            try:
                if fd_old := fd_dict.popitem(last=False)[1][0]:
                    libc.fanotify_mark(fan_fd, _FAN_MARK_REMOVE, _FAN_MODIFY, fd_old, None)
                    os.close(fd_old)
            except Exception:
                pass
        return (st_dev, st_ino, pid, fd_path, exe, cmd)
    # get current connections
    for proc in monitor_subprocess_initial_poll():
        try:
            stat = os.stat(f"/proc/{proc['pid']}/exe")
            pstat = os.stat(f"/proc/{proc['ppid']}/exe")
            st_dev, st_ino, pid, fd, exe, cmd = get_fd(stat.st_dev, stat.st_ino, proc["pid"], proc["port"])
            pst_dev, pst_ino, ppid, pfd, pexe, pcmd = get_fd(pstat.st_dev, pstat.st_ino, proc["ppid"], -1)
            if EVERY_EXE or proc["port"] != -1:
                snitch_pipe.send_bytes(pickle.dumps({"pid": pid, "name": proc["name"], "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd,
                                                     "ppid": ppid, "pname": proc["pname"], "pfd": pfd, "pdev": pst_dev, "pino": pst_ino, "pexe": pexe, "pcmdline": pcmd,
                                                     "uid": proc["uid"], "send": 0, "recv": 0, "port": proc["port"], "ip": proc["ip"], "domain": domain_dict[proc["ip"]]}))
        except Exception:
            pass
    # run bpf program
    bpf_text = bpf_text_base
    if config["Bandwidth monitor"]:
        try:
            if BPF.support_kfunc():
                bpf_text = bpf_text_base + bpf_text_bandwidth_structs + bpf_text_bandwidth_probe.replace("int flags, ", "") + bpf_text_bandwidth_probe.replace("sendmsg", "recvmsg")
            else:
                raise Exception()
        except Exception:
            config["Bandwidth monitor"] = False
            q_error.put("BPF.support_kfunc() was not True, cannot enable bandwidth monitor, check BCC version or Kernel Configuration")
    b = BPF(text=bpf_text)
    b.attach_kprobe(event="security_socket_connect", fn_name="security_socket_connect_entry")
    b.attach_kretprobe(event=b.get_syscall_fnname("execve"), fn_name="exec_entry")
    if tuple(map(int, bcc.__version__.split(".")[0:2])) >= (0, 23):
        b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="dns_entry")
        b.attach_uretprobe(name="c", sym="getaddrinfo", fn_name="dns_return")
    def queue_lost(event, *args):
        q_error.put(f"BPF callbacks not processing fast enough, missed {event} event, try increasing 'Perf ring buffer (pages)' (power of two) if this continues")
    def queue_ipv4_event(cpu, data, size):
        event = b["ipv4_events"].event(data)
        st_dev, st_ino, pid, fd, exe, cmd = get_fd(event.dev, event.ino, event.pid, event.dport)
        pst_dev, pst_ino, ppid, pfd, pexe, pcmd = get_fd(event.pdev, event.pino, event.ppid, -1)
        ip = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))
        snitch_pipe.send_bytes(pickle.dumps({"pid": pid, "name": event.comm.decode(), "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd,
                                             "ppid": ppid, "pname": event.pcomm.decode(), "pfd": pfd, "pdev": pst_dev, "pino": pst_ino, "pexe": pexe, "pcmdline": pcmd,
                                             "uid": event.uid, "send": 0, "recv": 0, "port": event.dport, "ip": ip, "domain": domain_dict[ip]}))
    def queue_ipv6_event(cpu, data, size):
        event = b["ipv6_events"].event(data)
        st_dev, st_ino, pid, fd, exe, cmd = get_fd(event.dev, event.ino, event.pid, event.dport)
        pst_dev, pst_ino, ppid, pfd, pexe, pcmd = get_fd(event.pdev, event.pino, event.ppid, -1)
        ip = socket.inet_ntop(socket.AF_INET6, event.daddr)
        snitch_pipe.send_bytes(pickle.dumps({"pid": pid, "name": event.comm.decode(), "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd,
                                             "ppid": ppid, "pname": event.pcomm.decode(), "pfd": pfd, "pdev": pst_dev, "pino": pst_ino, "pexe": pexe, "pcmdline": pcmd,
                                             "uid": event.uid, "send": 0, "recv": 0, "port": event.dport, "ip": ip, "domain": domain_dict[ip]}))
    def queue_other_event(cpu, data, size):
        event = b["other_socket_events"].event(data)
        st_dev, st_ino, pid, fd, exe, cmd = get_fd(event.dev, event.ino, event.pid, 0)
        pst_dev, pst_ino, ppid, pfd, pexe, pcmd = get_fd(event.pdev, event.pino, event.ppid, -1)
        snitch_pipe.send_bytes(pickle.dumps({"pid": pid, "name": event.comm.decode(), "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd,
                                             "ppid": ppid, "pname": event.pcomm.decode(), "pfd": pfd, "pdev": pst_dev, "pino": pst_ino, "pexe": pexe, "pcmdline": pcmd,
                                             "uid": event.uid, "send": 0, "recv": 0, "port": 0, "ip": "", "domain": ""}))
    def queue_sendv4_event(cpu, data, size):
        event = b["sendmsg_events"].event(data)
        st_dev, st_ino, pid, fd, exe, cmd = get_fd(event.dev, event.ino, event.pid, event.dport)
        pst_dev, pst_ino, ppid, pfd, pexe, pcmd = get_fd(event.pdev, event.pino, event.ppid, -1)
        ip =socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))
        snitch_pipe.send_bytes(pickle.dumps({"pid": pid, "name": event.comm.decode(), "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd,
                                             "ppid": ppid, "pname": event.pcomm.decode(), "pfd": pfd, "pdev": pst_dev, "pino": pst_ino, "pexe": pexe, "pcmdline": pcmd,
                                             "uid": event.uid, "send": event.bytes, "recv": 0, "port": event.dport, "ip": ip, "domain": domain_dict[ip]}))
    def queue_sendv6_event(cpu, data, size):
        event = b["sendmsg6_events"].event(data)
        st_dev, st_ino, pid, fd, exe, cmd = get_fd(event.dev, event.ino, event.pid, event.dport)
        pst_dev, pst_ino, ppid, pfd, pexe, pcmd = get_fd(event.pdev, event.pino, event.ppid, -1)
        ip = socket.inet_ntop(socket.AF_INET6, event.daddr)
        snitch_pipe.send_bytes(pickle.dumps({"pid": pid, "name": event.comm.decode(), "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd,
                                             "ppid": ppid, "pname": event.pcomm.decode(), "pfd": pfd, "pdev": pst_dev, "pino": pst_ino, "pexe": pexe, "pcmdline": pcmd,
                                             "uid": event.uid, "send": event.bytes, "recv": 0, "port": event.dport, "ip": ip, "domain": domain_dict[ip]}))
    def queue_recvv4_event(cpu, data, size):
        event = b["recvmsg_events"].event(data)
        st_dev, st_ino, pid, fd, exe, cmd = get_fd(event.dev, event.ino, event.pid, event.dport)
        pst_dev, pst_ino, ppid, pfd, pexe, pcmd = get_fd(event.pdev, event.pino, event.ppid, -1)
        ip = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))
        snitch_pipe.send_bytes(pickle.dumps({"pid": pid, "name": event.comm.decode(), "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd,
                                             "ppid": ppid, "pname": event.pcomm.decode(), "pfd": pfd, "pdev": pst_dev, "pino": pst_ino, "pexe": pexe, "pcmdline": pcmd,
                                             "uid": event.uid, "send": 0, "recv": event.bytes, "port": event.dport, "ip": ip, "domain": domain_dict[ip]}))
    def queue_recvv6_event(cpu, data, size):
        event = b["recvmsg6_events"].event(data)
        st_dev, st_ino, pid, fd, exe, cmd = get_fd(event.dev, event.ino, event.pid, event.dport)
        pst_dev, pst_ino, ppid, pfd, pexe, pcmd = get_fd(event.pdev, event.pino, event.ppid, -1)
        ip = socket.inet_ntop(socket.AF_INET6, event.daddr)
        snitch_pipe.send_bytes(pickle.dumps({"pid": pid, "name": event.comm.decode(), "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd,
                                             "ppid": ppid, "pname": event.pcomm.decode(), "pfd": pfd, "pdev": pst_dev, "pino": pst_ino, "pexe": pexe, "pcmdline": pcmd,
                                             "uid": event.uid, "send": 0, "recv": event.bytes, "port": event.dport, "ip": ip, "domain": domain_dict[ip]}))
    def queue_exec_event(cpu, data, size):
        event = b["exec_events"].event(data)
        st_dev, st_ino, pid, fd, exe, cmd = get_fd(event.dev, event.ino, event.pid, -1)
        pst_dev, pst_ino, ppid, pfd, pexe, pcmd = get_fd(event.pdev, event.pino, event.ppid, -1)
        if EVERY_EXE:
            snitch_pipe.send_bytes(pickle.dumps({"pid": pid, "name": event.comm.decode(), "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd,
                                                 "ppid": ppid, "pname": event.pcomm.decode(), "pfd": pfd, "pdev": pst_dev, "pino": pst_ino, "pexe": pexe, "pcmdline": pcmd,
                                                 "uid": event.uid, "send": 0, "recv": 0, "port": -1, "ip": "", "domain": ""}))
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
    b["ipv4_events"].open_perf_buffer(queue_ipv4_event, page_cnt=PAGE_CNT, lost_cb=lambda *args: queue_lost("ipv4", *args))
    b["ipv6_events"].open_perf_buffer(queue_ipv6_event, page_cnt=PAGE_CNT, lost_cb=lambda *args: queue_lost("ipv6", *args))
    b["other_socket_events"].open_perf_buffer(queue_other_event, page_cnt=PAGE_CNT, lost_cb=lambda *args: queue_lost("other", *args))
    b["exec_events"].open_perf_buffer(queue_exec_event, page_cnt=PAGE_CNT, lost_cb=lambda *args: queue_lost("exec", *args))
    if tuple(map(int, bcc.__version__.split(".")[0:2])) >= (0, 23):
        b["dns_events"].open_perf_buffer(queue_dns_event, page_cnt=PAGE_CNT, lost_cb=lambda *args: queue_lost("dns", *args))
    if config["Bandwidth monitor"]:
        b["sendmsg_events"].open_perf_buffer(queue_sendv4_event, page_cnt=PAGE_CNT*4, lost_cb=lambda *args: queue_lost("sendv4", *args))
        b["sendmsg6_events"].open_perf_buffer(queue_sendv6_event, page_cnt=PAGE_CNT*4, lost_cb=lambda *args: queue_lost("sendv6", *args))
        b["recvmsg_events"].open_perf_buffer(queue_recvv4_event, page_cnt=PAGE_CNT*4, lost_cb=lambda *args: queue_lost("recvv4", *args))
        b["recvmsg6_events"].open_perf_buffer(queue_recvv6_event, page_cnt=PAGE_CNT*4, lost_cb=lambda *args: queue_lost("recvv6", *args))
    while True:
        if not parent_process.is_alive() or not q_in.empty():
            return 0
        try:
            b.perf_buffer_poll(timeout=-1)
        except Exception as e:
            q_error.put("BPF %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))


def virustotal_subprocess(config: dict, q_error, q_vt_pending, q_vt_results):
    """get virustotal results of process executable"""
    parent_process = multiprocessing.parent_process()
    try:
        import requests
        vt_enabled = True
    except ImportError:
        vt_enabled = False
    if not (config["VT API key"] and vt_enabled):
        config["VT request limit (seconds)"] = 0
    headers = {"x-apikey": config["VT API key"]}
    def get_analysis(analysis_id: dict, sha256: str) -> dict:
        api_url = "https://www.virustotal.com/api/v3/analyses/" + analysis_id["data"]["id"]
        for i in range(90):
            time.sleep(max(5, config["VT request limit (seconds)"]))
            response = requests.get(api_url, headers=headers).json()
            if response["data"]["attributes"]["status"] == "completed":
                return response["data"]["attributes"]["stats"]
        return {"timeout": api_url, "sha256": sha256}
    while True:
        if not parent_process.is_alive():
            return 0
        try:
            time.sleep(config["VT request limit (seconds)"])
            proc, analysis = None, None
            proc, sha256 = pickle.loads(q_vt_pending.get(block=True, timeout=15))
            suspicious = False
            if config["VT API key"] and vt_enabled:
                try:
                    analysis = requests.get("https://www.virustotal.com/api/v3/files/" + sha256, headers=headers).json()
                    analysis = analysis["data"]["attributes"]["last_analysis_stats"]
                except Exception:
                    if config["VT file upload"]:
                        try:
                            with open(proc["fd"], "rb") as f:
                                assert (proc["dev"], proc["ino"]) == get_fstat(f.fileno())
                                files = {"file": (proc["exe"], f)}
                                analysis_id = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files).json()
                            analysis = get_analysis(analysis_id, sha256)
                        except Exception:
                            try:
                                readlink_exe_sha256 = hashlib.sha256()
                                with open(proc["exe"], "rb") as f:
                                    while data := f.read(1048576):
                                        readlink_exe_sha256.update(data)
                                assert readlink_exe_sha256.hexdigest() == sha256
                                with open(proc["exe"], "rb") as f:
                                    files = {"file": (proc["exe"], f)}
                                    analysis_id = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files).json()
                                analysis = get_analysis(analysis_id, sha256)
                            except Exception:
                                q_vt_results.put(pickle.dumps((proc, sha256, "Failed to read process for upload", suspicious)))
                                continue
                    else:
                        # could also be an invalid api key
                        q_vt_results.put(pickle.dumps((proc, sha256, "File not analyzed (analysis not found)", suspicious)))
                        continue
                if analysis["suspicious"] != 0 or analysis["malicious"] != 0:
                    suspicious = True
                q_vt_results.put(pickle.dumps((proc, sha256, str(analysis), suspicious)))
            elif vt_enabled:
                q_vt_results.put(pickle.dumps((proc, sha256, "File not analyzed (no api key)", suspicious)))
            else:
                q_vt_results.put(pickle.dumps((proc, sha256, "File not analyzed (requests library not found)", suspicious)))
        except queue.Empty:
            # have to timeout here to check whether to terminate otherwise this could stay hanging
            # daemon=True flag for multiprocessing.Process does not work after root privileges are dropped for parent
            pass
        except Exception as e:
            q_error.put("VT %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))
            try:
                analysis = str(analysis)
            except Exception:
                analysis = "unknown analysis"
            q_error.put("Last VT Exception on: %s with %s" % (str(proc), str(analysis)))


def main_process(snitch: dict):
    """coordinates all picosnitch subprocesses"""
    # init fanotify
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    _FAN_CLASS_CONTENT = 0x4
    _FAN_UNLIMITED_MARKS = 0x20
    flags = _FAN_CLASS_CONTENT if FD_CACHE < 8192 else _FAN_CLASS_CONTENT | _FAN_UNLIMITED_MARKS
    fan_fd = libc.fanotify_init(flags, os.O_RDONLY)
    # start subprocesses
    snitch_primary_pipe, snitch_monitor_pipe = multiprocessing.Pipe(duplex=False)
    secondary_recv_pipe, secondary_send_pipe = multiprocessing.Pipe(duplex=False)
    q_error = multiprocessing.Queue()
    p_monitor = ProcessManager(name="snitchmonitor", target=monitor_subprocess,
                               init_args=(snitch["Config"], fan_fd, snitch_monitor_pipe, q_error,))
    p_virustotal = ProcessManager(name="snitchvirustotal", target=virustotal_subprocess,
                                  init_args=(snitch["Config"], q_error,))
    p_primary = ProcessManager(name="snitchprimary", target=primary_subprocess,
                               init_args=(snitch, snitch_primary_pipe, secondary_send_pipe, q_error,))
    p_secondary = ProcessManager(name="snitchsecondary", target=secondary_subprocess,
                           init_args=(snitch, fan_fd, p_virustotal, secondary_recv_pipe, p_primary.q_in, q_error,))
    # set signals
    subprocesses = [p_monitor, p_virustotal, p_primary, p_secondary]
    def clean_exit():
        _ = [p.terminate() for p in subprocesses]
        sys.exit(0)
    signal.signal(signal.SIGINT, lambda *args: clean_exit())
    signal.signal(signal.SIGTERM, lambda *args: clean_exit())
    # watch subprocesses
    suspend_check_last = time.time()
    try:
        while True:
            time.sleep(5)
            if not all(p.is_alive() for p in subprocesses):
                q_error.put("picosnitch subprocess died, attempting restart, terminate by running `picosnitch stop`")
                break
            if any(p.is_zombie() for p in subprocesses):
                q_error.put("picosnitch subprocess became a zombie, attempting restart")
                break
            if sum(p.memory() for p in subprocesses) > 4096000000:
                q_error.put("picosnitch memory usage exceeded 4096 MB, attempting restart")
                break
            suspend_check_now = time.time()
            if suspend_check_now - suspend_check_last > 20:
                p_monitor.q_in.put("terminate")
                p_monitor.terminate()
                _ = p_monitor.q_in.get()
                p_monitor.start()
            suspend_check_last = suspend_check_now
    except Exception as e:
        q_error.put("picosnitch subprocess exception: %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))
    if sys.argv[1] == "start-no-daemon":
        return 1
    # attempt to restart picosnitch (terminate by running `picosnitch stop`)
    time.sleep(5)
    _ = [p.terminate() for p in subprocesses]
    args = [sys.executable, os.path.abspath(__file__), "restart"]
    subprocess.Popen(args)
    return 0


### user interface
def ui_loop(stdscr: curses.window, splash: str, con: sqlite3.Connection) -> int:
    """for curses wrapper"""
    # init and splash screen
    cur = con.cursor()
    curses.cbreak()
    curses.noecho()
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_CYAN)  # selection
    curses.init_pair(2, curses.COLOR_YELLOW, -1)  # splash
    curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_MAGENTA)  # header
    curses.init_pair(4, curses.COLOR_WHITE, -1)  # splash
    splash_lines = splash.splitlines()
    stdscr.clear()
    for i in range(len(splash_lines)):
        if "\u001b[33m" in splash_lines[i]:
            part1 = splash_lines[i].split("\u001b[33m")
            part2 = part1[1].split("\033[0m")
            stdscr.addstr(i, 0, part1[0], curses.color_pair(4))
            stdscr.addstr(i, len(part1[0]), part2[0], curses.color_pair(2))
            stdscr.addstr(i, len(part1[0]) + len(part2[0]), part2[1], curses.color_pair(4))
        else:
            stdscr.addstr(i, 0, splash_lines[i])
    stdscr.refresh()
    # screens from queries (exe text, name text, cmdline text, sha256 text, contime text, domain text, ip text, port integer, uid integer)
    time_i = 0
    time_j = 0
    time_period = ["all", "1 minute", "3 minutes", "5 minutes", "10 minutes", "15 minutes", "30 minutes", "1 hour", "3 hours", "6 hours", "12 hours", "1 day", "3 days", "7 days", "30 days", "365 days"]
    time_minutes = [0, 1, 3, 5, 10, 15, 30, 60, 180, 360, 720, 1440, 4320, 10080, 43200, 525600]
    time_deltas = [datetime.timedelta(minutes=x) for x in time_minutes]
    time_r = ["second"] + ["minute"]*6 + ["hour"]*4 + ["day"]*3 + ["month"] + ["year"]
    time_resolution = collections.OrderedDict({
        "second": lambda x: x.replace(microsecond=0),
        "minute": lambda x: x.replace(microsecond=0, second=0),
        "hour": lambda x: x.replace(microsecond=0, second=0, minute=0),
        "day": lambda x: x.replace(microsecond=0, second=0, minute=0, hour=0),
        "month": lambda x: x.replace(microsecond=0, second=0, minute=0, hour=0, day=1),
        "year": lambda x: x.replace(microsecond=0, second=0, minute=0, hour=0, day=1, month=1),
    })
    pri_i = 0
    p_screens = ["Executables", "Process Names", "Commands", "SHA256", "Entry Time", "Domains", "Destination IPs", "Destination Ports", "Users", "Parent Executables", "Parent Names", "Parent Commands", "Parent SHA256"]
    p_names = ["Executable", "Process Name", "Command", "SHA256", "Entry Time", "Domain", "Destination IP", "Destination Port", "User", "Parent Executable", "Parent Name", "Parent Command", "Parent SHA256"]
    p_col = ["exe", "name", "cmdline", "sha256", "contime", "domain", "ip", "port", "uid", "pexe", "pname", "pcmdline", "psha256"]
    sec_i = 0
    s_screens, s_names, s_col = p_screens, p_names, p_col
    byte_units = 3
    round_bytes = lambda size, b: f"{size if b == 0 else round(size/10**b, 1)!s:>{8 if b == 0 else 7}} {'k' if b == 3 else 'M' if b == 6 else 'G' if b == 9 else ''}B"
    # ui loop
    max_y, max_x = stdscr.getmaxyx()
    first_line = 4
    cursor, saved_cursor, line = first_line, first_line, first_line
    primary_value = ""
    toggle_subquery = False
    is_subquery = False
    update_query = True
    execute_query = True
    current_query, current_screen = "", [""]
    while True:
        # adjust cursor
        pri_i %= len(p_col)
        sec_i %= len(s_col)
        time_i %= len(time_period)
        if time_j < 0 or time_i == 0:
            time_j = 0
        cursor %= line
        if cursor < first_line:
            cursor = first_line
        # generate screen
        if update_query:
            if time_j == 0:
                time_history_start = (datetime.datetime.now() - time_deltas[time_i]).strftime("%Y-%m-%d %H:%M:%S")
                time_history_end = "now"
                time_history = time_resolution["second"](datetime.datetime.now())
            elif time_i != 0:
                time_history_start = time_resolution[time_r[time_i]](datetime.datetime.now() - time_deltas[time_i] * (time_j-1)).strftime("%Y-%m-%d %H:%M:%S")
                time_history_end = time_resolution[time_r[time_i]](datetime.datetime.now() - time_deltas[time_i] * (time_j-2)).strftime("%Y-%m-%d %H:%M:%S")
                time_history = f"{time_history_start} -> {time_history_end}"
            if time_i == 0:
                time_query = ""
            else:
                if is_subquery:
                    time_query = f" AND contime > datetime(\"{time_history_start}\") AND contime < datetime(\"{time_history_end}\")"
                else:
                    time_query = f" WHERE contime > datetime(\"{time_history_start}\") AND contime < datetime(\"{time_history_end}\")"
            if is_subquery:
                current_query = f"SELECT {s_col[sec_i]}, SUM(\"conns\"), SUM(\"send\"), SUM(\"recv\") FROM connections WHERE {p_col[pri_i]} IS \"{primary_value}\"{time_query} GROUP BY {s_col[sec_i]}"
            else:
                current_query = f"SELECT {p_col[pri_i]}, SUM(\"conns\"), SUM(\"send\"), SUM(\"recv\") FROM connections{time_query} GROUP BY {p_col[pri_i]}"
            update_query = False
        if execute_query:
            try:
                with open("/run/picosnitch.pid", "r") as f:
                    run_status = "pid: " + f.read().strip()
            except Exception:
                run_status = "not running"
            print(f"\033]0;picosnitch v{VERSION} ({run_status})\a", end="", flush=True)
            while True:
                try:
                    cur.execute(current_query)
                    break
                except sqlite3.OperationalError:
                    stdscr.clear()
                    for i in range(len(splash_lines)):
                        if "\u001b[33m" in splash_lines[i]:
                            part1 = splash_lines[i].split("\u001b[33m")
                            part2 = part1[1].split("\033[0m")
                            stdscr.addstr(i, 0, part1[0], curses.color_pair(4))
                            stdscr.addstr(i, len(part1[0]), part2[0], curses.color_pair(2))
                            stdscr.addstr(i, len(part1[0]) + len(part2[0]), part2[1], curses.color_pair(4))
                        else:
                            stdscr.addstr(i, 0, splash_lines[i])
                    stdscr.refresh()
                except KeyboardInterrupt:
                    con.close()
                    return 0
            current_screen = cur.fetchall()
            execute_query = False
        help_bar = f"space/enter: filter on entry  backspace: remove filter  h/H: history  t/T: time range  u/U: units  r: refresh  q: quit {' ':<{curses.COLS}}"
        status_bar = f"history: {time_history}  time range: {time_period[time_i]}  line: {cursor-first_line+1}/{len(current_screen)}{' ':<{curses.COLS}}"
        if is_subquery:
            l_tabs = " ".join(reversed([s_screens[sec_i-i] for i in range (1, len(s_screens))]))
            r_tabs = " ".join([s_screens[(sec_i+i) % len(s_screens)] for i in range(1, len(s_screens))])
            c_tab = s_screens[sec_i]
            column_names = f"{f'{s_names[sec_i]} (where {p_names[pri_i].lower()} = {primary_value})':<{curses.COLS - 32}.{curses.COLS - 32}}  Connects       Sent   Received"
        else:
            l_tabs = " ".join(reversed([p_screens[pri_i-i] for i in range(1, len(p_screens))]))
            r_tabs = " ".join([p_screens[(pri_i+i) % len(p_screens)] for i in range(1, len(p_screens))])
            c_tab = p_screens[pri_i]
            column_names = f"{p_names[pri_i]:<{curses.COLS - 32}}  Connects       Sent   Received"
        l_width = (curses.COLS - len(c_tab) - 14) // 2
        r_width = curses.COLS - len(c_tab) - 14 - l_width
        l_tabs = f" ...{l_tabs[-l_width:]:>{l_width}} "
        r_tabs = f" {r_tabs:<{r_width}.{r_width}}... "
        # display screen
        stdscr.clear()
        stdscr.attrset(curses.color_pair(3) | curses.A_BOLD)
        stdscr.addstr(0, 0, help_bar)
        stdscr.addstr(1, 0, status_bar)
        stdscr.addstr(2, 0, "<-")
        stdscr.addstr(2, 2, l_tabs, curses.color_pair(3))
        stdscr.addstr(2, 2 + l_width + 5, c_tab, curses.color_pair(3) | curses.A_BOLD | curses.A_UNDERLINE)
        stdscr.addstr(2, 2 + l_width + 5 + len(c_tab), r_tabs, curses.color_pair(3))
        stdscr.addstr(2, 2 + l_width + 5 + len(c_tab) + r_width + 5, "->")
        stdscr.addstr(3, 0, column_names)
        line = first_line
        cursor = min(cursor, len(current_screen) + first_line - 1)
        offset = max(0, cursor - curses.LINES + 3)
        for name, conns, send, recv in current_screen:
            if line == cursor:
                stdscr.attrset(curses.color_pair(1) | curses.A_BOLD)
                if toggle_subquery:
                    if is_subquery:
                        if s_col[sec_i] not in p_col:
                            is_subquery = False
                            break
                        pri_i = sec_i
                    primary_value = name
                    is_subquery = True
                    break
            else:
                stdscr.attrset(curses.color_pair(0))
            if first_line <= line - offset < curses.LINES - 1:
                # special cases (cmdline null chars, uid, maybe add sha256 and vt results or debsums lookup?)
                if type(name) == str:
                    name = name.replace("\0", "")
                elif (not is_subquery and p_col[pri_i] == "uid") or (is_subquery and s_col[sec_i] == "uid"):
                    try:
                        name = f"{pwd.getpwuid(name).pw_name} ({name})"
                    except Exception:
                        name = f"??? ({name})"
                value = f"{conns:>10} {round_bytes(send, byte_units):>10.10} {round_bytes(recv, byte_units):>10.10}"
                stdscr.addstr(line - offset, 0, f"{name!s:<{curses.COLS-32}.{curses.COLS-32}}{value}")
            line += 1
        stdscr.refresh()
        if toggle_subquery:
            toggle_subquery = False
            update_query = True
            execute_query = True
            continue
        # user input
        ch = stdscr.getch()
        if ch == ord("\n") or ch == ord(" "):
            toggle_subquery = True
            if not is_subquery:
                saved_cursor = cursor
        elif ch == curses.KEY_BACKSPACE:
            if is_subquery:
                cursor = saved_cursor
                line = saved_cursor + 1
            is_subquery = False
            update_query = True
            execute_query = True
        elif ch == ord("r"):
            update_query = True
            execute_query = True
        elif ch == ord("t"):
            time_j = 0
            time_i += 1
            update_query = True
            execute_query = True
        elif ch == ord("T"):
            time_j = 0
            time_i -= 1
            update_query = True
            execute_query = True
        elif ch == ord("h"):
            time_j += 1
            update_query = True
            execute_query = True
        elif ch == ord("H"):
            time_j -= 1
            update_query = True
            execute_query = True
        elif ch == ord("u"):
            byte_units = (byte_units + 3) % 12
        elif ch == ord("U"):
            byte_units = (byte_units - 3) % 12
        elif ch == curses.KEY_UP:
            cursor -= 1
            if cursor < first_line:
                cursor = -1
        elif ch == curses.KEY_DOWN:
            cursor += 1
        elif ch == curses.KEY_PPAGE:
            cursor -= curses.LINES
            if cursor < first_line:
                cursor = first_line
        elif ch == curses.KEY_NPAGE:
            cursor += curses.LINES
            if cursor >= line:
                cursor = line - 1
        elif ch == curses.KEY_HOME:
            cursor = first_line
        elif ch == curses.KEY_END:
            cursor = len(current_screen) + first_line - 1
        elif ch == curses.KEY_LEFT:
            if is_subquery:
                sec_i -= 1
            else:
                pri_i -= 1
            update_query = True
            execute_query = True
        elif ch == curses.KEY_RIGHT:
            if is_subquery:
                sec_i += 1
            else:
                pri_i += 1
            update_query = True
            execute_query = True
        elif ch == curses.KEY_RESIZE and curses.is_term_resized(max_y, max_x):
            max_y, max_x = stdscr.getmaxyx()
            stdscr.clear()
            curses.resizeterm(max_y, max_x)
            stdscr.refresh()
            cursor = first_line
        elif ch == 27 or ch == ord("q"):
            con.close()
            return 0


def ui_init() -> int:
    """init curses ui"""
    splash = textwrap.dedent("""
        @@&@@                                                              @@@@,
      &&.,,. &&&&&&%&%&&&&&&&&(..                      ..&&%&%&&&&&&&&%&&&&  .,#&%
        ,,/%#/(....,.,/(.  ...*,,%%                  %#*,..,... // ...,..//#%*,
             @@@@@@#((      #(/    @@  %@@@@@@@@  /@@    #(,      ##@@&@@@@
                   %@&    #(  .      @@\u001b[33m/********\033[0m@@(        (((    @@
                     .@@((    ,    @@\u001b[33m.,*,,****,,,,\033[0m(@@      . .#(@@
                        @@@@@@&@@@@@@\u001b[33m,,*,,,,,,,,,,\033[0m(@@@@@@@@&@@@@
                                   @@\u001b[33m**/*/*,**///*\033[0m(@@
                                   @@\u001b[33m.****/*//,*,*\033[0m/@@
                                     @&\u001b[33m//*////,/\033[0m&&(
                                       ,*\u001b[33m,,,,,,\033[0m,

    Loading database ...
    """)
    # init sql connection
    file_path = os.path.join(BASE_PATH, "snitch.db")
    con = sqlite3.connect(file_path, timeout=15)
    # check for table
    cur = con.cursor()
    cur.execute(''' PRAGMA user_version ''')
    assert cur.fetchone()[0] == 2, f"Incorrect database version of snitch.db for picosnitch v{VERSION}"
    con.close()
    con = sqlite3.connect(file_path, timeout=1)
    # start curses
    for err_count in reversed(range(30)):
        try:
            return curses.wrapper(ui_loop, splash, con)
        except curses.error:
            print("CURSES DISPLAY ERROR: try resizing your terminal, ui will close in %s seconds" % (err_count + 1), file=sys.stderr)
            time.sleep(1)
    return 1


def ui_dash():
    """gui with plotly dash"""
    from dash import Dash, dcc, html
    from dash.dependencies import Input, Output
    import pandas.io.sql as psql
    import plotly.express as px
    file_path = os.path.join(BASE_PATH, "snitch.db")
    all_dims = ["exe", "name", "cmdline", "sha256", "domain", "ip", "port", "uid", "pexe", "pname", "pcmdline", "psha256"]
    dim_labels = {"exe": "Executable", "name": "Process Name", "cmdline": "Command", "sha256": "SHA256", "domain": "Domain", "ip": "Destination IP", "port": "Destination Port", "uid": "User", "pexe": "Parent Executable", "pname": "Parent Name", "pcmdline": "Parent Command", "psha256": "Parent SHA256"}
    time_period = ["all", "1 minute", "3 minutes", "5 minutes", "10 minutes", "15 minutes", "30 minutes", "1 hour", "3 hours", "6 hours", "12 hours", "1 day", "3 days", "7 days", "30 days", "365 days"]
    time_minutes = [0, 1, 3, 5, 10, 15, 30, 60, 180, 360, 720, 1440, 4320, 10080, 43200, 525600]
    time_deltas = [datetime.timedelta(minutes=x) for x in time_minutes]
    time_r = ["second"] + ["minute"]*6 + ["hour"]*4 + ["day"]*3 + ["month"] + ["year"]
    time_resolution = collections.OrderedDict({
        "second": lambda x: x.replace(microsecond=0),
        "minute": lambda x: x.replace(microsecond=0, second=0),
        "hour": lambda x: x.replace(microsecond=0, second=0, minute=0),
        "day": lambda x: x.replace(microsecond=0, second=0, minute=0, hour=0),
        "month": lambda x: x.replace(microsecond=0, second=0, minute=0, hour=0, day=1),
        "year": lambda x: x.replace(microsecond=0, second=0, minute=0, hour=0, day=1, month=1),
    })
    def get_user(uid) -> str:
        try:
            return f"{pwd.getpwuid(uid).pw_name} ({uid})"
        except Exception:
            return f"??? ({uid})"
    def get_totals(df, dim) -> str:
        size = df[dim]
        if size > 10**9:
            return f"{dim} ({round(size/10**9, 2)!s} GB)"
        elif size > 10**6:
            return f"{dim} ({round(size/10**6, 2)!s} MB)"
        elif size > 10**3:
            return f"{dim} ({round(size/10**3, 2)!s} kB)"
        else:
            return f"{dim} ({size!s} B)"
    def trim_cmdline(cmdline, trim) -> str:
        if trim and len(cmdline) > 64:
            return f"{cmdline[:32]}...{cmdline[-29:]}"
        return cmdline
    def serve_layout():
        try:
            with open("/run/picosnitch.pid", "r") as f:
                run_status = "pid: " + f.read().strip()
        except Exception:
            run_status = "not running"
        return html.Div([
            dcc.Interval(
                id="interval-component",
                interval=10000,
                disabled=True,
            ),
            html.Div(html.Button("Stop Dash", id="exit"), style={"float": "right"}),
            html.Div([
                dcc.Dropdown(
                    id="smoothing",
                    options=[
                        {"label": "Use Rolling Window", "value": True},
                        {"label": "Raw Values", "value": False},
                    ],
                    value=True,
                    clearable=False,
                ),
            ], style={"display":"inline-block", "width": "20%"}),
            html.Div([
                dcc.Dropdown(
                    id="trim-cmds",
                    options=[
                        {"label": "Trim Commands", "value": True},
                        {"label": "Show Full Commands", "value": False},
                    ],
                    value=True,
                    clearable=False,
                ),
            ], style={"display":"inline-block", "width": "20%"}),
            html.Div([
                dcc.Dropdown(
                    id="auto-refresh",
                    options=[
                        {"label": "Auto-Refresh (10 seconds)", "value": True},
                        {"label": "Disable Auto-Refresh", "value": False},
                    ],
                    value=False,
                    clearable=False,
                ),
            ], style={"display":"inline-block", "width": "20%"}),
            html.Div(),
            html.Div([
                dcc.Dropdown(
                    id="select",
                    options=[{"label": f"Select {dim_labels[x]}", "value": x} for x in all_dims],
                    value="exe",
                    clearable=False,
                ),
            ], style={"display":"inline-block", "width": "33%"}),
            html.Div([
                dcc.Dropdown(
                    id="where",
                    options=[{"label": f"Where {dim_labels[x]}", "value": x} for x in all_dims],
                    placeholder="Where...",
                ),
            ], style={"display":"inline-block", "width": "33%"}),
            html.Div([
                dcc.Dropdown(
                    id="whereis",
                    placeholder="Is...",
                ),
            ], style={"display":"inline-block", "width": "33%"}),
            html.Div([
                dcc.RadioItems(
                    id="time_i",
                    options=[{"label": time_period[i], "value": i} for i in range(len(time_period))],
                    value=8,
                ),
            ]),
            html.Div([
                dcc.Slider(
                    id="time_j",
                    min=0, max=100, step=1, value=0,
                    included=False,
                ),
            ]),
            dcc.Graph(id="send", config={"scrollZoom": False}),
            dcc.Graph(id="recv", config={"scrollZoom": False}),
            html.Footer(f"picosnitch v{VERSION} ({run_status}) (using {file_path})"),
        ])
    app = Dash(__name__)
    app.layout = serve_layout
    @app.callback(Output("interval-component", "disabled"), Input("auto-refresh", "value"))
    def toggle_refresh(value):
        return not value
    @app.callback(Output("time_j", "marks"), Input("time_i", "value"), Input("time_j", "value"))
    def update_time_slider(time_i, _):
        return {x: time_resolution[time_r[time_i]](datetime.datetime.now() - time_deltas[time_i] * (x-2)).strftime("%Y-%m-%d %H:%M:%S") for x in range(2,100,10)}
    @app.callback(Output("send", "figure"), Output("recv", "figure"), Output("whereis", "options"), Input("smoothing", "value"), Input("trim-cmds", "value"), Input("select", "value"), Input("where", "value"), Input("whereis", "value"), Input("time_i", "value"), Input("time_j", "value"), Input("interval-component", "n_intervals"))
    def update(smoothing, trim, dim, where, whereis, time_i, time_j, _):
        if time_j == 0:
            time_history_start = (datetime.datetime.now() - time_deltas[time_i]).strftime("%Y-%m-%d %H:%M:%S")
            time_history_end = "now"
        elif time_i != 0:
            time_history_start = time_resolution[time_r[time_i]](datetime.datetime.now() - time_deltas[time_i] * (time_j-1)).strftime("%Y-%m-%d %H:%M:%S")
            time_history_end = time_resolution[time_r[time_i]](datetime.datetime.now() - time_deltas[time_i] * (time_j-2)).strftime("%Y-%m-%d %H:%M:%S")
        if time_i == 0:
            time_query = ""
        else:
            if where and whereis:
                time_query = f" AND contime > datetime(\"{time_history_start}\") AND contime < datetime(\"{time_history_end}\")"
            else:
                time_query = f" WHERE contime > datetime(\"{time_history_start}\") AND contime < datetime(\"{time_history_end}\")"
        if where and whereis:
            query = f"SELECT {dim}, contime, send, recv FROM connections WHERE {where} IS \"{whereis}\"{time_query}"
        else:
            query = f"SELECT {dim}, contime, send, recv FROM connections{time_query}"
        con = sqlite3.connect(file_path)
        df = psql.read_sql(query, con)
        whereis_options = []
        if where:
            if time_query.startswith(" AND"):
                time_query = time_query.replace(" AND", " WHERE", 1)
            query = f"SELECT DISTINCT {where} FROM connections{time_query}"
            cur = con.cursor()
            cur.execute(query)
            whereis_values = cur.fetchall()
            if where == "uid":
                whereis_options = [{"label": f"is {get_user(x[0])}", "value": x[0]} for x in whereis_values]
            elif where in ["cmdline", "pcmdline"]:
                whereis_options = [{"label": f"is {trim_cmdline(x[0], trim)}", "value": x[0]} for x in whereis_values]
            else:
                whereis_options = [{"label": f"is {x[0]}", "value": x[0]} for x in whereis_values]
        con.close()
        df_send = df.pivot_table(index="contime", columns=dim, values="send", fill_value=0, dropna=False, aggfunc=sum)
        df_recv = df.pivot_table(index="contime", columns=dim, values="recv", fill_value=0, dropna=False, aggfunc=sum)
        if dim == "uid":
            df_send.rename(columns=get_user, inplace=True)
            df_recv.rename(columns=get_user, inplace=True)
        elif dim in ["cmdline", "pcmdline"]:
            df_send.rename(columns=lambda x: trim_cmdline(x, trim), inplace=True)
            df_recv.rename(columns=lambda x: trim_cmdline(x, trim), inplace=True)
        df_send_total = df_send.sum()
        df_recv_total = df_recv.sum()
        if smoothing:
            df_send = df_send.rolling(4).mean()
            df_recv = df_recv.rolling(4).mean()
        df_send.rename(columns=lambda dim: get_totals(df_send_total, dim), inplace=True)
        df_recv.rename(columns=lambda dim: get_totals(df_recv_total, dim), inplace=True)
        fig_send = px.line(df_send, line_shape="linear", render_mode="svg", labels={
            "contime": "", "value": "Data Sent (bytes)", dim: dim_labels[dim]})
        fig_send.update_layout(uirevision=dim)
        fig_send.update_yaxes(autorange=True, fixedrange=True)
        fig_send.update_traces(fill="tozeroy", line_simplify=True)
        fig_recv = px.line(df_recv, line_shape="linear", render_mode="svg", labels={
            "contime": "", "value": "Data Received (bytes)", dim: dim_labels[dim]})
        fig_recv.update_layout(uirevision=dim)
        fig_recv.update_yaxes(autorange=True, fixedrange=True)
        fig_recv.update_traces(fill="tozeroy", line_simplify=True)
        return fig_send, fig_recv, whereis_options
    @app.callback(Output("exit", "n_clicks"), Input("exit", "n_clicks"))
    def exit(clicks):
        if clicks:
            os.kill(os.getpid(), signal.SIGTERM)
        return 0
    app.run_server(host=os.getenv("HOST", "localhost"), port=os.getenv("PORT", "5100"), debug=bool(eval(os.getenv("DASH_DEBUG", "False"))))


### startup
def main():
    """init picosnitch"""
    # master copy of the snitch dictionary, all subprocesses only receive a static copy of it from this point in time
    snitch = read_snitch()
    # start picosnitch process monitor
    with open("/run/picosnitch.pid", "r") as f:
        assert int(f.read().strip()) == os.getpid()
    if __name__ == "__main__" or sys.argv[1] == "start-no-daemon":
        sys.exit(main_process(snitch))
    print("Snitch subprocess init failed, __name__ != __main__", file=sys.stderr)
    sys.exit(1)


def start_picosnitch():
    """command line interface, pre-startup checks, and run"""
    readme = textwrap.dedent(f"""    Monitor your system for applications that make network connections, track their
    bandwidth, verify hashes, and receive notifications.

    picosnitch comes with ABSOLUTELY NO WARRANTY. This is free software, and you
    are welcome to redistribute it under certain conditions. See version 3 of the
    GNU General Public License for details.

    website: https://elesiuta.github.io/picosnitch
    version: {VERSION} ({os.path.abspath(__file__)})
    config and log files: {BASE_PATH}

    usage:
        picosnitch dash|view|status|version|help
                    |    |    |      |       |--> this text
                    |    |    |      |--> version info
                    |    |    |--> show pid
                    |    |--> curses tui
                    |--> start web gui (http://{os.getenv("HOST", "localhost")}:{os.getenv("PORT", "5100")})

        systemctl enable|disable|start|stop|restart|status picosnitch
                   |      |       |     |    |       |--> show status with systemd
                   |      |       |_____|____|--> start/stop/restart picosnitch
                   |______|--> enable/disable autostart on reboot

    * if systemctl isn't working, recreate the service with `picosnitch systemd`

    * if you don't use systemd, you can use `picosnitch start|stop|restart` instead
    """)
    systemd_service = textwrap.dedent(f"""    [Unit]
    Description=picosnitch

    [Service]
    Type=simple
    Restart=always
    RestartSec=5
    Environment="SUDO_UID={os.getenv("SUDO_UID")}" "SUDO_USER={os.getenv("SUDO_USER")}" "DBUS_SESSION_BUS_ADDRESS={os.getenv("DBUS_SESSION_BUS_ADDRESS")}" "PYTHON_USER_SITE={site.USER_SITE}"
    ExecStart={sys.executable} "{os.path.abspath(__file__)}" start-no-daemon
    PIDFile=/run/picosnitch.pid

    [Install]
    WantedBy=multi-user.target
    """)
    if len(sys.argv) == 2:
        if sys.argv[1] == "help":
            print(readme)
            return 0
        elif sys.argv[1] == "dash":
            if os.getuid() != 0:
                subprocess.Popen(["bash", "-c", f'let i=0; rm {BASE_PATH}/dash; while [[ ! -f {BASE_PATH}/dash || "$i" -gt 30 ]]; do let i++; sleep 1; done; rm {BASE_PATH}/dash && /usr/bin/env python3 -m webbrowser -t http://{os.getenv("HOST", "localhost")}:{os.getenv("PORT", "5100")}'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.getuid() != 0:
            args = ["sudo", "-E", sys.executable, os.path.abspath(__file__), sys.argv[1]]
            os.execvp("sudo", args)
        with open("/proc/self/status", "r") as f:
            proc_status = f.read()
            capeff = int(proc_status[proc_status.find("CapEff:")+8:].splitlines()[0].strip(), base=16)
            cap_sys_admin = 2**21
            assert capeff & cap_sys_admin, "Missing capability CAP_SYS_ADMIN"
        assert importlib.util.find_spec("bcc"), "Requires BCC https://github.com/iovisor/bcc/blob/master/INSTALL.md"
        tmp_snitch = read_snitch()
        con = sqlite3.connect(os.path.join(BASE_PATH, "snitch.db"))
        cur = con.cursor()
        cur.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='connections' ''')
        if cur.fetchone()[0] != 1:
            cur.execute(''' CREATE TABLE connections
                            (exe text, name text, cmdline text, sha256 text, contime text, domain text, ip text, port integer, uid integer, pexe text, pname text, pcmdline text, psha256 text, conns integer, send integer, recv integer) ''')
            cur.execute(''' PRAGMA user_version = 2 ''')
            con.commit()
        else:
            cur.execute(''' PRAGMA user_version ''')
            user_version = cur.fetchone()[0]
            if user_version == 0:
                cur.execute(''' ALTER TABLE connections RENAME COLUMN events TO conns ''')
                cur.execute(''' ALTER TABLE connections ADD COLUMN send integer DEFAULT 0 NOT NULL ''')
                cur.execute(''' ALTER TABLE connections ADD COLUMN recv integer DEFAULT 0 NOT NULL ''')
                cur.execute(''' PRAGMA user_version = 1 ''')
                con.commit()
            if user_version <= 1:
                cur.execute(''' ALTER TABLE connections RENAME TO tmp ''')
                cur.execute(''' CREATE TABLE connections
                                (exe text, name text, cmdline text, sha256 text, contime text, domain text, ip text, port integer, uid integer, pexe text DEFAULT "", pname text DEFAULT "", pcmdline text DEFAULT "", psha256 text DEFAULT "", conns integer, send integer, recv integer) ''')
                cur.execute(''' INSERT INTO connections
                                (exe, name, cmdline, sha256, contime, domain, ip, port, uid, conns, send, recv) SELECT exe, name, cmdline, sha256, contime, domain, ip, port, uid, conns, send, recv FROM tmp ''')
                cur.execute(''' DROP TABLE tmp ''')
                cur.execute(''' PRAGMA user_version = 2 ''')
                con.commit()
        con.close()
        if sql_kwargs := tmp_snitch["Config"]["DB sql server"]:
            sql_client = sql_kwargs.pop("client", "no client error")
            table_name = sql_kwargs.pop("table_name", "connections")
            sql = importlib.import_module(sql_client)
            if sql_client not in ["mariadb", "psycopg", "psycopg2", "pymysql"]:
                print(f"Warning, using {sql_client} for \"DB sql server\" \"client\" may not be supported, ensure it implements PEP 249", file=sys.stderr)
            try:
                con = sql.connect(**sql_kwargs)
                cur = con.cursor()
                cur.execute(f''' CREATE TABLE IF NOT EXISTS {table_name}
                                 (exe text, name text, cmdline text, sha256 text, contime text, domain text, ip text, port integer, uid integer, pexe text, pname text, pcmdline text, psha256 text, conns integer, send integer, recv integer) ''')
                con.commit()
                con.close()
            except Exception as e:
                print("Warning: %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno), file=sys.stderr)
        if sys.argv[1] in ["start", "stop", "restart"]:
            if os.path.exists("/usr/lib/systemd/system/picosnitch.service"):
                print("Found /usr/lib/systemd/system/picosnitch.service but you are not using systemctl")
                if sys.stdin.isatty():
                    confirm = input(f"Did you intend to run `systemctl {sys.argv[1]} picosnitch` (y/N)? ")
                    if confirm.lower().startswith("y"):
                        subprocess.run(["systemctl", sys.argv[1], "picosnitch"])
                        return 0
        class PicoDaemon(Daemon):
            def run(self):
                main()
        daemon = PicoDaemon("/run/picosnitch.pid")
        if sys.argv[1] == "start":
            print("starting picosnitch daemon")
            daemon.start()
        elif sys.argv[1] == "stop":
            print("stopping picosnitch daemon")
            daemon.stop()
        elif sys.argv[1] == "restart":
            print("restarting picosnitch daemon")
            daemon.restart()
        elif sys.argv[1] == "status":
            daemon.status()
        elif sys.argv[1] == "systemd":
            with open("/usr/lib/systemd/system/picosnitch.service", "w") as f:
                f.write(systemd_service)
            subprocess.run(["systemctl", "daemon-reload"])
            print("Wrote /usr/lib/systemd/system/picosnitch.service\nYou can now run picosnitch using systemctl")
            return 0
        elif sys.argv[1] == "start-no-daemon":
            assert not os.path.exists("/run/picosnitch.pid")
            def delpid():
                os.remove("/run/picosnitch.pid")
            atexit.register(delpid)
            with open("/run/picosnitch.pid", "w") as f:
                f.write(str(os.getpid()) + "\n")
            print("starting picosnitch in simple mode")
            print(f"using config and log files from: {BASE_PATH}")
            print(f"using DBUS_SESSION_BUS_ADDRESS: {os.getenv('DBUS_SESSION_BUS_ADDRESS')}")
            sys.exit(main())
        elif sys.argv[1] == "dash":
            import dash, pandas, plotly
            assert dash.__version__ and pandas.__version__ and plotly.__version__
            print(f"serving web gui on http://{os.getenv('HOST', 'localhost')}:{os.getenv('PORT', '5100')}")
            args = ["bash", "-c", f"sudo -i -u {os.getenv('SUDO_USER')} touch {BASE_PATH}/dash; nohup {sys.executable} \"{os.path.abspath(__file__)}\" start-dash > /dev/null 2>&1 &"]
            os.execvp("bash", args)
        elif sys.argv[1] == "start-dash":
            return ui_dash()
        elif sys.argv[1] == "view":
            return ui_init()
        elif sys.argv[1] == "version":
            print(f"version: {VERSION} ({os.path.abspath(__file__)})\nconfig and log files: {BASE_PATH}")
            return 0
        else:
            print(readme)
            return 2
        return 0
    else:
        print(readme)
        return 2


### bpf program
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

struct ipv4_event_t {
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    u64 ino;
    u64 pino;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 dev;
    u32 pdev;
    u32 daddr;
    u16 dport;
} __attribute__((packed));
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_event_t {
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    unsigned __int128 daddr;
    u64 ino;
    u64 pino;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 dev;
    u32 pdev;
    u16 dport;
} __attribute__((packed));
BPF_PERF_OUTPUT(ipv6_events);

struct other_socket_event_t {
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
BPF_PERF_OUTPUT(other_socket_events);

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

int security_socket_connect_entry(struct pt_regs *ctx, struct socket *sock, struct sockaddr *address, int addrlen) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;
    u64 ino = task->mm->exe_file->f_path.dentry->d_inode->i_ino;
    u32 dev = task->mm->exe_file->f_path.dentry->d_inode->i_sb->s_dev;
    dev = new_encode_dev(dev);
    u64 pino = task->real_parent->mm->exe_file->f_path.dentry->d_inode->i_ino;
    u32 pdev = task->real_parent->mm->exe_file->f_path.dentry->d_inode->i_sb->s_dev;
    pdev = new_encode_dev(pdev);
    u32 address_family = address->sa_family;
    if (address_family == AF_INET) {
        struct ipv4_event_t data4 = {.pid = pid, .ppid = ppid, .uid = uid, .dev = dev, .pdev = pdev, .ino = ino, .pino = pino};
        struct sockaddr_in *daddr = (struct sockaddr_in *)address;
        bpf_probe_read(&data4.daddr, sizeof(data4.daddr), &daddr->sin_addr.s_addr);
        u16 dport = 0;
        bpf_probe_read(&dport, sizeof(dport), &daddr->sin_port);
        data4.dport = ntohs(dport);
        bpf_get_current_comm(&data4.comm, sizeof(data4.comm));
        bpf_probe_read_kernel_str(&data4.pcomm, sizeof(data4.pcomm), &task->real_parent->comm);
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    }
    else if (address_family == AF_INET6) {
        struct ipv6_event_t data6 = {.pid = pid, .ppid = ppid, .uid = uid, .dev = dev, .pdev = pdev, .ino = ino, .pino = pino};
        struct sockaddr_in6 *daddr6 = (struct sockaddr_in6 *)address;
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr), &daddr6->sin6_addr.in6_u.u6_addr32);
        u16 dport6 = 0;
        bpf_probe_read(&dport6, sizeof(dport6), &daddr6->sin6_port);
        data6.dport = ntohs(dport6);
        bpf_get_current_comm(&data6.comm, sizeof(data6.comm));
        bpf_probe_read_kernel_str(&data6.pcomm, sizeof(data6.pcomm), &task->real_parent->comm);
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    else if (address_family != AF_UNIX && address_family != AF_UNSPEC) {
        struct other_socket_event_t socket_event = {.pid = pid, .ppid = ppid, .uid = uid, .dev = dev, .pdev = pdev, .ino = ino, .pino = pino};
        bpf_get_current_comm(&socket_event.comm, sizeof(socket_event.comm));
        other_socket_events.perf_submit(ctx, &socket_event, sizeof(socket_event));
    }
    return 0;
}

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
#include <net/sock.h>

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
    u16 dport;
} __attribute__((packed));
BPF_PERF_OUTPUT(sendmsg_events);
BPF_PERF_OUTPUT(recvmsg_events);

struct sendrecv6_event_t {
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    unsigned __int128 daddr;
    u64 ino;
    u64 pino;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 dev;
    u32 pdev;
    u32 bytes;
    u16 dport;
} __attribute__((packed));
BPF_PERF_OUTPUT(sendmsg6_events);
BPF_PERF_OUTPUT(recvmsg6_events);
"""

bpf_text_bandwidth_probe = """
KRETFUNC_PROBE(sock_sendmsg, struct socket *sock, struct msghdr *msg, int flags, u32 retval) {
    if (retval > 0 && retval < 0x7fffffff) {
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
            bpf_probe_read(&data.dport, sizeof(data.dport), &sock->sk->__sk_common.skc_dport);
            data.dport = ntohs(data.dport);
            sendmsg_events.perf_submit(ctx, &data, sizeof(data));
        }
        else if (address_family == AF_INET6) {
            struct sendrecv6_event_t data = {.pid = pid, .ppid = ppid, .uid = uid, .dev = dev, .pdev = pdev, .ino = ino, .pino = pino, .bytes = retval};
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            bpf_probe_read_kernel_str(&data.pcomm, sizeof(data.pcomm), &parent->comm);
            bpf_probe_read(&data.daddr, sizeof(data.daddr), &sock->sk->__sk_common.skc_v6_daddr);
            bpf_probe_read(&data.dport, sizeof(data.dport), &sock->sk->__sk_common.skc_dport);
            data.dport = ntohs(data.dport);
            sendmsg6_events.perf_submit(ctx, &data, sizeof(data));
        }
    }
    return 0;
}
"""

if __name__ == "__main__":
    sys.exit(start_picosnitch())
