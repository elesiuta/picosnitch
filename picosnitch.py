#!/usr/bin/env python3
# picosnitch
# Copyright (C) 2020-2021 Eric Lesiuta

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

# set constants and RLIMIT_NOFILE if configured
VERSION: typing.Final[str] = "0.8.0"
PAGE_CNT: typing.Final[int] = 8
if sys.platform.startswith("linux") and os.getuid() == 0 and (os.getenv("SUDO_UID") or os.getenv("SUDO_USER")):
    if os.getenv("SUDO_USER"):
        home_dir = os.path.join("/home", os.getenv("SUDO_USER"))
    else:
        home_dir = pwd.getpwuid(int(os.getenv("SUDO_UID"))).pw_dir
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


### classes
class Daemon:
    """A generic daemon class from http://www.jejik.com/files/examples/daemon3x.py"""
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
                self.system_notification(msg)
            else:
                print(msg, file=file)
                self.notification_queue.append(msg)
                if self.dbus_notifications:
                    self.enable_notifications()
                    if self.notifications_ready:
                        for msg in self.notification_queue:
                            try:
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
            "DB retention (days)": 365,
            "DB sql log": True,
            "DB text log": False,
            "DB write limit (seconds)": 1,
            "Desktop notifications": True,
            "Log addresses": True,
            "Log commands": True,
            "Log ignore": [],
            "Set RLIMIT_NOFILE": None,
            "VT API key": "",
            "VT file upload": False,
            "VT request limit (seconds)": 15
        },
        "Error Log": [],
        "Exe Log": [],
        "Executables": {},
        "Names": {},
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
        for key in ["Executables", "Names", "SHA256"]:
            if key in snitch_record:
                data[key] = snitch_record[key]
    assert all(type(data[key]) == type(template[key]) for key in template), "Invalid json files"
    assert all(key == "Set RLIMIT_NOFILE" or type(data["Config"][key]) == type(template["Config"][key]) for key in template["Config"]), "Invalid config"
    if write_config:
        write_snitch(data, True)
    return data


def write_snitch(snitch: dict, write_config: bool = False) -> None:
    """write the snitch dictionary to config.json, record.json, exe.log, and error.log"""
    config_path = os.path.join(BASE_PATH, "config.json")
    record_path = os.path.join(BASE_PATH, "record.json")
    exe_log_path = os.path.join(BASE_PATH, "exe.log")
    error_log_path = os.path.join(BASE_PATH, "error.log")
    if not os.path.isdir(BASE_PATH):
        os.makedirs(BASE_PATH)
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
            if not st_dev or not st_ino:
                return "!!! FD Stat Error"
            if (st_dev, st_ino) != get_fstat(f.fileno()):
                return "!!! FD_CACHE Overflow Error"
            while data := f.read(1048576):
                sha256.update(data)
        return sha256.hexdigest()
    except Exception:
        return "!!! Hash FD Read Error"


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
        return "!!! Hash PID Read Error"


def get_stat(path: str, follow_symlinks: bool = True) -> typing.Tuple[int, int]:
    try:
        stat = os.stat(path, follow_symlinks=follow_symlinks)
        return stat.st_dev, stat.st_ino
    except Exception:
        return 0, 0


def get_fstat(fd: int) -> typing.Tuple[int, int]:
    try:
        stat = os.fstat(fd)
        return stat.st_dev, stat.st_ino
    except Exception:
        return 0, 0


def get_fanotify_events(fan_fd: int, fan_mod_cnt: dict, q_error: multiprocessing.Queue) -> None:
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
                if snitch["SHA256"][exe][sha256] in ["VT Pending", "Failed to read process for upload", "", None]:
                    if exe in snitch["Executables"] and snitch["Executables"][exe]:
                        name = snitch["Executables"][exe][0]
                    else:
                        name = exe
                    proc = {"exe": exe, "name": name}
                    q_vt.put(pickle.dumps((proc, sha256)))
    else:
        while not q_vt.empty():
            proc, sha256, result, suspicious = pickle.loads(q_vt.get())
            snitch["SHA256"][proc["exe"]][sha256] = result
            q_out.put(pickle.dumps({"type": "vt_result", "name": proc["name"], "exe": proc["exe"], "sha256": sha256, "result": result, "suspicious": suspicious}))


def initial_poll(snitch: dict) -> list:
    """poll initial processes and connections using psutil and queue for updater_subprocess"""
    datetime_now = time.strftime("%Y-%m-%d %H:%M:%S")
    initial_processes = []
    current_connections = set(psutil.net_connections(kind="all"))
    for conn in current_connections:
        try:
            if conn.pid is not None and conn.raddr and not ipaddress.ip_address(conn.raddr.ip).is_private:
                proc = psutil.Process(conn.pid).as_dict(attrs=["name", "exe", "cmdline", "pid", "uids"], ad_value="")
                proc["cmdline"] = shlex.join(proc["cmdline"])
                proc["fd"] = "/proc/%d/exe" % proc["pid"]  # default path so there is still a chance of hashing if not enough available file descriptors, without modifying code
                proc["dev"], proc["ino"] = get_stat(proc["fd"])
                proc["uid"] = proc["uids"][0]
                proc["ip"] = conn.raddr.ip
                proc["port"] = conn.raddr.port
                initial_processes.append(proc)
        except Exception as e:
            # too late to grab process info (most likely) or some other error
            error = "Init " + type(e).__name__ + str(e.args) + str(conn)
            if conn.pid == proc["pid"]:
                error += str(proc)
            else:
                error += "{process no longer exists}"
            snitch["Error Log"].append(datetime_now + " " + error)
    return initial_processes


def sql_subprocess_helper(snitch: dict, fan_mod_cnt: dict, new_processes: typing.List[bytes], q_vt: multiprocessing.Queue, q_out: multiprocessing.Queue, q_error: multiprocessing.Queue) -> typing.List[tuple]:
    """iterate over the list of process/connection data and get sha256 to generate a list of transactions for the sql database"""
    datetime_now = time.strftime("%Y-%m-%d %H:%M:%S")
    event_counter = collections.defaultdict(int)
    transactions = set()
    for proc in new_processes:
        proc = pickle.loads(proc)
        if type(proc) != dict:
            q_error.put("sync error between sql and updater, received '%s' in middle of transfer" % str(proc))
            continue
        sha_fd_error = ""
        sha256 = get_sha256_fd(proc["fd"], proc["dev"], proc["ino"], fan_mod_cnt["%d %d" % (proc["dev"], proc["ino"])])
        if sha256.startswith("!"):
            # fallback on trying to read directly (if still alive) if fd_cache fails
            sha_fd_error = sha256
            sha256 = get_sha256_pid(proc["pid"], proc["dev"], proc["ino"])
            if sha256.startswith("!"):
                # notify user with what went wrong (may be cause for suspicion)
                sha256_error = sha_fd_error[4:] + " and " + sha256[4:]
                sha256 = sha_fd_error + " " + sha256
                q_error.put(sha256_error + " for " + str(proc))
        if proc["exe"] in snitch["SHA256"]:
            if sha256 not in snitch["SHA256"][proc["exe"]]:
                snitch["SHA256"][proc["exe"]][sha256] = "VT Pending"
                q_vt.put(pickle.dumps((proc, sha256)))
                q_out.put(pickle.dumps({"type": "sha256", "name": proc["name"], "exe": proc["exe"], "sha256": sha256}))
        else:
            snitch["SHA256"][proc["exe"]] = {sha256: "VT Pending"}
            q_vt.put(pickle.dumps((proc, sha256)))
            q_out.put(pickle.dumps({"type": "sha256", "name": proc["name"], "exe": proc["exe"], "sha256": sha256}))
        # filter from logs
        if snitch["Config"]["Log commands"]:
            proc["cmdline"] = proc["cmdline"].encode("utf-8", "ignore").decode("utf-8", "ignore").replace("\0", "").strip()
        else:
            proc["cmdline"] = ""
        if snitch["Config"]["Log addresses"]:
            domain = reverse_dns_lookup(proc["ip"])
        else:
            domain, proc["ip"] = "", ""
        if proc["port"] in snitch["Config"]["Log ignore"] or proc["name"] in snitch["Config"]["Log ignore"]:
            continue
        event = (proc["exe"], proc["name"], proc["cmdline"], sha256, datetime_now, domain, proc["ip"], proc["port"], proc["uid"])
        event_counter[str(event)] += 1
        transactions.add(event)
    return [(*event, event_counter[str(event)]) for event in transactions]


def updater_subprocess_helper(snitch: dict, new_processes: typing.List[bytes]) -> None:
    """iterate over the list of process/connection data to update the snitch dictionary and create notifications on new entries"""
    datetime_now = time.strftime("%Y-%m-%d %H:%M:%S")
    for proc in new_processes:
        proc = pickle.loads(proc)
        if proc["exe"] not in snitch["Executables"] and proc["name"] not in snitch["Names"]:
            snitch["Exe Log"].append(datetime_now + " " + proc["name"] + " - " + proc["exe"] + " (new)")
            NotificationManager().toast("First network connection detected for " + proc["name"])
        if proc["name"] in snitch["Names"]:
            if proc["exe"] not in snitch["Names"][proc["name"]]:
                snitch["Names"][proc["name"]].append(proc["exe"])
                snitch["Exe Log"].append(datetime_now + " " + proc["name"] + " - " + proc["exe"] + " (exe)")
                NotificationManager().toast("New executable detected for " + proc["name"] + ": " + proc["exe"])
        else:
            snitch["Names"][proc["name"]] = [proc["exe"]]
        if proc["exe"] in snitch["Executables"]:
            if proc["name"] not in snitch["Executables"][proc["exe"]]:
                snitch["Executables"][proc["exe"]].append(proc["name"])
                snitch["Exe Log"].append(datetime_now + " " + proc["name"] + " - " + proc["exe"] + " (name)")
                NotificationManager().toast("New name detected for " + proc["exe"] + ": " + proc["name"])
        else:
            snitch["Executables"][proc["exe"]] = [proc["name"]]
            snitch["SHA256"][proc["exe"]] = {}


### processes
def updater_subprocess(init_pickle, snitch_pipe, sql_pipe, q_error, q_in, _q_out):
    """coordinates connection data between subprocesses, updates the snitch dictionary with new processes, and creates notifications"""
    os.nice(-20)
    # init variables for loop
    parent_process = multiprocessing.parent_process()
    snitch, initial_processes = pickle.loads(init_pickle)
    sizeof_snitch = sys.getsizeof(pickle.dumps(snitch))
    last_write = 0
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
    # update snitch with initial running processes and connections
    updater_subprocess_helper(snitch, [pickle.dumps(proc) for proc in initial_processes])
    del initial_processes
    processes_to_send = []
    # snitch updater main loop
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
                q_error.put("thread timeout error for updater subprocess")
                write_snitch_and_exit(snitch, q_error, snitch_pipe)
            new_processes = pipe_data[0]
            pipe_data[0] = []
            ready.clear()
            listen.set()
            # process the list and update snitch, send new process/connection data to sql subprocess if ready
            updater_subprocess_helper(snitch, new_processes)
            processes_to_send += new_processes
            while not q_in.empty():
                msg: dict = pickle.loads(q_in.get())
                if msg["type"] == "ready":
                    sql_pipe.send_bytes(pickle.dumps(len(processes_to_send)))
                    for proc in processes_to_send:
                        sql_pipe.send_bytes(proc)
                    sql_pipe.send_bytes(pickle.dumps("done"))
                    processes_to_send = []
                    break
                elif msg["type"] == "sha256":
                    if msg["exe"] in snitch["SHA256"]:
                        if msg["sha256"] not in snitch["SHA256"][msg["exe"]]:
                            snitch["SHA256"][msg["exe"]][msg["sha256"]] = "VT Pending"
                            snitch["Exe Log"].append(time.strftime("%Y-%m-%d %H:%M:%S") + " " + msg["name"] + " - " + msg["sha256"] + " (new)")
                            NotificationManager().toast("New sha256 detected for " + msg["name"] + ": " + msg["exe"])
                    else:
                        snitch["SHA256"][msg["exe"]] = {msg["sha256"]: "VT Pending"}
                elif msg["type"] == "vt_result":
                    if msg["exe"] in snitch["SHA256"]:
                        if msg["sha256"] not in snitch["SHA256"][msg["exe"]]:
                            snitch["Exe Log"].append(time.strftime("%Y-%m-%d %H:%M:%S") + " " + msg["name"] + " - " + msg["sha256"] + " (new)")
                            NotificationManager().toast("New sha256 detected for " + msg["name"] + ": " + msg["exe"])
                        snitch["SHA256"][msg["exe"]][msg["sha256"]] = msg["result"]
                    else:
                        snitch["SHA256"][msg["exe"]] = {msg["sha256"]: msg["result"]}
                    if msg["suspicious"]:
                        snitch["Exe Log"].append(time.strftime("%Y-%m-%d %H:%M:%S") + " " + msg["name"] + " - " + msg["sha256"] + " (suspicious)")
                        NotificationManager().toast("Suspicious VT results for " + msg["name"])
            # write the snitch dictionary to record.json, error.log, and exe.log (limit writes to reduce disk wear)
            if time.time() - last_write > 30 or ((snitch["Error Log"] or snitch["Exe Log"]) and time.time() - last_write > 5):
                new_size = sys.getsizeof(pickle.dumps(snitch))
                if snitch["Error Log"] or snitch["Exe Log"] or new_size != sizeof_snitch or time.time() - last_write > 600:
                    sizeof_snitch = new_size
                    last_write = time.time()
                    write_snitch(snitch)
        except Exception as e:
            q_error.put("Updater %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))


def sql_subprocess(fan_fd, init_pickle, p_virustotal: ProcessManager, sql_pipe, q_updater_in, q_error, _q_in, _q_out):
    """updates the snitch sqlite3 db with new connections and reports sha256/vt_results back to updater_subprocess if needed"""
    parent_process = multiprocessing.parent_process()
    # maintain a separate copy of the snitch dictionary here and coordinate with the updater_subprocess (sha256 and vt_results)
    snitch, initial_processes = pickle.loads(init_pickle)
    get_vt_results(snitch, p_virustotal.q_in, q_updater_in, True)
    # init sql database
    file_path = os.path.join(BASE_PATH, "snitch.db")
    text_path = os.path.join(BASE_PATH, "conn.log")
    con = sqlite3.connect(file_path)
    cur = con.cursor()
    cur.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='connections' ''')
    if cur.fetchone()[0] !=1:
        cur.execute(''' CREATE TABLE connections
                        (exe text, name text, cmdline text, sha256 text, contime text, domain text, ip text, port integer, uid integer, events integer) ''')
    else:
        cur.execute(''' DELETE FROM connections WHERE contime < datetime("now", "localtime", "-%d days") ''' % int(snitch["Config"]["DB retention (days)"]))
    con.commit()
    con.close()
    # init fanotify mod counter, {"st_dev st_ino": modify_count}
    fan_mod_cnt = collections.defaultdict(int)
    # process initial connections
    initial_processes_fd = initial_processes[FD_CACHE:]
    temp_fd = []
    if len(initial_processes) > FD_CACHE:
        q_error.put("Warning: too many preexisting connections to open file descriptors for hashing in time, may result in unknown hashes/errors if any terminate")
    for proc in initial_processes[:FD_CACHE]:
        try:
            fd = os.open(proc["fd"], os.O_RDONLY)
            temp_fd.append(fd)
            proc["fd"] = f"/proc/self/fd/{fd}"
            initial_processes_fd.append(proc)
        except Exception:
            q_error.put("Process closed during init " + str(proc))
    transactions = sql_subprocess_helper(snitch, fan_mod_cnt, [pickle.dumps(proc) for proc in initial_processes_fd], p_virustotal.q_in, q_updater_in, q_error)
    for fd in temp_fd:
        try:
            os.close(fd)
        except Exception:
            pass
    del initial_processes
    del initial_processes_fd
    del temp_fd
    con = sqlite3.connect(file_path)
    if snitch["Config"]["DB sql log"]:
        with con:
            # (proc["exe"], proc["name"], proc["cmdline"], sha256, datetime_now, domain, proc["ip"], proc["port"], proc["uid"], event_counter[str(event)])
            con.executemany(''' INSERT INTO connections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ''', transactions)
        con.close()
    if snitch["Config"]["DB text log"]:
        with open(text_path, "a", encoding="utf-8", errors="surrogateescape") as text_file:
            for entry in transactions:
                clean_entry = [str(value).replace(",", "").replace("\n", "").replace("\0", "") for value in entry]
                text_file.write(",".join(clean_entry) + "\n")
    # main loop
    transactions = []
    new_processes = []
    last_write = 0
    while True:
        if not parent_process.is_alive():
            return 0
        try:
            # prep to receive new connections
            if sql_pipe.poll():
                q_error.put("sync error between sql and updater on ready (pipe not empty)")
            else:
                q_updater_in.put(pickle.dumps({"type": "ready"}))
                sql_pipe.poll(timeout=300)
                if not sql_pipe.poll():
                    q_error.put("sync error between sql and updater on ready (sql timed out waiting for first message)")
            # receive first message, should be transfer size
            transfer_size = 0
            if sql_pipe.poll():
                first_pickle = sql_pipe.recv_bytes()
                if type(pickle.loads(first_pickle)) == int:
                    transfer_size = pickle.loads(first_pickle)
                elif pickle.loads(first_pickle) == "done":
                    q_error.put("sync error between sql and updater on ready (received done)")
                else:
                    q_error.put("sync error between sql and updater on ready (did not receive transfer size)")
                    new_processes.append(first_pickle)
            # receive new connections until "done"
            timeout_counter = 0
            while True:
                while sql_pipe.poll(timeout=1):
                    new_processes.append(sql_pipe.recv_bytes())
                    transfer_size -= 1
                timeout_counter += 1
                if pickle.loads(new_processes[-1]) == "done":
                    _ = new_processes.pop()
                    transfer_size += 1
                    break
                elif timeout_counter > 30:
                    q_error.put("sync error between sql and updater on receive (did not receive done)")
            if transfer_size > 0:
                q_error.put("sync error between sql and updater on receive (did not receive all messages)")
            elif transfer_size < 0:
                q_error.put("sync error between sql and updater on receive (received extra messages)")
            # process new connections
            get_vt_results(snitch, p_virustotal.q_out, q_updater_in, False)
            get_fanotify_events(fan_fd, fan_mod_cnt, q_error)
            if time.time() - last_write > snitch["Config"]["DB write limit (seconds)"]:
                transactions += sql_subprocess_helper(snitch, fan_mod_cnt, new_processes, p_virustotal.q_in, q_updater_in, q_error)
                new_processes = []
                con = sqlite3.connect(file_path)
                try:
                    if snitch["Config"]["DB sql log"]:
                        with con:
                            # (proc["exe"], proc["name"], proc["cmdline"], sha256, datetime_now, domain, proc["ip"], proc["port"], proc["uid"], event_counter[str(event)])
                            con.executemany(''' INSERT INTO connections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ''', transactions)
                    if snitch["Config"]["DB text log"]:
                        with open(text_path, "a", encoding="utf-8", errors="surrogateescape") as text_file:
                            for entry in transactions:
                                clean_entry = [str(value).replace(",", "").replace("\n", "").replace("\0", "") for value in entry]
                                text_file.write(",".join(clean_entry) + "\n")
                    transactions = []
                    last_write = time.time()
                except Exception as e:
                    q_error.put("SQL execute %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))
                con.close()
        except Exception as e:
            q_error.put("SQL subprocess %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))


def monitor_subprocess(fan_fd, snitch_pipe, q_error, q_in, _q_out):
    """runs a bpf program to monitor the system for new connections and puts info into a pipe for updater_subprocess"""
    os.nice(-20)
    from bcc import BPF
    parent_process = multiprocessing.parent_process()
    signal.signal(signal.SIGTERM, lambda *args: sys.exit(0))
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    _FAN_MARK_ADD = 0x1
    _FAN_MARK_REMOVE = 0x2
    _FAN_MARK_FLUSH = 0x80
    _FAN_MODIFY = 0x2
    libc.fanotify_mark(fan_fd, _FAN_MARK_FLUSH, _FAN_MODIFY, -1, None)
    fd_dict = collections.OrderedDict()
    for x in range(FD_CACHE):
        fd_dict[f"tmp{x}"] = (0,)
    self_pid = os.getpid()
    def get_fd(st_dev: int, st_ino: int, pid: int) -> typing.Tuple[str, str, str]:
        sig = f"{st_dev} {st_ino}"
        try:
            fd_dict.move_to_end(sig)
            fd, fd_path, exe, cmd = fd_dict[sig]
            return (fd_path, exe, cmd)
        except Exception:
            try:
                fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY)
                libc.fanotify_mark(fan_fd, _FAN_MARK_ADD, _FAN_MODIFY, fd, None)
                fd_path = f"/proc/{self_pid}/fd/{fd}"
                # assert (st_dev, st_ino) == get_fstat(fd), don't need to check here, if fails will trigger !!! FD_CACHE Overflow Error (or !!! FD Stat Error)
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
            fd_dict[sig] = (fd, fd_path, exe, cmd)
            try:
                if fd_old := fd_dict.popitem(last=False)[1][0]:
                    libc.fanotify_mark(fan_fd, _FAN_MARK_REMOVE, _FAN_MODIFY, fd_old, None)
                    os.close(fd_old)
            except Exception:
                pass
            return (fd_path, exe, cmd)
    if os.getuid() == 0:
        b = BPF(text=bpf_text)
        b.attach_kprobe(event="security_socket_connect", fn_name="security_socket_connect_entry")
        def queue_lost(*args):
            # if you see this, try increasing priority with nice or increasing PAGE_CNT
            q_error.put("BPF callbacks not processing fast enough, may have lost data")
        def queue_ipv4_event(cpu, data, size):
            event = b["ipv4_events"].event(data)
            st_dev, st_ino = get_stat(f"/proc/{event.pid}/exe")
            fd, exe, cmd = get_fd(st_dev, st_ino, event.pid)
            snitch_pipe.send_bytes(pickle.dumps({"pid": event.pid, "uid": event.uid, "name": event.task.decode(), "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd, "port": event.dport, "ip": socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))}))
        def queue_ipv6_event(cpu, data, size):
            event = b["ipv6_events"].event(data)
            st_dev, st_ino = get_stat(f"/proc/{event.pid}/exe")
            fd, exe, cmd = get_fd(st_dev, st_ino, event.pid)
            snitch_pipe.send_bytes(pickle.dumps({"pid": event.pid, "uid": event.uid, "name": event.task.decode(), "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd, "port": event.dport, "ip": socket.inet_ntop(socket.AF_INET6, event.daddr)}))
        def queue_other_event(cpu, data, size):
            event = b["other_socket_events"].event(data)
            st_dev, st_ino = get_stat(f"/proc/{event.pid}/exe")
            fd, exe, cmd = get_fd(st_dev, st_ino, event.pid)
            snitch_pipe.send_bytes(pickle.dumps({"pid": event.pid, "uid": event.uid, "name": event.task.decode(), "fd": fd, "dev": st_dev, "ino": st_ino, "exe": exe, "cmdline": cmd, "port": 0, "ip": ""}))
        b["ipv4_events"].open_perf_buffer(queue_ipv4_event, page_cnt=PAGE_CNT, lost_cb=queue_lost)
        b["ipv6_events"].open_perf_buffer(queue_ipv6_event, page_cnt=PAGE_CNT, lost_cb=queue_lost)
        b["other_socket_events"].open_perf_buffer(queue_other_event, page_cnt=PAGE_CNT, lost_cb=queue_lost)
        while True:
            if not parent_process.is_alive() or not q_in.empty():
                return 0
            try:
                b.perf_buffer_poll(timeout=-1)
            except Exception as e:
                q_error.put("BPF %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))
    else:
        q_error.put("Snitch subprocess permission error, requires root")
    return 1


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
        try:
            if not parent_process.is_alive():
                return 0
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


def picosnitch_master_process(config, snitch_updater_pickle):
    """coordinates all picosnitch subprocesses"""
    # init fanotify
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    _FAN_CLASS_CONTENT = 0x4
    _FAN_UNLIMITED_MARKS = 0x20
    flags = _FAN_CLASS_CONTENT if FD_CACHE < 8192 else _FAN_CLASS_CONTENT | _FAN_UNLIMITED_MARKS
    fan_fd = libc.fanotify_init(flags, os.O_RDONLY)
    # start subprocesses
    snitch_updater_pipe, snitch_monitor_pipe = multiprocessing.Pipe(duplex=False)
    sql_recv_pipe, sql_send_pipe = multiprocessing.Pipe(duplex=False)
    q_error = multiprocessing.Queue()
    p_monitor = ProcessManager(name="snitchmonitor", target=monitor_subprocess, init_args=(fan_fd, snitch_monitor_pipe, q_error,))
    p_virustotal = ProcessManager(name="snitchvirustotal", target=virustotal_subprocess, init_args=(config, q_error,))
    p_updater = ProcessManager(name="snitchupdater", target=updater_subprocess,
                               init_args=(snitch_updater_pickle, snitch_updater_pipe, sql_send_pipe, q_error,)
                              )
    p_sql = ProcessManager(name="snitchsql", target=sql_subprocess,
                           init_args=(fan_fd, snitch_updater_pickle, p_virustotal, sql_recv_pipe, p_updater.q_in, q_error,)
                          )
    del snitch_updater_pickle
    # set signals
    subprocesses = [p_monitor, p_virustotal, p_updater, p_sql]
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
    if importlib.util.find_spec("picosnitch"):
        args = [sys.executable, "-m", "picosnitch", "restart"]
    else:
        args = [sys.executable, sys.argv[0], "restart"]
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
    p_screens = ["Applications", "Names", "SHA256", "Host Names", "Host IPs", "Ports", "Users", "Connection Time"]
    p_names = ["Application", "Name", "SHA256", "Host Name", "Host IP", "Port", "User", "Connection Time"]
    p_col = ["exe", "name", "sha256", "domain", "ip", "port", "uid", "contime"]
    sec_i = 0
    s_screens = p_screens + ["Commands"]
    s_names = p_names + ["Command"]
    s_col = p_col + ["cmdline"]
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
                current_query = f"SELECT {s_col[sec_i]}, SUM(\"events\") as Sum FROM connections WHERE {p_col[pri_i]} IS \"{primary_value}\"{time_query} GROUP BY {s_col[sec_i]}"
            else:
                current_query = f"SELECT {p_col[pri_i]}, SUM(\"events\") as Sum FROM connections{time_query} GROUP BY {p_col[pri_i]}"
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
        help_bar = f"space/enter: filter on entry  backspace: remove filter  h/H: history  t/T: time range  r: refresh  q: quit {' ': <{curses.COLS}}"
        status_bar = f"history: {time_history}  time range: {time_period[time_i]}  line: {cursor-first_line+1}/{len(current_screen)}{' ': <{curses.COLS}}"
        if is_subquery:
            tab_bar = f"<- {s_screens[sec_i-1]: <{curses.COLS//3 - 2}}{s_screens[sec_i]: ^{curses.COLS//3 - 2}}{s_screens[(sec_i+1) % len(s_screens)]: >{curses.COLS-((curses.COLS//3-2)*2+6)}} ->"
            column_names = f"{f'{s_names[sec_i]} (where {p_names[pri_i].lower()} = {primary_value})': <{curses.COLS*7//8}}{'Entries': <{curses.COLS//8+7}}"
        else:
            tab_bar = f"<- {p_screens[pri_i-1]: <{curses.COLS//3 - 2}}{p_screens[pri_i]: ^{curses.COLS//3 - 2}}{p_screens[(pri_i+1) % len(p_screens)]: >{curses.COLS-((curses.COLS//3-2)*2+6)}} ->"
            column_names = f"{p_names[pri_i]: <{curses.COLS*7//8}}{'Entries': <{curses.COLS//8+7}}"
        # display screen
        stdscr.clear()
        stdscr.attrset(curses.color_pair(3) | curses.A_BOLD)
        stdscr.addstr(0, 0, help_bar)
        stdscr.addstr(1, 0, status_bar)
        stdscr.addstr(2, 0, tab_bar)
        stdscr.addstr(3, 0, column_names)
        line = first_line
        cursor = min(cursor, len(current_screen) + first_line - 1)
        offset = max(0, cursor - curses.LINES + 3)
        for name, value in current_screen:
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
                stdscr.addstr(line - offset, 0, f"{name: <{curses.COLS*7//8}}{value: <{curses.COLS-(curses.COLS*7//8)}}")
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
        elif ch == ord("s"):
            sec_i += 1
            update_query = True
            execute_query = True
        elif ch == ord("S"):
            sec_i -= 1
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
    cur.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='connections' ''')
    if cur.fetchone()[0] !=1:
        raise Exception(f"Table 'connections' does not exist in {file_path}")
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


### startup
def main():
    """init picosnitch"""
    # master copy of the snitch dictionary, all subprocesses only receive a static copy of it from this point in time
    snitch = read_snitch()
    # do initial poll of current network connections
    initial_processes = initial_poll(snitch)
    snitch_updater_pickle = pickle.dumps((snitch, initial_processes))
    # start picosnitch process monitor
    with open("/run/picosnitch.pid", "r") as f:
        assert int(f.read().strip()) == os.getpid()
    if __name__ == "__main__" or sys.argv[1] == "start-no-daemon":
        sys.exit(picosnitch_master_process(snitch["Config"], snitch_updater_pickle))
    print("Snitch subprocess init failed, __name__ != __main__", file=sys.stderr)
    sys.exit(1)


def start_picosnitch():
    """command line interface, pre-startup checks, and run"""
    readme = textwrap.dedent(f"""    picosnitch is a small program to monitor your system for processes that
    make network connections.

    picosnitch comes with ABSOLUTELY NO WARRANTY. This is free software, and you
    are welcome to redistribute it under certain conditions. See the GNU General
    Public License for details.

    website: https://elesiuta.github.io/picosnitch
    version: {VERSION} ({__file__})
    config and log files: {BASE_PATH}

    usage:
        picosnitch status|view|version|help
                    |      |    |       |--> this text
                    |      |    |--> version info
                    |      |--> curses ui
                    |--> show pid

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
    ExecStart={sys.executable} "{__file__}" start-no-daemon
    PIDFile=/run/picosnitch.pid

    [Install]
    WantedBy=multi-user.target
    """)
    if sys.platform.startswith("linux"):
        if os.path.expanduser("~") == "/root" and not os.getenv("DBUS_SESSION_BUS_ADDRESS"):
            print("Warning: picosnitch was run as root without preserving environment, notifications won't work", file=sys.stderr)
        if len(sys.argv) == 2:
            if sys.argv[1] == "help":
                print(readme)
                return 0
            if os.getuid() != 0:
                if importlib.util.find_spec("picosnitch"):
                    args = ["sudo", "-E", sys.executable, "-m", "picosnitch", sys.argv[1]]
                else:
                    args = ["sudo", "-E", sys.executable] + sys.argv
                os.execvp("sudo", args)
            with open("/proc/self/status", "r") as f:
                proc_status = f.read()
                capeff = int(proc_status[proc_status.find("CapEff:")+8:].splitlines()[0].strip(), base=16)
                cap_sys_admin = 2**21
                assert capeff & cap_sys_admin, "Missing capability CAP_SYS_ADMIN"
            assert importlib.util.find_spec("bcc"), "Requires BCC https://github.com/iovisor/bcc/blob/master/INSTALL.md"
            test_read_snitch = read_snitch()
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
                sys.exit(main())
            elif sys.argv[1] == "view":
                return ui_init()
            elif sys.argv[1] == "version":
                print(f"version: {VERSION} ({__file__})")
                return 0
            else:
                print(readme)
                return 2
            return 0
        else:
            print(readme)
            return 2
    else:
        print("Did not detect a supported operating system", file=sys.stderr)
        return 1


### bpf program
bpf_text = """
// This BPF program comes from the following source, licensed under the Apache License, Version 2.0
// https://github.com/p-/socket-connect-bpf/blob/7f386e368759e53868a078570254348e73e73e22/securitySocketConnectSrc.bpf
// Copyright 2019 Peter Stöckli

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <uapi/linux/ptrace.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>

struct ipv4_event_t {
    u32 pid;
    u32 uid;
    u32 af;
    char task[TASK_COMM_LEN];
    u32 daddr;
    u16 dport;
} __attribute__((packed));
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_event_t {
    u32 pid;
    u32 uid;
    u32 af;
    char task[TASK_COMM_LEN];
    unsigned __int128 daddr;
    u16 dport;
} __attribute__((packed));
BPF_PERF_OUTPUT(ipv6_events);

struct other_socket_event_t {
    u32 pid;
    u32 uid;
    u32 af;
    char task[TASK_COMM_LEN];
} __attribute__((packed));
BPF_PERF_OUTPUT(other_socket_events);

int security_socket_connect_entry(struct pt_regs *ctx, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct task_struct *task;
    int ret = PT_REGS_RC(ctx);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u32 uid = bpf_get_current_uid_gid();

    struct sock *skp = sock->sk;

    // The AF options are listed in https://github.com/torvalds/linux/blob/master/include/linux/socket.h

    u32 address_family = address->sa_family;
    if (address_family == AF_INET) {
        struct ipv4_event_t data4 = {.pid = pid, .uid = uid, .af = address_family};

        struct sockaddr_in *daddr = (struct sockaddr_in *)address;

        bpf_probe_read(&data4.daddr, sizeof(data4.daddr), &daddr->sin_addr.s_addr);

        u16 dport = 0;
        bpf_probe_read(&dport, sizeof(dport), &daddr->sin_port);
        data4.dport = ntohs(dport);

        bpf_get_current_comm(&data4.task, sizeof(data4.task));

        if (data4.dport != 0) {
            ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
        }
    }
    else if (address_family == AF_INET6) {
        struct ipv6_event_t data6 = {.pid = pid, .uid = uid, .af = address_family};

        struct sockaddr_in6 *daddr6 = (struct sockaddr_in6 *)address;

        bpf_probe_read(&data6.daddr, sizeof(data6.daddr), &daddr6->sin6_addr.in6_u.u6_addr32);

        u16 dport6 = 0;
        bpf_probe_read(&dport6, sizeof(dport6), &daddr6->sin6_port);
        data6.dport = ntohs(dport6);

        bpf_get_current_comm(&data6.task, sizeof(data6.task));

        if (data6.dport != 0) {
            ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
        }
    }
    else if (address_family != AF_UNIX && address_family != AF_UNSPEC) { // other sockets, except UNIX and UNSPEC sockets
        struct other_socket_event_t socket_event = {.pid = pid, .uid = uid, .af = address_family};
        bpf_get_current_comm(&socket_event.task, sizeof(socket_event.task));
        other_socket_events.perf_submit(ctx, &socket_event, sizeof(socket_event));
    }

    return 0;
}
"""

if __name__ == "__main__":
    sys.exit(start_picosnitch())
