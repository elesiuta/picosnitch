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

import atexit
import collections
import curses
import functools
import ipaddress
import json
import hashlib
import importlib
import multiprocessing
import os
import pickle
import pwd
import queue
import shlex
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import textwrap
import time
import typing

try:
    import psutil
except Exception as e:
    print(type(e).__name__ + str(e.args), file=sys.stderr)
    print("Make sure dependency is installed, or environment is preserved if running with sudo", file=sys.stderr)

try:
    import plyer
    system_notification = plyer.notification.notify
except Exception:
    system_notification = lambda title, message, app_name: print(message)

VERSION = "0.5.0"


class Daemon:
	"""A generic daemon class from http://www.jejik.com/files/examples/daemon3x.py

	Usage: subclass the daemon class and override the run() method."""

	def __init__(self, pidfile): self.pidfile = pidfile

	def daemonize(self):
		"""Deamonize class. UNIX double fork mechanism."""

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

	def start(self):
		"""Start the daemon."""

		# Check for a pidfile to see if the daemon already runs
		try:
			with open(self.pidfile,'r') as pf:

				pid = int(pf.read().strip())
		except IOError:
			pid = None

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

		# Get the pid from the pidfile
		try:
			with open(self.pidfile,'r') as pf:
				pid = int(pf.read().strip())
		except IOError:
			pid = None

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

	def run(self):
		"""You should override this method when you subclass Daemon.

		It will be called after the process has been daemonized by
		start() or restart()."""


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
        self.p.join(timeout=20)
        if self.p.is_alive():
            self.p.kill()
        self.p.join(timeout=20)
        self.p.close()

    def is_alive(self) -> bool:
        return self.p.is_alive()

    def is_zombie(self) -> bool:
        return self.pp.is_running() and self.pp.status() == psutil.STATUS_ZOMBIE

    def memory(self) -> int:
        return self.pp.memory_info().rss


def read_snitch() -> dict:
    """read snitch from correct location (even if sudo is used without preserve-env), or init a new one if not found"""
    template = {
        "Config": {
            "DB write min (sec)": 1,
            "Keep logs (days)": 365,
            "Log command lines": True,
            "Log remote address": True,
            "Log ignore": [],
            "VT API key": "",
            "VT file upload": False,
            "VT limit request": 15
        },
        "Errors": [],
        "Latest Entries": [],
        "Names": {},
        "Processes": {},
        "SHA256": {}
    }
    if sys.platform.startswith("linux") and os.getuid() == 0 and os.getenv("SUDO_USER") is not None:
        home_dir = os.path.join("/home", os.getenv("SUDO_USER"))
    else:
        home_dir = os.path.expanduser("~")
    file_path = os.path.join(home_dir, ".config", "picosnitch", "snitch.json")
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="surrogateescape") as json_file:
            data = json.load(json_file)
        data["Errors"] = []
        assert all(key in data and type(data[key]) == type(template[key]) for key in template), "Invalid snitch.json"
        assert all(key in data["Config"] and type(data["Config"][key]) == type(template["Config"][key]) for key in template["Config"]), "Invalid config"
        return data
    template["Template"] = True
    return template


def write_snitch(snitch: dict) -> None:
    """write snitch to correct location (root privileges should be dropped first)"""
    file_path = os.path.join(os.path.expanduser("~"), ".config", "picosnitch", "snitch.json")
    error_log = os.path.join(os.path.expanduser("~"), ".config", "picosnitch", "error.log")
    if snitch.pop("WRITELOCK", False):
        file_path += "~"
    if not os.path.isdir(os.path.dirname(file_path)):
        os.makedirs(os.path.dirname(file_path))
    try:
        if snitch["Errors"]:
            with open(error_log, "a", encoding="utf-8", errors="surrogateescape") as text_file:
                text_file.write("\n".join(snitch["Errors"]) + "\n")
        del snitch["Errors"]
        with open(file_path, "w", encoding="utf-8", errors="surrogateescape") as json_file:
            json.dump(snitch, json_file, indent=2, separators=(',', ': '), sort_keys=True, ensure_ascii=False)
        snitch["Errors"] = []
    except Exception:
        snitch["Errors"] = []
        toast("picosnitch write error", file=sys.stderr)


def drop_root_privileges() -> None:
    """drop root privileges on linux"""
    if sys.platform.startswith("linux") and os.getuid() == 0:
        os.setgid(int(os.getenv("SUDO_GID")))
        os.setuid(int(os.getenv("SUDO_UID")))


def write_snitch_and_exit(snitch: dict, q_error: multiprocessing.Queue, snitch_pipe):
    """write snitch one last time"""
    while not q_error.empty():
        error = q_error.get()
        snitch["Errors"].append(time.strftime("%Y-%m-%d %H:%M:%S") + " " + error)
        toast(error, file=sys.stderr)
    write_snitch(snitch)
    snitch_pipe.close()
    sys.exit(0)


def toast(msg: str, file=sys.stdout) -> None:
    """create a system tray notification, tries printing as a fallback, requires -E if running with sudo"""
    try:
        system_notification(title="picosnitch", message=msg, app_name="picosnitch")
    except Exception:
        print("picosnitch (toast failed): " + msg, file=file)


@functools.cache
def reverse_dns_lookup(ip: str) -> str:
    """do a reverse dns lookup, return original ip if fails"""
    try:
        host = socket.getnameinfo((ip, 0), 0)[0]
        return ".".join(reversed(host.split(".")))
    except Exception:
        return ip


@functools.cache
def get_sha256(exe: str) -> str:
    """get sha256 of process executable"""
    try:
        with open(exe, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        return sha256
    except Exception:
        return "0000000000000000000000000000000000000000000000000000000000000000"


def get_vt_results(snitch: dict, q_vt: multiprocessing.Queue, q_out: multiprocessing.Queue, check_pending: bool = False) -> None:
    """get virustotal results from subprocess and update snitch"""
    if check_pending:
        for exe in snitch["SHA256"]:
            for sha256 in snitch["SHA256"][exe]:
                if snitch["SHA256"][exe][sha256] == "VT Pending":
                    if exe in snitch["Processes"] and snitch["Processes"][exe]:
                        name = snitch["Processes"][exe][0]
                    else:
                        name = exe
                    proc = {"exe": exe, "name": name}
                    q_vt.put(pickle.dumps((proc, sha256)))
    else:
        while not q_vt.empty():
            proc, sha256, result, suspicious = pickle.loads(q_vt.get())
            snitch["SHA256"][proc["exe"]][sha256] = result
            q_out.put(pickle.dumps({"type": "vt", "name": proc["name"], "exe": proc["exe"], "sha256": sha256, "result": result, "suspicious": suspicious}))


def initial_poll(snitch: dict) -> list:
    """poll initial processes and connections using psutil and queue for update_snitch()"""
    datetime = time.strftime("%Y-%m-%d %H:%M:%S")
    initial_processes = []
    current_connections = set(psutil.net_connections(kind="all"))
    for conn in current_connections:
        try:
            if conn.pid is not None and conn.raddr and not ipaddress.ip_address(conn.raddr.ip).is_private:
                proc = psutil.Process(conn.pid).as_dict(attrs=["name", "exe", "cmdline", "pid", "uids"], ad_value="")
                proc["cmdline"] = shlex.join(proc["cmdline"])
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
            snitch["Errors"].append(datetime + " " + error)
    return initial_processes


def update_snitch_sha_and_sql(snitch: dict, new_processes: list[bytes], q_vt: multiprocessing.Queue, q_out: multiprocessing.Queue) -> list[tuple]:
    """update the snitch with sha data, update sql with conns, return list of notifications"""
    datetime = time.strftime("%Y-%m-%d %H:%M:%S")
    event_counter = collections.defaultdict(int)
    transactions = set()
    for proc in new_processes:
        proc = pickle.loads(proc)
        if type(proc) != dict:
            continue
        sha256 = get_sha256(proc["exe"])
        if proc["exe"] in snitch["SHA256"]:
            if sha256 not in snitch["SHA256"][proc["exe"]]:
                snitch["SHA256"][proc["exe"]][sha256] = "VT Pending"
                q_vt.put(pickle.dumps((proc, sha256)))
                q_out.put(pickle.dumps({"type": "sha", "name": proc["name"], "exe": proc["exe"], "sha256": sha256}))
        else:
            snitch["SHA256"][proc["exe"]] = {sha256: "VT Pending"}
            q_vt.put(pickle.dumps((proc, sha256)))
            q_out.put(pickle.dumps({"type": "sha256", "name": proc["name"], "exe": proc["exe"], "sha256": sha256}))
        # filter from logs
        if snitch["Config"]["Log command lines"]:
            proc["cmdline"] = proc["cmdline"].encode("utf-8", "ignore").decode("utf-8", "ignore").replace("\0", "")
        else:
            proc["cmdline"] = ""
        if snitch["Config"]["Log remote address"]:
            domain = reverse_dns_lookup(proc["ip"])
        else:
            domain, proc["ip"] = "", ""
        if proc["port"] in snitch["Config"]["Log ignore"] or proc["name"] in snitch["Config"]["Log ignore"]:
            continue
        event = (proc["exe"], proc["name"], proc["cmdline"], sha256, datetime, domain, proc["ip"], proc["port"], proc["uid"])
        event_counter[str(event)] += 1
        transactions.add(event)
    return [(*event, event_counter[str(event)]) for event in transactions]


def update_snitch_proc_and_notify(snitch: dict, new_processes: list[bytes]) -> None:
    """update the snitch with data from queues and create a notification if new entry"""
    # Prevent overwriting the snitch before this function completes in the event of a termination signal
    snitch["WRITELOCK"] = True
    datetime = time.strftime("%Y-%m-%d %H:%M:%S")
    for proc in new_processes:
        proc = pickle.loads(proc)
        if proc["exe"] not in snitch["Processes"] or proc["name"] not in snitch["Names"]:
            snitch["Latest Entries"].append(datetime + " " + proc["name"] + " - " + proc["exe"])
        if proc["name"] in snitch["Names"]:
            if proc["exe"] not in snitch["Names"][proc["name"]]:
                snitch["Names"][proc["name"]].append(proc["exe"])
                toast("New executable detected for " + proc["name"] + ": " + proc["exe"])
        else:
            snitch["Names"][proc["name"]] = [proc["exe"]]
            toast("First network connection detected for " + proc["name"])
        if proc["exe"] in snitch["Processes"]:
            if proc["name"] not in snitch["Processes"][proc["exe"]]:
                snitch["Processes"][proc["exe"]].append(proc["name"])
                toast("New name detected for " + proc["exe"] + ": " + proc["name"])
        else:
            snitch["Processes"][proc["exe"]] = [proc["name"]]
            snitch["SHA256"][proc["exe"]] = {}
    _ = snitch.pop("WRITELOCK")


def updater_subprocess(init_pickle, snitch_pipe, sql_pipe, q_error, q_in, _q_out):
    """main subprocess where snitch.json is updated with new connections and the user is notified"""
    # drop root privileges and init variables for loop
    parent_process = multiprocessing.parent_process()
    drop_root_privileges()
    snitch, initial_processes = pickle.loads(init_pickle)
    sizeof_snitch = sys.getsizeof(pickle.dumps(snitch))
    last_write = 0
    # init signal handlers
    signal.signal(signal.SIGTERM, lambda *args: write_snitch_and_exit(snitch, q_error, snitch_pipe))
    signal.signal(signal.SIGINT, lambda *args: write_snitch_and_exit(snitch, q_error, snitch_pipe))
    # update snitch with initial running processes and connections
    update_snitch_proc_and_notify(snitch, [pickle.dumps(proc) for proc in initial_processes])
    del initial_processes
    new_processes = []
    new_processes_q = []
    # snitch updater main loop
    while True:
        if not parent_process.is_alive():
            snitch["Errors"].append(time.strftime("%Y-%m-%d %H:%M:%S") + " picosnitch has stopped")
            toast("picosnitch has stopped", file=sys.stderr)
            write_snitch_and_exit(snitch, q_error, snitch_pipe)
        try:
            # check for errors
            while not q_error.empty():
                error = q_error.get()
                snitch["Errors"].append(time.strftime("%Y-%m-%d %H:%M:%S") + " " + error)
                toast(error, file=sys.stderr)
            # get list of new processes and connections since last update (might give this loop its own subprocess)
            snitch_pipe.poll(timeout=5)
            while snitch_pipe.poll():
                new_processes.append(snitch_pipe.recv_bytes())
            # process the list and update snitch
            update_snitch_proc_and_notify(snitch, new_processes)
            new_processes_q += new_processes
            new_processes = []
            while not q_in.empty():
                msg: dict = pickle.loads(q_in.get())
                if msg["type"] == "ready":
                    sql_pipe.send_bytes(pickle.dumps(len(new_processes_q)))
                    for proc in new_processes_q:
                        sql_pipe.send_bytes(proc)
                    sql_pipe.send_bytes(pickle.dumps("done"))
                    new_processes_q = []
                    break
                elif msg["type"] == "sha256":
                    if msg["exe"] in snitch["SHA256"]:
                        if msg["sha256"] not in snitch["SHA256"][msg["exe"]]:
                            snitch["SHA256"][msg["exe"]][msg["sha256"]] = "VT Pending"
                            toast("New sha256 detected for " + msg["name"] + ": " + msg["exe"])
                    else:
                        snitch["SHA256"][msg["exe"]] = {msg["sha256"]: "VT Pending"}
                elif msg["type"] == "vt":
                    if msg["exe"] in snitch["SHA256"]:
                        if msg["sha256"] not in snitch["SHA256"][msg["exe"]]:
                            toast("New sha256 detected for " + msg["name"] + ": " + msg["exe"])
                        snitch["SHA256"][msg["exe"]][msg["sha256"]] = msg["result"]
                    else:
                        snitch["SHA256"][msg["exe"]] = {msg["sha256"]: msg["result"]}
                    if msg["suspicious"]:
                        toast("Suspicious VT results for " + msg["name"])
            # write snitch.json and error.log (no more than once per 30 seconds, and at least once per 10 minutes, may need adjusting, eg no delay if snitch["Errors"])
            if time.time() - last_write > 30:
                new_size = sys.getsizeof(pickle.dumps(snitch))
                if new_size != sizeof_snitch or time.time() - last_write > 600:
                    sizeof_snitch = new_size
                    last_write = time.time()
                    write_snitch(snitch)
        except Exception as e:
            q_error.put("Updater %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))


def sql_subprocess(init_pickle, p_virustotal: ProcessManager, sql_pipe, q_updater_in, q_error, _q_in, _q_out):
    """updates sqlite db with new connections and reports back to updater_subprocess if needed"""
    parent_process = multiprocessing.parent_process()
    # easier to update a copy of snitch here than trying to keep them in sync (just need to track sha256 and vt_results after this)
    snitch, initial_processes = pickle.loads(init_pickle)
    get_vt_results(snitch, p_virustotal.q_in, q_updater_in, True)
    # init sql database
    if sys.platform.startswith("linux") and os.getuid() == 0 and os.getenv("SUDO_USER") is not None:
        home_dir = os.path.join("/home", os.getenv("SUDO_USER"))
    else:
        home_dir = os.path.expanduser("~")
    file_path = os.path.join(home_dir, ".config", "picosnitch", "snitch.db")
    con = sqlite3.connect(file_path)
    cur = con.cursor()
    cur.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='connections' ''')
    if cur.fetchone()[0] !=1:
        cur.execute(''' CREATE TABLE connections
                        (exe text, name text, cmdline text, sha256 text, contime text, domain text, ip text, port integer, uid integer, events integer) ''')
    else:
        cur.execute(''' DELETE FROM connections WHERE contime < datetime("now", "localtime", "-%d days") ''' % int(snitch["Config"]["Keep logs (days)"]))
    con.commit()
    con.close()
    # process initial connections
    transactions = update_snitch_sha_and_sql(snitch, [pickle.dumps(proc) for proc in initial_processes], p_virustotal.q_in, q_updater_in)
    del initial_processes
    con = sqlite3.connect(file_path)
    with con:
        # (proc["exe"], proc["name"], proc["cmdline"], sha256, datetime, domain, proc["ip"], proc["port"], proc["uid"])
        con.executemany(''' INSERT INTO connections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ''', transactions)
    con.close()
    transactions = []
    new_processes = []
    last_write = 0
    # main loop
    while True:
        if not parent_process.is_alive():
            return 0
        try:
            # prep to receive new connections
            if sql_pipe.poll():
                q_error.put("sync error between sql and updater on ready (pipe not empty)")
            else:
                q_updater_in.put(pickle.dumps({"type": "ready"}))
                sql_pipe.poll(timeout=None)
            # receive first message, should be transfer size
            transfer_size = -1
            if sql_pipe.poll(timeout=10):
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
            # process new connections
            get_vt_results(snitch, p_virustotal.q_out, q_updater_in, False)
            if time.time() - last_write > snitch["Config"]["DB write min (sec)"]:
                transactions += update_snitch_sha_and_sql(snitch, new_processes, p_virustotal.q_in, q_updater_in)
                new_processes = []
                con = sqlite3.connect(file_path)
                try:
                    with con:
                        # (proc["exe"], proc["name"], proc["cmdline"], sha256, datetime, domain, proc["ip"], proc["port"], proc["uid"])
                        con.executemany(''' INSERT INTO connections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ''', transactions)
                    transactions = []
                    last_write = time.time()
                except Exception as e:
                    q_error.put("SQL execute %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))
                con.close()
        except Exception as e:
            q_error.put("SQL subprocess %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))


def monitor_subprocess(snitch_pipe, q_error, q_in, _q_out):
    """runs a bpf program to monitor the system for new connections and puts info into a pipe"""
    from bcc import BPF
    parent_process = multiprocessing.parent_process()
    signal.signal(signal.SIGTERM, lambda *args: sys.exit(0))
    # backup_queue = multiprocessing.Queue() # could hold stuff if pipe error then try sending later?
    @functools.lru_cache(maxsize=1024)
    def get_exe(pid: int) -> str:
        try:
            return os.readlink("/proc/%d/exe" % pid)
        except Exception:
            return ""
    @functools.lru_cache(maxsize=1024)
    def get_cmd(pid: int) -> str:
        try:
            with open("/proc/%d/cmdline" % pid, "r") as f:
                return f.read()
        except Exception:
            return ""
    if os.getuid() == 0:
        b = BPF(text=bpf_text)
        b.attach_kprobe(event="security_socket_connect", fn_name="security_socket_connect_entry")
        def queue_ipv4_event(cpu, data, size):
            event = b["ipv4_events"].event(data)
            exe, cmd = get_exe(event.pid), get_cmd(event.pid)
            snitch_pipe.send_bytes(pickle.dumps({"pid": event.pid, "ppid": event.ppid, "uid": event.uid, "name": event.task.decode(), "exe": exe, "cmdline": cmd, "port": event.dport, "ip": socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))}))
        def queue_ipv6_event(cpu, data, size):
            event = b["ipv6_events"].event(data)
            exe, cmd = get_exe(event.pid), get_cmd(event.pid)
            snitch_pipe.send_bytes(pickle.dumps({"pid": event.pid, "ppid": event.ppid, "uid": event.uid, "name": event.task.decode(), "exe": exe, "cmdline": cmd, "port": event.dport, "ip": socket.inet_ntop(socket.AF_INET6, event.daddr)}))
        def queue_other_event(cpu, data, size):
            event = b["other_socket_events"].event(data)
            exe, cmd = get_exe(event.pid), get_cmd(event.pid)
            snitch_pipe.send_bytes(pickle.dumps({"pid": event.pid, "ppid": event.ppid, "uid": event.uid, "name": event.task.decode(), "exe": exe, "cmdline": cmd, "port": 0, "ip": ""}))
        b["ipv4_events"].open_perf_buffer(queue_ipv4_event)
        b["ipv6_events"].open_perf_buffer(queue_ipv6_event)
        b["other_socket_events"].open_perf_buffer(queue_other_event)
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
    drop_root_privileges()
    try:
        import vt
        vt_enabled = True
    except ImportError:
        vt_enabled = False
    while True:
        try:
            if not parent_process.is_alive():
                return 0
            time.sleep(config["VT limit request"])
            proc, sha256 = pickle.loads(q_vt_pending.get(block=True, timeout=15))
            suspicious = False
            if config["VT API key"] and vt_enabled:
                client = vt.Client(config["VT API key"])
                try:
                    analysis = client.get_object("/files/" + sha256)
                except Exception:
                    if config["VT file upload"]:
                        try:
                            with open(proc["exe"], "rb") as f:
                                analysis = client.scan_file(f, wait_for_completion=True)
                        except Exception:
                            q_vt_results.put(pickle.dumps((proc, sha256, "Failed to read file for upload", suspicious)))
                            continue
                    else:
                        # could also be an invalid api key
                        q_vt_results.put(pickle.dumps((proc, sha256, "File not analyzed (analysis not found)", suspicious)))
                        continue
                if analysis.last_analysis_stats["malicious"] != 0 or analysis.last_analysis_stats["suspicious"] != 0:
                    suspicious = True
                q_vt_results.put(pickle.dumps((proc, sha256, str(analysis.last_analysis_stats), suspicious)))
            elif vt_enabled:
                q_vt_results.put(pickle.dumps((proc, sha256, "File not analyzed (no api key)", suspicious)))
            else:
                q_vt_results.put(pickle.dumps((proc, sha256, "File not analyzed (virustotal not enabled)", suspicious)))
        except queue.Empty:
            # have to timeout here to check whether to terminate otherwise this could stay hanging
            # daemon=True flag for multiprocessing.Process does not work after root privileges are dropped for parent
            pass
        except Exception as e:
            q_error.put("VT %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))


def picosnitch_master_process(config, snitch_updater_pickle):
    """coordinates all picosnitch subprocesses"""
    # start subprocesses
    snitch_updater_pipe, snitch_monitor_pipe = multiprocessing.Pipe(duplex=False)
    sql_recv_pipe, sql_send_pipe = multiprocessing.Pipe(duplex=False)
    q_error = multiprocessing.Queue()
    p_monitor = ProcessManager(name="snitchmonitor", target=monitor_subprocess, init_args=(snitch_monitor_pipe, q_error,))
    p_virustotal = ProcessManager(name="snitchvirustotal", target=virustotal_subprocess, init_args=(config, q_error,))
    p_updater = ProcessManager(name="snitchupdater", target=updater_subprocess,
                               init_args=(snitch_updater_pickle, snitch_updater_pipe, sql_send_pipe, q_error,)
                              )
    p_sql = ProcessManager(name="snitchsql", target=sql_subprocess,
                           init_args=(snitch_updater_pickle, p_virustotal, sql_recv_pipe, p_updater.q_in, q_error,)
                          )
    del snitch_updater_pickle
    # set signals
    subprocesses = [p_monitor, p_virustotal, p_updater, p_sql]
    signal.signal(signal.SIGINT, lambda *args: [p.terminate() for p in subprocesses])
    signal.signal(signal.SIGTERM, lambda *args: [p.terminate() for p in subprocesses])
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
            if sum(p.memory() for p in subprocesses) > 512000000:
                q_error.put("picosnitch memory usage exceeded 512 MB, attempting restart")
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
    # attempt to restart picosnitch (terminate by running `picosnitch stop`)
    time.sleep(5)
    _ = [p.terminate() for p in subprocesses]
    if importlib.util.find_spec("picosnitch"):
        args = ["python3", "-m", "picosnitch", "restart"]
    else:
        args = [sys.executable, sys.argv[0], "restart"]
    subprocess.Popen(args)
    return 0


def main(vt_api_key: str = ""):
    """init picosnitch"""
    # read config and set VT API key if entered
    snitch = read_snitch()
    _ = snitch.pop("Template", 0)
    if vt_api_key:
        snitch["Config"]["VT API key"] = vt_api_key
    # do initial poll of current network connections
    initial_processes = initial_poll(snitch)
    snitch_updater_pickle = pickle.dumps((snitch, initial_processes))
    # start picosnitch process monitor
    if __name__ == "__main__":
        sys.exit(picosnitch_master_process(snitch["Config"], snitch_updater_pickle))
    print("Snitch subprocess init failed, __name__ != __main__, try: sudo -E python -m picosnitch", file=sys.stderr)
    sys.exit(1)


def main_ui(stdscr: curses.window, splash: str, con: sqlite3.Connection) -> int:
    """for curses"""
    # init and splash screen
    cur = con.cursor()
    curses.cbreak()
    curses.noecho()
    curses.curs_set(0)
    curses.start_color()
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_WHITE)
    curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_MAGENTA)
    splash_lines = splash.splitlines()
    stdscr.clear()
    for i in range(len(splash_lines)):
        if "\u001b[33m" in splash_lines[i]:
            part1 = splash_lines[i].split("\u001b[33m")
            part2 = part1[1].split("\033[0m")
            stdscr.addstr(i, 0, part1[0])
            stdscr.addstr(i, len(part1[0]), part2[0], curses.color_pair(2))
            stdscr.addstr(i, len(part1[0]) + len(part2[0]), part2[1])
        else:
            stdscr.addstr(i, 0, splash_lines[i])
    stdscr.refresh()
    # screens from queries (exe text, name text, cmdline text, sha256 text, contime text, domain text, ip text, port integer, uid integer)
    time_i = 0
    time_period = ["All", "1 minute", "3 minutes", "5 minutes", "10 minutes", "15 minutes", "30 minutes", "1 hour", "3 hours", "6 hours", "12 hours", "1 day", "3 days", "7 days", "30 days", "365 days"]
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
        cursor %= line
        if cursor < first_line:
            cursor = first_line
        # generate screen
        if update_query:
            if time_i == 0:
                time_query = ""
            else:
                if is_subquery:
                    time_query = f" AND contime > datetime(\"now\", \"localtime\",\"-{time_period[time_i]}\")"
                else:
                    time_query = f" WHERE contime > datetime(\"now\", \"localtime\", \"-{time_period[time_i]}\")"
            if is_subquery:
                current_query = f"SELECT {s_col[sec_i]}, SUM(\"events\") as Sum FROM connections WHERE {p_col[pri_i]} IS \"{primary_value}\"{time_query} GROUP BY {s_col[sec_i]}"
            else:
                current_query = f"SELECT {p_col[pri_i]}, SUM(\"events\") as Sum FROM connections{time_query} GROUP BY {p_col[pri_i]}"
            update_query = False
        if execute_query:
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
                            stdscr.addstr(i, 0, part1[0])
                            stdscr.addstr(i, len(part1[0]), part2[0], curses.color_pair(2))
                            stdscr.addstr(i, len(part1[0]) + len(part2[0]), part2[1])
                        else:
                            stdscr.addstr(i, 0, splash_lines[i])
                    stdscr.refresh()
                except KeyboardInterrupt:
                    con.close()
                    return 0
            current_screen = cur.fetchall()
            execute_query = False
        help_bar = f"space/enter: filter on entry  backspace: remove filter  t: time period  r: refresh  q: quit {' ': <{curses.COLS}}"
        if is_subquery:
            title_bar = f"<- {s_screens[sec_i-1]: <{curses.COLS//3 - 2}}{s_screens[sec_i]: ^{curses.COLS//3 - 2}}{s_screens[(sec_i+1) % len(s_screens)]: >{curses.COLS-((curses.COLS//3-2)*2+6)}} ->"
            status_bar = f"picosnitch {VERSION}\t time period: {time_period[time_i]}\t {p_names[pri_i].lower()}: {primary_value}{' ': <{curses.COLS}}"
            column_names = f"{s_names[sec_i]: <{curses.COLS*7//8}}{'Entries': <{curses.COLS//8+7}}"
        else:
            title_bar = f"<- {p_screens[pri_i-1]: <{curses.COLS//3 - 2}}{p_screens[pri_i]: ^{curses.COLS//3 - 2}}{p_screens[(pri_i+1) % len(p_screens)]: >{curses.COLS-((curses.COLS//3-2)*2+6)}} ->"
            status_bar = f"picosnitch {VERSION}\t time period: {time_period[time_i]}{' ': <{curses.COLS}}"
            column_names = f"{p_names[pri_i]: <{curses.COLS*7//8}}{'Entries': <{curses.COLS//8+7}}"
        # display screen
        stdscr.clear()
        stdscr.attrset(curses.color_pair(4) | curses.A_BOLD)
        stdscr.addstr(0, 0, status_bar)
        stdscr.addstr(1, 0, help_bar)
        stdscr.addstr(2, 0, title_bar)
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
            if 0 <= line - offset < curses.LINES - 1:
                # special cases (cmdline null chars, uid, maybe add sha256 and vt results or debsums lookup?)
                if type(name) == str:
                    name = name.replace("\0", "")
                elif (not is_subquery and p_col[pri_i] == "uid") or (is_subquery and s_col[sec_i] == "uid"):
                    name = f"{pwd.getpwuid(name).pw_name} ({name})"
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
            time_i += 1
            update_query = True
            execute_query = True
        elif ch == ord("T"):
            time_i -= 1
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

def start_ui() -> int:
    """start a curses ui"""
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
    if sys.platform.startswith("linux") and os.getuid() == 0 and os.getenv("SUDO_USER") is not None:
        home_dir = os.path.join("/home", os.getenv("SUDO_USER"))
    else:
        home_dir = os.path.expanduser("~")
    file_path = os.path.join(home_dir, ".config", "picosnitch", "snitch.db")
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
            return curses.wrapper(main_ui, splash, con)
        except curses.error:
            print("CURSES DISPLAY ERROR: try resizing your terminal, ui will close in %s seconds" % (err_count + 1), file=sys.stderr)
            time.sleep(1)
    return 1


def start_daemon():
    """startup picosnitch as a daemon and ensure only one instance is running"""
    readme = textwrap.dedent(f"""    picosnitch is a small program to monitor your system for processes that
    make network connections - https://github.com/elesiuta/picosnitch

    picosnitch comes with ABSOLUTELY NO WARRANTY. This is free software, and you
    are welcome to redistribute it under certain conditions. See the GNU General
    Public Licence for details.

    usage: picosnitch start|stop|restart|view|version
                        |    |      |      |     |--> {VERSION}
                        |    |      |      |--> curses ui
                        |____|______|--> daemon controls
    """)
    if sys.prefix != sys.base_prefix:
            print("Warning: picosnitch is running in a virtual environment, notifications may not function", file=sys.stderr)
    if os.name == "posix":
        if os.path.expanduser("~") == "/root":
            print("Warning: picosnitch was run as root without preserving environment", file=sys.stderr)
        if len(sys.argv) == 2:
            if os.getuid() != 0:
                print("Warning: picosnitch was run without root privileges, requesting root privileges", file=sys.stderr)
                if importlib.util.find_spec("picosnitch"):
                    args = ["sudo", "-E", "python3", "-m", "picosnitch", sys.argv[1]]
                else:
                    args = ["sudo", "-E", sys.executable] + sys.argv
                os.execvp("sudo", args)
            assert importlib.util.find_spec("bcc"), "Requires BCC https://github.com/iovisor/bcc/blob/master/INSTALL.md"
            vt_api_key = ""
            if sys.argv[1] in ["start", "restart"]:
                try:
                    tmp_snitch = read_snitch()
                    if not tmp_snitch["Config"]["VT API key"] and "Template" in tmp_snitch:
                        vt_api_key = input("Enter your VirusTotal API key (optional)\n>>> ")
                except Exception as e:
                    print(type(e).__name__ + str(e.args), file=sys.stderr)
                    sys.exit(1)
            class PicoDaemon(Daemon):
                def run(self):
                    main(vt_api_key)
            daemon = PicoDaemon("/tmp/daemon-picosnitch.pid")
            if sys.argv[1] == "start":
                print("starting picosnitch")
                daemon.start()
            elif sys.argv[1] == "stop":
                print("stopping picosnitch")
                daemon.stop()
            elif sys.argv[1] == "restart":
                daemon.restart()
            elif sys.argv[1] == "view":
                return start_ui()
            elif sys.argv[1] == "version":
                print(f"version: {VERSION} ({__file__})")
                return 0
            else:
                print(readme)
                return 0
            return 0
        else:
            print(readme)
            return 0
    else:
        print("Did not detect a supported operating system", file=sys.stderr)
        return 1


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
    u32 ppid;
    u32 uid;
    u32 af;
    char task[TASK_COMM_LEN];
    u32 daddr;
    u16 dport;
} __attribute__((packed));
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 af;
    char task[TASK_COMM_LEN];
    unsigned __int128 daddr;
    u16 dport;
} __attribute__((packed));
BPF_PERF_OUTPUT(ipv6_events);

struct other_socket_event_t {
    u32 pid;
    u32 ppid;
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

    task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;

    struct sock *skp = sock->sk;

    // The AF options are listed in https://github.com/torvalds/linux/blob/master/include/linux/socket.h

    u32 address_family = address->sa_family;
    if (address_family == AF_INET) {
        struct ipv4_event_t data4 = {.pid = pid, .ppid = ppid, .uid = uid, .af = address_family};

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
        struct ipv6_event_t data6 = {.pid = pid, .ppid = ppid, .uid = uid, .af = address_family};

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
        struct other_socket_event_t socket_event = {.pid = pid, .ppid = ppid, .uid = uid, .af = address_family};
        bpf_get_current_comm(&socket_event.task, sizeof(socket_event.task));
        other_socket_events.perf_submit(ctx, &socket_event, sizeof(socket_event));
    }

    return 0;
}
"""

if __name__ == "__main__":
    sys.exit(start_daemon())
