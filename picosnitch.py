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
import functools
import ipaddress
import json
import hashlib
import importlib
import multiprocessing
import os
import pickle
import queue
import shlex
import signal
import socket
import struct
import subprocess
import sys
import time
import typing

try:
    import psutil
except Exception as e:
    print(type(e).__name__ + str(e.args))
    print("Make sure dependency is installed, or environment is preserved if running with sudo")

try:
    import plyer
    system_notification = plyer.notification.notify
except Exception:
    system_notification = lambda title, message, app_name: print(message)

VERSION = "0.4.8dev"


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
        self.p = multiprocessing.Process(name=self.name, target=self.target, daemon=True,
                                         args=(*self.init_args, self.q_in, self.q_out)
                                        )
        self.p.start()
        self.pp = psutil.Process(self.p.pid)
        self.time_last_start = time.time()

    def terminate(self) -> None:
        if self.p.is_alive():
            self.p.terminate()
        self.p.join(timeout=20)
        if self.p.is_alive():
            self.p.kill()
        self.p.join(timeout=10)
        self.q_in.close()
        self.q_out.close()
        self.p.close()

    def is_alive(self) -> bool:
        return self.p.is_alive()

    def is_zombie(self) -> bool:
        return self.pp.is_running() and self.pp.status() == psutil.STATUS_ZOMBIE

    def memory(self) -> int:
        return self.pp.memory_info().rss


def read() -> dict:
    """read snitch from correct location (even if sudo is used without preserve-env), or init a new one if not found"""
    template = {
        "Config": {
            "Keep logs (days)": 365,
            "Log command lines": True,
            "Log remote address": True,
            "Log ignore": [80, "chrome", "firefox"],
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
        assert all(key in data["Config"] for key in template["Config"]), "Invalid config"
        return data
    template["Template"] = True
    return template


def write(snitch: dict) -> None:
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
        snitch["Errors"].append(time.ctime() + " " + error)
        toast(error, file=sys.stderr)
    write(snitch)
    snitch_pipe.close()
    sys.exit(0)


def toast(msg: str, file=sys.stdout) -> None:
    """create a system tray notification, tries printing as a fallback, requires -E if running with sudo"""
    try:
        system_notification(title="picosnitch", message=msg, app_name="picosnitch")
    except Exception:
        print("picosnitch (toast failed): " + msg, file=file)


def reverse_dns_lookup(ip: str) -> str:
    """do a reverse dns lookup, return original ip if fails"""
    try:
        return socket.getnameinfo((ip, 0), 0)[0]
    except Exception:
        return ip


def reverse_domain_name(dns: str) -> str:
    """reverse domain name, don't reverse if ip"""
    try:
        _ = ipaddress.ip_address(dns)
        return dns
    except ValueError:
        return ".".join(reversed(dns.split(".")))


# def get_common_pattern(a: str, l: list, cutoff: float) -> None:
#     """if there is a close match to a in l, replace it with a common pattern, otherwise append a to l"""
#     b = difflib.get_close_matches(a, l, n=1, cutoff=cutoff)
#     if b:
#         common_pattern = ""
#         for match in difflib.SequenceMatcher(None, a.lower(), b[0].lower(), False).get_matching_blocks():
#             common_pattern += "*" * (match.a - len(common_pattern))
#             common_pattern += a[match.a:match.a+match.size]
#         l[l.index(b[0])] = common_pattern
#         while l.count(common_pattern) > 1:
#             l.remove(common_pattern)
#     else:
#         l.append(a)


def merge_commands(cmd: str, cmd_list: list) -> None:
    """if there is a close match to cmd in cmd_list, replace it with a common pattern, otherwise append cmd to cmd_list"""
    args = shlex.split(cmd)
    for i in range(len(cmd_list)):  # cmds
        i_args = shlex.split(cmd_list[i])
        if len(args) == len(i_args) and all(len(args[a]) == len(i_args[a]) for a in range(len(args))):
            new_args = []
            for a in range(len(args)):  # args
                new_arg = ""
                for c in range(len(args[a])):  # chars
                    if args[a][c] == i_args[a][c]:
                        new_arg += args[a][c]
                    else:
                        new_arg += "*"
                new_args.append(new_arg)
            cmd_list[i] = shlex.join(new_args)
            return
    cmd_list.append(cmd)


def get_sha256(exe: str) -> str:
    """get sha256 of process executable"""
    try:
        with open(exe, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        return sha256
    except Exception:
        return "0000000000000000000000000000000000000000000000000000000000000000"


# def get_proc_info(pid: int) -> typing.Union[dict, None]:
#     """use psutil to get proc info from pid"""
#     try:
#         proc = psutil.Process(pid).as_dict(attrs=["name", "exe", "cmdline", "pid"], ad_value="")
#     except Exception:
#         proc = None
#     return proc


def get_vt_results(snitch: dict, q_vt: multiprocessing.Queue, check_pending: bool = False):
    """get virustotal results from subprocess and update snitch"""
    if check_pending:
        for exe in snitch["Processes"]:
            for sha256 in snitch["Processes"][exe]["results"]:
                if snitch["Processes"][exe]["results"][sha256] == "Pending":
                    proc = {"exe": exe}
                    q_vt.put(pickle.dumps((proc, sha256)))
    else:
        while not q_vt.empty():
            proc, sha256, result, suspicious = pickle.loads(q_vt.get())
            snitch["Processes"][proc["exe"]]["results"][sha256] = result
            if suspicious:
                toast("Suspicious results for " + proc["name"])


def safe_q_get(p: multiprocessing.Process, q: multiprocessing.Queue):
    """prevent the asking subprocess from hanging on the next request/result check if func_subprocess dies"""
    parent_process = multiprocessing.parent_process()
    while True:
        try:
            if not parent_process.is_alive() or p.is_alive():
                # send signal so handler is called if registered for asking subprocess
                os.kill(os.getpid(), signal.SIGTERM)
            return q.get(block=True, timeout=15)
        except queue.Empty:
            # try again until something dies or gets results
            pass


def initial_poll(snitch: dict) -> list:
    """poll initial processes and connections using psutil and queue for update_snitch()"""
    ctime = time.ctime()
    update_snitch_pending = []
    # current_processes = {}
    # for proc in psutil.process_iter(attrs=["name", "exe", "cmdline", "pid"], ad_value=""):
    #     proc = proc.info
    #     if os.path.isfile(proc["exe"]):
    #         proc["cmdline"] = shlex.join(proc["cmdline"])
    #         current_processes[proc["exe"]] = proc
    #         known_pids[proc["pid"]] = proc
    # proc = {"name": "", "exe": "", "cmdline": "", "pid": ""}
    current_connections = set(psutil.net_connections(kind="all"))
    for conn in current_connections:
        try:
            if conn.pid is not None and conn.raddr and not ipaddress.ip_address(conn.raddr.ip).is_private:
                proc = psutil.Process(conn.pid).as_dict(attrs=["name", "exe", "cmdline", "pid"], ad_value="")
                proc["cmdline"] = shlex.join(proc["cmdline"])
                proc["ip"] = conn.raddr.ip
                proc["port"] = conn.raddr.port
                # _ = current_processes.pop(proc["exe"], 0)
                update_snitch_pending.append(proc)
        except Exception as e:
            # too late to grab process info (most likely) or some other error
            error = "Init " + type(e).__name__ + str(e.args) + str(conn)
            if conn.pid == proc["pid"]:
                error += str(proc)
            else:
                error += "{process no longer exists}"
            snitch["Errors"].append(ctime + " " + error)
    # if not snitch["Config"]["Only log connections"]:
    #     conn = {"ip": "", "port": -1}
    #     for proc in current_processes.values():
    #         update_snitch_pending.append((proc, conn, ctime))
    return update_snitch_pending


def update_snitch_wrapper(snitch: dict, update_snitch_pending: list):
    """loop over update_snitch() with pending update list"""
    ctime = time.ctime()
    for proc in update_snitch_pending:
        try:
            # q_sha_pending.put(pickle.dumps(proc["exe"]))
            # sha256 = pickle.loads(safe_q_get(q_sha_results, q_updater_term))
            update_snitch(snitch, proc, ctime)
        except Exception as e:
            error = "Update snitch " + type(e).__name__ + str(e.args) + str(proc)
            snitch["Errors"].append(ctime + " " + error)
            toast("Update snitch error: " + error, file=sys.stderr)


def update_snitch(snitch: dict, proc: dict, ctime: str) -> None:
    """update the snitch with data from queues and create a notification if new entry"""
    # Prevent overwriting the snitch before this function completes in the event of a termination signal
    snitch["WRITELOCK"] = True
    # Get DNS reverse name and reverse the name for sorting
    # reversed_dns = reverse_domain_name(reverse_dns_lookup(conn["ip"]))
    # Omit fields from log
    # if True or not snitch["Config"]["Log command lines"]:
    #     proc["cmdline"] = ""
    # if True or not snitch["Config"]["Log remote address"]:
    #     reversed_dns = ""
    # Update Latest Entries
    if proc["exe"] not in snitch["Processes"] or proc["name"] not in snitch["Names"]:
        snitch["Latest Entries"].append(ctime + " " + proc["name"] + " - " + proc["exe"])
    # Update Names
    if proc["name"] in snitch["Names"]:
        if proc["exe"] not in snitch["Names"][proc["name"]]:
            snitch["Names"][proc["name"]].append(proc["exe"])
            toast("New executable detected for " + proc["name"] + ": " + proc["exe"])
    else: # elif conn["ip"] or conn["port"] >= 0:  # port 0 is a conn where port wasn't detected, -1 is proc without conn detected
        snitch["Names"][proc["name"]] = [proc["exe"]]
        toast("First network connection detected for " + proc["name"])
    # elif not snitch["Config"]["Only log connections"]:
    #     snitch["Names"][proc["name"]] = [proc["exe"]]
    # Update Processes
    if proc["exe"] in snitch["Processes"]:
        if proc["name"] not in snitch["Processes"][proc["exe"]]:
            snitch["Processes"][proc["exe"]].append(proc["name"])
            toast("New name detected for " + proc["exe"] + ": " + proc["name"])
    else:
        snitch["Processes"][proc["exe"]] = [proc["name"]]
        snitch["SHA256"][proc["exe"]] = {}
        # snitch["Processes"][proc["exe"]] = {
        #     "name": proc["name"],
        #     "cmdlines": [proc["cmdline"]],
        #     "first seen": ctime,
        #     "last seen": ctime,
        #     "days seen": 1,
        #     "ports": [conn["port"]],
        #     "remote addresses": [],
        #     "results": {sha256: "Pending"}
        # }
        # q_vt_pending.put(pickle.dumps((proc, sha256)))
        # if conn["port"] not in snitch["Config"]["Remote address unlog"] and proc["name"] not in snitch["Config"]["Remote address unlog"]:
        #     snitch["Processes"][proc["exe"]]["remote addresses"].append(reversed_dns)
    # else:
    #     entry = snitch["Processes"][proc["exe"]]
    #     if proc["name"] not in entry["name"]:
    #         entry["name"] += " alternative=" + proc["name"]
    #     if proc["cmdline"] not in entry["cmdlines"]:
    #         merge_commands(proc["cmdline"], entry["cmdlines"])
    #         entry["cmdlines"].sort()
    #     if conn["port"] not in entry["ports"]:
    #         entry["ports"].append(conn["port"])
    #         entry["ports"].sort()
    #     if reversed_dns not in entry["remote addresses"]:
    #         if conn["port"] not in snitch["Config"]["Remote address unlog"] and proc["name"] not in snitch["Config"]["Remote address unlog"]:
    #             entry["remote addresses"].append(reversed_dns)
    #     if sha256 not in entry["results"]:
    #         entry["results"][sha256] = "Pending"
    #         q_vt_pending.put(pickle.dumps((proc, sha256)))
    #         toast("New sha256 detected for " + proc["name"] + ": " + proc["exe"])
    #     if ctime.split()[:3] != entry["last seen"].split()[:3]:
    #         entry["days seen"] += 1
    #     entry["last seen"] = ctime
    # # Update Remote Addresses
    # if reversed_dns in snitch["Remote Addresses"]:
    #     if proc["exe"] not in snitch["Remote Addresses"][reversed_dns]:
    #         snitch["Remote Addresses"][reversed_dns].insert(1, proc["exe"])
    #         if "No processes found during polling" in snitch["Remote Addresses"][reversed_dns]:
    #             snitch["Remote Addresses"][reversed_dns].remove("No processes found during polling")
    # else:
    #     if conn["port"] not in snitch["Config"]["Remote address unlog"] and proc["name"] not in snitch["Config"]["Remote address unlog"]:
    #         snitch["Remote Addresses"][reversed_dns] = ["First connection: " + ctime, proc["exe"]]
    # Unlock the snitch for writing
    _ = snitch.pop("WRITELOCK")


def updater_subprocess(init_pickle, snitch_pipe, sql_pipe, q_error, q_in, _q_out):
    """main subprocess where snitch.json is updated with new connections and the user is notified"""
    # drop root privileges and init variables for loop
    parent_process = multiprocessing.parent_process()
    drop_root_privileges()
    # pickle_path = os.path.join(os.path.expanduser("~"), ".config", "picosnitch", "pickle.tmp")
    # if init_pickle is None:
    #     with open(pickle_path, "rb") as pickle_file:
    #         snitch, update_snitch_pending = pickle.load(pickle_file)
    # else:
    snitch, update_snitch_pending = pickle.loads(init_pickle)
    sizeof_snitch = sys.getsizeof(pickle.dumps(snitch))
    last_write = 0
    # init signal handlers
    signal.signal(signal.SIGTERM, lambda *args: write_snitch_and_exit(snitch, q_error, snitch_pipe))
    signal.signal(signal.SIGINT, lambda *args: write_snitch_and_exit(snitch, q_error, snitch_pipe))
    # update snitch with initial running processes and connections
    # if init_scan:
        # get_vt_results(snitch, q_vt_pending, True)
    update_snitch_wrapper(snitch, update_snitch_pending)
    # known_pids[p_virustotal.pid] = {"name": p_virustotal.name, "exe": __file__, "cmdline": shlex.join(sys.argv), "pid": p_virustotal.pid}
    # known_pids[os.getpid()] = {"name": "snitchupdater", "exe": __file__, "cmdline": shlex.join(sys.argv), "pid": os.getpid()}
    # snitch updater main loop
    while True:
        # check for errors
        while not q_error.empty():
            error = q_error.get()
            snitch["Errors"].append(time.ctime() + " " + error)
            toast(error, file=sys.stderr)
        # check if terminating
        if not parent_process.is_alive():
            snitch["Errors"].append(time.ctime() + " picosnitch has stopped")
            toast("picosnitch has stopped", file=sys.stderr)
            write_snitch_and_exit(snitch, q_error, snitch_pipe)
        # check if updater needs to restart
        # try:
        #     _ = q_updater_restart.get(block=False)
        #     with open(pickle_path, "wb") as pickle_file:
        #         pickle.dump((snitch, known_pids, missed_conns, update_snitch_pending), pickle_file)
        #     q_updater_ready.put("READY")
        #     return
        # except queue.Empty:
        #     pass
        # get list of new processes and connections since last update
        # time.sleep(5)
        new_processes_q = []
        snitch_pipe.poll(timeout=5)
        while snitch_pipe.poll():
            new_processes_q.append(snitch_pipe.recv_bytes())
        # process the list and update snitch
        new_processes = [pickle.loads(proc) for proc in new_processes_q]
        update_snitch_wrapper(snitch, new_processes)
        # get_vt_results(snitch, q_vt_results, False)
        del new_processes_q
        del new_processes
        # write snitch
        if time.time() - last_write > 30:
            new_size = sys.getsizeof(pickle.dumps(snitch))
            if new_size != sizeof_snitch or time.time() - last_write > 600:
                sizeof_snitch = new_size
                last_write = time.time()
                write(snitch)


def sql_subprocess(init_pickle, p_sha, p_virustotal, sql_pipe, q_updater_in, q_error, _q_in, _q_out):
    """updates sqlite db with new connections and reports back to updater_subprocess if needed"""
    import sqlite3
    parent_process = multiprocessing.parent_process()
    # easier to update a copy of snitch here than trying to keep them in sync (just need to track sha256 and vt_results after this)
    snitch, update_snitch_pending = pickle.loads(init_pickle)
    ctime = time.ctime()
    for proc in update_snitch_pending:
        try:
            update_snitch(snitch, proc, ctime)
        except Exception as e:
            error = "SQL update snitch " + type(e).__name__ + str(e.args) + str(proc)
            q_error.put(error)
    # init sql connection
    if sys.platform.startswith("linux") and os.getuid() == 0 and os.getenv("SUDO_USER") is not None:
        home_dir = os.path.join("/home", os.getenv("SUDO_USER"))
    else:
        home_dir = os.path.expanduser("~")
    file_path = os.path.join(home_dir, ".config", "picosnitch", "snitch.db")
    con = sqlite3.connect(file_path)
    # set signals to close sql connection on termination (probably not necessary unless wanting to commit too, should it?)
    signal.signal(signal.SIGTERM, lambda *args: con.close())
    signal.signal(signal.SIGINT, lambda *args: con.close())
    # main loop
    while True:
        if not parent_process.is_alive():
            return 0
        try:
            q_updater_in.put("ready")  # should I make sure this is empty first? which side, or both?
            new_processes_q = []
            sql_pipe.poll(timeout=15)  # updater should be able to respond within this much time
            while sql_pipe.poll(timeout=0.1):  # make sure updater is done
                new_processes_q.append(sql_pipe.recv_bytes())
            new_processes = [pickle.loads(proc) for proc in new_processes_q]
            # iterate through them, adding each to db (if logging enabled)
            # don't need to update snitch completely, just check for new processes, new sha, new vt
            # put them in q_update_in
        except Exception as e:
            error = "SQL " + type(e).__name__ + str(e.args)
            q_error.put(error)


def monitor_subprocess(snitch_pipe, q_error, _q_in, _q_out):
    """runs a bpf program to monitor the system for new connections and puts info into a pipe"""
    from bcc import BPF
    parent_process = multiprocessing.parent_process()
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
            if not parent_process.is_alive():
                return 0
            try:
                b.perf_buffer_poll(timeout=-1)
            except Exception as e:
                error = "BPF " + type(e).__name__ + str(e.args)
                q_error.put(error)
    else:
        q_error.put("Snitch subprocess permission error, requires root")
    return 1


def func_subprocess(func: typing.Callable, q_pending, q_results):
    """wrapper function for subprocess"""
    parent_process = multiprocessing.parent_process()
    last_error = 0
    while True:
        try:
            if not parent_process.is_alive():
                return 0
            arg = pickle.loads(q_pending.get(block=True, timeout=15))
            q_results.put(pickle.dumps(func(arg)))
        except queue.Empty:
            # have to timeout here to check whether to terminate otherwise this could stay hanging
            # daemon=True flag for multiprocessing.Process does not work after root privileges are dropped for parent
            pass
        except Exception:
            if time.time() - last_error < 30:
                return 1
            last_error = time.time()


def virustotal_subprocess(config: dict, q_vt_pending, q_vt_results):
    """get virustotal results of process executable"""
    parent_process = multiprocessing.parent_process()
    drop_root_privileges()
    try:
        import vt
        vt_enabled = True
    except ImportError:
        vt_enabled = False
    last_error = 0
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
        except Exception:
            if time.time() - last_error < 30:
                return 1
            last_error = time.time()


def picosnitch_master_process(config, snitch_updater_pickle):
    """coordinates all picosnitch subprocesses"""
    # start subprocesses
    snitch_updater_pipe, snitch_monitor_pipe = multiprocessing.Pipe(duplex=False)
    sql_recv_pipe, sql_send_pipe = multiprocessing.Pipe(duplex=False)
    q_error = multiprocessing.Queue()
    p_monitor = ProcessManager(name="snitchmonitor", target=monitor_subprocess, init_args=(snitch_monitor_pipe, q_error,))
    p_sha = ProcessManager(name="snitchsha", target=func_subprocess, init_args=(functools.lru_cache(get_sha256),))
    p_virustotal = ProcessManager(name="snitchvirustotal", target=virustotal_subprocess, init_args=(config,))
    p_updater = ProcessManager(name="snitchupdater", target=updater_subprocess,
                               init_args=(snitch_updater_pickle, snitch_updater_pipe, sql_send_pipe, q_error,)
                              )
    p_sql = ProcessManager(name="snitchsql", target=sql_subprocess,
                           init_args=(snitch_updater_pickle, p_sha, p_virustotal, sql_recv_pipe, p_updater.q_in, q_error,)
                          )
    del snitch_updater_pickle
    # set signals
    subprocesses = [p_monitor, p_sha, p_virustotal, p_updater, p_sql]
    signal.signal(signal.SIGINT, lambda *args: [p.terminate() for p in subprocesses])
    signal.signal(signal.SIGTERM, lambda *args: [p.terminate() for p in subprocesses])
    # watch subprocesses
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
    except Exception as e:
        q_error.put("picosnitch subprocess exception: " + str(e))
    # something went wrong, attempt to restart picosnitch (terminate by running `picosnitch stop`)
    _ = [p.terminate() for p in subprocesses]
    subprocess.Popen(sys.argv[:-1] + ["restart"])
    return 0


def main(vt_api_key: str = ""):
    """init picosnitch"""
    # read config and set VT API key if entered
    snitch = read()
    _ = snitch.pop("Template", 0)
    if vt_api_key:
        snitch["Config"]["VT API key"] = vt_api_key
    # do initial poll of current network connections
    update_snitch_pending = initial_poll(snitch)
    snitch_updater_pickle = pickle.dumps((snitch, update_snitch_pending))
    # start picosnitch process monitor
    if __name__ == "__main__":
        sys.exit(picosnitch_master_process(snitch["Config"], snitch_updater_pickle))
    print("Snitch subprocess init failed, __name__ != __main__, try: sudo -E python -m picosnitch", file=sys.stderr)
    sys.exit(1)


def start_ui():
    """start a curses ui"""
    pass


def start_daemon():
    """startup picosnitch as a daemon and ensure only one instance is running"""
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
            try:
                tmp_snitch = read()
                if not tmp_snitch["Config"]["VT API key"] and "Template" in tmp_snitch:
                    tmp_snitch["Config"]["VT API key"] = input("Enter your VirusTotal API key (optional)\n>>> ")
            except Exception as e:
                print(type(e).__name__ + str(e.args))
                sys.exit(1)
            class PicoDaemon(Daemon):
                def run(self):
                    main(tmp_snitch["Config"]["VT API key"])
            daemon = PicoDaemon("/tmp/daemon-picosnitch.pid")
            if sys.argv[1] == "start":
                daemon.start()
            elif sys.argv[1] == "stop":
                daemon.stop()
            elif sys.argv[1] == "restart":
                daemon.restart()
            elif sys.argv[1] == "version":
                print(VERSION)
                return 0
            else:
                print("usage: picosnitch start|stop|restart|version|view")
                return 0
            return 0
        else:
            print("usage: picosnitch start|stop|restart|version|view")
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
