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
import difflib
import functools
import gc
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

VERSION = "0.4.4"


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
    def __init__(self, name: str, target: typing.Callable, init_args: tuple = (), extra_args: tuple = ()) -> None:
        self.name, self.target, self.init_args = name, target, init_args
        self.q_in, self.q_out, self.q_term = multiprocessing.Queue(), multiprocessing.Queue(), multiprocessing.Queue()
        self.start(*extra_args)

    def _init_process(self, *extra_args) -> multiprocessing.Process:
        return multiprocessing.Process(name=self.name, target=self.target, daemon=True,
                                       args=(*extra_args,
                                             *self.init_args,
                                             self.q_in, self.q_out, self.q_term)
                                      )

    def start(self, *extra_args) -> None:
        self.p = self._init_process(*extra_args)
        self.p.start()
        self.pp = psutil.Process(self.p.pid)
        self.time_last_start = time.time()

    def terminate(self, t: float, use_q_term: bool = False, close_queues: bool = False) -> None:
        if use_q_term:
            self.q_term.put("TERMINATE")
        # terminate_subprocess = lambda p, t: p.join(t) or (p.is_alive() and p.terminate()) or p.join(1) or (p.is_alive() and p.kill()) or p.join(1) or p.close()
        self.p.join(timeout=t)
        if self.p.is_alive():
            self.p.terminate()
        self.p.join(timeout=20)
        if self.p.is_alive():
            self.p.kill()
        self.p.join(timeout=10)
        if close_queues:
            self.q_in.close()
            self.q_out.close()
        self.p.close()
        # clear_queue = lambda q: (q.get() for i in range(q.qsize()))
        if use_q_term:
            # can clear q_term if p successfully closed
            for i in range(self.q_term.qsize()):
                _ = self.q_term.get()
        if close_queues:
            # can close q_term if p successfully closed
            self.q_term.close()

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
            "Log command lines": True,
            "Log remote address": True,
            "Only log connections": True,
            "Remote address unlog": [80, "chrome", "firefox"],
            "VT API key": "",
            "VT file upload": False,
            "VT limit request": 15
        },
        "Errors": [],
        "Latest Entries": [],
        "Names": {},
        "Processes": {},
        "Remote Addresses": {}
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


def terminate_snitch_updater(snitch: dict, q_error: multiprocessing.Queue):
    """write snitch one last time"""
    while not q_error.empty():
        error = q_error.get()
        snitch["Errors"].append(time.ctime() + " " + error)
        toast(error, file=sys.stderr)
    write(snitch)
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


def get_common_pattern(a: str, l: list, cutoff: float) -> None:
    """if there is a close match to a in l, replace it with a common pattern, otherwise append a to l"""
    b = difflib.get_close_matches(a, l, n=1, cutoff=cutoff)
    if b:
        common_pattern = ""
        for match in difflib.SequenceMatcher(None, a.lower(), b[0].lower(), False).get_matching_blocks():
            common_pattern += "*" * (match.a - len(common_pattern))
            common_pattern += a[match.a:match.a+match.size]
        l[l.index(b[0])] = common_pattern
        while l.count(common_pattern) > 1:
            l.remove(common_pattern)
    else:
        l.append(a)


def get_sha256(exe: str) -> str:
    """get sha256 of process executable"""
    try:
        with open(exe, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        return sha256
    except Exception:
        return "0000000000000000000000000000000000000000000000000000000000000000"


def get_proc_info(pid: int) -> typing.Union[dict, None]:
    """use psutil to get proc info from pid"""
    try:
        proc = psutil.Process(pid).as_dict(attrs=["name", "exe", "cmdline", "pid"], ad_value="")
    except Exception:
        proc = None
    return proc


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


def safe_q_get(q: multiprocessing.Queue, q_term: multiprocessing.Queue):
    """prevent the updater subprocess from hanging on the next request/result check if p_sha or p_psutil die"""
    while True:
        try:
            if not q_term.empty() or not multiprocessing.parent_process().is_alive():
                os.kill(os.getpid(), signal.SIGTERM)
                # raise Exception("Process terminated")
                # sys.exit(1)
            return q.get(block=True, timeout=15)
        except queue.Empty:
            # have to timeout here to check whether to terminate otherwise this could stay hanging
            pass


def initial_poll(snitch: dict, known_pids: dict) -> list:
    """poll initial processes and connections using psutil and queue for update_snitch()"""
    ctime = time.ctime()
    update_snitch_pending = []
    current_processes = {}
    for proc in psutil.process_iter(attrs=["name", "exe", "cmdline", "pid"], ad_value=""):
        proc = proc.info
        if os.path.isfile(proc["exe"]):
            proc["cmdline"] = shlex.join(proc["cmdline"])
            current_processes[proc["exe"]] = proc
            known_pids[proc["pid"]] = proc
    proc = {"name": "", "exe": "", "cmdline": "", "pid": ""}
    current_connections = set(psutil.net_connections(kind="all"))
    for conn in current_connections:
        try:
            if conn.pid is not None and conn.raddr and not ipaddress.ip_address(conn.raddr.ip).is_private:
                proc = psutil.Process(conn.pid).as_dict(attrs=["name", "exe", "cmdline", "pid"], ad_value="")
                proc["cmdline"] = shlex.join(proc["cmdline"])
                conn_dict = {"ip": conn.raddr.ip, "port": conn.raddr.port}
                _ = current_processes.pop(proc["exe"], 0)
                update_snitch_pending.append((proc, conn_dict, ctime))
        except Exception as e:
            # too late to grab process info (most likely) or some other error
            error = "Init " + type(e).__name__ + str(e.args) + str(conn)
            if conn.pid == proc["pid"]:
                error += str(proc)
            else:
                error += "{process no longer exists}"
            snitch["Errors"].append(ctime + " " + error)
    if not snitch["Config"]["Only log connections"]:
        conn = {"ip": "", "port": -1}
        for proc in current_processes.values():
            update_snitch_pending.append((proc, conn, ctime))
    return update_snitch_pending


def update_snitch_processor(snitch: dict, known_pids: dict, missed_conns: list, new_processes: list,
                  q_updater_term: multiprocessing.Queue,
                  q_psutil_pending: multiprocessing.Queue,
                  q_psutil_results: multiprocessing.Queue
                  ) -> tuple:
    """process list of new processes and queue for update_snitch()"""
    ctime = time.ctime()
    update_snitch_pending = []
    pending_list = []
    pending_conns = []
    for proc in new_processes:
        try:
            if proc["type"] == "exec":
                try:
                    cmdline = shlex.split(proc["cmdline"])
                except Exception:
                    cmdline = proc["cmdline"].strip().split()
                proc["exe"] = cmdline[0]
                if proc["exe"] == "exec":
                    proc["exe"] = cmdline[1]
                known_pids[proc["pid"]] = proc
                if not snitch["Config"]["Only log connections"]:
                    pending_list.append(proc)
            elif proc["type"] == "conn":
                if proc["pid"] in known_pids:
                    proc["name"] = known_pids[proc["pid"]]["name"]
                    proc["exe"] = known_pids[proc["pid"]]["exe"]
                    proc["cmdline"] = known_pids[proc["pid"]]["cmdline"]
                    pending_list.append(proc)
                else:
                    try:
                        q_psutil_pending.put(pickle.dumps(proc["pid"]))
                        proc_psutil = pickle.loads(safe_q_get(q_psutil_results, q_updater_term))
                        if proc_psutil["exe"]:
                            proc_psutil["cmdline"] = shlex.join(proc_psutil["cmdline"])
                            known_pids[proc_psutil["pid"]] = proc_psutil
                    except Exception:
                        if proc["ppid"] not in known_pids:
                            try:
                                q_psutil_pending.put(pickle.dumps(proc["ppid"]))
                                proc_psutil = pickle.loads(safe_q_get(q_psutil_results, q_updater_term))
                                if proc_psutil["exe"]:
                                    proc_psutil["cmdline"] = shlex.join(proc_psutil["cmdline"])
                                    known_pids[proc_psutil["pid"]] = proc_psutil
                                    # use this as best guess for child too since it probably forked and was short lived
                                    # if not, exec should have caught it on the next round
                                    # this is why pending conns is now postponed till the next iteration
                                    known_pids[proc["pid"]] = proc_psutil
                            except Exception:
                                pass
                    proc["missed"] = 1
                    pending_conns.append(proc)
        except Exception as e:
            error = "Process queue " + type(e).__name__ + str(e.args) + str(proc)
            snitch["Errors"].append(ctime + " " + error)
    for proc in missed_conns:
        if proc["pid"] in known_pids:
            proc["name"] = known_pids[proc["pid"]]["name"]
            proc["exe"] = known_pids[proc["pid"]]["exe"]
            proc["cmdline"] = known_pids[proc["pid"]]["cmdline"]
            pending_list.append(proc)
        elif proc["missed"] < 5:
            # give it 5 rounds to find the pid in exec (2 should be enough)
            # don't waste cpu checking psutil anymore since it would be short lived
            # therefore ppid is also unlikely to appear (less harm in checking this maybe once more)
            proc["missed"] += 1
            pending_conns.append(proc)
        else:
            _ = proc.pop("missed")
            snitch["Errors"].append(ctime + " no known process for conn: " + str(proc))
    for proc in pending_list:
        if proc["type"] == "conn":
            conn = {"ip": proc["ip"], "port": proc["port"]}
        else:
            conn = {"ip": "", "port": -1}
        update_snitch_pending.append((proc, conn, ctime))
    del missed_conns
    return pending_conns, update_snitch_pending


def update_snitch_wrapper(snitch: dict, update_snitch_pending: list,
                          q_updater_term: multiprocessing.Queue,
                          q_sha_pending: multiprocessing.Queue,
                          q_sha_results: multiprocessing.Queue,
                          q_vt_pending: multiprocessing.Queue):
    """loop over update_snitch() with pending update list"""
    for proc, conn, ctime in update_snitch_pending:
        try:
            q_sha_pending.put(pickle.dumps(proc["exe"]))
            sha256 = pickle.loads(safe_q_get(q_sha_results, q_updater_term))
            update_snitch(snitch, proc, conn, sha256, ctime, q_vt_pending)
        except Exception as e:
            error = "Update snitch " + type(e).__name__ + str(e.args) + str(proc)
            snitch["Errors"].append(ctime + " " + error)
            toast("Update snitch error: " + error, file=sys.stderr)


def update_snitch(snitch: dict, proc: dict, conn: dict, sha256: str, ctime: str, q_vt_pending: multiprocessing.Queue) -> None:
    """update the snitch with data from queues and create a notification if new entry"""
    # Prevent overwriting the snitch before this function completes in the event of a termination signal
    snitch["WRITELOCK"] = True
    # Get DNS reverse name and reverse the name for sorting
    reversed_dns = reverse_domain_name(reverse_dns_lookup(conn["ip"]))
    # Omit fields from log
    if not snitch["Config"]["Log command lines"]:
        proc["cmdline"] = ""
    if not snitch["Config"]["Log remote address"]:
        reversed_dns = ""
    # Update Latest Entries
    if proc["exe"] not in snitch["Processes"] or proc["name"] not in snitch["Names"]:
        snitch["Latest Entries"].append(ctime + " " + proc["name"] + " - " + proc["exe"])
    # Update Names
    if proc["name"] in snitch["Names"]:
        if proc["exe"] not in snitch["Names"][proc["name"]]:
            snitch["Names"][proc["name"]].append(proc["exe"])
            toast("New executable detected for " + proc["name"] + ": " + proc["exe"])
    elif conn["ip"] or conn["port"] >= 0:  # port 0 is a conn where port wasn't detected, -1 is proc without conn detected
        snitch["Names"][proc["name"]] = [proc["exe"]]
        toast("First network connection detected for " + proc["name"])
    elif not snitch["Config"]["Only log connections"]:
        snitch["Names"][proc["name"]] = [proc["exe"]]
    # Update Processes
    if proc["exe"] not in snitch["Processes"]:
        snitch["Processes"][proc["exe"]] = {
            "name": proc["name"],
            "cmdlines": [proc["cmdline"]],
            "first seen": ctime,
            "last seen": ctime,
            "days seen": 1,
            "ports": [conn["port"]],
            "remote addresses": [],
            "results": {sha256: "Pending"}
        }
        q_vt_pending.put(pickle.dumps((proc, sha256)))
        if conn["port"] not in snitch["Config"]["Remote address unlog"] and proc["name"] not in snitch["Config"]["Remote address unlog"]:
            snitch["Processes"][proc["exe"]]["remote addresses"].append(reversed_dns)
    else:
        entry = snitch["Processes"][proc["exe"]]
        if proc["name"] not in entry["name"]:
            entry["name"] += " alternative=" + proc["name"]
        if proc["cmdline"] not in entry["cmdlines"]:
            get_common_pattern(proc["cmdline"], entry["cmdlines"], 0.8)
            entry["cmdlines"].sort()
        if conn["port"] not in entry["ports"]:
            entry["ports"].append(conn["port"])
            entry["ports"].sort()
        if reversed_dns not in entry["remote addresses"]:
            if conn["port"] not in snitch["Config"]["Remote address unlog"] and proc["name"] not in snitch["Config"]["Remote address unlog"]:
                entry["remote addresses"].append(reversed_dns)
        if sha256 not in entry["results"]:
            entry["results"][sha256] = "Pending"
            q_vt_pending.put(pickle.dumps((proc, sha256)))
            toast("New sha256 detected for " + proc["name"] + ": " + proc["exe"])
        if ctime.split()[:3] != entry["last seen"].split()[:3]:
            entry["days seen"] += 1
        entry["last seen"] = ctime
    # Update Remote Addresses
    if reversed_dns in snitch["Remote Addresses"]:
        if proc["exe"] not in snitch["Remote Addresses"][reversed_dns]:
            snitch["Remote Addresses"][reversed_dns].insert(1, proc["exe"])
            if "No processes found during polling" in snitch["Remote Addresses"][reversed_dns]:
                snitch["Remote Addresses"][reversed_dns].remove("No processes found during polling")
    else:
        if conn["port"] not in snitch["Config"]["Remote address unlog"] and proc["name"] not in snitch["Config"]["Remote address unlog"]:
            snitch["Remote Addresses"][reversed_dns] = ["First connection: " + ctime, proc["exe"]]
    # Unlock the snitch for writing
    _ = snitch.pop("WRITELOCK")


def updater_subprocess(p_virustotal, init_scan, init_pickle,
                       q_snitch, q_error,
                       q_sha_pending, q_sha_results,
                       q_psutil_pending, q_psutil_results,
                       q_vt_pending, q_vt_results,
                       q_updater_restart, q_updater_ready, q_updater_term
                      ):
    """main subprocess where snitch.json is updated with new connections and the user is notified"""
    # drop root privileges and init variables for loop
    drop_root_privileges()
    pickle_path = os.path.join(os.path.expanduser("~"), ".config", "picosnitch", "pickle.tmp")
    if init_pickle is None:
        with open(pickle_path, "rb") as pickle_file:
            snitch, known_pids, missed_conns, update_snitch_pending = pickle.load(pickle_file)
    else:
        snitch, known_pids, missed_conns, update_snitch_pending = pickle.loads(init_pickle)
    sizeof_snitch = sys.getsizeof(pickle.dumps(snitch))
    last_write = 0
    # init signal handlers
    signal.signal(signal.SIGTERM, lambda *args: terminate_snitch_updater(snitch, q_error))
    signal.signal(signal.SIGINT, lambda *args: terminate_snitch_updater(snitch, q_error))
    # update snitch with initial running processes and connections
    if init_scan:
        get_vt_results(snitch, q_vt_pending, True)
        update_snitch_wrapper(snitch, update_snitch_pending, q_updater_term, q_sha_pending, q_sha_results, q_vt_pending)
    known_pids[p_virustotal.pid] = {"name": p_virustotal.name, "exe": __file__, "cmdline": shlex.join(sys.argv), "pid": p_virustotal.pid}
    known_pids[os.getpid()] = {"name": "snitchupdater", "exe": __file__, "cmdline": shlex.join(sys.argv), "pid": os.getpid()}
    # snitch updater main loop
    while True:
        # check for errors
        while not q_error.empty():
            error = q_error.get()
            snitch["Errors"].append(time.ctime() + " " + error)
            toast(error, file=sys.stderr)
        # check if terminating
        try:
            _ = q_updater_term.get(block=False)
            terminate_snitch_updater(snitch, q_error)
        except queue.Empty:
            if not multiprocessing.parent_process().is_alive():
                snitch["Errors"].append(time.ctime() + " picosnitch has stopped")
                toast("picosnitch has stopped", file=sys.stderr)
                terminate_snitch_updater(snitch, q_error)
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
        time.sleep(5)
        new_processes = []
        try:
            while True:
                new_processes.append(q_snitch.get(block=False))
        except queue.Empty:
            pass
        # process the list and update snitch
        new_processes = [pickle.loads(proc) for proc in new_processes]
        missed_conns, update_snitch_pending = update_snitch_processor(snitch, known_pids, missed_conns, new_processes, q_updater_term, q_psutil_pending, q_psutil_results)
        update_snitch_wrapper(snitch, update_snitch_pending, q_updater_term, q_sha_pending, q_sha_results, q_vt_pending)
        get_vt_results(snitch, q_vt_results, False)
        # free some memory
        while len(known_pids) > 9000:
            _ = known_pids.popitem(last=False)
        del new_processes
        del update_snitch_pending
        gc.collect()
        update_snitch_pending = []
        # write snitch
        if time.time() - last_write > 30:
            new_size = sys.getsizeof(pickle.dumps(snitch))
            if new_size != sizeof_snitch or time.time() - last_write > 600:
                sizeof_snitch = new_size
                last_write = time.time()
                write(snitch)


def linux_monitor_subprocess(q_snitch, q_error, q_monitor_term):
    """runs a bpf program to monitor the system for new processes and connections and puts them in the queue"""
    from bcc import BPF
    if os.getuid() == 0:
        b = BPF(text=bpf_text)
        execve_fnname = b.get_syscall_fnname("execve")
        b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
        b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")
        b.attach_kprobe(event="security_socket_connect", fn_name="security_socket_connect_entry")
        b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="do_entry", pid=-1)
        b.attach_uprobe(name="c", sym="gethostbyname", fn_name="do_entry", pid=-1)
        b.attach_uprobe(name="c", sym="gethostbyname2", fn_name="do_entry", pid=-1)
        b.attach_uretprobe(name="c", sym="getaddrinfo", fn_name="do_return", pid=-1)
        b.attach_uretprobe(name="c", sym="gethostbyname", fn_name="do_return", pid=-1)
        b.attach_uretprobe(name="c", sym="gethostbyname2", fn_name="do_return", pid=-1)
        argv = collections.defaultdict(list)
        def queue_exec_event(cpu, data, size):
            event = b["exec_events"].event(data)
            if event.type == 0:  # EVENT_ARG
                argv[event.pid].append(event.argv)
            elif event.type == 1:  # EVENT_RET
                argv_text = b' '.join(argv[event.pid]).replace(b'\n', b'\\n')
                q_snitch.put(pickle.dumps({"type": "exec", "pid": event.pid, "name": event.comm.decode(), "cmdline": argv_text.decode()}))
                try:
                    del argv[event.pid]
                except Exception:
                    pass
        def queue_ipv4_event(cpu, data, size):
            event = b["ipv4_events"].event(data)
            q_snitch.put(pickle.dumps({"type": "conn", "pid": event.pid, "ppid": event.ppid, "name": event.task.decode(), "port": event.dport, "ip": socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))}))
        def queue_ipv6_event(cpu, data, size):
            event = b["ipv6_events"].event(data)
            q_snitch.put(pickle.dumps({"type": "conn", "pid": event.pid, "ppid": event.ppid, "name": event.task.decode(), "port": event.dport, "ip": socket.inet_ntop(socket.AF_INET6, event.daddr)}))
        def queue_other_event(cpu, data, size):
            event = b["other_socket_events"].event(data)
            q_snitch.put(pickle.dumps({"type": "conn", "pid": event.pid, "ppid": event.ppid, "name": event.task.decode(), "port": 0, "ip": ""}))
        def queue_dns_event(cpu, data, size):
            event = b["dns_events"].event(data)
            q_snitch.put(pickle.dumps({"type": "conn", "pid": event.pid, "ppid": event.ppid, "name": event.comm.decode(), "port": 0, "ip": "", "host": event.host.decode()}))
        b["exec_events"].open_perf_buffer(queue_exec_event)
        b["ipv4_events"].open_perf_buffer(queue_ipv4_event)
        b["ipv6_events"].open_perf_buffer(queue_ipv6_event)
        b["other_socket_events"].open_perf_buffer(queue_other_event)
        b["dns_events"].open_perf_buffer(queue_dns_event)
        while True:
            if not q_monitor_term.empty() or not multiprocessing.parent_process().is_alive():
                return 0
            try:
                b.perf_buffer_poll(timeout=15)
            except Exception as e:
                error = "BPF " + type(e).__name__ + str(e.args)
                q_error.put(error)
    else:
        q_error.put("Snitch subprocess permission error, requires root")
    return 1


def func_subprocess(func: typing.Callable, q_pending, q_results, q_term):
    """wrapper function for subprocess"""
    last_error = 0
    while True:
        try:
            if not q_term.empty() or not multiprocessing.parent_process().is_alive():
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


def virustotal_subprocess(config: dict, q_vt_pending, q_vt_results, q_vt_term):
    """get virustotal results of process executable"""
    drop_root_privileges()
    try:
        import vt
        vt_enabled = True
    except ImportError:
        vt_enabled = False
    last_error = 0
    while True:
        try:
            if not q_vt_term.empty() or not multiprocessing.parent_process().is_alive():
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
    signal.signal(signal.SIGINT, lambda *args: None)
    if sys.platform.startswith("linux"):
        multiprocessing.set_start_method("fork")
        monitor_subprocess = linux_monitor_subprocess
    # elif sys.platform.startswith("win"):
    #     monitor_subprocess = snitch_windows_subprocess
    else:
        print("Did not detect a supported operating system", file=sys.stderr)
        return 1
    # start subprocesses
    p_monitor = ProcessManager(name="snitchmonitor", target=monitor_subprocess)
    q_snitch, q_error = p_monitor.q_in, p_monitor.q_out
    p_sha = ProcessManager(name="snitchsha", target=func_subprocess, init_args=(functools.lru_cache(get_sha256),))
    p_psutil = ProcessManager(name="snitchpsutil", target=func_subprocess, init_args=(get_proc_info,))
    p_virustotal = ProcessManager(name="snitchvirustotal", target=virustotal_subprocess, init_args=(config,))
    p_updater = ProcessManager(name="snitchupdater", target=updater_subprocess,
                               extra_args=(p_virustotal.p, True, snitch_updater_pickle),
                               init_args=(q_snitch, q_error,
                                          p_sha.q_in, p_sha.q_out,
                                          p_psutil.q_in, p_psutil.q_out,
                                          p_virustotal.q_in, p_virustotal.q_out)
                              )
    del snitch_updater_pickle
    # watch subprocesses
    subprocesses = [p_monitor, p_sha, p_psutil, p_virustotal, p_updater]
    try:
        while True:
            time.sleep(5)
            if not all(p.is_alive() for p in subprocesses):
                q_error.put("picosnitch subprocess died, attempting restart, terminate by running `picosnitch stop`")
                break
            if any(p.is_zombie() for p in subprocesses):
                q_error.put("picosnitch subprocess became a zombie, attempting restart")
                break
            if p_monitor.memory() > 256000000:
                q_error.put("Snitch monitor memory usage exceeded 256 MB, attempting restart")
                break
            if p_updater.memory() > 256000000:
                q_error.put("Snitch updater memory usage exceeded 256 MB, attempting restart")
                break
    except Exception as e:
        q_error.put("picosnitch subprocess exception: " + str(e))
    # something went wrong, attempt to restart picosnitch (terminate by running `picosnitch stop`)
    try:
        p_updater.terminate(60, True)
    except Exception:
        try:
            p_updater.terminate(10)
        except Exception:
            pass
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
    missed_conns = []
    known_pids = collections.OrderedDict()
    update_snitch_pending = initial_poll(snitch, known_pids)
    snitch_updater_pickle = pickle.dumps((snitch, known_pids, missed_conns, update_snitch_pending))
    # start picosnitch process monitor
    if __name__ == "__main__":
        sys.exit(picosnitch_master_process(snitch["Config"], snitch_updater_pickle))
    print("Snitch subprocess init failed, __name__ != __main__, try: sudo -E python -m picosnitch", file=sys.stderr)
    sys.exit(1)


def start_daemon():
    """startup picosnitch as a daemon on posix systems, regular process otherwise, and ensure only one instance is running"""
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
                print("usage: picosnitch start|stop|restart|version")
                return 0
            return 0
        else:
            print("usage: picosnitch start|stop|restart|version")
            return 0
    # elif ... :
        # not really supported right now (waiting to see what happens with https://github.com/microsoft/ebpf-for-windows)
        # main(tmp_snitch["Config"]["VT API key"])
    else:
        print("Did not detect a supported operating system", file=sys.stderr)
        return 1


bpf_text = """
// This BPF program was adapted from the following sources, both licensed under the Apache License, Version 2.0
// https://github.com/iovisor/bcc/blob/023154c7708087ddf6c2031cef5d25c2445b70c4/tools/execsnoop.py
// https://github.com/iovisor/bcc/blob/ab14fafec3fc13f89bd4678b7fc94829dcacaa7b/tools/gethostlatency.py
// https://github.com/p-/socket-connect-bpf/blob/7f386e368759e53868a078570254348e73e73e22/securitySocketConnectSrc.bpf
// https://github.com/p-/socket-connect-bpf/blob/7f386e368759e53868a078570254348e73e73e22/dnsLookupSrc.bpf
// Copyright 2016 Netflix, Inc.
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
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>

// execsnoop structs

#define ARGSIZE  128

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    u32 uid;
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};
BPF_PERF_OUTPUT(exec_events);

// securitySocketConnect structs

struct ipv4_event_t {
    u64 ts_us;
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
    u64 ts_us;
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
    u64 ts_us;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 af;
    char task[TASK_COMM_LEN];
} __attribute__((packed));
BPF_PERF_OUTPUT(other_socket_events);

// gethostlatency structs

struct val_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char host[80];
};

struct data_dns_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char host[80];
};

BPF_HASH(start, u32, struct val_t);
BPF_PERF_OUTPUT(dns_events);

// execsnoop functions

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
    exec_events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    __submit_arg(ctx, (void *)filename, &data);

    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < 20; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct task_struct *task;

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = uid;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    exec_events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

// securitySocketConnect functions

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
        data4.ts_us = bpf_ktime_get_ns() / 1000;

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
        data6.ts_us = bpf_ktime_get_ns() / 1000;

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
        socket_event.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_get_current_comm(&socket_event.task, sizeof(socket_event.task));
        other_socket_events.perf_submit(ctx, &socket_event, sizeof(socket_event));
    }

    return 0;
}

// gethostlatency functions

int do_entry(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
    struct val_t val = {};
    u32 pid = bpf_get_current_pid_tgid();
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        bpf_probe_read_user(&val.host, sizeof(val.host),
                       (void *)PT_REGS_PARM1(ctx));
        val.pid = pid;
        start.update(&pid, &val);
    }
    return 0;
}

int do_return(struct pt_regs *ctx) {
    struct val_t *valp;
    struct data_dns_t data = {};
    struct task_struct *task;
    u32 pid = bpf_get_current_pid_tgid();
    valp = start.lookup(&pid);
    if (valp == 0)
        return 0;       // missed start
    bpf_probe_read_kernel(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read_kernel(&data.host, sizeof(data.host), (void *)valp->host);
    data.pid = valp->pid;
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    dns_events.perf_submit(ctx, &data, sizeof(data));
    start.delete(&pid);
    return 0;
}
"""

if __name__ == "__main__":
    sys.exit(start_daemon())
