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

import difflib
import json
import hashlib
import multiprocessing
import os
import pickle
import queue
import shlex
import signal
import subprocess
import sys
import time
import typing

try:
    import filelock
    import plyer
    import psutil
    # import vt
except Exception as e:
    print(type(e).__name__ + str(e.args))
    print("Make sure dependency is installed, or environment is preserved if running with sudo")


def read() -> dict:
    """read snitch from correct location (even if sudo is used without preserve-env), or init a new one if not found"""
    template = {
        "Config": {"Execsnoop cmd": "execsnoop-bpfcc", "VT API key": "", "VT file upload": True},
        "Errors": [],
        "Latest Entries": [],
        "Names": {},
        "Processes": {}
    }
    if sys.platform.startswith("linux") and os.getuid() == 0 and os.getenv("SUDO_USER") is not None:
        home_dir = os.path.join("/home", os.getenv("SUDO_USER"))
    else:
        home_dir = os.path.expanduser("~")
    file_path = os.path.join(home_dir, ".config", "picosnitch", "psnitch.json")
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="surrogateescape") as json_file:
            data = json.load(json_file)
        assert all(key in data and type(data[key]) == type(template[key]) for key in template), "Invalid psnitch.json"
        assert all(key in data["Config"] for key in template["Config"]), "Invalid config"
        return data
    return template


def write(snitch: dict) -> None:
    """write snitch to correct location (root privileges should be dropped first)"""
    file_path = os.path.join(os.path.expanduser("~"), ".config", "picosnitch", "psnitch.json")
    if not os.path.isdir(os.path.dirname(file_path)):
        os.makedirs(os.path.dirname(file_path))
    try:
        with open(file_path, "w", encoding="utf-8", errors="surrogateescape") as json_file:
            json.dump(snitch, json_file, indent=2, separators=(',', ': '), sort_keys=True, ensure_ascii=False)
    except Exception:
        toast("processsnitch write error", file=sys.stderr)


def drop_root_privileges() -> None:
    """drop root privileges on linux"""
    if sys.platform.startswith("linux") and os.getuid() == 0:
        os.setgid(int(os.getenv("SUDO_GID")))
        os.setuid(int(os.getenv("SUDO_UID")))


def terminate(snitch: dict, p_snitch: multiprocessing.Process, q_term: multiprocessing.Queue) -> None:
    """write snitch one last time, then terminate processsnitch and subprocesses if running"""
    write(snitch)
    q_term.put("TERMINATE")
    p_snitch.join(5)
    p_snitch.close()
    sys.exit(0)


def toast(msg: str, file=sys.stdout) -> None:
    """create a system tray notification, tries printing as a last resort, requires -E if running with sudo"""
    try:
        plyer.notification.notify(title="processsnitch", message=msg, app_name="processsnitch")
    except Exception:
        print("processsnitch (toast failed): " + msg, file=file)


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
    with open(exe, "rb") as f:
        sha256 = hashlib.sha256(f.read())
    return sha256.hexdigest()


def get_vt_results(sha256: str, proc: dict, upload: bool) -> str:
    """get virustotal results of process executable and toast negative results"""
    return ""


def process_queue(snitch: dict, new_processes: list) -> None:
    """process list of new processes and call update_snitch"""
    ctime = time.ctime()
    for proc in new_processes:
        try:
            sha256 = get_sha256(proc["exe"])
            update_snitch(snitch, proc, sha256, ctime)
        except Exception as e:
            error = type(e).__name__ + str(e.args) + str(proc)
            snitch["Errors"].append(ctime + " " + error)
            toast("Processsnitch error: " + error, file=sys.stderr)


def update_snitch(snitch: dict, proc: dict, sha256: str, ctime: str) -> None:
    """update the snitch with a new process"""
    # Update Latest Entries
    if proc["exe"] not in snitch["Processes"] or proc["name"] not in snitch["Names"]:
        snitch["Latest Entries"].append(ctime + " " + proc["name"] + ": " + proc["exe"])
    # Update Names
    if proc["name"] in snitch["Names"]:
        if proc["exe"] not in snitch["Names"][proc["name"]]:
            snitch["Names"][proc["name"]].append(proc["exe"])
            toast("New executable detected for " + proc["name"] + ": " + proc["exe"])
    else:
        snitch["Names"][proc["name"]] = [proc["exe"]]
    # Update Processes
    if proc["exe"] not in snitch["Processes"]:
        snitch["Processes"][proc["exe"]] = {
            "name": proc["name"],
            "cmdlines": [str(proc["cmdline"])],
            "first seen": ctime,
            "last seen": ctime,
            "days seen": 1,
            "results": {sha256: get_vt_results(sha256, proc, snitch["Config"]["VT file upload"])}
        }
    else:
        entry = snitch["Processes"][proc["exe"]]
        if proc["name"] != entry["name"]:
            entry["name"] = proc["name"]
        if str(proc["cmdline"]) not in entry["cmdlines"]:
            get_common_pattern(str(proc["cmdline"]), entry["cmdlines"], 0.8)
            entry["cmdlines"].sort()
        if sha256 not in entry["results"]:
            entry["results"][sha256] = get_vt_results(sha256, proc, snitch["Config"]["VT file upload"])
        if ctime.split()[:3] != entry["last seen"].split()[:3]:
            entry["days seen"] += 1
        entry["last seen"] = ctime


def loop():
    """main loop"""
    # acquire lock (since the prior one would be released by starting the daemon)
    lock = filelock.FileLock(os.path.join(os.path.expanduser("~"), ".processsnitch_lock"), timeout=1)
    lock.acquire()
    # read config and init sniffer if enabled
    snitch = read()
    p_snitch, q_process, q_error, q_term = init_process_monitor()
    drop_root_privileges()
    # set signal handlers
    signal.signal(signal.SIGTERM, lambda *args: terminate(snitch, p_snitch, q_term))
    signal.signal(signal.SIGINT, lambda *args: terminate(snitch, p_snitch, q_term))
    # snitch init checks
    if p_snitch is None:
        snitch["Errors"].append(time.ctime() + " Process snitch init failed, __name__ != __main__, try: python -m processsnitch")
        toast("Process snitch init failed, try: python -m processsnitch", file=sys.stderr)
    # init variables for loop
    sizeof_snitch = sys.getsizeof(pickle.dumps(snitch))
    last_write = 0
    while True:
        # check for process monitor errors
        while not q_error.empty():
            error = q_error.get()
            snitch["Errors"].append(time.ctime() + " " + error)
            toast(error, file=sys.stderr)
        # log snitch death, exit processsnitch
        if not p_snitch.is_alive():
            snitch["Errors"].append(time.ctime() + " process monitor stopped")
            toast("process monitor stopped, exited processsnitch", file=sys.stderr)
            terminate(snitch, p_snitch, q_term)
        # list of new processes since last poll
        new_processes = []
        if q_process.empty():
            time.sleep(5)
        while not q_process.empty():
            new_processes.append(pickle.loads(q_process.get()))
        process_queue(snitch, new_processes)
        # write snitch
        if time.time() - last_write > 30:
            new_size = sys.getsizeof(pickle.dumps(snitch))
            if new_size != sizeof_snitch or time.time() - last_write > 600:
                sizeof_snitch = new_size
                last_write = time.time()
                write(snitch)


def init_process_monitor() -> typing.Tuple[multiprocessing.Process, multiprocessing.Queue, multiprocessing.Queue, multiprocessing.Queue]:
    """init process monitor with root before dropping root privileges"""
    def process_monitor_linux(q_process, q_error, q_term_monitor):
        """runs another program to monitor the system for new processes and puts them in the queue"""
        # using: https://github.com/iovisor/bcc/blob/master/tools/execsnoop.py
        # alternative: https://github.com/ColinIanKing/forkstat
        # alternative: https://github.com/DominicBreuker/pspy
        if os.getuid() == 0:
            for proc in psutil.process_iter(attrs=["name", "exe", "cmdline"], ad_value=""):
                if os.path.isfile(proc.info["exe"]):
                    q_process.put(pickle.dumps(proc.info))
            process_monitor = subprocess.Popen(["execsnoop-bpfcc"], stdout=subprocess.PIPE, universal_newlines=True)
            while process_monitor.poll() is None:
                try:
                    proc = process_monitor.stdout.readline()
                    proc = shlex.split(proc.strip())
                    proc = {"name": proc[0], "exe": proc[4], "cmdline": str(proc[4:])}
                    if os.path.isfile(proc["exe"]):
                        q_process.put(pickle.dumps(proc))
                except Exception as e:
                    error = type(e).__name__ + str(e.args) + str(proc)
                    q_error.put(error)
                try:
                    if q_term_monitor.get(block=False):
                        return 0
                except queue.Empty:
                    if not multiprocessing.parent_process().is_alive():
                        return 0
        else:
            q_error.put("Process monitor permission error, requires root")
        return 1

    def process_monitor_windows(q_process, q_error, q_term_monitor):
        """runs another program to trace new processes and puts them in the queue"""
        # poll psutil since I don't know an easy way to reliably trace windows process creation events yet
        current_procs = []
        for proc in psutil.process_iter(attrs=["name", "exe", "cmdline"], ad_value=""):
            current_procs.append(proc.info["exe"])
            q_process.put(pickle.dumps(proc.info))
        for serv in psutil.win_service_iter():
            current_procs.append(serv.name)
            serv = psutil.win_service_get(serv.name)
            serv = {"name": serv.name(), "exe": shlex.split(serv.binpath())[0], "cmdline": "service"}
            q_process.put(pickle.dumps(serv))
        while True:
            previous_procs = current_procs
            current_procs = []
            for proc in psutil.process_iter(attrs=["name", "exe", "cmdline"], ad_value=""):
                current_procs.append(proc.info["exe"])
                if proc.info["exe"] not in previous_procs:
                    q_process.put(pickle.dumps(proc.info))
            for serv in psutil.win_service_iter():
                current_procs.append(serv.name)
                if serv.name not in previous_procs:
                    serv = psutil.win_service_get(serv.name)
                    serv = {"name": serv.name(), "exe": shlex.split(serv.binpath())[0], "cmdline": "service"}
                    q_process.put(pickle.dumps(serv))
            try:
                if q_term_monitor.get(block=True, timeout=5):
                    return 0
            except queue.Empty:
                if not multiprocessing.parent_process().is_alive():
                    return 0
        return 1

    def process_mon_master(q_process, q_error, q_term):
        """monitor the process monitor and parent process, has same privileges as the sniffer for clean termination at the command or death of the parent"""
        signal.signal(signal.SIGINT, lambda *args: None)
        if sys.platform.startswith("linux"):
            process_monitor = process_monitor_linux
        elif sys.platform.startswith("win"):
            process_monitor = process_monitor_windows
        else:
            q_error.put("Did not detect a supported operating system")
            return 1
        q_term_monitor = multiprocessing.Queue()
        terminate_monitor = lambda p_monitor: q_term_monitor.put("TERMINATE") or p_monitor.join(2) or (p_monitor.is_alive() and p_monitor.kill()) or p_monitor.close()
        p_monitor = multiprocessing.Process(name="processsnitchmon", target=process_monitor, args=(q_process, q_error, q_term_monitor), daemon=True)
        p_monitor.start()
        while True:
            if p_monitor.is_alive() and psutil.Process(p_monitor.pid).memory_info().vms > 256000000:
                q_error.put("Process monitor memory usage exceeded 256 MB, restarting monitor")
                terminate_monitor(p_monitor)
                p_monitor = multiprocessing.Process(name="processsnitchmon", target=process_monitor, args=(q_process, q_error, q_term_monitor), daemon=True)
                p_monitor.start()
            try:
                if q_term.get(block=True, timeout=10):
                    break
            except queue.Empty:
                if not multiprocessing.parent_process().is_alive() or not p_monitor.is_alive():
                    break
        terminate_monitor(p_monitor)
        return 0

    if __name__ == "__main__":
        q_process, q_error, q_term = multiprocessing.Queue(), multiprocessing.Queue(), multiprocessing.Queue()
        p_snitch = multiprocessing.Process(name="processsnitchmonmaster", target=process_mon_master, args=(q_process, q_error, q_term))
        p_snitch.start()
        return p_snitch, q_process, q_error, q_term
    return None, None, None, None


def main():
    """startup processsnitch as a daemon on posix systems, regular process otherwise, and ensure only one instance is running"""
    lock = filelock.FileLock(os.path.join(os.path.expanduser("~"), ".processsnitch_lock"), timeout=1)
    try:
        lock.acquire()
        lock.release()
    except filelock.Timeout:
        print("Error: another instance of this application is currently running", file=sys.stderr)
        sys.exit(1)
    try:
        _ = read()
    except Exception as e:
        print(type(e).__name__ + str(e.args))
        sys.exit(1)
    if sys.prefix != sys.base_prefix:
            print("Warning: processsnitch is running in a virtual environment, notifications may not function", file=sys.stderr)
    if os.name == "posix":
        if os.path.expanduser("~") == "/root":
            print("Warning: processsnitch was run as root without preserving environment", file=sys.stderr)
        import daemon
        with daemon.DaemonContext():
            loop()
    else:
        loop()


if __name__ == "__main__":
    sys.exit(main())
