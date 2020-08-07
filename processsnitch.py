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
import multiprocessing
import os
import pickle
import queue
import signal
import sys
import time
import typing

import filelock
import plyer
import psutil
import vt-py


def read() -> dict:
    """read snitch from correct location (even if sudo is used without preserve-env), or init a new one if not found"""
    template = {
        "Config": {"API key": ""},
        "Errors": [],
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


def terminate(snitch: dict, p_snitch: multiprocessing.Process = None, q_term: multiprocessing.Queue = None):
    """write snitch one last time, then terminate processsnitch and subprocesses if running"""
    write(snitch)
    if q_term is not None:
        q_term.put("TERMINATE")
        p_snitch.join(5)
        p_snitch.close()
    sys.exit(0)


def toast(msg: str, file=sys.stdout) -> None:
    """create a system tray notification, tries printing as a last resort"""
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


def process_queue(snitch: dict, last_connections: set, pcap_dict: dict) -> set:
    """poll processes and connections using psutil, and queued pcap if available, then run update_snitch_*"""
    ctime = time.ctime()
    proc = {"name": "", "exe": "", "cmdline": "", "pid": ""}
    current_connections = set(psutil.net_connections(kind="all"))
    # check processes for all new connections
    for conn in current_connections - last_connections:
        try:
            if conn.pid is not None and conn.raddr and not ipaddress.ip_address(conn.raddr.ip).is_private:
                # update snitch (if necessary) with new non-local connection (pop from pcap)
                _ = pcap_dict.pop(str(conn.raddr.ip), None)
                proc = psutil.Process(conn.pid).as_dict(attrs=["name", "exe", "cmdline", "pid"], ad_value="")
                update_snitch_proc(snitch, proc, conn, ctime)
        except Exception as e:
            # too late to grab process info (most likely) or some other error
            error = str(conn)
            if conn.pid == proc["pid"]:
                error += str(proc)
            else:
                error += "{process no longer exists}"
            error += type(e).__name__ + str(e.args)
            snitch["Errors"].append(ctime + " " + error)
            toast("Polling error: " + error, file=sys.stderr)
    # check any connection still in the pcap that wasn't already identified
    for pcap in pcap_dict.values():
        update_snitch_pcap(snitch, pcap, ctime)
    return current_connections


def update_snitch(snitch: dict, proc: dict, conn: typing.NamedTuple, ctime: str) -> None:
    """update the snitch with new processes and create a notification if negative vt results"""
    # Get DNS reverse name and reverse the name for sorting
    reversed_dns = reverse_domain_name(reverse_dns_lookup(conn.raddr.ip))
    # Update Latest Entries
    if proc["exe"] not in snitch["Processes"] or proc["name"] not in snitch["Names"]:
        snitch["Latest Entries"].append(ctime + " " + proc["name"] + " - " + proc["exe"])
    # Update Names
    if proc["name"] in snitch["Names"]:
        if proc["exe"] not in snitch["Names"][proc["name"]]:
            snitch["Names"][proc["name"]].append(proc["exe"])
            toast("New executable detected for " + proc["name"] + ": " + proc["exe"])
    else:
        snitch["Names"][proc["name"]] = [proc["exe"]]
        toast("First network connection detected for " + proc["name"])
    # Update Processes
    if proc["exe"] not in snitch["Processes"]:
        snitch["Processes"][proc["exe"]] = {
            "name": proc["name"],
            "cmdlines": [str(proc["cmdline"])],
            "first seen": ctime,
            "last seen": ctime,
            "days seen": 1,
            "results": {'sha256(proc["exe"])': 'vt(sha256, proc["exe"])'}
        }
        if conn.raddr.port not in snitch["Config"]["Remote address unlog"] and proc["name"] not in snitch["Config"]["Remote address unlog"]:
            snitch["Processes"][proc["exe"]]["remote addresses"].append(reversed_dns)
    else:
        entry = snitch["Processes"][proc["exe"]]
        if proc["name"] not in entry["name"]:
            entry["name"] += " alternative=" + proc["name"]
        if str(proc["cmdline"]) not in entry["cmdlines"]:
            get_common_pattern(str(proc["cmdline"]), entry["cmdlines"], 0.8)
            entry["cmdlines"].sort()
        if conn.raddr.port not in entry["ports"]:
            entry["ports"].append(conn.raddr.port)
            entry["ports"].sort()
        if reversed_dns not in entry["remote addresses"]:
            if conn.raddr.port not in snitch["Config"]["Remote address unlog"] and proc["name"] not in snitch["Config"]["Remote address unlog"]:
                entry["remote addresses"].append(reversed_dns)
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
        if conn.raddr.port not in snitch["Config"]["Remote address unlog"] and proc["name"] not in snitch["Config"]["Remote address unlog"]:
            snitch["Remote Addresses"][reversed_dns] = ["First connection: " + ctime, proc["exe"]]


def loop():
    """main loop"""
    # acquire lock (since the prior one would be released by starting the daemon)
    lock = filelock.FileLock(os.path.join(os.path.expanduser("~"), ".processsnitch_lock"), timeout=1)
    lock.acquire()
    # read config and init sniffer if enabled
    snitch = read()
    p_snitch, q_packet, q_error, q_term = None, None, None, None
    if snitch["Config"]["Enable pcap"]:
        p_snitch, q_packet, q_error, q_term = init_pcap()
    drop_root_privileges()
    # set signal handlers
    signal.signal(signal.SIGTERM, lambda *args: terminate(snitch, p_snitch, q_term))
    signal.signal(signal.SIGINT, lambda *args: terminate(snitch, p_snitch, q_term))
    # sniffer init checks
    if snitch["Config"]["Enable pcap"] and p_snitch is None:
        snitch["Errors"].append(time.ctime() + " Sniffer init failed, __name__ != __main__, try: python -m picosnitch")
        toast("Sniffer init failed, try: python -m picosnitch", file=sys.stderr)
    if not snitch["Config"]["Enable pcap"] and os.getenv("SUDO_USER") is not None:
        toast("Sniffer is disabled, root is not necessary, did you intend to enable it?", file=sys.stderr)
    # init variables for loop
    connections = set()
    polling_interval = snitch["Config"]["Polling interval"]
    sizeof_snitch = sys.getsizeof(pickle.dumps(snitch))
    last_write = 0
    while True:
        # check sniffer status and for any connections that were missed during the last poll
        pcap_dict = {}
        if p_snitch is not None:
            # list of known connections from last poll, l/raddr could be a path if AF_UNIX socket, and raddr could be None
            known_raddr = [conn.raddr.ip for conn in connections if hasattr(conn.raddr, "ip")]
            while not q_packet.empty():
                packet = q_packet.get()
                if packet["raddr_ip"] not in known_raddr:
                    # new connection, log and check during polling
                    pcap_dict[str(packet["raddr_ip"])] = packet
            while not q_error.empty():
                # log sniffer errors
                error = q_error.get()
                snitch["Errors"].append(time.ctime() + " " + error)
                toast(error, file=sys.stderr)
            if not p_snitch.is_alive():
                # log sniffer death, stop checking it and try to keep running
                snitch["Errors"].append(time.ctime() + " picosnitch sniffer process stopped")
                toast("picosnitch sniffer process stopped", file=sys.stderr)
                p_snitch, q_packet, q_error, q_term = None, None, None, None
        # poll connections and processes with psutil
        connections = poll(snitch, connections, pcap_dict)
        time.sleep(polling_interval)
        if time.time() - last_write > 30:
            new_size = sys.getsizeof(pickle.dumps(snitch))
            if new_size != sizeof_snitch or time.time() - last_write > 600:
                sizeof_snitch = new_size
                last_write = time.time()
                write(snitch)


def init_process_snitch() -> typing.Tuple[multiprocessing.Process, multiprocessing.Queue, multiprocessing.Queue, multiprocessing.Queue]:
    """init subprocess monitor with root before dropping root privileges (root may not be necessary)"""
    def process_snitch(q_process, q_error):
        """runs another program to trace new processes and puts them in the queue"""
        # use one of
        # https://github.com/iovisor/bcc/blob/master/tools/execsnoop.py
        # https://github.com/ColinIanKing/forkstat
        # https://github.com/DominicBreuker/pspy
        # and possibly ProcMon for windows
        pass

    def snitch_mon(q_process, q_error, q_term):
        """monitor the process snooper and parent process, has same privileges as the sniffer for clean termination at the command or death of the parent"""
        signal.signal(signal.SIGINT, lambda *args: None)
        terminate_snitch = lambda p_snitch: p_snitch.terminate() or p_snitch.join(1) or (p_snitch.is_alive() and p_snitch.kill()) or p_snitch.close()
        p_snitch = multiprocessing.Process(name="processsnitch", target=process_snitch, args=(q_packet, q_error), daemon=True)
        p_snitch.start()
        while True:
            if p_snitch.is_alive() and psutil.Process(p_snitch.pid).memory_info().vms > 256000000:
                q_error.put("Sniffer memory usage exceeded 256 MB, restarting sniffer")
                terminate_snitch(p_snitch)
                p_snitch = multiprocessing.Process(name="processsnitch", target=process_snitch, args=(q_packet, q_error), daemon=True)
                p_snitch.start()
            try:
                if q_term.get(block=True, timeout=10):
                    break
            except queue.Empty:
                if not multiprocessing.parent_process().is_alive() or not p_snitch.is_alive():
                    break
        terminate_snitch(p_snitch)
        return 0

    if __name__ == "__main__":
        q_packet, q_error, q_term = multiprocessing.Queue(), multiprocessing.Queue(), multiprocessing.Queue()
        p_snitch = multiprocessing.Process(name="processsnitchmon", target=snitch_mon, args=(q_packet, q_error, q_term))
        p_snitch.start()
        return p_snitch, q_packet, q_error, q_term
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
