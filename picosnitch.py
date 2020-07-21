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

import ipaddress
import json
import multiprocessing
import os
import pickle
import signal
import socket
import sys
import time
import typing


def read() -> dict:
    """read snitch from correct location (even if sudo is used without preserve-env), or init a new one if not found"""
    template = {
        "Config": {"Enable pcap": False, "Polling interval": 0.2, "Remote address unlog": ["firefox"]},
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
        assert all(key in data and type(data[key]) == type(template[key]) for key in template), "Invalid snitch.json"
        assert all(key in data["Config"] for key in template["Config"]), "Invalid config"
        return data
    return template


def write(snitch: dict) -> None:
    """write snitch to correct location (root privileges should be dropped first)"""
    file_path = os.path.join(os.path.expanduser("~"), ".config", "picosnitch", "snitch.json")
    if not os.path.isdir(os.path.dirname(file_path)):
        os.makedirs(os.path.dirname(file_path))
    try:
        with open(file_path, "w", encoding="utf-8", errors="surrogateescape") as json_file:
            json.dump(snitch, json_file, indent=2, separators=(',', ': '), sort_keys=True, ensure_ascii=False)
    except Exception:
        toast("picosnitch write error", file=sys.stderr)


def drop_root_privileges() -> None:
    """drop root privileges on linux"""
    if sys.platform.startswith("linux") and os.getuid() == 0:
        os.setgid(int(os.getenv("SUDO_GID")))
        os.setuid(int(os.getenv("SUDO_UID")))


def terminate(snitch: dict, p_sniff: multiprocessing.Process = None, q_term: multiprocessing.Queue = None):
    """write snitch one last time, then terminate picosnitch and subprocesses if running"""
    write(snitch)
    if q_term is not None:
        q_term.put("TERMINATE")
        p_sniff.join(5)
        p_sniff.close()
    sys.exit(0)


def toast(msg: str, file=sys.stdout) -> None:
    """create a system tray notification, tries printing as a last resort"""
    try:
        plyer.notification.notify(title="picosnitch", message=msg, app_name="picosnitch")
    except Exception:
        print("picosnitch (toast failed):" + msg, file=file)


def poll(snitch: dict, last_connections: set, pcap_dict: dict) -> set:
    """poll processes and connections using psutil, and queued pcap if available, then run update_snitch_*"""
    ctime = time.ctime()
    proc = {"name": "", "exe": "", "cmdline": "", "pid": ""}
    current_connections = set(psutil.net_connections(kind="all"))
    # check processes for all new connections
    for conn in current_connections - last_connections:
        try:
            if conn.pid is not None and conn.raddr and not ipaddress.ip_address(conn.raddr.ip).is_private:
                # update snitch (if necessary) with new non-local connection (pop from pcap)
                _ = pcap_dict.pop(str(conn.laddr.port) + str(conn.raddr.ip), None)
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
            toast("picosnitch polling error: " + error, file=sys.stderr)
    # check any connection still in the pcap that wasn't already identified
    for pcap in pcap_dict.values():
        update_snitch_pcap(snitch, pcap, ctime)
    return current_connections


def update_snitch_proc(snitch: dict, proc: dict, conn: typing.NamedTuple, ctime: str) -> None:
    """update the snitch with polled data from psutil and create a notification if new"""
    # Get DNS reverse name and reverse the name for sorting
    reversed_dns = ".".join(reversed(socket.getnameinfo((conn.raddr.ip, 0), 0)[0].split(".")))
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
            "ports": [conn.laddr.port],
            "remote addresses": []
        }
        if conn.laddr.port not in snitch["Config"]["Remote address unlog"] and proc["name"] not in snitch["Config"]["Remote address unlog"]:
            snitch["Processes"][proc["exe"]]["remote addresses"].append(reversed_dns)
    else:
        entry = snitch["Processes"][proc["exe"]]
        if proc["name"] not in entry["name"]:
            entry["name"] += " alternative=" + proc["name"]
        if str(proc["cmdline"]) not in entry["cmdlines"]:
            entry["cmdlines"].append(str(proc["cmdline"]))
        if conn.laddr.port not in entry["ports"]:
            entry["ports"].append(conn.laddr.port)
            entry["ports"].sort()
        if reversed_dns not in entry["remote addresses"]:
            if conn.laddr.port not in snitch["Config"]["Remote address unlog"] and proc["name"] not in snitch["Config"]["Remote address unlog"]:
                entry["remote addresses"].append(reversed_dns)
        if ctime.split()[:3] != entry["last seen"].split()[:3]:
            entry["days seen"] += 1
        entry["last seen"] = ctime
    # Update Remote Addresses
    if reversed_dns in snitch["Remote Addresses"]:
        if proc["exe"] not in snitch["Remote Addresses"][reversed_dns]:
            snitch["Remote Addresses"][reversed_dns].append(proc["exe"])
    else:
        if conn.laddr.port not in snitch["Config"]["Remote address unlog"] and proc["name"] not in snitch["Config"]["Remote address unlog"]:
            snitch["Remote Addresses"][reversed_dns] = ["First connection: " + ctime, proc["exe"]]


def update_snitch_pcap(snitch: dict, pcap: dict, ctime: str) -> None:
    """update the snitch with queued data from Scapy and create a notification if new"""
    # Get DNS reverse name and reverse the name for sorting
    reversed_dns = ".".join(reversed(socket.getnameinfo((pcap["raddr_ip"], 0), 0)[0].split(".")))
    if pcap["laddr_port"] not in snitch["Config"]["Remote address unlog"]:
        if reversed_dns not in snitch["Remote Addresses"]:
            snitch["Remote Addresses"][reversed_dns] = ["First connection: " + ctime, pcap["summary"]]
            toast("polling missed process for connection: " + pcap["summary"])
        elif pcap["summary"] not in snitch["Remote Addresses"][reversed_dns]:
            snitch["Remote Addresses"][reversed_dns].append(pcap["summary"])


def loop():
    """main loop"""
    # acquire lock (since the prior one would be released by starting the daemon)
    lock = filelock.FileLock(os.path.join(os.path.expanduser("~"), ".picosnitch_lock"), timeout=1)
    lock.acquire()
    # read config and init sniffer if enabled
    snitch = read()
    p_sniff, q_packet, q_error, q_term = None, None, None, None
    if snitch["Config"]["Enable pcap"]:
        p_sniff, q_packet, q_error, q_term = init_pcap()
    drop_root_privileges()
    # import dependencies here to save memory since sniffer doesn't need to load them
    global plyer, psutil
    import plyer, psutil
    # set signal handlers
    signal.signal(signal.SIGTERM, lambda *args: terminate(snitch, p_sniff, q_term))
    signal.signal(signal.SIGINT, lambda *args: terminate(snitch, p_sniff, q_term))
    # init variables for loop
    connections = set()
    polling_interval = snitch["Config"]["Polling interval"]
    sizeof_snitch = sys.getsizeof(pickle.dumps(snitch))
    last_write = 0
    while True:
        # check sniffer status and for any connections that were missed during the last poll
        pcap_dict = {}
        if p_sniff is not None:
            # list of known connections from last poll, l/raddr could be a path if AF_UNIX socket, and raddr could be None
            known_ports = [conn.laddr.port for conn in connections if hasattr(conn.laddr, "port")]
            known_raddr = [conn.raddr.ip for conn in connections if hasattr(conn.raddr, "ip")]
            while not q_packet.empty():
                packet = q_packet.get()
                if not (packet["laddr_port"] in known_ports or packet["raddr_ip"] in known_raddr):
                    # new connection, log and check during polling
                    pcap_dict[str(packet["laddr_port"]) + str(packet["raddr_ip"])] = packet
            while not q_error.empty():
                # log sniffer errors
                error = q_error.get()
                snitch["Errors"].append(time.ctime() + " " + error)
                toast("picosnitch " + error, file=sys.stderr)
            if not p_sniff.is_alive():
                # log sniffer death, stop checking it and try to keep running
                snitch["Errors"].append(time.ctime() + " picosnitch sniffer process stopped")
                toast("picosnitch sniffer process stopped", file=sys.stderr)
                p_sniff, q_packet, q_error, q_term = None, None, None, None
        # poll connections and processes with psutil
        connections = poll(snitch, connections, pcap_dict)
        time.sleep(polling_interval)
        new_size = sys.getsizeof(pickle.dumps(snitch))
        if new_size > sizeof_snitch or time.time() - last_write > 300:
            sizeof_snitch = new_size
            last_write = time.time()
            write(snitch)


def init_pcap() -> typing.Tuple[multiprocessing.Process, multiprocessing.Queue, multiprocessing.Queue, multiprocessing.Queue]:
    """init sniffing subprocess and monitor with root (before dropping root privileges)"""
    def parse_packet(packet) -> dict:
        """create a dict from the packet"""
        output = {"summary": packet.summary(), "laddr_port": None}
        # output["packet"] = str(packet.show(dump=True))
        src = packet.getlayer(scapy.layers.all.IP).src
        dst = packet.getlayer(scapy.layers.all.IP).dst
        if ipaddress.ip_address(src).is_private:
            output["direction"] = "outgoing"
            output["laddr_ip"], output["raddr_ip"] = src, dst
            if hasattr(packet, "sport"):
                output["laddr_port"] = packet.sport
        elif ipaddress.ip_address(dst).is_private:
            output["direction"] = "incoming"
            output["laddr_ip"], output["raddr_ip"] = dst, src
            if hasattr(packet, "dport"):
                output["laddr_port"] = packet.dport
        return output

    def filter_packet(packet) -> bool:
        """filter remote connections (ignore local only) (either src or dst is remote)"""
        try:
            src = ipaddress.ip_address(packet.getlayer(scapy.layers.all.IP).src)
            dst = ipaddress.ip_address(packet.getlayer(scapy.layers.all.IP).dst)
            return src.is_private != dst.is_private
        except:
            return False

    def sniffer(q_packet, q_error):
        """always running packet sniffer that queues parsed packets after filtering"""
        global scapy
        import scapy
        from scapy.all import sniff
        error_counter = 0
        while True:
            try:
                sniff(count=0, prn=lambda x: q_packet.put(parse_packet(x)), lfilter=filter_packet)
            except PermissionError:
                q_error.put("sniffer permission error, it needs to run with sudo -E")
                break
            except Exception as e:
                q_error.put("sniffer exception: " + type(e).__name__ + str(e.args))
                error_counter += 1
                if error_counter >= 42:
                    break

    def sniffer_mon(q_packet, q_error, q_term):
        """monitor the sniffer and parent process, has same privileges as the sniffer for clean termination at the command or death of the parent"""
        import queue
        signal.signal(signal.SIGINT, lambda *args: None)
        p_sniff = multiprocessing.Process(name="pico-sniffer", target=sniffer, args=(q_packet, q_error), daemon=True)
        p_sniff.start()
        while True:
            try:
                if q_term.get(block=True, timeout=5):
                    break
            except queue.Empty:
                if not multiprocessing.parent_process().is_alive() or not p_sniff.is_alive():
                    break
        p_sniff.terminate()
        p_sniff.join(1)
        if p_sniff.is_alive():
            p_sniff.kill()
        p_sniff.close()
        return 0

    if __name__ == "__main__":
        q_packet = multiprocessing.Queue()
        q_error = multiprocessing.Queue()
        q_term = multiprocessing.Queue()
        p_sniff = multiprocessing.Process(name="pico-sniffermon", target=sniffer_mon, args=(q_packet, q_error, q_term))
        p_sniff.start()
        return p_sniff, q_packet, q_error, q_term


def main():
    """startup picosnitch as a daemon on posix systems, regular process otherwise, and ensure only one instance is running"""
    global filelock
    import filelock
    lock = filelock.FileLock(os.path.join(os.path.expanduser("~"), ".picosnitch_lock"), timeout=1)
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
            print("Warning: picosnitch is running in a virtual environment, notifications may not function", file=sys.stderr)
    if os.name == "posix":
        if os.path.expanduser("~") == "/root":
            print("Warning: picosnitch was run as root without preserving environment", file=sys.stderr)
        import daemon
        with daemon.DaemonContext():
            loop()
    else:
        loop()


if __name__ == "__main__":
    sys.exit(main())
