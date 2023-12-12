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

import collections
import importlib
import importlib.util
import ipaddress
import multiprocessing
import os
import pickle
import shlex
import sqlite3
import sys
import time
import typing

from .constants import BASE_PATH, VERSION
from .process_manager import ProcessManager
from .utils import get_sha256_fd, get_sha256_fuse, get_sha256_pid, reverse_dns_lookup


def secondary_subprocess_sha_wrapper(snitch: dict, fan_mod_cnt: dict, proc: dict, p_rfuse: ProcessManager, q_vt: multiprocessing.Queue, q_out: multiprocessing.Queue, q_error: multiprocessing.Queue) -> str:
    """get sha256 of executable and submit to primary_subprocess or virustotal_subprocess if necessary"""
    sha_fd_error = ""
    sha_pid_error = ""
    sha256 = get_sha256_fd(proc["fd"], proc["dev"], proc["ino"], fan_mod_cnt["%d %d" % (proc["dev"], proc["ino"])])
    if sha256.startswith("!"):
        # fallback on trying to read directly (if still alive) if fd_cache fails, probable causes include:
        # system suspends in the middle of hashing (since cache is reset)
        # process too short lived to open fd or stat in time (then fallback will fail too)
        # too many executables on system (see Set RLIMIT_NOFILE)
        sha_fd_error = sha256
        sha256 = get_sha256_pid(proc["pid"], proc["dev"], proc["ino"])
        if sha256.startswith("!"):
            # fallback to trying to read from fuse mount
            # this is meant for appimages that are run as the same user as the one running picosnitch, since they are not readable as root
            sha_pid_error = sha256
            sha256 = get_sha256_fuse(p_rfuse.q_in, p_rfuse.q_out, proc["fd"], proc["pid"], proc["dev"], proc["ino"], fan_mod_cnt["%d %d" % (proc["dev"], proc["ino"])])
            if sha256.startswith("!"):
                # notify user with what went wrong (may be cause for suspicion)
                sha256_error = sha_fd_error[4:] + " and " + sha_pid_error[4:] + " and " + sha256[4:]
                sha256 = sha_fd_error + " " + sha_pid_error + " " + sha256
                q_error.put(sha256_error + " for " + str(proc))
            elif proc["exe"] not in snitch["SHA256"] or sha256 not in snitch["SHA256"][proc["exe"]]:
                q_error.put("Fallback to FUSE hash successful on " + sha_fd_error[4:] + " and " + sha_pid_error[4:] + " for " + str(proc))
        elif proc["exe"] not in snitch["SHA256"] or sha256 not in snitch["SHA256"][proc["exe"]]:
            q_error.put("Fallback to PID hash successful on " + sha_fd_error[4:] + " for " + str(proc))
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


def secondary_subprocess_helper(snitch: dict, fan_mod_cnt: dict, new_processes: typing.List[bytes], p_rfuse: ProcessManager, q_vt: multiprocessing.Queue, q_out: multiprocessing.Queue, q_error: multiprocessing.Queue) -> typing.List[tuple]:
    """iterate over the list of process/connection data to generate a list of entries for the sql database"""
    datetime_now = time.strftime("%Y-%m-%d %H:%M:%S")
    traffic_counter = collections.defaultdict(int)
    transaction = set()
    for proc_pickle in new_processes:
        proc: BpfEvent = pickle.loads(proc_pickle)
        if type(proc) != dict:
            q_error.put("sync error between secondary and primary, received '%s' in middle of transfer" % str(proc))
            continue
        # get the sha256 of the process executable and its parent
        sha256 = secondary_subprocess_sha_wrapper(snitch, fan_mod_cnt, proc, p_rfuse, q_vt, q_out, q_error)
        pproc = {"pid": proc["ppid"], "name": proc["pname"], "exe": proc["pexe"], "fd": proc["pfd"], "dev": proc["pdev"], "ino": proc["pino"]}
        psha256 = secondary_subprocess_sha_wrapper(snitch, fan_mod_cnt, pproc, p_rfuse, q_vt, q_out, q_error)
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
                proc["domain"] = reverse_dns_lookup(proc["raddr"])
        else:
            proc["domain"], proc["raddr"] = "", ""
        if not snitch["Config"]["Log ports"]:
            proc["lport"] = min(0, proc["lport"])
            proc["rport"] = min(0, proc["rport"])
        # omit entry from logs
        ignored = False
        for ignore in snitch["Config"]["Log ignore"]:
            if ((proc["rport"] == ignore) or
                (proc["lport"] == ignore) or
                (sha256 == ignore) or
                (type(ignore) == str and proc["domain"].startswith(ignore))
               ):
                ignored = True
                break
        if ignored:
            continue
        if snitch["Config"]["Log ignore IP"] and proc["raddr"]:
            raddr = ipaddress.ip_address(proc["raddr"])
            if (any(raddr in network for network in snitch["Config"]["Log ignore IP"])):
                continue
            laddr = ipaddress.ip_address(proc["laddr"])
            if (any(laddr in network for network in snitch["Config"]["Log ignore IP"])):
                continue
        # create sql entry
        event = (proc["exe"], proc["name"], proc["cmdline"], sha256, proc["pexe"], proc["pname"], proc["pcmdline"], psha256, proc["uid"], proc["lport"], proc["rport"], proc["laddr"], proc["raddr"], proc["domain"])
        traffic_counter["send " + str(event)] += proc["send"]
        traffic_counter["recv " + str(event)] += proc["recv"]
        transaction.add(event)
    return [(datetime_now, traffic_counter["send " + str(event)], traffic_counter["recv " + str(event)], *event) for event in transaction]



def secondary_subprocess(snitch, fan_fd, p_rfuse: ProcessManager, p_virustotal: ProcessManager, secondary_pipe, q_primary_in, q_error, _q_in, _q_out):
    """second to receive connection data from monitor, less responsive than primary, coordinates connection data with virustotal subprocess and checks fanotify, updates connection logs and reports sha256/vt_results back to primary_subprocess if needed"""
    parent_process = multiprocessing.parent_process()
    # maintain a separate copy of the snitch dictionary here and coordinate with the primary_subprocess (sha256 and vt_results)
    get_vt_results(snitch, p_virustotal.q_in, q_primary_in, True)
    # init sql
    # (contime text, send integer, recv integer, exe text, name text, cmdline text, sha256 text, pexe text, pname text, pcmdline text, psha256 text, uid integer, lport integer, rport integer, laddr text, raddr text, domain text)
    # (datetime_now, traffic_counter["send " + str(event)], traffic_counter["recv " + str(event)], *(proc["exe"], proc["name"], proc["cmdline"], sha256, proc["pexe"], proc["pname"], proc["pcmdline"], psha256, proc["uid"], proc["lport"], proc["rport"], proc["laddr"], proc["raddr"], proc["domain"]))
    sqlite_query = ''' INSERT INTO connections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) '''
    file_path = os.path.join(BASE_PATH, "snitch.db")
    text_path = os.path.join(BASE_PATH, "conn.log")
    if snitch["Config"]["DB sql log"]:
        con = sqlite3.connect(file_path)
        cur = con.cursor()
        cur.execute(''' PRAGMA user_version ''')
        assert cur.fetchone()[0] == 3, f"Incorrect database version of snitch.db for picosnitch v{VERSION}"
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
                transaction += secondary_subprocess_helper(snitch, fan_mod_cnt, new_processes, p_rfuse, p_virustotal.q_in, q_primary_in, q_error)
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

