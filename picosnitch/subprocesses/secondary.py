# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import collections
import importlib
import ipaddress
import logging
import multiprocessing
import multiprocessing.connection
import pickle
import shlex
import sqlite3
import sys
import time

from ..config import Config
from ..constants import DATA_DIR, DB_VERSION, LOG_DIR, VERSION
from ..process_manager import ProcessManager
from ..types import BpfEvent, ProcessHashInfo, State
from ..utils import get_fanotify_events, get_sha256_fd, get_sha256_fuse, get_sha256_pid, reverse_dns_lookup, sync_vt_results


def resolve_hash(
    state: State,
    fan_mod_cnt: dict[str, int],
    proc: ProcessHashInfo,
    p_fuse: ProcessManager,
    q_vt: multiprocessing.Queue[bytes],
    q_out: multiprocessing.Queue[bytes],
    q_error: multiprocessing.Queue[str],
) -> str:
    """get sha256 of executable and submit to primary or virustotal subprocess if necessary"""
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
            sha256 = get_sha256_fuse(p_fuse.q_in, p_fuse.q_out, proc["fd"], proc["pid"], proc["dev"], proc["ino"], fan_mod_cnt["%d %d" % (proc["dev"], proc["ino"])])
            if sha256.startswith("!"):
                # notify user with what went wrong (may be cause for suspicion)
                sha256_error = sha_fd_error[4:] + " and " + sha_pid_error[4:] + " and " + sha256[4:]
                sha256 = sha_fd_error + " " + sha_pid_error + " " + sha256
                q_error.put(sha256_error + " for " + str(proc))
            elif proc["exe"] not in state["SHA256"] or sha256 not in state["SHA256"][proc["exe"]]:
                q_error.put("Fallback to FUSE hash successful on " + sha_fd_error[4:] + " and " + sha_pid_error[4:] + " for " + str(proc))
        elif proc["exe"] not in state["SHA256"] or sha256 not in state["SHA256"][proc["exe"]]:
            q_error.put("Fallback to PID hash successful on " + sha_fd_error[4:] + " for " + str(proc))
    if proc["exe"] in state["SHA256"]:
        if sha256 not in state["SHA256"][proc["exe"]]:
            state["SHA256"][proc["exe"]][sha256] = "SUBMITTED"
            q_vt.put(pickle.dumps((proc, sha256)))
            q_out.put(pickle.dumps({"type": "sha256", "name": proc["name"], "exe": proc["exe"], "sha256": sha256}))
        elif state["SHA256"][proc["exe"]][sha256] == "Failed to read process for upload":
            state["SHA256"][proc["exe"]][sha256] = "RETRY"
            q_vt.put(pickle.dumps((proc, sha256)))
    else:
        state["SHA256"][proc["exe"]] = {sha256: "SUBMITTED"}
        q_vt.put(pickle.dumps((proc, sha256)))
        q_out.put(pickle.dumps({"type": "sha256", "name": proc["name"], "exe": proc["exe"], "sha256": sha256}))
    return sha256


def build_log_entries(
    config: Config,
    state: State,
    fan_mod_cnt: dict[str, int],
    new_processes: list[bytes],
    p_fuse: ProcessManager,
    q_vt: multiprocessing.Queue[bytes],
    q_out: multiprocessing.Queue[bytes],
    q_error: multiprocessing.Queue[str],
    ignored_networks: list,
) -> list[tuple]:
    """iterate over the list of process/connection data to generate a list of entries for the sql database"""
    datetime_now = int(time.time())
    traffic_counter: dict[tuple, list[int]] = {}
    for proc_pickle in new_processes:
        proc: BpfEvent = pickle.loads(proc_pickle)
        if not isinstance(proc, dict):
            q_error.put("sync error between secondary and primary, received '%s' in middle of transfer" % str(proc))
            continue
        # get the sha256 of the process executable and its parent
        sha256 = resolve_hash(state, fan_mod_cnt, proc, p_fuse, q_vt, q_out, q_error)
        pproc: ProcessHashInfo = {"pid": proc["ppid"], "name": proc["pname"], "exe": proc["pexe"], "fd": proc["pfd"], "dev": proc["pdev"], "ino": proc["pino"]}
        psha256 = resolve_hash(state, fan_mod_cnt, pproc, p_fuse, q_vt, q_out, q_error)
        # join or omit commands from logs
        if config.log.commands:
            proc["cmdline"] = shlex.join(proc["cmdline"].encode("utf-8", "ignore").decode("utf-8", "ignore").strip("\0\t\n ").split("\0"))
            proc["pcmdline"] = shlex.join(proc["pcmdline"].encode("utf-8", "ignore").decode("utf-8", "ignore").strip("\0\t\n ").split("\0"))
        else:
            proc["cmdline"] = ""
            proc["pcmdline"] = ""
        # reverse dns lookup or omit with IP from logs
        if config.log.addresses:
            if not proc["domain"]:
                proc["domain"] = reverse_dns_lookup(proc["raddr"])
        else:
            proc["domain"], proc["raddr"] = "", ""
        if not config.log.ports:
            proc["lport"] = min(0, proc["lport"])
            proc["rport"] = min(0, proc["rport"])
        # omit entry from logs
        ignored = False
        if proc["rport"] in config.log.ignore_ports or proc["lport"] in config.log.ignore_ports:
            ignored = True
        if not ignored and sha256 in config.log.ignore_sha256:
            ignored = True
        if not ignored:
            for domain_prefix in config.log.ignore_domains:
                if proc["domain"].startswith(domain_prefix):
                    ignored = True
                    break
        if ignored:
            continue
        if ignored_networks and proc["raddr"]:
            raddr = ipaddress.ip_address(proc["raddr"])
            if any(raddr in network for network in ignored_networks):
                continue
            laddr = ipaddress.ip_address(proc["laddr"])
            if any(laddr in network for network in ignored_networks):
                continue
        # create sql entry (exe info as tuples for normalization, connection-specific fields)
        exe_key = (proc["exe"], proc["name"], proc["cmdline"], sha256)
        pexe_key = (proc["pexe"], proc["pname"], proc["pcmdline"], psha256)
        event = (
            exe_key,
            pexe_key,
            proc["uid"],
            proc["lport"],
            proc["rport"],
            proc["laddr"],
            proc["raddr"],
            proc["domain"],
        )
        if event in traffic_counter:
            traffic_counter[event][0] += proc["send"]
            traffic_counter[event][1] += proc["recv"]
        else:
            traffic_counter[event] = [proc["send"], proc["recv"]]
    return [(datetime_now, send, recv, *event) for event, (send, recv) in traffic_counter.items()]


def run_secondary(
    config: Config,
    state: State,
    fan_fd: int,
    p_fuse: ProcessManager,
    p_virustotal: ProcessManager,
    secondary_pipe: multiprocessing.connection.Connection,
    q_primary_in: multiprocessing.Queue[bytes],
    q_error: multiprocessing.Queue[str],
    _q_in: multiprocessing.Queue,
    _q_out: multiprocessing.Queue,
) -> int:
    """second to receive connection data from monitor, less responsive than primary, coordinates connection data with virustotal subprocess and checks fanotify, updates connection logs and reports sha256/vt_results back to primary subprocess if needed"""
    parent_process = multiprocessing.parent_process()
    # maintain a separate copy of the state dictionary here and coordinate with the primary subprocess (sha256 and vt_results)
    sync_vt_results(state, p_virustotal.q_in, q_primary_in, True)
    # init sql
    # connections: (contime integer, send integer, recv integer, exe_id integer, pexe_id integer, uid integer, lport integer, rport integer, laddr text, raddr text, domain text)
    # executables: (id integer primary key, exe text, name text, cmdline text, sha256 text)
    sqlite_insert_exe = "INSERT OR IGNORE INTO executables(exe, name, cmdline, sha256) VALUES (?, ?, ?, ?)"
    sqlite_select_exe = "SELECT id FROM executables WHERE exe = ? AND name = ? AND cmdline = ? AND sha256 = ?"
    sqlite_insert_conn = "INSERT INTO connections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    file_path = DATA_DIR / "picosnitch.db"
    text_path = LOG_DIR / "conn.log"
    exe_id_cache: dict[tuple, int] = {}
    if config.database.enabled:
        con = sqlite3.connect(file_path)
        cur = con.cursor()
        cur.execute(""" PRAGMA user_version """)
        db_version = cur.fetchone()[0]
        if db_version != DB_VERSION:
            logging.error(f"Incorrect database version of picosnitch.db for picosnitch v{VERSION}")
            sys.exit(1)
        retention_cutoff = int(time.time()) - int(config.database.retention_days) * 86400
        cur.execute("DELETE FROM connections WHERE contime < ?", (retention_cutoff,))
        con.commit()
        con.close()
    if sql_kwargs := dict(config.database.remote):
        sql_client = sql_kwargs.pop("client", "no client error")
        conn_table = sql_kwargs.pop("connections_table", "connections")
        exe_table = sql_kwargs.pop("executables_table", "executables")
        sql = importlib.import_module(sql_client)
        sql_insert_exe = sqlite_insert_exe.replace("?", "%s").replace("OR IGNORE ", "IGNORE ").replace("executables", exe_table)
        sql_select_exe = sqlite_select_exe.replace("?", "%s").replace("executables", exe_table)
        sql_insert_conn = sqlite_insert_conn.replace("?", "%s").replace("connections", conn_table)
    log_destinations = int(bool(config.database.enabled)) + int(bool(sql_kwargs)) + int(bool(config.database.text_log))
    # init fanotify mod counter = {"st_dev st_ino": modify_count}, and traffic counter = {"send|recv pid socket_ino": bytes}
    fan_mod_cnt = collections.defaultdict(int)
    # get network address and mask for ignored IP subnets
    ignored_networks = [ipaddress.ip_network(ip_subnet) for ip_subnet in config.log.ignore_ips]

    # resolve exe tuples to IDs with caching
    def resolve_exe_id(con: sqlite3.Connection, exe_key: tuple) -> int:
        if exe_key in exe_id_cache:
            return exe_id_cache[exe_key]
        con.execute(sqlite_insert_exe, exe_key)
        row = con.execute(sqlite_select_exe, exe_key).fetchone()
        exe_id_cache[exe_key] = row[0]
        return row[0]

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
                if isinstance(pickle.loads(first_pickle), int):
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
                    new_processes.pop()
                    transfer_size += 1
                    break
                elif timeout_counter > 30:
                    q_error.put("sync error between secondary and primary on receive (did not receive done)")
            if transfer_size > 0:
                q_error.put("sync error between secondary and primary on receive (did not receive all messages)")
            elif transfer_size < 0:
                q_error.put("sync error between secondary and primary on receive (received extra messages)")
            # check for other pending data (vt, fanotify)
            sync_vt_results(state, p_virustotal.q_out, q_primary_in, False)
            get_fanotify_events(fan_fd, fan_mod_cnt, q_error)
            # process connection data
            if time.time() - last_write > config.database.write_limit_seconds and (transaction or new_processes):
                current_write = time.time()
                transaction += build_log_entries(config, state, fan_mod_cnt, new_processes, p_fuse, p_virustotal.q_in, q_primary_in, q_error, ignored_networks)
                new_processes = []
                transaction_success = False
                try:
                    if config.database.enabled:
                        con = sqlite3.connect(file_path)
                        with con:
                            conn_rows = []
                            for contime, send, recv, exe_key, pexe_key, uid, lport, rport, laddr, raddr, domain in transaction:
                                exe_id = resolve_exe_id(con, exe_key)
                                pexe_id = resolve_exe_id(con, pexe_key)
                                conn_rows.append((contime, send, recv, exe_id, pexe_id, uid, lport, rport, laddr, raddr, domain))
                            con.executemany(sqlite_insert_conn, conn_rows)
                        con.close()
                        transaction_success = True
                except Exception as e:
                    q_error.put("SQLite execute %s%s on line %s, lost %s entries" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno, len(transaction)))
                try:
                    if sql_kwargs:
                        con = sql.connect(**sql_kwargs)
                        with con.cursor() as cur:
                            conn_rows = []
                            for contime, send, recv, exe_key, pexe_key, uid, lport, rport, laddr, raddr, domain in transaction:
                                cur.execute(sql_insert_exe, exe_key)
                                cur.execute(sql_select_exe, exe_key)
                                exe_id = cur.fetchone()[0]
                                cur.execute(sql_insert_exe, pexe_key)
                                cur.execute(sql_select_exe, pexe_key)
                                pexe_id = cur.fetchone()[0]
                                conn_rows.append((contime, send, recv, exe_id, pexe_id, uid, lport, rport, laddr, raddr, domain))
                            cur.executemany(sql_insert_conn, conn_rows)
                        con.commit()
                        con.close()
                        transaction_success = True
                except Exception as e:
                    q_error.put("SQL server execute %s%s on line %s, lost %s entries" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno, len(transaction)))
                try:
                    if config.database.text_log:
                        with open(text_path, "a", encoding="utf-8", errors="surrogateescape") as text_file:
                            for contime, send, recv, exe_key, pexe_key, uid, lport, rport, laddr, raddr, domain in transaction:
                                flat = (contime, send, recv, *exe_key, *pexe_key, uid, lport, rport, laddr, raddr, domain)
                                clean_entry = [str(value).replace(",", "").replace("\n", "").replace("\0", "") for value in flat]
                                clean_entry[0] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(contime))
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
