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
import re
import shlex
import sqlite3
import sys
import time

from picosnitch.config import Config
from picosnitch.constants import DATA_DIR, DB_VERSION, LOG_DIR, VERSION
from picosnitch.process_manager import ProcessManager
from picosnitch.types import BpfEvent, ProcessHashInfo, State
from picosnitch.utils import get_fanotify_events, get_sha256_fd, get_sha256_fuse, get_sha256_pid, reverse_dns_lookup, safe_log_open, sync_vt_results


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
    # short-circuit when there is no executable to hash (e.g. kernel grandparent /
    # init's parent, daemons whose parent walk hits PID 0 / swapper, or events
    # where /proc readability was lost). returning "" produces a stable
    # ("", "", "", "") executables row instead of spamming hash-failure
    # toasts and polluting the DB with garbage sha256 values.
    if not proc["exe"] or proc["pid"] <= 0:
        return ""
    sha_fd_error = ""
    sha_pid_error = ""
    sha256 = get_sha256_fd(proc["fd"], proc["dev"], proc["ino"], fan_mod_cnt["%d %d" % (proc["dev"], proc["ino"])])
    if sha256.startswith("!"):
        # fallback on trying to read directly (if still alive) if fd_cache fails, probable causes include:
        # system suspends in the middle of hashing (since cache is reset)
        # process too short lived to open fd or stat in time (then fallback will fail too)
        # too many executables on system (see [monitoring].rlimit_nofile)
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
        # get the sha256 of the process executable, parent, and grandparent
        sha256 = resolve_hash(state, fan_mod_cnt, proc, p_fuse, q_vt, q_out, q_error)
        pproc: ProcessHashInfo = {"pid": proc["ppid"], "name": proc["pname"], "exe": proc["pexe"], "fd": proc["pfd"], "dev": proc["pdev"], "ino": proc["pino"]}
        psha256 = resolve_hash(state, fan_mod_cnt, pproc, p_fuse, q_vt, q_out, q_error)
        gpproc: ProcessHashInfo = {"pid": proc["gppid"], "name": proc["gpname"], "exe": proc["gpexe"], "fd": proc["gpfd"], "dev": proc["gpdev"], "ino": proc["gpino"]}
        gpsha256 = resolve_hash(state, fan_mod_cnt, gpproc, p_fuse, q_vt, q_out, q_error)
        # join or omit commands from logs
        if config.log.commands:
            proc["cmdline"] = shlex.join(proc["cmdline"].encode("utf-8", "ignore").decode("utf-8", "ignore").strip("\0\t\n ").split("\0"))
            proc["pcmdline"] = shlex.join(proc["pcmdline"].encode("utf-8", "ignore").decode("utf-8", "ignore").strip("\0\t\n ").split("\0"))
            proc["gpcmdline"] = shlex.join(proc["gpcmdline"].encode("utf-8", "ignore").decode("utf-8", "ignore").strip("\0\t\n ").split("\0"))
        else:
            proc["cmdline"] = ""
            proc["pcmdline"] = ""
            proc["gpcmdline"] = ""
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
        gpexe_key = (proc["gpexe"], proc["gpname"], proc["gpcmdline"], gpsha256)
        event = (
            exe_key,
            pexe_key,
            gpexe_key,
            proc["uid"],
            int(proc.get("family", 0) or 0),
            int(proc.get("protocol", 0) or 0),
            proc["lport"],
            proc["rport"],
            proc["laddr"],
            proc["raddr"],
            proc["domain"],
            int(proc.get("netns", 0) or 0),
        )
        if event in traffic_counter:
            traffic_counter[event][0] += proc["send"]
            traffic_counter[event][1] += proc["recv"]
            traffic_counter[event][2] += proc.get("pkts", 1)
        else:
            traffic_counter[event] = [proc["send"], proc["recv"], proc.get("pkts", 1)]
    return [(datetime_now, send, recv, n_events, *event) for event, (send, recv, n_events) in traffic_counter.items()]


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
    assert parent_process is not None
    # maintain a separate copy of the state dictionary here and coordinate with the primary subprocess (sha256 and vt_results)
    sync_vt_results(state, p_virustotal.q_in, q_primary_in, True)
    # init sql
    # connections columns: contime, send, recv, events, exe_id, pexe_id, gpexe_id, uid,
    # family, protocol, lport, rport, laddr_id, raddr_id, domain_id, netns  (16 cols).
    # executables: (id, exe, name, cmdline, sha256). domains/addresses: (id, value).
    sqlite_insert_exe = "INSERT OR IGNORE INTO executables(exe, name, cmdline, sha256) VALUES (?, ?, ?, ?)"
    sqlite_select_exe = "SELECT id FROM executables WHERE exe = ? AND name = ? AND cmdline = ? AND sha256 = ?"
    sqlite_insert_dom = "INSERT OR IGNORE INTO domains(domain) VALUES (?)"
    sqlite_select_dom = "SELECT id FROM domains WHERE domain = ?"
    sqlite_insert_addr = "INSERT OR IGNORE INTO addresses(addr) VALUES (?)"
    sqlite_select_addr = "SELECT id FROM addresses WHERE addr = ?"
    sqlite_insert_conn = "INSERT INTO connections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    file_path = DATA_DIR / "picosnitch.db"
    text_path = LOG_DIR / "conn.log"
    exe_id_cache: dict[tuple, int] = {}
    domain_id_cache: dict[str, int] = {"": 0}
    addr_id_cache: dict[str, int] = {"": 0}
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
        cur.execute("DELETE FROM domains WHERE id != 0 AND id NOT IN (SELECT DISTINCT domain_id FROM connections)")
        cur.execute("DELETE FROM addresses WHERE id != 0 AND id NOT IN (SELECT DISTINCT laddr_id FROM connections UNION SELECT DISTINCT raddr_id FROM connections)")
        con.commit()
        con.close()
    if sql_kwargs := dict(config.database.remote):
        sql_client = sql_kwargs.pop("client", "no client error")
        conn_table = sql_kwargs.pop("connections_table", "connections")
        if sql_client not in ["mariadb", "psycopg", "psycopg2", "pymysql"]:
            q_error.put(f'unsupported database.remote "client": {sql_client}')
            sql_kwargs = {}
        elif not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", conn_table):
            q_error.put(f"invalid remote table name: {conn_table!r}")
            sql_kwargs = {}
        else:
            sql = importlib.import_module(sql_client)
            sql_insert_exe = sqlite_insert_exe.replace("?", "%s").replace("OR IGNORE ", "IGNORE ")
            sql_select_exe = sqlite_select_exe.replace("?", "%s")
            sql_insert_dom = sqlite_insert_dom.replace("?", "%s").replace("OR IGNORE ", "IGNORE ")
            sql_select_dom = sqlite_select_dom.replace("?", "%s")
            sql_insert_addr = sqlite_insert_addr.replace("?", "%s").replace("OR IGNORE ", "IGNORE ")
            sql_select_addr = sqlite_select_addr.replace("?", "%s")
            sql_insert_conn = sqlite_insert_conn.replace("?", "%s").replace("connections", conn_table)
            if not any(k in sql_kwargs for k in ("ssl", "ssl_context", "sslmode", "ssl_mode")):
                q_error.put("warning: remote database connection has no SSL/TLS parameters configured")
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

    def resolve_domain_id(con: sqlite3.Connection, domain: str) -> int:
        if domain in domain_id_cache:
            return domain_id_cache[domain]
        con.execute(sqlite_insert_dom, (domain,))
        row = con.execute(sqlite_select_dom, (domain,)).fetchone()
        domain_id_cache[domain] = row[0]
        return row[0]

    def resolve_addr_id(con: sqlite3.Connection, addr: str) -> int:
        if addr in addr_id_cache:
            return addr_id_cache[addr]
        con.execute(sqlite_insert_addr, (addr,))
        row = con.execute(sqlite_select_addr, (addr,)).fetchone()
        addr_id_cache[addr] = row[0]
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
                            for contime, send, recv, n_events, exe_key, pexe_key, gpexe_key, uid, family, protocol, lport, rport, laddr, raddr, domain, netns in transaction:
                                exe_id = resolve_exe_id(con, exe_key)
                                pexe_id = resolve_exe_id(con, pexe_key)
                                gpexe_id = resolve_exe_id(con, gpexe_key)
                                laddr_id = resolve_addr_id(con, laddr)
                                raddr_id = resolve_addr_id(con, raddr)
                                domain_id = resolve_domain_id(con, domain)
                                conn_rows.append((contime, send, recv, n_events, exe_id, pexe_id, gpexe_id, uid, family, protocol, lport, rport, laddr_id, raddr_id, domain_id, netns))
                            con.executemany(sqlite_insert_conn, conn_rows)
                        con.close()
                        transaction_success = True
                except Exception as e:
                    q_error.put("SQLite execute %s%s on line %s, lost %s entries" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?", len(transaction)))
                try:
                    if sql_kwargs:
                        con = sql.connect(**sql_kwargs)
                        with con.cursor() as cur:
                            conn_rows = []
                            for contime, send, recv, n_events, exe_key, pexe_key, gpexe_key, uid, family, protocol, lport, rport, laddr, raddr, domain, netns in transaction:
                                cur.execute(sql_insert_exe, exe_key)
                                cur.execute(sql_select_exe, exe_key)
                                exe_id = cur.fetchone()[0]
                                cur.execute(sql_insert_exe, pexe_key)
                                cur.execute(sql_select_exe, pexe_key)
                                pexe_id = cur.fetchone()[0]
                                cur.execute(sql_insert_exe, gpexe_key)
                                cur.execute(sql_select_exe, gpexe_key)
                                gpexe_id = cur.fetchone()[0]
                                cur.execute(sql_insert_addr, (laddr,))
                                cur.execute(sql_select_addr, (laddr,))
                                laddr_id = cur.fetchone()[0]
                                cur.execute(sql_insert_addr, (raddr,))
                                cur.execute(sql_select_addr, (raddr,))
                                raddr_id = cur.fetchone()[0]
                                cur.execute(sql_insert_dom, (domain,))
                                cur.execute(sql_select_dom, (domain,))
                                domain_id = cur.fetchone()[0]
                                conn_rows.append((contime, send, recv, n_events, exe_id, pexe_id, gpexe_id, uid, family, protocol, lport, rport, laddr_id, raddr_id, domain_id, netns))
                            cur.executemany(sql_insert_conn, conn_rows)
                        con.commit()
                        con.close()
                        transaction_success = True
                except Exception as e:
                    q_error.put("SQL server execute %s%s on line %s, lost %s entries" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?", len(transaction)))
                try:
                    if config.database.text_log:
                        with safe_log_open(text_path) as text_file:
                            for contime, send, recv, n_events, exe_key, pexe_key, gpexe_key, uid, family, protocol, lport, rport, laddr, raddr, domain, netns in transaction:
                                flat = (contime, send, recv, n_events, *exe_key, *pexe_key, *gpexe_key, uid, family, protocol, lport, rport, laddr, raddr, domain, netns)
                                clean_entry = [str(value).replace(",", "").replace("\n", "").replace("\0", "") for value in flat]
                                clean_entry[0] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(contime))
                                text_file.write(",".join(clean_entry) + "\n")
                        transaction_success = True
                except Exception as e:
                    q_error.put("text log %s%s on line %s, lost %s entries" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?", len(transaction)))
                if transaction_success or log_destinations == 0:
                    transaction = []
                else:
                    q_error.put("secondary subprocess all log desinations failed, will retry %s entries with next write" % (len(transaction)))
                last_write = current_write
        except Exception as e:
            q_error.put("secondary subprocess %s%s on line %s" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?"))
