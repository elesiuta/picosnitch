# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import importlib
import multiprocessing
import os
import pickle
import pwd
import queue
import re

from picosnitch.config import Config
from picosnitch.constants import SCHEMA_ADDRESSES, SCHEMA_CONNECTIONS, SCHEMA_DOMAINS, SCHEMA_EXECUTABLES


def create_tables(con, conn_table: str) -> None:
    """create the remote tables if missing (SQL server dialect tweaks on the sqlite schema)"""
    cur = con.cursor()
    remote_exe_schema = SCHEMA_EXECUTABLES.replace("INTEGER PRIMARY KEY", "INTEGER PRIMARY KEY AUTO_INCREMENT").replace(
        "UNIQUE(exe, name, cmdline, sha256)", "UNIQUE(exe(255), name(255), cmdline(255), sha256(64))"
    )
    remote_dom_schema = SCHEMA_DOMAINS.replace("INTEGER PRIMARY KEY", "INTEGER PRIMARY KEY AUTO_INCREMENT").replace("domain TEXT NOT NULL UNIQUE", "domain VARCHAR(255) NOT NULL UNIQUE")
    remote_addr_schema = SCHEMA_ADDRESSES.replace("INTEGER PRIMARY KEY", "INTEGER PRIMARY KEY AUTO_INCREMENT").replace("addr TEXT NOT NULL UNIQUE", "addr VARCHAR(64) NOT NULL UNIQUE")
    cur.execute(f"CREATE TABLE IF NOT EXISTS executables ({remote_exe_schema})")
    cur.execute(f"CREATE TABLE IF NOT EXISTS domains ({remote_dom_schema})")
    cur.execute(f"CREATE TABLE IF NOT EXISTS addresses ({remote_addr_schema})")
    cur.execute(f"CREATE TABLE IF NOT EXISTS {conn_table} ({SCHEMA_CONNECTIONS})")
    con.commit()


def insert_entries(con, conn_table: str, entries: list[tuple]) -> None:
    """resolve normalized ids and insert each connection entry (INSERT only, %s paramstyle)"""
    sql_insert_exe = "INSERT IGNORE INTO executables(exe, name, cmdline, sha256) VALUES (%s, %s, %s, %s)"
    sql_select_exe = "SELECT id FROM executables WHERE exe = %s AND name = %s AND cmdline = %s AND sha256 = %s"
    sql_insert_dom = "INSERT IGNORE INTO domains(domain) VALUES (%s)"
    sql_select_dom = "SELECT id FROM domains WHERE domain = %s"
    sql_insert_addr = "INSERT IGNORE INTO addresses(addr) VALUES (%s)"
    sql_select_addr = "SELECT id FROM addresses WHERE addr = %s"
    sql_insert_conn = f"INSERT INTO {conn_table} VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    with con.cursor() as cur:
        conn_rows = []
        for contime, send, recv, n_events, exe_key, pexe_key, gpexe_key, uid, family, protocol, lport, rport, laddr, raddr, domain, netns in entries:
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


def run_remote_sql(config: Config, fan_fd: int, q_error: multiprocessing.Queue[str], q_in: multiprocessing.Queue[bytes], _q_out: multiprocessing.Queue) -> int:
    """writes connection log entries from secondary to the remote SQL server ([database.remote]),
    runs without root so third-party database drivers are never imported by a root process"""
    parent_process = multiprocessing.parent_process()
    assert parent_process is not None
    # drop root (desktop.user, or nobody) before importing or running any third-party code
    from ..utils import drop_root_permanent, resolve_group, resolve_owner

    if config.desktop.user:
        uid, gid = resolve_owner(config.desktop.user), resolve_group(config.desktop.user)
    else:
        try:
            uid, gid = pwd.getpwnam("nobody").pw_uid, pwd.getpwnam("nobody").pw_gid
        except KeyError:
            uid, gid = 65534, 65534
    drop_root_permanent(uid, gid)
    # fan_fd is inherited via fork() but never used here; close it so a privileged
    # fanotify handle doesn't leak into a dropped-privilege security domain
    try:
        os.close(fan_fd)
    except OSError:
        pass
    # config was validated loudly by check_remote_config at start; revalidate before use
    # (defense in depth) but only report and idle, never crash-loop the daemon
    sql = None
    sql_kwargs = dict(config.database.remote)
    sql_client = sql_kwargs.pop("client", "no client error")
    conn_table = sql_kwargs.pop("connections_table", "connections")
    if config.database.remote:
        if sql_client not in ["mariadb", "psycopg", "psycopg2", "pymysql"]:
            q_error.put(f'unsupported database.remote "client": {sql_client}')
        elif not isinstance(conn_table, str) or not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", conn_table):
            q_error.put(f"invalid remote table name: {conn_table!r}")
        else:
            try:
                sql = importlib.import_module(sql_client)
            except ImportError:
                q_error.put(f'database.remote "client" {sql_client} is not installed, remote logging disabled')
        if sql is not None and not any(k in sql_kwargs for k in ("ssl", "ssl_context", "sslmode", "ssl_mode")):
            q_error.put("warning: remote database connection has no SSL/TLS parameters configured")
    tables_ready = False
    while True:
        if not parent_process.is_alive():
            return 0
        entries: list[tuple] = []
        try:
            # timeout so the parent-alive check above runs even when idle
            entries = pickle.loads(q_in.get(block=True, timeout=15))
            if sql is None:
                continue
            con = sql.connect(**sql_kwargs)
            if not tables_ready:
                create_tables(con, conn_table)
                tables_ready = True
            insert_entries(con, conn_table, entries)
            con.close()
        except queue.Empty:
            pass
        except Exception as e:
            q_error.put("SQL server execute %s%s on line %s, lost %s entries" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?", len(entries)))
