# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""Tests for the remote SQL path: loud config validation at the cli entry point (no
third-party import as root), and the unprivileged writer's id-resolve/insert logic."""

import importlib.util
import sqlite3

import pytest

from picosnitch.cli import check_remote_config
from picosnitch.constants import SCHEMA_ADDRESSES, SCHEMA_CONNECTIONS, SCHEMA_DOMAINS, SCHEMA_EXECUTABLES
from picosnitch.subprocesses.remote_sql import insert_entries, remote_dialect


def test_check_remote_config_fails_loudly(monkeypatch):
    """`picosnitch start` must abort (return 1) on a bad [database.remote], and must
    validate without importing the driver (only find_spec, which runs no driver code)."""
    assert check_remote_config({}) == 0  # remote not configured
    assert check_remote_config({"client": "bogus"}) == 1  # unsupported client
    assert check_remote_config({"client": "pymysql", "connections_table": 5}) == 1  # non-string table
    assert check_remote_config({"client": "pymysql", "connections_table": "bad-name"}) == 1  # invalid table
    assert check_remote_config({"client": "pymysql"}) == 1  # driver not installed
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: object())  # driver installed
    assert check_remote_config({"client": "pymysql", "connections_table": "conns", "host": "h"}) == 0


def test_remote_dialect():
    """client name -> (is_postgres, placeholder); mariadb's connector is qmark."""
    assert remote_dialect("pymysql") == (False, "%s")
    assert remote_dialect("mariadb") == (False, "?")
    assert remote_dialect("psycopg") == (True, "%s")
    assert remote_dialect("psycopg2") == (True, "%s")


class FakeCursor:
    """DBAPI-ish cursor backed by sqlite: translates the %s paramstyle and MySQL
    INSERT IGNORE so insert_entries can be exercised without a real SQL server.
    sqlite natively understands `?`, `INSERT OR IGNORE`, and `ON CONFLICT DO
    NOTHING`, so both the MySQL and Postgres statement shapes run against it."""

    def __init__(self, cur):
        self.cur = cur

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def _translate(self, sql: str) -> str:
        return sql.replace("%s", "?").replace("INSERT IGNORE", "INSERT OR IGNORE")

    def execute(self, sql, params=()):
        self.cur.execute(self._translate(sql), params)

    def executemany(self, sql, rows):
        self.cur.executemany(self._translate(sql), rows)

    def fetchone(self):
        return self.cur.fetchone()


class FakeCon:
    def __init__(self, con):
        self.con = con

    def cursor(self):
        return FakeCursor(self.con.cursor())

    def commit(self):
        self.con.commit()


@pytest.mark.parametrize("is_postgres, ph", [(False, "%s"), (False, "?"), (True, "%s")])
def test_insert_entries_resolves_ids(is_postgres, ph):
    """entries from build_log_entries land as normalized rows: shared exe/domain/addr
    values resolve to the same interned id, connections reference them correctly.
    Runs for each dialect/paramstyle shape (pymysql, mariadb, psycopg). send/recv
    and netns carry values past 2**31 to exercise the BIGINT columns."""
    con = sqlite3.connect(":memory:")
    con.execute(f"CREATE TABLE executables ({SCHEMA_EXECUTABLES})")
    con.execute(f"CREATE TABLE domains ({SCHEMA_DOMAINS})")
    con.execute(f"CREATE TABLE addresses ({SCHEMA_ADDRESSES})")
    con.execute(f"CREATE TABLE connections ({SCHEMA_CONNECTIONS})")
    curl = ("/usr/bin/curl", "curl", "curl example.com", "a" * 64)
    bash = ("/usr/bin/bash", "bash", "bash", "b" * 64)
    entries = [
        (1000, 5_000_000_000, 6_000_000_000, 1, curl, bash, bash, 1000, 2, 6, 40000, 443, "10.0.0.2", "93.184.216.34", "example.com", 4026531840),
        (1005, 10, 20, 2, curl, bash, bash, 1000, 2, 6, 40001, 80, "10.0.0.2", "93.184.216.34", "example.com", 4026531840),
    ]
    insert_entries(FakeCon(con), "connections", entries, is_postgres, ph)
    insert_entries(FakeCon(con), "connections", entries, is_postgres, ph)  # dedup: reference tables must not grow
    assert con.execute("SELECT COUNT(*) FROM executables").fetchone()[0] == 2  # curl + bash interned once
    assert con.execute("SELECT COUNT(*) FROM addresses").fetchone()[0] == 2
    assert con.execute("SELECT COUNT(*) FROM domains").fetchone()[0] == 1
    assert con.execute("SELECT COUNT(*) FROM connections").fetchone()[0] == 4  # 2 entries x 2 inserts (append-only)
    rows = con.execute(
        "SELECT DISTINCT c.contime, c.send, c.recv, c.netns, e.name, p.name, a.addr, d.domain FROM connections c "
        "JOIN executables e ON c.exe_id = e.id JOIN executables p ON c.pexe_id = p.id "
        "JOIN addresses a ON c.raddr_id = a.id JOIN domains d ON c.domain_id = d.id ORDER BY c.contime"
    ).fetchall()
    assert rows == [
        (1000, 5_000_000_000, 6_000_000_000, 4026531840, "curl", "bash", "93.184.216.34", "example.com"),
        (1005, 10, 20, 4026531840, "curl", "bash", "93.184.216.34", "example.com"),
    ]
