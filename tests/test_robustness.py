# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""Regression tests for robustness against corrupt inputs: a malformed config.toml,
state.json, or pidfile must never crash-loop the daemon. All pure-Python, no root/BPF."""

import ctypes
import json
import multiprocessing
import pickle
import socket
import struct
import subprocess
import sys
import time

import picosnitch.utils as utils
from picosnitch.bpf_wrapper import DNSEvent
from picosnitch.config import Config, load_config
from picosnitch.daemon import Daemon
from picosnitch.utils import get_sha256_fuse


def test_corrupt_config_falls_back_to_defaults(tmp_path):
    (tmp_path / "config.toml").write_text("this is [not valid toml @@@\nx=")
    config = load_config(tmp_path)
    assert isinstance(config, Config)
    assert config.database.enabled is True  # defaults intact, no exception raised


def test_config_numeric_clamps(tmp_path):
    (tmp_path / "config.toml").write_text("[monitoring]\nperf_ring_buffer_pages = 3\nconn_map_max_entries = 0\n")
    config = load_config(tmp_path)
    assert config.monitoring.perf_ring_buffer_pages == 256  # non-power-of-two clamped to default
    assert config.monitoring.conn_map_max_entries == 65536  # < 1 clamped to default


def test_config_valid_values_preserved(tmp_path):
    (tmp_path / "config.toml").write_text("[monitoring]\nperf_ring_buffer_pages = 512\nconn_map_max_entries = 1024\n")
    config = load_config(tmp_path)
    assert config.monitoring.perf_ring_buffer_pages == 512
    assert config.monitoring.conn_map_max_entries == 1024


def test_config_numeric_upper_clamps(tmp_path):
    """Absurd but positive / power-of-two BPF sizes must be clamped to defaults, not handed to
    the perf mmap or BPF map alloc where they crash-loop the daemon (conn also wraps a c_uint32)."""
    (tmp_path / "config.toml").write_text("[monitoring]\nperf_ring_buffer_pages = 1073741824\nconn_map_max_entries = 8589934592\n")
    config = load_config(tmp_path)
    assert config.monitoring.perf_ring_buffer_pages == 256  # 2^30 is a power of two but over max
    assert config.monitoring.conn_map_max_entries == 65536  # 2^33 over max (and would wrap c_uint32)


def test_config_unresolvable_owner_group_user_reset(tmp_path, monkeypatch):
    """owner/group/desktop.user that don't resolve to a real uid/gid, or a non-octal mode, must
    reset to defaults -- else apply_data_permissions / the subprocess privilege drop raise an
    uncaught KeyError/ValueError at boot and crash-loop the daemon."""
    monkeypatch.delenv("SUDO_UID", raising=False)  # else the reset user falls back to SUDO_UID
    (tmp_path / "config.toml").write_text('[data]\nowner = "no_such_user_xyz123"\ngroup = "no_such_group_xyz123"\nmode = "garbage"\n[desktop]\nuser = "no_such_user_xyz123"\n')
    config = load_config(tmp_path)
    assert config.data.owner == "root" and config.data.group == "root" and config.data.mode == "0644"
    assert config.desktop.user == ""


def test_config_valid_owner_preserved(tmp_path):
    """a resolvable name and a numeric uid/gid must be kept, not falsely reset."""
    (tmp_path / "config.toml").write_text('[data]\nowner = "root"\ngroup = "0"\nmode = "0600"\n')
    config = load_config(tmp_path)
    assert config.data.owner == "root" and config.data.group == "0" and config.data.mode == "0600"


def test_config_ignore_ips_validated(tmp_path):
    """log.ignore_ips entries that aren't valid networks must be dropped (a host-bit CIDR is kept
    and later normalized with strict=False); else secondary crashes building ignored_networks at
    boot (list[str] skips load_config's type check, so a non-list must also reset to [])."""
    import ipaddress

    (tmp_path / "config.toml").write_text('[log]\nignore_ips = ["not-an-ip", "192.168.1.5/24", "10.0.0.0/8"]\n')
    config = load_config(tmp_path)
    assert config.log.ignore_ips == ["192.168.1.5/24", "10.0.0.0/8"]  # invalid dropped, valid kept
    [ipaddress.ip_network(x, strict=False) for x in config.log.ignore_ips]  # consumer must not raise
    (tmp_path / "config.toml").write_text('[log]\nignore_ips = "1.2.3.4"\n')  # not a list
    assert load_config(tmp_path).log.ignore_ips == []


def test_maintain_database_quarantines_corrupt(tmp_path):
    """maintain_database must purge a healthy db, but quarantine a corrupt/table-missing db to
    .bad and exit (so the next boot recreates it) rather than crash-loop; a version mismatch must
    exit WITHOUT quarantining (migratable data preserved)."""
    import sqlite3

    import pytest

    from picosnitch.constants import DB_VERSION
    from picosnitch.subprocesses.secondary import maintain_database

    db = tmp_path / "picosnitch.db"
    bad = tmp_path / "picosnitch.db.bad"

    def fresh(version=DB_VERSION):
        db.unlink(missing_ok=True)
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE connections (contime INTEGER, domain_id INTEGER, laddr_id INTEGER, raddr_id INTEGER, exe_id INTEGER, pexe_id INTEGER, gpexe_id INTEGER)")
        con.execute("CREATE TABLE domains (id INTEGER)")
        con.execute("CREATE TABLE addresses (id INTEGER)")
        con.execute("CREATE TABLE executables (id INTEGER)")
        con.execute(f"PRAGMA user_version = {version}")
        con.commit()
        con.close()

    fresh()  # healthy -> purge, no quarantine, no exit
    maintain_database(db, 365)
    assert db.exists() and not bad.exists()

    fresh()  # missing table -> quarantine + exit
    con = sqlite3.connect(db)
    con.execute("DROP TABLE connections")
    con.commit()
    con.close()
    with pytest.raises(SystemExit):
        maintain_database(db, 365)
    assert bad.exists() and not db.exists()

    bad.unlink()  # not-a-database file -> quarantine + exit
    db.write_bytes(b"this is not a sqlite database" * 8)
    with pytest.raises(SystemExit):
        maintain_database(db, 365)
    assert bad.exists() and not db.exists()

    bad.unlink()  # wrong version -> exit but do NOT destroy the db
    fresh(version=DB_VERSION - 1)
    with pytest.raises(SystemExit):
        maintain_database(db, 365)
    assert db.exists() and not bad.exists()

    bad.unlink(missing_ok=True)  # right table name, wrong columns -> "no such column" -> quarantine
    db.unlink(missing_ok=True)
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE connections (foo INTEGER)")
    con.execute(f"PRAGMA user_version = {DB_VERSION}")
    con.commit()
    con.close()
    with pytest.raises(SystemExit):
        maintain_database(db, 365)
    assert bad.exists() and not db.exists()


def test_maintain_database_purges_orphans(tmp_path):
    """after connections age out, the reference tables (executables/domains/addresses)
    must shed rows no live connection points at, while referenced rows and the id=0
    sentinel survive -- otherwise executables grows unbounded with argv cardinality."""
    import sqlite3
    import time

    from picosnitch.constants import DB_VERSION, SCHEMA_ADDRESSES, SCHEMA_CONNECTIONS, SCHEMA_DOMAINS, SCHEMA_EXECUTABLES
    from picosnitch.subprocesses.secondary import maintain_database

    db = tmp_path / "picosnitch.db"
    con = sqlite3.connect(db)
    con.execute(f"CREATE TABLE executables ({SCHEMA_EXECUTABLES}) STRICT")
    con.execute(f"CREATE TABLE domains ({SCHEMA_DOMAINS}) STRICT")
    con.execute(f"CREATE TABLE addresses ({SCHEMA_ADDRESSES}) STRICT")
    con.execute(f"CREATE TABLE connections ({SCHEMA_CONNECTIONS}) STRICT")
    for t in ("executables", "domains", "addresses"):
        col = "exe, name, cmdline, sha256" if t == "executables" else ("domain" if t == "domains" else "addr")
        vals = "'', '', '', ''" if t == "executables" else "''"
        con.execute(f"INSERT INTO {t}(id, {col}) VALUES (0, {vals})")  # sentinel
    # id 1 = referenced by a live connection; id 2 = orphan (no connection points at it)
    con.execute("INSERT INTO executables(id, exe, name, cmdline, sha256) VALUES (1, '/bin/live', 'live', 'live', 'a')")
    con.execute("INSERT INTO executables(id, exe, name, cmdline, sha256) VALUES (2, '/bin/orphan', 'orphan', 'orphan --token-999', 'b')")
    con.execute("INSERT INTO domains(id, domain) VALUES (1, 'live.example'), (2, 'orphan.example')")
    con.execute("INSERT INTO addresses(id, addr) VALUES (1, '10.0.0.1'), (2, '10.0.0.2')")
    now = int(time.time())
    # one live connection referencing exe 1 / domain 1 / addr 1 (as laddr AND raddr)
    con.execute(f"INSERT INTO connections VALUES ({now}, 0, 0, 1, 1, 1, 1, 0, 2, 6, 0, 443, 1, 1, 1, 0)")
    con.execute(f"PRAGMA user_version = {DB_VERSION}")
    con.commit()
    con.close()

    maintain_database(db, 365)

    con = sqlite3.connect(db)
    assert sorted(r[0] for r in con.execute("SELECT id FROM executables")) == [0, 1]  # orphan 2 purged, sentinel + live kept
    assert sorted(r[0] for r in con.execute("SELECT id FROM domains")) == [0, 1]
    assert sorted(r[0] for r in con.execute("SELECT id FROM addresses")) == [0, 1]
    con.close()


def test_db_is_corrupt(tmp_path):
    """_db_is_corrupt must flag an unopenable / missing-table / wrong-column db (to be
    quarantined) but not a valid or merely wrong-version one."""
    import sqlite3

    from picosnitch.cli import _db_is_corrupt
    from picosnitch.constants import DB_VERSION

    def mkdb(name, connections_cols="contime INTEGER, domain_id INTEGER, laddr_id INTEGER, raddr_id INTEGER", tables=True, version=DB_VERSION):
        p = tmp_path / name
        con = sqlite3.connect(p)
        if tables:
            con.execute(f"CREATE TABLE connections ({connections_cols})")
            con.execute("CREATE TABLE domains (id INTEGER)")
            con.execute("CREATE TABLE addresses (id INTEGER)")
            con.execute("CREATE TABLE executables (id INTEGER, exe TEXT, name TEXT, cmdline TEXT, sha256 TEXT)")
        con.execute(f"PRAGMA user_version = {version}")
        con.commit()
        con.close()
        return p

    assert _db_is_corrupt(mkdb("ok.db")) is False
    assert _db_is_corrupt(mkdb("notables.db", tables=False)) is True  # missing tables -> quarantine
    assert _db_is_corrupt(mkdb("wrongcols.db", connections_cols="foo INTEGER")) is True  # right name, wrong columns
    assert _db_is_corrupt(mkdb("oldver.db", version=DB_VERSION - 1)) is False  # wrong version -> keep for check_database
    garbage = tmp_path / "garbage.db"
    garbage.write_bytes(b"not a sqlite database" * 8)
    assert _db_is_corrupt(garbage) is True


def test_db_is_corrupt_ignores_transient_errors(tmp_path, monkeypatch):
    """a healthy db that's merely locked (the live daemon mid-write, or a user's sqlite session)
    must NOT be flagged corrupt -- `start` runs _db_is_corrupt before the already-running check,
    so a lock false-positive would quarantine the live database out from under the daemon."""
    import sqlite3

    from picosnitch.cli import _db_is_corrupt
    from picosnitch.constants import DB_VERSION
    from picosnitch.utils import sqlite_error_means_corrupt

    db = tmp_path / "picosnitch.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE connections (contime INTEGER, domain_id INTEGER, laddr_id INTEGER, raddr_id INTEGER)")
    con.execute("CREATE TABLE domains (id INTEGER)")
    con.execute("CREATE TABLE addresses (id INTEGER)")
    con.execute("CREATE TABLE executables (id INTEGER, exe TEXT, name TEXT, cmdline TEXT, sha256 TEXT)")
    con.execute(f"PRAGMA user_version = {DB_VERSION}")
    con.commit()
    con.execute("BEGIN EXCLUSIVE")  # hold a write lock, as the live secondary would
    orig_connect = sqlite3.connect
    monkeypatch.setattr(sqlite3, "connect", lambda p, **kw: orig_connect(p, timeout=0.05, **kw))  # don't wait out the 5s busy timeout
    assert _db_is_corrupt(db) is False
    con.rollback()
    con.close()

    # the shared classifier: only structural errors mean corrupt
    assert sqlite_error_means_corrupt(sqlite3.DatabaseError("database disk image is malformed")) is True
    assert sqlite_error_means_corrupt(sqlite3.OperationalError("no such table: connections")) is True
    assert sqlite_error_means_corrupt(sqlite3.OperationalError("database is locked")) is False
    assert sqlite_error_means_corrupt(sqlite3.OperationalError("disk I/O error")) is False


def test_check_database_handles_corrupt(tmp_path, monkeypatch):
    """check_database must return 1 (not crash with sqlite3.DatabaseError, which is not an
    OperationalError) on a corrupt db, so the boot path doesn't crash-loop before init quarantines it."""
    import picosnitch.cli as cli

    monkeypatch.setattr(cli, "DATA_DIR", tmp_path)
    (tmp_path / "picosnitch.db").write_bytes(b"not a sqlite database" * 8)
    assert cli.check_database() == 1


def test_config_scalar_section_falls_back(tmp_path):
    """A valid-TOML-but-wrong-shape section (a scalar where a table is expected) must be
    ignored, not crash the daemon (regression: `field.name in section_data` raised
    TypeError on an int/bool/float section and crash-looped under systemd Restart=always)."""
    (tmp_path / "config.toml").write_text("monitoring = 5\ndatabase = true\n")
    config = load_config(tmp_path)  # must not raise TypeError
    assert isinstance(config, Config)
    assert config.database.enabled is True  # defaults intact
    assert config.monitoring.perf_ring_buffer_pages == 256


def test_relaunch_argv_reexecs_console_script(monkeypatch, tmp_path):
    """relaunch_argv must re-exec an executable picosnitch console script / nix wrapper
    directly (never `python <bash-wrapper>`, which SyntaxErrors on nix), and fall back to
    `-m picosnitch` when not launched from a picosnitch entry point."""
    for name in ("picosnitch", ".picosnitch-wrapped"):  # pip/venv console script and nix wrapper
        script = tmp_path / name
        script.write_text("#!/bin/sh\n")
        script.chmod(0o755)
        monkeypatch.setattr(sys, "argv", [str(script), "top"])
        assert utils.relaunch_argv("restart") == [str(script), "restart"]
    # non-picosnitch argv0 (e.g. `python -m picosnitch`) -> fall back to -m picosnitch
    monkeypatch.setattr(sys, "argv", ["/usr/bin/python3", "top"])
    assert utils.relaunch_argv("restart") == [sys.executable, "-m", "picosnitch", "restart"]


def test_corrupt_state_json_quarantined(tmp_path, monkeypatch):
    monkeypatch.setattr(utils, "DATA_DIR", tmp_path)
    (tmp_path / "state.json").write_text("{ not valid json ")
    state = utils.load_state()  # must not raise SystemExit
    assert state["Executables"] == {} and state["SHA256"] == {}
    assert (tmp_path / "state.json.bad").exists()
    assert not (tmp_path / "state.json").exists()


def test_state_json_non_dict_value_reset(tmp_path, monkeypatch):
    monkeypatch.setattr(utils, "DATA_DIR", tmp_path)
    (tmp_path / "state.json").write_text('{"Executables": [1, 2, 3]}')
    state = utils.load_state()
    assert state["Executables"] == {}
    assert (tmp_path / "state.json.bad").exists()


def test_state_json_nested_non_dict_value_reset(tmp_path, monkeypatch):
    """A state.json whose top-level keys are dicts but whose INNER values are the wrong shape
    (SHA256 exe -> str, or a name-history exe -> non-list) must be quarantined, not accepted --
    else sync_vt_results crashes at startup outside its try/except and crash-loops the daemon."""
    monkeypatch.setattr(utils, "DATA_DIR", tmp_path)
    (tmp_path / "state.json").write_text('{"SHA256": {"/bin/x": "corrupt"}}')  # inner must be a dict
    state = utils.load_state()
    assert state["SHA256"] == {}
    assert (tmp_path / "state.json.bad").exists()
    (tmp_path / "state.json").write_text('{"Executables": {"/bin/x": 5}}')  # inner must be a list
    state = utils.load_state()
    assert state["Executables"] == {}


def test_valid_state_json_loads(tmp_path, monkeypatch):
    monkeypatch.setattr(utils, "DATA_DIR", tmp_path)
    (tmp_path / "state.json").write_text(json.dumps({"Executables": {"/bin/x": ["abc"]}, "SHA256": {}}))
    state = utils.load_state()
    assert state["Executables"] == {"/bin/x": ["abc"]}
    assert not (tmp_path / "state.json.bad").exists()


def test_daemon_getpid_handles_bad_pidfile(tmp_path):
    pidfile = tmp_path / "pico.pid"
    daemon = Daemon(pidfile)
    assert daemon.getpid() is None  # missing pidfile
    pidfile.write_text("")
    assert daemon.getpid() is None  # empty
    pidfile.write_text("garbage\n")
    assert daemon.getpid() is None  # non-numeric
    pidfile.write_text("4242\n")
    assert daemon.getpid() == 4242


def test_daemon_pid_is_picosnitch_rejects_unrelated(tmp_path):
    daemon = Daemon(tmp_path / "pico.pid")
    # pid 1 is init/systemd, never picosnitch -> a stale/recycled pid is not signalled
    assert daemon._pid_is_picosnitch(1) is False


def test_daemon_cmdline_matching_is_exact():
    assert Daemon._cmdline_is_picosnitch(b"/usr/bin/picosnitch\0start\0")
    assert Daemon._cmdline_is_picosnitch(b"/usr/bin/python3\0-m\0picosnitch\0start\0")
    assert Daemon._cmdline_is_picosnitch(b"/usr/bin/python3\0-I\0-m\0picosnitch\0start-no-daemon\0")
    assert Daemon._cmdline_is_picosnitch(b"/usr/bin/python3\0/venv/bin/picosnitch\0restart\0")
    # interpreter-agnostic: env-shebang and nix/bash-wrapper launches (picosnitch as a
    # script path, not argv0) must still match, else stop()/start() break on those installs
    assert Daemon._cmdline_is_picosnitch(b"/usr/bin/env\0python3\0/usr/bin/picosnitch\0start-no-daemon\0")
    assert Daemon._cmdline_is_picosnitch(b"/bin/bash\0/nix/store/x/bin/picosnitch\0start-no-daemon\0")
    # real nix runs the entry point as `.picosnitch-wrapped` (verified in a nix container)
    assert Daemon._cmdline_is_picosnitch(b"/nix/store/a-python3/bin/python3.13\0/nix/store/b-picosnitch/bin/.picosnitch-wrapped\0start-no-daemon\0")
    assert not Daemon._cmdline_is_picosnitch(b"/usr/bin/picosnitch\0status\0")
    assert not Daemon._cmdline_is_picosnitch(b"/usr/bin/python3\0-m\0picosnitch\0version\0")
    assert not Daemon._cmdline_is_picosnitch(b"/usr/bin/sleep\0picosnitch\0")
    assert not Daemon._cmdline_is_picosnitch(b"/usr/bin/python3\0-c\0import time; time.sleep(30)\0picosnitch\0")
    assert not Daemon._cmdline_is_picosnitch(b"/usr/bin/sleep\0picosnitch\0start\0")  # bare-arg spoof w/ daemon cmd
    # a /path/to/picosnitch passed as a file argument to an unrelated program (argv0 is neither
    # picosnitch nor an interpreter) must not match, so a recycled pid is never signalled
    assert not Daemon._cmdline_is_picosnitch(b"/usr/bin/tail\0-f\0/var/backups/picosnitch\0start-no-daemon\0")
    assert not Daemon._cmdline_is_picosnitch(b"/bin/cp\0/etc/picosnitch\0restart\0")


def test_daemon_pid_is_picosnitch_rejects_spoofed_arg(tmp_path):
    daemon = Daemon(tmp_path / "pico.pid")
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", "picosnitch"])
    try:
        time.sleep(0.1)
        assert daemon._pid_is_picosnitch(proc.pid) is False
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_dns_event_family_demux():
    """dns_event_t <-> DNSEvent must stay byte-synced, and the family field must tell a
    v4 0.0.0.0 answer from a v6 :: answer (regression: 0.0.0.0 was demuxed as IPv6
    because daddr == 0)."""
    assert ctypes.sizeof(DNSEvent) == 102  # host80 + daddr4 + daddr6_16 + family2, packed
    v4 = b"sinkhole.test".ljust(80, b"\x00") + struct.pack("I", 0) + b"\x00" * 16 + struct.pack("H", socket.AF_INET)
    assert DNSEvent.from_buffer_copy(v4).family == socket.AF_INET  # -> "0.0.0.0", not "::"
    v6 = b"ipv6.test".ljust(80, b"\x00") + struct.pack("I", 0) + b"\x00" * 16 + struct.pack("H", socket.AF_INET6)
    assert DNSEvent.from_buffer_copy(v6).family == socket.AF_INET6


def test_fuse_reply_correlation_discards_stale():
    """A late fuse reply left over from a previously timed-out call must be discarded,
    not returned for the next (different) request -- otherwise sha256s desync."""
    q_in: multiprocessing.Queue = multiprocessing.Queue()
    q_out: multiprocessing.Queue = multiprocessing.Queue()
    new_key = ("/new/exe", 222, 3, 4)
    q_out.put(pickle.dumps((("/old/exe", 111, 1, 2), "STALE_SHA")))  # leftover from a timed-out call
    q_out.put(pickle.dumps((new_key, "CORRECT_SHA")))  # the matching reply for our request
    got = get_sha256_fuse.__wrapped__(q_in, q_out, *new_key, 0)
    assert got == "CORRECT_SHA", got


def test_fuse_no_reply_times_out(monkeypatch):
    monkeypatch.setattr(utils, "FUSE_HASH_TIMEOUT", 0.1)
    q_in: multiprocessing.Queue = multiprocessing.Queue()
    q_out: multiprocessing.Queue = multiprocessing.Queue()
    start = time.monotonic()
    got = get_sha256_fuse.__wrapped__(q_in, q_out, "/new/exe", 222, 3, 4, 0)
    assert got == "!!! FUSE Subprocess Timeout"
    assert time.monotonic() - start < 1
