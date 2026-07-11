# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""Regression tests for robustness against corrupt inputs: a malformed config.toml,
state.json, or pidfile must never crash-loop the daemon. All pure-Python, no root/BPF."""

import ctypes
import json
import multiprocessing
import os
import pickle
import socket
import struct
import subprocess
import sys
import time

import pytest

import picosnitch.utils as utils
from picosnitch.bpf_wrapper import ConnKey4, ConnKey6, ConnVal, DNSEvent, ExecEvent
from picosnitch.config import Config, load_config, write_default_config
from picosnitch.daemon import Daemon
from picosnitch.types import FanotifyEventMetadata, State
from picosnitch.utils import get_sha256_fuse, resolve_unprivileged_user


def test_corrupt_config_falls_back_to_defaults(tmp_path):
    (tmp_path / "config.toml").write_text("this is [not valid toml @@@\nx=")
    config = load_config(tmp_path)
    assert isinstance(config, Config)
    assert config.database.enabled is True  # defaults intact, no exception raised


def test_non_utf8_config_falls_back_to_defaults(tmp_path):
    # non-UTF-8 config.toml raises UnicodeDecodeError (not TOMLDecodeError); must still fall back
    (tmp_path / "config.toml").write_bytes(b'owner = "caf\xe9"\n')  # latin-1 e-acute, invalid UTF-8
    config = load_config(tmp_path)
    assert isinstance(config, Config)
    assert config.database.enabled is True  # defaults intact, no exception raised


def test_config_numeric_clamps(tmp_path):
    (tmp_path / "config.toml").write_text(
        "[monitoring]\nperf_ring_buffer_pages = 3\nconn_map_max_entries = 0\nrlimit_nofile = true\nst_dev_mask = 4294967296\n"
        "[database]\nretention_days = -1\nwrite_limit_seconds = -1\n"
        "[virustotal]\nrequest_limit_seconds = -1\n"
    )
    config = load_config(tmp_path)
    assert config.monitoring.perf_ring_buffer_pages == 256  # non-power-of-two clamped to default
    assert config.monitoring.conn_map_max_entries == 65536  # < 1 clamped to default
    assert config.monitoring.rlimit_nofile is None
    assert config.monitoring.st_dev_mask is None
    assert config.database.retention_days == 30
    assert config.database.write_limit_seconds == 10
    assert config.virustotal.request_limit_seconds == 15


def test_config_valid_values_preserved(tmp_path):
    (tmp_path / "config.toml").write_text("[monitoring]\nperf_ring_buffer_pages = 512\nconn_map_max_entries = 1024\n")
    config = load_config(tmp_path)
    assert config.monitoring.perf_ring_buffer_pages == 512
    assert config.monitoring.conn_map_max_entries == 1024


def test_config_scalar_for_list_field_skipped(tmp_path):
    """a scalar where a list is expected (e.g. ignore_ports = 443) must keep the default:
    it would TypeError in the secondary's filters every write cycle, halting connection
    logging and growing new_processes unboundedly."""
    (tmp_path / "config.toml").write_text('[log]\nignore_ports = 443\nignore_domains = "example.com"\nignore_ips = "10.0.0.1"\n')
    config = load_config(tmp_path)
    assert config.log.ignore_ports == []
    assert config.log.ignore_domains == []
    assert config.log.ignore_ips == []


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


def test_desktop_user_uses_passwd_primary_group(tmp_path, monkeypatch):
    import pwd

    monkeypatch.delenv("SUDO_UID", raising=False)
    nobody = pwd.getpwnam("nobody")
    (tmp_path / "config.toml").write_text(f'[desktop]\nuser = "{nobody.pw_name}"\n')
    assert load_config(tmp_path).desktop.user == nobody.pw_name
    assert resolve_unprivileged_user(nobody.pw_name) == (nobody.pw_uid, nobody.pw_gid)
    (tmp_path / "config.toml").write_text('[desktop]\nuser = "root"\n')
    assert load_config(tmp_path).desktop.user == ""
    assert resolve_unprivileged_user("9" * 100) != (0, 0)


def test_resolve_unprivileged_user_rejects_gid_zero(monkeypatch):
    """a non-root user whose primary group is root (gid 0) must fall back to nobody, not drop to
    gid 0 -- setgid(0) would keep group-root on the dropped-privilege side of the boundary."""
    import pwd

    nobody = pwd.getpwnam("nobody")
    gid0 = pwd.struct_passwd(("appliance", "x", 1000, 0, "", "/home/appliance", "/bin/sh"))
    monkeypatch.setattr(utils.pwd, "getpwnam", lambda name: gid0 if name == "appliance" else nobody)
    assert resolve_unprivileged_user("appliance") == (nobody.pw_uid, nobody.pw_gid)


def test_default_config_is_private(tmp_path):
    config_path = tmp_path / "config.toml"
    write_default_config(config_path)
    assert config_path.stat().st_mode & 0o777 == 0o600


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


def test_config_ignore_domains_validated(tmp_path):
    """log.ignore_domains entries that aren't non-empty strings must be dropped: a non-str crashes
    secondary's startswith() filter every write cycle (halting all logging), an empty string matches
    every domain (silently dropping all connections) -- both outside the subprocess try/except."""
    (tmp_path / "config.toml").write_text('[log]\nignore_domains = ["ads.", "", "telemetry."]\n')
    config = load_config(tmp_path)
    assert config.log.ignore_domains == ["ads.", "telemetry."]  # empty string dropped
    for prefix in config.log.ignore_domains:  # consumer must not raise
        "example.com".startswith(prefix)


def test_config_ignore_ports_and_hashes_validated(tmp_path):
    digest = "A" * 64
    (tmp_path / "config.toml").write_text(f'[log]\nignore_ports = [true, -2, -1, 443, 65536]\nignore_sha256 = [5, "bad", "{digest}"]\n')
    config = load_config(tmp_path)
    assert config.log.ignore_ports == [-1, 443]
    assert config.log.ignore_sha256 == [digest.lower()]


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
    target = mkdb("target.db")
    symlink = tmp_path / "symlink.db"
    symlink.symlink_to(target)
    assert _db_is_corrupt(symlink) is True
    hardlink = tmp_path / "hardlink.db"
    os.link(target, hardlink)
    assert _db_is_corrupt(hardlink) is True
    with pytest.raises(sqlite3.OperationalError):
        utils.connect_db_readonly(symlink)


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
    # a bare/relative argv0 must fall back to -m, never be re-exec'd directly (Popen would resolve
    # it via $PATH/cwd) -- even an executable ./picosnitch in cwd
    (tmp_path / "picosnitch").chmod(0o755)  # exists and executable, but relative
    monkeypatch.chdir(tmp_path)
    for bad_argv0 in ("picosnitch", "./picosnitch"):
        monkeypatch.setattr(sys, "argv", [bad_argv0, "top"])
        assert utils.relaunch_argv("restart") == [sys.executable, "-m", "picosnitch", "restart"]


def test_resolve_tool_prefers_trusted_dirs(tmp_path, monkeypatch):
    """a build tool must resolve from a standard system dir even when another dir is earlier on
    $PATH (a bare-name lookup would resolve the other one first)."""
    import pytest

    from picosnitch import bpf_wrapper

    other = tmp_path / "other"
    other.mkdir()
    (other / "env").write_text("#!/bin/sh\ntrue\n")  # shadow a tool that exists in /usr/bin
    (other / "env").chmod(0o755)
    monkeypatch.setenv("PATH", str(other) + os.pathsep + os.environ.get("PATH", ""))
    resolved = bpf_wrapper._resolve_tool("env")
    assert os.path.isabs(resolved)
    assert str(other) not in resolved
    with pytest.raises(RuntimeError):
        bpf_wrapper._resolve_tool("picosnitch-no-such-build-tool-xyz")


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


def test_state_json_rejects_hardlinks_and_oversize(tmp_path, monkeypatch):
    monkeypatch.setattr(utils, "DATA_DIR", tmp_path)
    target = tmp_path / "target"
    target.write_text("{}")
    os.link(target, tmp_path / "state.json")
    assert utils.load_state()["Executables"] == {}
    assert (tmp_path / "state.json.bad").exists()
    (tmp_path / "state.json.bad").unlink()
    oversized = tmp_path / "state.json"
    with open(oversized, "wb") as f:
        f.truncate(256 * 1024 * 1024 + 1)
    assert utils.load_state()["Executables"] == {}
    assert (tmp_path / "state.json.bad").exists()


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


def test_exec_event_byte_synced_with_bpf():
    """exec_event_t <-> ExecEvent must stay byte-synced or exec ancestry misparses."""
    assert ctypes.sizeof(ExecEvent) == 100  # 3*comm16 + 3*ino8 + 7*u32, packed
    assert (ExecEvent.ino.offset, ExecEvent.pid.offset, ExecEvent.dev.offset) == (48, 72, 88)


def test_conn_structs_byte_synced_with_bpf():
    """conn_key4_t/conn_key6_t/conn_val_t drive all send/recv/pkt accounting and the connection
    key; the ctypes mirrors must stay byte-exact with picosnitch.bpf.c or counts silently corrupt."""
    # keys are packed (_pack_=1): u32 pid+netns+(saddr,daddr), then u16 lport,dport,protocol,_pad
    assert ctypes.sizeof(ConnKey4) == 24  # 4+4 + 4+4 (v4 addrs) + 2*4
    assert (ConnKey4.saddr.offset, ConnKey4.daddr.offset, ConnKey4.dport.offset) == (8, 12, 18)
    assert ctypes.sizeof(ConnKey6) == 48  # 4+4 + 16+16 (v6 addrs) + 2*4
    assert (ConnKey6.saddr.offset, ConnKey6.daddr.offset, ConnKey6.dport.offset) == (8, 24, 42)
    # value is NOT packed: 3*char[16] then 7*u64 counters (8-byte aligned) then 6*u32
    assert ctypes.sizeof(ConnVal) == 128  # 48 + 56 + 24, no internal or trailing padding
    assert (ConnVal.send_bytes.offset, ConnVal.recv_bytes.offset) == (72, 80)
    assert (ConnVal.send_pkts.offset, ConnVal.recv_pkts.offset) == (88, 96)


def test_fuse_reply_correlation_discards_stale():
    """A late fuse reply left over from a previously timed-out call must be discarded,
    not returned for the next (different) request -- otherwise sha256s desync."""
    q_in: multiprocessing.Queue = multiprocessing.Queue()
    q_out: multiprocessing.Queue = multiprocessing.Queue()
    new_key = ("/new/exe", 222, 3, 4, 0)  # wire key is (path, pid, st_dev, st_ino, _mod_cnt)
    q_out.put(pickle.dumps((("/old/exe", 111, 1, 2, 0), "STALE_SHA")))  # leftover from a timed-out call
    q_out.put(pickle.dumps((new_key, "CORRECT_SHA")))  # the matching reply for our request
    got = get_sha256_fuse.__wrapped__(q_in, q_out, *new_key)
    assert got == "CORRECT_SHA", got


def test_fuse_reply_correlation_keys_on_mod_cnt():
    """A post-modification re-hash (same path/pid/dev/ino, bumped _mod_cnt) must not be served
    the stale pre-modification reply -- the wire key includes _mod_cnt so it's discarded."""
    q_in: multiprocessing.Queue = multiprocessing.Queue()
    q_out: multiprocessing.Queue = multiprocessing.Queue()
    ident = ("/app.AppImage", 222, 3, 4)  # same file, pid, and inode across both hashes
    q_out.put(pickle.dumps(((*ident, 0), "OLD_PREMOD_SHA")))  # leftover from the timed-out mod_cnt=0 call
    q_out.put(pickle.dumps(((*ident, 1), "NEW_POSTMOD_SHA")))  # reply for the mod_cnt=1 re-hash
    got = get_sha256_fuse.__wrapped__(q_in, q_out, *ident, 1)
    assert got == "NEW_POSTMOD_SHA", got  # not the stale pre-modification hash


def test_fuse_no_reply_times_out(monkeypatch):
    monkeypatch.setattr(utils, "FUSE_HASH_TIMEOUT", 0.1)
    q_in: multiprocessing.Queue = multiprocessing.Queue()
    q_out: multiprocessing.Queue = multiprocessing.Queue()
    start = time.monotonic()
    got = get_sha256_fuse.__wrapped__(q_in, q_out, "/new/exe", 222, 3, 4, 0)
    assert got == "!!! FUSE Subprocess Timeout"
    assert time.monotonic() - start < 1


def test_fanotify_overflow_invalidates_all_hashes():
    class Errors:
        def __init__(self):
            self.items = []

        def put(self, item):
            self.items.append(item)

    event = FanotifyEventMetadata()
    event.event_len = ctypes.sizeof(event)
    event.metadata_len = ctypes.sizeof(event)
    event.mask = 0x4000  # FAN_Q_OVERFLOW
    event.fd = -1
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, bytes(event))
        counts = {}
        errors = Errors()
        utils.get_fanotify_events(read_fd, counts, errors)  # ty: ignore[invalid-argument-type]
        assert counts == {"*": 1}
        assert errors.items == ["fanotify queue overflowed; invalidating all cached executable hashes"]
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_proc_reads_survive_non_utf8_comm():
    """a process can set a non-UTF-8 comm via prctl(PR_SET_NAME); the monitor's /proc text
    readers must degrade to replacement chars, not raise UnicodeDecodeError (which dropped
    the process's drain entry) or misparse stat/status (ppid 0, uid 0)"""
    from picosnitch.subprocesses.monitor import _read_proc_comm, _read_proc_ppid, _read_proc_status_uid

    code = 'import ctypes, time\nctypes.CDLL(None).prctl(15, b"\\xff\\xfe*bad", 0, 0, 0)\nprint("x", flush=True)\ntime.sleep(30)'
    p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE)
    try:
        assert p.stdout is not None and p.stdout.read(1) == b"x"  # comm is set once the child prints
        comm = _read_proc_comm(p.pid)
        assert "\ufffd" in comm and "*bad" in comm  # replaced, not raised or emptied
        assert _read_proc_ppid(p.pid) == os.getpid()  # stat parse survives the comm bytes
        assert _read_proc_status_uid(p.pid) == os.geteuid()  # status parse reaches the Uid: line
    finally:
        p.kill()
        p.wait()


def test_apply_data_permissions_keeps_dirs_root_owned(tmp_path):
    """[data].owner may be a non-root account (to read/restrict the logs); the data/log/cache
    DIRECTORIES must stay root-owned and non-group/other-writable so that account can't swap a
    file for a symlink/FIFO and attack the root daemon. Only the FILES take the configured owner."""
    if os.geteuid() != 0:
        pytest.skip("requires root to chown to another account")
    import pwd

    try:
        nobody = pwd.getpwnam("nobody").pw_uid
    except KeyError:
        pytest.skip("no 'nobody' account")
    etc, data, log, cache = (tmp_path / d for d in ("etc", "data", "log", "cache"))
    for d in (etc, data, log, cache):
        d.mkdir()
    (etc / "config.toml").write_text('[data]\nowner = "nobody"\n')
    (data / "picosnitch.db").write_text("x")
    utils.apply_data_permissions(etc, data, log, cache)
    assert (etc / "config.toml").stat().st_uid == 0
    assert (etc / "config.toml").stat().st_mode & 0o777 == 0o600
    assert data.stat().st_uid == 0  # dir stays root-owned -> no symlink/FIFO swap by [data].owner
    assert not (data.stat().st_mode & 0o022)  # never group/other-writable
    assert (data / "picosnitch.db").stat().st_uid == nobody  # the file takes [data].owner (readable)


def test_save_state_preserves_configured_owner(tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("requires root to chown to another account")
    import pwd

    try:
        nobody = pwd.getpwnam("nobody").pw_uid
    except KeyError:
        pytest.skip("no 'nobody' account")
    monkeypatch.setattr(utils, "DATA_DIR", tmp_path)
    config = Config()
    config.data.owner = str(nobody)
    config.data.group = str(nobody)
    config.data.mode = "0640"
    state: State = {
        "Error Log": [],
        "Exe Log": [],
        "Executables": {},
        "Names": {},
        "Parent Executables": {},
        "Parent Names": {},
        "Grandparent Executables": {},
        "Grandparent Names": {},
        "SHA256": {},
    }
    utils.save_state(state, config=config)
    state_path = tmp_path / "state.json"
    assert (state_path.stat().st_uid, state_path.stat().st_gid) == (nobody, nobody)
    assert state_path.stat().st_mode & 0o777 == 0o640
    utils.save_state(state, config=config)
    assert (state_path.stat().st_uid, state_path.stat().st_gid) == (nobody, nobody)


def test_sanitize_log_line_neutralizes_control_chars():
    """attacker-influenced fields (comm/cmdline/domain) reach conn.log/error.log/exe.log; every
    C0 (except tab), DEL, and C1 (e.g. U+009B CSI) must be stripped so a viewed log can't be
    driven to emit a terminal escape or overwrite a prior line."""
    dirty = "safe\x1b[2K\x07\x08\r\n\x00mid\x7f\x9bend\ttab\u202eignored\udc9b"
    clean = utils.sanitize_log_line(dirty)
    assert all(c not in clean for c in "\x1b\x07\x08\r\n\x00\x7f\x9b")  # all control chars gone
    assert "safe" in clean and "mid" in clean and "end" in clean  # printable text preserved
    assert "\ttab" in clean  # tab kept (harmless in a log, not cursor movement here)
    assert "\u202e" not in clean
    assert "\udc9b" not in clean


def test_safe_log_open_rejects_fifo_and_symlink(tmp_path):
    """LOG_DIR may be owned by [data].owner, who could swap a log for a FIFO (hang the root daemon
    on open) or a symlink (redirect its writes); safe_log_open must reject both, not block."""
    import signal

    fifo = tmp_path / "conn.log"
    os.mkfifo(fifo)

    def _alarm(*_):
        raise TimeoutError("safe_log_open hung on a FIFO")

    signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(5)
    try:
        with pytest.raises(OSError):  # ENXIO (no reader) or the S_ISREG reject -- never a hang
            utils.safe_log_open(fifo)
    finally:
        signal.alarm(0)
    fifo.unlink()
    target = tmp_path / "root_secret"
    target.write_text("secret")
    link = tmp_path / "error.log"
    link.symlink_to(target)
    with pytest.raises(OSError):  # O_NOFOLLOW -> ELOOP
        utils.safe_log_open(link)
    assert target.read_text() == "secret"  # untouched
    hardlink = tmp_path / "hardlink.log"
    os.link(target, hardlink)
    with pytest.raises(OSError):
        utils.safe_log_open(hardlink)
    # a real regular file still opens and appends
    reg = tmp_path / "ok.log"
    with utils.safe_log_open(reg) as f:
        f.write("hi\n")
    assert reg.read_text() == "hi\n"


def test_safe_log_open_applies_configured_permissions(tmp_path):
    if os.geteuid() != 0:
        pytest.skip("requires root to chown")
    import pwd

    nobody = pwd.getpwnam("nobody")
    config = Config()
    config.data.owner = str(nobody.pw_uid)
    config.data.group = str(nobody.pw_gid)
    config.data.mode = "0640"
    path = tmp_path / "new.log"
    with utils.safe_log_open(path, config=config) as f:
        f.write("x")
    assert (path.stat().st_uid, path.stat().st_gid, path.stat().st_mode & 0o777) == (nobody.pw_uid, nobody.pw_gid, 0o640)
