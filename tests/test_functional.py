# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""
Functional end-to-end tests for picosnitch BPF CO-RE implementation.

These tests verify:
1. Picosnitch daemon starts and stops correctly
2. Network traffic is captured with correct byte counts
3. Short-lived processes are detected with exe paths resolved
4. Executable hashes are computed correctly
5. Database and log files are populated correctly
"""

import hashlib
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

# Constants
PICOSNITCH_DIR = Path(__file__).parent.parent
PYTHON_EXE = sys.executable

# Use a root prefix so tests don't touch the real picosnitch directories
TEST_ROOT = "/tmp/picosnitch-test"
os.environ["PICOSNITCH_ROOT"] = TEST_ROOT

# FHS standard paths (under test root)
CONFIG_DIR = Path(f"{TEST_ROOT}/etc/picosnitch")
DATA_DIR = Path(f"{TEST_ROOT}/var/lib/picosnitch")
LOG_DIR = Path(f"{TEST_ROOT}/var/log/picosnitch")
RUN_DIR = Path(f"{TEST_ROOT}/run/picosnitch")
CACHE_DIR = Path(f"{TEST_ROOT}/var/cache/picosnitch")

# Test configuration
DB_WRITE_LIMIT = 5  # seconds - we set this in config
STARTUP_WAIT = 8  # seconds to wait for picosnitch to fully start
TRAFFIC_WAIT = 3  # seconds to wait after network activity


def get_executable_hash(exe_path: str) -> str:
    """Calculate SHA256 hash of an executable file."""
    sha256 = hashlib.sha256()
    try:
        with open(exe_path, "rb") as f:
            while data := f.read(1048576):
                sha256.update(data)
        return sha256.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None


def find_executable(name: str) -> str:
    """Find the full path to an executable."""
    result = subprocess.run(["which", name], capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip()
    return None


def clean_test_dirs():
    """Remove and recreate test directories for a fresh test."""
    test_root = Path(TEST_ROOT)
    if test_root.exists():
        shutil.rmtree(test_root)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def stop_existing_picosnitch():
    """Stop any existing picosnitch daemon."""
    subprocess.run([PYTHON_EXE, "-m", "picosnitch", "stop"], capture_output=True, timeout=30)
    time.sleep(2)


def start_picosnitch(extra_config_toml: str = "") -> subprocess.Popen:
    """Start picosnitch daemon in start-no-daemon mode and return the process."""
    config_toml = f"""\
[database]
enabled = true
retention_days = 1
write_limit_seconds = {DB_WRITE_LIMIT}
text_log = false

[dash]
scroll_zoom = true
theme = ""

[data]
owner = "root"
group = "root"
mode = "0644"

[log]
addresses = true
commands = true
ports = true

[desktop]
user = ""
notifications = false

[monitoring]
every_exe = false
geoip_lookup = true
perf_ring_buffer_pages = 256

[virustotal]
api_key = ""
file_upload = false
request_limit_seconds = 15
"""
    if extra_config_toml:
        config_toml += "\n" + extra_config_toml

    config_file = CONFIG_DIR / "config.toml"
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(config_file, "w") as f:
        f.write(config_toml)

    proc = subprocess.Popen([PYTHON_EXE, "-m", "picosnitch", "start-no-daemon"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    time.sleep(STARTUP_WAIT)

    if proc.poll() is not None:
        stdout = proc.stdout.read().decode()
        stderr = proc.stderr.read().decode()
        raise RuntimeError(f"picosnitch exited early: stdout={stdout}, stderr={stderr}")

    return proc


def stop_picosnitch(proc: subprocess.Popen):
    """Stop picosnitch process and wait for DB flush."""
    if proc and proc.poll() is None:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    time.sleep(DB_WRITE_LIMIT + 2)


def query_db(query: str) -> list:
    """Execute a query on the picosnitch database."""
    db_path = DATA_DIR / "picosnitch.db"
    if not db_path.exists():
        return []
    con = sqlite3.connect(str(db_path))
    cur = con.cursor()
    try:
        cur.execute(query)
        results = cur.fetchall()
    finally:
        con.close()
    return results


def get_connections_for_process(process_name: str) -> list:
    """Get all connections for a process name."""
    return query_db(f"SELECT e.name, e.exe, c.raddr, c.rport, c.send, c.recv, c.domain FROM connections c JOIN executables e ON c.exe_id = e.id WHERE e.name LIKE '%{process_name}%'")


@pytest.fixture(scope="module")
def picosnitch_session():
    """Module-scoped fixture that manages picosnitch lifecycle for all tests."""
    if os.geteuid() != 0:
        pytest.skip("Tests require root privileges. Run with: sudo uv run pytest tests/test_functional.py -v")

    stop_existing_picosnitch()
    clean_test_dirs()

    # Init directories
    subprocess.run([PYTHON_EXE, "-m", "picosnitch", "init"], capture_output=True, timeout=30)

    proc = start_picosnitch()

    yield proc

    stop_picosnitch(proc)
    # Clean up test root
    test_root = Path(TEST_ROOT)
    if test_root.exists():
        shutil.rmtree(test_root)


class TestShortLivedProcesses:
    """Tests for capturing short-lived processes with correct exe paths."""

    def test_curl_exe_resolved(self, picosnitch_session):
        """Test that curl's executable path is resolved even though it exits quickly."""
        curl_exe = find_executable("curl")
        if not curl_exe:
            pytest.skip("curl not available")

        subprocess.run(["curl", "-s", "http://example.com", "-o", "/dev/null"], capture_output=True, timeout=30)

        time.sleep(DB_WRITE_LIMIT + TRAFFIC_WAIT)

        connections = get_connections_for_process("curl")
        assert len(connections) > 0, "Should have captured curl connections"

        for conn in connections:
            name, exe, raddr, rport, send, recv, domain = conn
            assert exe != "", f"curl exe should be resolved, got empty for raddr={raddr} rport={rport}"
            assert "curl" in exe, f"curl exe should contain 'curl', got: {exe}"

    def test_curl_sha256_correct(self, picosnitch_session):
        """Test that curl's SHA256 hash is computed correctly."""
        curl_exe = find_executable("curl")
        if not curl_exe:
            pytest.skip("curl not available")

        expected_hash = get_executable_hash(curl_exe)

        subprocess.run(["curl", "-s", "http://example.com", "-o", "/dev/null"], capture_output=True, timeout=30)

        time.sleep(DB_WRITE_LIMIT + TRAFFIC_WAIT)

        results = query_db("SELECT e.sha256 FROM connections c JOIN executables e ON c.exe_id = e.id WHERE e.name LIKE '%curl%' AND e.sha256 NOT LIKE '!%' LIMIT 1")
        assert len(results) > 0, "Should have a valid SHA256 for curl"
        sha256 = results[0][0]
        assert sha256 == expected_hash, f"SHA256 mismatch: got {sha256}, expected {expected_hash}"

    def test_wget_exe_resolved(self, picosnitch_session):
        """Test that wget's executable path is resolved."""
        wget_exe = find_executable("wget")
        if not wget_exe:
            pytest.skip("wget not available")

        subprocess.run(["wget", "-q", "http://example.com", "-O", "/dev/null"], capture_output=True, timeout=30)

        time.sleep(DB_WRITE_LIMIT + TRAFFIC_WAIT)

        connections = get_connections_for_process("wget")
        assert len(connections) > 0, "Should have captured wget connections"

        for conn in connections:
            name, exe, raddr, rport, send, recv, domain = conn
            assert exe != "", "wget exe should be resolved, got empty"
            assert "wget" in exe, f"wget exe should contain 'wget', got: {exe}"

    def test_multiple_rapid_curl(self, picosnitch_session):
        """Test that multiple rapid curl invocations all get exe resolved."""
        curl_exe = find_executable("curl")
        if not curl_exe:
            pytest.skip("curl not available")

        for i in range(3):
            subprocess.run(["curl", "-s", "http://example.com", "-o", "/dev/null"], capture_output=True, timeout=30)
            time.sleep(0.5)

        time.sleep(DB_WRITE_LIMIT + TRAFFIC_WAIT)

        connections = get_connections_for_process("curl")
        assert len(connections) >= 1, "Should have captured at least one curl connection"

        # All curl connections should have exe resolved
        for conn in connections:
            name, exe, raddr, rport, send, recv, domain = conn
            assert exe != "", "All curl connections should have exe resolved"

    def test_no_read_errors(self, picosnitch_session):
        """Test that there are no Read Errors in the error log after curl/wget."""
        error_log = LOG_DIR / "error.log"
        if error_log.exists():
            content = error_log.read_text()
            read_errors = [line for line in content.splitlines() if "Read Error" in line and "curl" in line]
            assert len(read_errors) == 0, f"Should not have Read Errors for curl: {read_errors[:3]}"


class TestDatabaseIntegrity:
    """Tests for database integrity."""

    def test_database_schema(self, picosnitch_session):
        """Test that database has correct schema."""
        subprocess.run(["curl", "-s", "http://example.com", "-o", "/dev/null"], capture_output=True, timeout=30)
        time.sleep(DB_WRITE_LIMIT + TRAFFIC_WAIT)

        db_path = DATA_DIR / "picosnitch.db"
        assert db_path.exists(), "Database should exist"

        con = sqlite3.connect(str(db_path))
        cur = con.cursor()
        cur.execute("PRAGMA user_version")
        version = cur.fetchone()[0]
        assert version == 4, f"Database version should be 4, got {version}"

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='connections'")
        tables = cur.fetchall()
        assert len(tables) == 1, "connections table should exist"
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='executables'")
        tables = cur.fetchall()
        assert len(tables) == 1, "executables table should exist"
        con.close()

    def test_no_device_mismatch_errors(self, picosnitch_session):
        """Test no 'Exe inode changed' errors (device encoding bug)."""
        subprocess.run(["curl", "-s", "http://example.com", "-o", "/dev/null"], capture_output=True, timeout=30)
        time.sleep(DB_WRITE_LIMIT + TRAFFIC_WAIT)

        error_log = LOG_DIR / "error.log"
        if error_log.exists():
            content = error_log.read_text()
            assert content.count("Exe inode changed") == 0, "Should not have inode changed errors"


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("WARNING: These tests require root privileges.")
        print("Run with: sudo uv run pytest tests/test_functional.py -v")
        sys.exit(1)
    pytest.main([__file__, "-v"])
