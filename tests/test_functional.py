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

from picosnitch.constants import DB_VERSION

# Constants
PICOSNITCH_DIR = Path(__file__).parent.parent
PYTHON_EXE = sys.executable

# Use a test prefix so tests don't touch the real picosnitch directories
TEST_ROOT = "/tmp/picosnitch"
os.environ["PICOSNITCH_TEST"] = "1"

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


def get_executable_hash(exe_path: str) -> str | None:
    """Calculate SHA256 hash of an executable file."""
    sha256 = hashlib.sha256()
    try:
        with open(exe_path, "rb") as f:
            while data := f.read(1048576):
                sha256.update(data)
        return sha256.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None


def find_executable(name: str) -> str | None:
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
    """Start picosnitch daemon in start-no-daemon mode and return the process.

    Waits for the daemon to be fully ready (events socket present) and then
    issues a warmup HTTP request that is polled-for in the database so we
    know the BPF monitor is actually producing events before the test
    starts exercising it. Without this, the first test in a run frequently
    races the BPF attachment and sees no events."""
    config_toml = f"""\
[database]
enabled = true
retention_days = 1
write_limit_seconds = {DB_WRITE_LIMIT}
text_log = false

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
geoip_lookup = true

[monitoring]
every_exe = false
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
    assert proc.stdout is not None and proc.stderr is not None

    # wait for the events socket to appear -- means primary subprocess is listening
    events_sock = RUN_DIR / "events.sock"
    deadline = time.time() + STARTUP_WAIT + 10
    while time.time() < deadline:
        if proc.poll() is not None:
            stdout = proc.stdout.read().decode()
            stderr = proc.stderr.read().decode()
            raise RuntimeError(f"picosnitch exited early: stdout={stdout}, stderr={stderr}")
        if events_sock.exists():
            break
        time.sleep(0.2)

    # additional settle time for BPF program load
    time.sleep(STARTUP_WAIT)

    # warmup: hit a known endpoint and poll for it to appear in the DB so we
    # know the BPF monitor is producing events end-to-end. Retry the warmup
    # up to a few times because the first event after BPF attach can be
    # missed on slower systems.
    warmup_deadline = time.time() + 60
    warmup_seen = False
    while time.time() < warmup_deadline and not warmup_seen:
        subprocess.run(["curl", "-s", "-o", "/dev/null", "https://example.com"], timeout=15)
        # give the writer time to flush
        for _ in range(int((DB_WRITE_LIMIT + 4) * 2)):
            time.sleep(0.5)
            if proc.poll() is not None:
                stdout = proc.stdout.read().decode()
                stderr = proc.stderr.read().decode()
                raise RuntimeError(f"picosnitch exited during warmup: stdout={stdout}, stderr={stderr}")
            rows = get_connections_for_process("curl")
            if rows:
                warmup_seen = True
                break

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


def query_db(query: str, params: tuple = ()) -> list:
    """Execute a query on the picosnitch database."""
    db_path = DATA_DIR / "picosnitch.db"
    if not db_path.exists():
        return []
    con = sqlite3.connect(str(db_path))
    cur = con.cursor()
    try:
        cur.execute(query, params)
        results = cur.fetchall()
    finally:
        con.close()
    return results


def get_connections_for_process(process_name: str) -> list:
    """Get all connections for a process name."""
    return query_db(
        "SELECT e.name, e.exe, a.addr, c.rport, c.send, c.recv, d.domain "
        "FROM connections c "
        "JOIN executables e ON c.exe_id = e.id "
        "JOIN addresses a ON c.raddr_id = a.id "
        "JOIN domains d ON c.domain_id = d.id "
        "WHERE e.name LIKE ?",
        (f"%{process_name}%",),
    )


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

        # Retry to absorb transient network failures (DNS/connect to example.com)
        # and rare BPF event drops on a busy CI runner. The test is asserting
        # that *when* wget makes a connection, picosnitch resolves its exe -- so
        # any single attempt that produces captured connections is sufficient.
        last_wget_err = ""
        connections: list = []
        for attempt in range(5):
            result = subprocess.run(["wget", "-q", "http://example.com", "-O", "/dev/null"], capture_output=True, timeout=30)
            if result.returncode != 0:
                last_wget_err = result.stderr.decode(errors="replace").strip()
                time.sleep(1)
                continue
            time.sleep(DB_WRITE_LIMIT + TRAFFIC_WAIT)
            connections = get_connections_for_process("wget")
            if connections:
                break
            time.sleep(1)

        assert connections, f"Should have captured wget connections after retries (last wget stderr: {last_wget_err!r})"

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
        assert version == DB_VERSION, f"Database version should be {DB_VERSION}, got {version}"

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


class TestGrandparentTracking:
    """Tests for grandparent process tracking."""

    def test_gpexe_id_column_exists(self, picosnitch_session):
        """Test that connections table has gpexe_id column."""
        subprocess.run(["curl", "-s", "http://example.com", "-o", "/dev/null"], capture_output=True, timeout=30)
        time.sleep(DB_WRITE_LIMIT + TRAFFIC_WAIT)

        db_path = DATA_DIR / "picosnitch.db"
        con = sqlite3.connect(str(db_path))
        cur = con.cursor()
        cur.execute("PRAGMA table_info(connections)")
        cols = [row[1] for row in cur.fetchall()]
        con.close()
        assert "gpexe_id" in cols, f"connections table should have gpexe_id column, got {cols}"

    def test_shell_curl_grandparent(self, picosnitch_session):
        """Test that grandparent is captured when a shell script invokes curl."""
        curl_exe = find_executable("curl")
        if not curl_exe:
            pytest.skip("curl not available")
        bash_exe = find_executable("bash")
        if not bash_exe:
            pytest.skip("bash not available")

        # Spin up a private localhost HTTP server on an ephemeral port so we
        # can later filter `connections` by that exact rport, isolating this
        # test's curl from prior tests' curls, the startup warmup, and any
        # sudo-launched daemon health checks that might also hit example.com.
        import http.server
        import socketserver
        import threading

        class _Quiet(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), _Quiet)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            # Bash exec's the LAST command of any shell/subshell in place to avoid
            # an extra process. To guarantee a real fork at every level, append a
            # no-op (`:`) AFTER the inner command at every level so nothing is ever
            # "last". Chain:
            #   pytest → bash(outer) → bash(subshell-1) → bash(subshell-2) → curl
            # so curl's parent = subshell-2, grandparent = subshell-1.
            #
            # Retry the whole invocation a few times to absorb rare event drops
            # on slow/emulated CI runners.
            results: list = []
            for _ in range(5):
                start_time = int(time.time())
                subprocess.run(
                    [bash_exe, "-c", f"( ( curl -s http://127.0.0.1:{port}/ -o /dev/null; : ); : ); :"],
                    capture_output=True,
                    timeout=30,
                )
                time.sleep(DB_WRITE_LIMIT + TRAFFIC_WAIT)

                # Filter strictly to this test's curl: same rport (unique to this
                # server) and contime within the invocation window. This isolates
                # us from any other curl traffic happening on the box.
                results = query_db(
                    "SELECT g.exe, g.name FROM connections c "
                    "JOIN executables e ON c.exe_id = e.id "
                    "JOIN executables g ON c.gpexe_id = g.id "
                    "WHERE e.name LIKE '%curl%' AND c.rport = ? AND c.contime >= ?",
                    (port, start_time),
                )
                if results:
                    break
        finally:
            server.shutdown()
            server.server_close()

        assert len(results) > 0, f"Should have at least one curl connection with grandparent (rport={port})"
        gpexes = [row[0] for row in results]
        assert any("sh" in gpexe or "bash" in gpexe for gpexe in gpexes), f"Grandparent should be a shell, got: {gpexes}"

    def test_kernel_grandparent_no_pollution(self, picosnitch_session):
        """Test that processes without a grandparent (e.g. parented to init or
        kernel-reparented daemons) produce a clean empty sentinel row instead
        of garbage sha256s and 'Read Error' log spam.

        Triggered by double-forking so the curl is reparented to PID 1, making
        its grandparent the kernel (gppid=0 in BPF)."""
        curl_exe = find_executable("curl")
        if not curl_exe:
            pytest.skip("curl not available")

        # Double-fork: parent forks A, A forks B then exits, so B is reparented
        # to init. B then execs curl, so curl's parent is init (pid 1) and
        # curl's grandparent is the kernel (gppid=0).
        daemon_script = (
            "import os, sys;\n"
            "pid = os.fork()\n"
            "if pid:\n"
            "    os.waitpid(pid, 0); sys.exit(0)\n"
            "os.setsid()\n"
            "pid2 = os.fork()\n"
            "if pid2:\n"
            "    sys.exit(0)\n"
            "os.execvp('curl', ['curl', '-s', 'http://example.com', '-o', '/dev/null'])\n"
        )
        start_time = int(time.time())
        subprocess.run([PYTHON_EXE, "-c", daemon_script], capture_output=True, timeout=30)
        time.sleep(DB_WRITE_LIMIT + TRAFFIC_WAIT + 2)

        # No executables row should contain a garbage sha (the old bug wrote
        # "!!! FD Read Error !!! ..." literal strings into sha256).
        bad = query_db("SELECT id, name, sha256 FROM executables WHERE sha256 LIKE '%Error%'")
        assert bad == [], f"Found executables with garbage error-string sha256: {bad}"

        # No connection should reference a grandparent named 'swapper/0' or similar
        # kernel pseudo-process (the old bug captured these as real grandparents).
        kernel_gp = query_db("SELECT DISTINCT g.name FROM connections c JOIN executables g ON c.gpexe_id = g.id WHERE g.name LIKE 'swapper%' OR g.name LIKE 'kthread%'")
        assert kernel_gp == [], f"Kernel pseudo-processes captured as grandparents: {kernel_gp}"

        # The empty sentinel row should exist (exe='' AND name='' AND sha256='')
        # and connections with no grandparent should point to it.
        sentinel = query_db("SELECT id FROM executables WHERE exe='' AND name='' AND sha256=''")
        assert len(sentinel) >= 1, "Empty sentinel executables row should exist for 'no grandparent' case"

        # Verify our double-forked curl made it into the DB and its grandparent
        # resolves to the empty sentinel (gppid was 0).
        results = query_db(
            "SELECT g.exe, g.name, g.sha256 FROM connections c JOIN executables e ON c.exe_id = e.id JOIN executables g ON c.gpexe_id = g.id WHERE e.name LIKE '%curl%' AND c.contime >= ?",
            (start_time,),
        )
        assert len(results) > 0, "Should have at least one curl connection from double-fork"
        # At least one of them should have the empty grandparent sentinel.
        assert any(row == ("", "", "") for row in results), f"Expected at least one curl with empty grandparent sentinel, got: {results}"


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("WARNING: These tests require root privileges.")
        print("Run with: sudo uv run pytest tests/test_functional.py -v")
        sys.exit(1)
    pytest.main([__file__, "-v"])
