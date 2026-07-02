# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

import atexit
import importlib.util
import logging
import multiprocessing
import os
import re
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

from picosnitch.config import load_config, write_default_config
from picosnitch.constants import CACHE_DIR, CONFIG_DIR, DATA_DIR, DB_VERSION, LOG_DIR, RUN_DIR, SCHEMA_ADDRESSES, SCHEMA_CONNECTIONS, SCHEMA_DOMAINS, SCHEMA_EXECUTABLES, VERSION
from picosnitch.daemon import Daemon
from picosnitch.main_loop import run_main_loop
from picosnitch.ui.top import top_init
from picosnitch.ui.tui import tui_init
from picosnitch.ui.webui import web_dashboard
from picosnitch.utils import apply_data_permissions, connect_db_readonly, load_state, safe_log_open, sqlite_error_means_corrupt


def check_root(cmd: str) -> int:
    """check for root privileges, return exit code on failure"""
    if os.getuid() != 0:
        logging.error(f"This command requires root. Try: sudo {Path(sys.argv[0]).resolve()} {cmd}")
        return 1
    return 0


def check_bpf() -> int:
    """check BPF capabilities and requirements, return exit code on failure"""
    with open("/proc/self/status", "r") as f:
        proc_status = f.read()
    capeff = int(proc_status[proc_status.find("CapEff:") + 8 :].splitlines()[0].strip(), base=16)
    if not (capeff & (1 << 21)):
        logging.error("Missing capability CAP_SYS_ADMIN")
        return 1
    from .bpf_wrapper import check_bpf_requirements

    try:
        check_bpf_requirements()
    except (RuntimeError, FileNotFoundError) as e:
        logging.error(f"{e}")
        return 1
    return 0


def check_database() -> int:
    """check database exists and has correct version, return exit code on failure"""
    db_path = DATA_DIR / "picosnitch.db"
    if not db_path.exists():
        logging.error(f"Database not found: {db_path}")
        logging.error(f"Run: sudo {Path(sys.argv[0]).resolve()} start (or use systemctl) to create it")
        return 1
    con = None
    try:
        con = connect_db_readonly(db_path)
        cur = con.cursor()
        cur.execute("PRAGMA user_version")
        user_version = cur.fetchone()[0]
    except sqlite3.Error as e:
        # sqlite3.Error (not just OperationalError) so a corrupt db -> DatabaseError returns 1
        # instead of crashing the boot path (init_dirs_and_config quarantines it beforehand)
        logging.error(f"Could not open database {db_path}: {e}")
        return 1
    finally:
        if con is not None:
            con.close()
    if user_version != DB_VERSION:
        logging.error(f"Unsupported database version {user_version}, expected {DB_VERSION}")
        return 1
    return 0


def check_remote_config(remote: dict) -> int:
    """validate [database.remote] without importing the driver (third-party code never runs
    as root -- the unprivileged remote_sql subprocess imports it), return exit code on failure"""
    sql_kwargs = dict(remote)
    if not sql_kwargs:
        return 0
    sql_client = sql_kwargs.pop("client", "no client error")
    conn_table = sql_kwargs.pop("connections_table", "connections")
    if sql_client not in ["mariadb", "psycopg", "psycopg2", "pymysql"]:
        logging.error(f'unsupported database.remote "client": {sql_client}')
        return 1
    if not isinstance(conn_table, str) or not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", conn_table):
        logging.error(f"invalid remote table name: {conn_table!r}")
        return 1
    if importlib.util.find_spec(sql_client) is None:
        logging.error(f'database.remote "client" {sql_client} is not installed, install it or picosnitch[sql]')
        return 1
    return 0


def _db_is_corrupt(db_path: Path) -> bool:
    """True if the db can't be opened, its version read, or its expected tables are present -- such
    a db must be quarantined+recreated, else check_database or the secondary boot purge crash-loops
    the daemon. A valid db with the wrong version is NOT corrupt (returns False) so check_database
    can reject it without destroying migratable data."""
    try:
        con = sqlite3.connect(db_path)
        try:
            cur = con.cursor()
            if cur.execute("PRAGMA user_version").fetchone()[0] != DB_VERSION:
                return False  # wrong version but structurally readable -> leave for check_database
            # validate the tables AND the columns the boot purge / inserts need: a db with the
            # right table names but wrong columns (partial migration / foreign db sharing the
            # version) passes a name-only check yet crashes the secondary. LIMIT 0 validates the
            # columns without reading any rows; a missing table or column raises here.
            cur.execute("SELECT contime, domain_id, laddr_id, raddr_id FROM connections LIMIT 0")
            cur.execute("SELECT id FROM domains LIMIT 0")
            cur.execute("SELECT id FROM addresses LIMIT 0")
            cur.execute("SELECT id, exe, name, cmdline, sha256 FROM executables LIMIT 0")
            return False
        finally:
            con.close()
    except sqlite3.DatabaseError as e:
        # not a database / malformed header / missing table or column -> corrupt; a transient
        # error (locked by the live daemon or a user's sqlite session, busy, disk I/O) must
        # NOT quarantine a healthy db (`start` runs this before the already-running check)
        return sqlite_error_means_corrupt(e)


def init_dirs_and_config() -> None:
    """create FHS directories, write default config, and create database if missing"""
    for d in [CONFIG_DIR, DATA_DIR, LOG_DIR, RUN_DIR, CACHE_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    config_path = CONFIG_DIR / "config.toml"
    if not config_path.exists():
        write_default_config(config_path)
    db_path = DATA_DIR / "picosnitch.db"
    if db_path.exists() and _db_is_corrupt(db_path):
        # quarantine a corrupt db and recreate it below, so check_database / the secondary boot
        # purge don't crash-loop the daemon (data is kept in picosnitch.db.bad)
        logging.error(f"picosnitch.db is unusable, quarantining to {db_path.name}.bad and recreating")
        try:
            db_path.rename(db_path.with_name("picosnitch.db.bad"))
        except OSError:
            pass
    if not db_path.exists():
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute(f"CREATE TABLE executables ({SCHEMA_EXECUTABLES}) STRICT")
        cur.execute(f"CREATE TABLE domains ({SCHEMA_DOMAINS}) STRICT")
        cur.execute(f"CREATE TABLE addresses ({SCHEMA_ADDRESSES}) STRICT")
        cur.execute(f"CREATE TABLE connections ({SCHEMA_CONNECTIONS}) STRICT")
        cur.execute("INSERT INTO executables(id, exe, name, cmdline, sha256) VALUES (0, '', '', '', '')")
        cur.execute("INSERT INTO domains(id, domain) VALUES (0, '')")
        cur.execute("INSERT INTO addresses(id, addr) VALUES (0, '')")
        cur.execute("CREATE INDEX idx_contime ON connections(contime)")
        cur.execute("CREATE INDEX idx_exe_id_contime ON connections(exe_id, contime)")
        cur.execute("CREATE INDEX idx_pexe_id_contime ON connections(pexe_id, contime)")
        cur.execute("CREATE INDEX idx_gpexe_id_contime ON connections(gpexe_id, contime)")
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute(f"PRAGMA user_version = {DB_VERSION}")
        con.commit()
        con.close()
    apply_data_permissions(CONFIG_DIR, DATA_DIR, LOG_DIR, CACHE_DIR)


def main() -> None:
    """init picosnitch"""
    # master copy of config and state, all subprocesses only receive a static copy from this point in time
    config = load_config()
    state = load_state()
    # start picosnitch process monitor
    pid_file = RUN_DIR / "picosnitch.pid"
    with open(pid_file, "r") as f:
        pid = int(f.read().strip())
    if pid != os.getpid():
        logging.error(f"PID mismatch: pidfile has {pid}, current process is {os.getpid()}")
        sys.exit(1)
    sys.exit(run_main_loop(config, state))


def start_picosnitch() -> int:
    """command line interface, pre-startup checks, and run"""
    if sys.version_info < (3, 12):
        logging.error("Python version >= 3.12 is required")
        return 1
    if not sys.platform.startswith("linux"):
        logging.error("Did not detect a supported operating system")
        return 1
    multiprocessing.set_start_method("fork", force=True)
    pid_file = RUN_DIR / "picosnitch.pid"

    class PicoDaemon(Daemon):
        def run(self) -> None:
            try:
                main()
            except Exception:
                logging.exception("picosnitch daemon crashed")
                raise

    readme = textwrap.dedent(
        f"""
        Monitor your system for applications that make network connections, track their
        bandwidth, verify hashes, and receive notifications.

        Picosnitch comes with ABSOLUTELY NO WARRANTY. This is free software, and you
        are welcome to redistribute it under certain conditions. See version 3 of the
        GNU General Public License for details.

        website: https://github.com/elesiuta/picosnitch
        version: {VERSION}
        entrypoint: {Path(sys.argv[0]).resolve()}
        config: {CONFIG_DIR}
        data: {DATA_DIR}
        logs: {LOG_DIR}
        cache: {CACHE_DIR}
        run: {RUN_DIR}

        usage:
            picosnitch webui|tui|top|status|version|help
                        |     |   |   |      |       |--> this text
                        |     |   |   |      |--> version number
                        |     |   |   |--> show pid and service status
                        |     |   |--> live event monitor
                        |     |--> curses tui
                        |--> web gui (http://{os.getenv("PICOSNITCH_HOST", "localhost")}:{os.getenv("PICOSNITCH_PORT", "5100")})

            picosnitch start|stop|restart|start-no-daemon|systemd
                        |     |    |       |               |--> create service
                        |     |    |       |--> run without daemonizing
                        |_____|____|--> start/stop/restart daemon

            systemctl enable|disable|start|stop|restart|status picosnitch
                       |      |       |     |    |       |--> show status with systemd
                       |      |       |_____|____|--> start/stop/restart picosnitch
                       |______|--> enable/disable autostart on reboot

        * if systemctl isn't working, recreate the service with `sudo picosnitch systemd`
        * if you don't use systemd, you can use `sudo picosnitch start|stop|restart`
        * if the daemon isn't working, try `sudo picosnitch start-no-daemon`
        * available environment variables for webui: PICOSNITCH_HOST, PICOSNITCH_PORT
        """.lstrip("\n")
    )
    systemd_service = textwrap.dedent(
        f"""
        [Unit]
        Description=picosnitch

        [Service]
        Type=simple
        Restart=always
        RestartSec=5
        ExecStart={sys.executable} -m picosnitch start-no-daemon
        PIDFile={pid_file}

        # Auto-create FHS dirs (so ProtectSystem/ReadWritePaths can bind them on a clean install)
        RuntimeDirectory=picosnitch
        StateDirectory=picosnitch
        LogsDirectory=picosnitch
        CacheDirectory=picosnitch
        ConfigurationDirectory=picosnitch

        # Required for libbpf to mmap the per-cpu perf event ring buffers
        # (~16 MiB by default) without hitting the inherited 8 MiB cap.
        LimitMEMLOCK=infinity

        # Hardening
        ProtectHome=read-only
        ProtectSystem=strict
        ReadWritePaths={DATA_DIR} {LOG_DIR} {RUN_DIR} {CACHE_DIR}
        PrivateTmp=yes
        NoNewPrivileges=yes
        CapabilityBoundingSet=CAP_BPF CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_PERFMON CAP_SETGID CAP_SETUID CAP_SYS_ADMIN CAP_SYS_PTRACE
        ProtectKernelModules=yes
        ProtectKernelLogs=yes
        ProtectControlGroups=yes
        ProtectClock=yes
        RestrictRealtime=yes
        LockPersonality=yes
        RestrictSUIDSGID=yes

        [Install]
        WantedBy=multi-user.target
        """.lstrip("\n")
    )
    if len(sys.argv) != 2:
        print(readme)
        return 2
    cmd = sys.argv[1]
    # the built-in daemon (start/stop/restart) works on Nix once picosnitch is re-invoked
    # via its wrapped entry point rather than `-m picosnitch`; only `systemd` is unsupported
    if sys.executable.startswith("/nix/") and cmd == "systemd":
        logging.error("Command not supported on Nix, add `services.picosnitch.enable = true;` to your Nix configuration")
        return 2
    # command dispatch
    if cmd == "help":
        print(readme)
        return 0
    elif cmd == "version":
        print(f"version: {VERSION}")
        return 0
    elif cmd == "status":
        Daemon(pid_file).status()
        if Path("/usr/lib/systemd/system/picosnitch.service").exists() or Path("/etc/systemd/system/picosnitch.service").exists():
            try:
                r = subprocess.run(["systemctl", "is-active", "picosnitch"], capture_output=True, text=True, check=False)
                state = (r.stdout or r.stderr).strip() or "unknown"
            except FileNotFoundError:
                state = "unknown (systemctl not found)"
            logging.info(f"picosnitch.service (systemd): {state}")
        return 0
    elif cmd == "systemd":
        if err := check_root(cmd):
            return err
        with open("/usr/lib/systemd/system/picosnitch.service", "w") as f:
            f.write(systemd_service)
        subprocess.run(["systemctl", "daemon-reload"])
        logging.info("Wrote /usr/lib/systemd/system/picosnitch.service")
        logging.info("Enable on boot and start now with: sudo systemctl enable --now picosnitch")
        return 0
    elif cmd == "stop":
        if err := check_root(cmd):
            return err
        if Path("/usr/lib/systemd/system/picosnitch.service").exists() or Path("/etc/systemd/system/picosnitch.service").exists():
            try:
                active = (
                    subprocess.run(
                        ["systemctl", "is-active", "--quiet", "picosnitch"],
                        check=False,
                    ).returncode
                    == 0
                )
            except FileNotFoundError:
                active = False
            if active:
                logging.info("picosnitch.service is active under systemd; killing the pid would just be respawned by Restart=always")
                if sys.stdin.isatty():
                    try:
                        confirm = input("Run `systemctl stop picosnitch` instead (Y/n)? ")
                    except EOFError:
                        confirm = ""
                    if not confirm.lower().startswith("n"):
                        subprocess.run(["systemctl", "stop", "picosnitch"])
                        return 0
                else:
                    logging.error("aborted; run `systemctl stop picosnitch` instead")
                    return 1
        logging.info("stopping picosnitch daemon")
        Daemon(pid_file).stop()
        return 0
    elif cmd in ("start", "restart", "start-no-daemon"):
        if err := check_root(cmd):
            return err
        if err := check_bpf():
            return err
        init_dirs_and_config()
        if err := check_database():
            return err
        if err := check_remote_config(load_config().database.remote):
            return err
        # offer systemctl for start/restart
        if cmd in ("start", "restart"):
            if Path("/usr/lib/systemd/system/picosnitch.service").exists() or Path("/etc/systemd/system/picosnitch.service").exists():
                try:
                    active = (
                        subprocess.run(
                            ["systemctl", "is-active", "--quiet", "picosnitch"],
                            check=False,
                        ).returncode
                        == 0
                    )
                except FileNotFoundError:
                    active = False
                if active:
                    logging.info("picosnitch.service is active under systemd; the built-in daemon would conflict with it")
                    if sys.stdin.isatty():
                        try:
                            confirm = input(f"Run `systemctl {cmd} picosnitch` instead (Y/n)? ")
                        except EOFError:
                            confirm = ""
                        if not confirm.lower().startswith("n"):
                            subprocess.run(["systemctl", cmd, "picosnitch"])
                            return 0
                    else:
                        logging.error(f"aborted; run `systemctl {cmd} picosnitch` instead")
                        return 1
                else:
                    logging.info("Found picosnitch.service but you are not using systemctl")
                    if sys.stdin.isatty():
                        try:
                            confirm = input(f"Did you intend to run `systemctl {cmd} picosnitch` (y/N)? ")
                        except EOFError:
                            confirm = ""
                        if confirm.lower().startswith("y"):
                            subprocess.run(["systemctl", cmd, "picosnitch"])
                            return 0
        apply_data_permissions(CONFIG_DIR, DATA_DIR, LOG_DIR, CACHE_DIR)
        # log warnings/errors to the existing error.log so failures in the
        # forked daemon (where stderr is /dev/null) are still visible.
        # Use O_NOFOLLOW so the daemon never follows an attacker-placed
        # symlink in LOG_DIR (relevant when [data].owner is non-root).
        error_log_stream = safe_log_open(LOG_DIR / "error.log")
        error_log_handler = logging.StreamHandler(error_log_stream)
        error_log_handler.setLevel(logging.WARNING)
        error_log_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        logging.getLogger().addHandler(error_log_handler)
        # dispatch
        if cmd == "start":
            logging.info("starting picosnitch daemon")
            PicoDaemon(pid_file).start()
        elif cmd == "restart":
            logging.info("restarting picosnitch daemon")
            PicoDaemon(pid_file).restart()
        elif cmd == "start-no-daemon":
            if pid_file.exists():
                logging.error(f"pid file already exists: {pid_file}")
                return 1

            def delpid():
                try:
                    pid_file.unlink()
                except FileNotFoundError:
                    pass

            atexit.register(delpid)
            RUN_DIR.mkdir(parents=True, exist_ok=True)
            with open(pid_file, "w") as f:
                f.write(str(os.getpid()) + "\n")
            try:
                os.chmod(pid_file, 0o644)
            except OSError:
                pass
            logging.info("starting picosnitch in simple mode")
            logging.info(f"config: {CONFIG_DIR}")
            logging.info(f"data: {DATA_DIR}")
            logging.info(f"logs: {LOG_DIR}")
            sys.exit(main())
        return 0
    elif cmd == "webui":
        if err := check_database():
            return err
        return web_dashboard()
    elif cmd == "tui":
        if err := check_database():
            return err
        return tui_init()
    elif cmd == "top":
        return top_init()
    else:
        print(readme)
        return 2


if __name__ == "__main__":
    sys.exit(start_picosnitch())
