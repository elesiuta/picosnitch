#!/usr/bin/env python3
# picosnitch
# Copyright (C) 2020 Eric Lesiuta

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

import atexit
import importlib
import logging
import os
import sqlite3
import subprocess
import sys
import textwrap

from .config import load_config, write_default_config
from .constants import CACHE_DIR, CONFIG_DIR, DATA_DIR, LOG_DIR, RUN_DIR, VERSION
from .daemon import Daemon
from .main_loop import run_main_loop
from .ui.tui import tui_init
from .ui.webui import web_dashboard
from .utils import apply_data_permissions, load_state


def check_root(cmd: str) -> int | None:
    """check for root privileges, return exit code on failure"""
    if os.getuid() != 0:
        logging.error(f"This command requires root. Try: sudo {os.path.abspath(sys.argv[0])} {cmd}")
        return 1
    return None


def check_bpf() -> int | None:
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
    return None


def check_database() -> int | None:
    """check database exists and has correct version, return exit code on failure"""
    db_path = os.path.join(DATA_DIR, "picosnitch.db")
    if not os.path.exists(db_path):
        logging.error(f"Database not found: {db_path}")
        logging.error(f"Run: sudo {os.path.abspath(sys.argv[0])} init")
        return 1
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute(""" PRAGMA user_version """)
    user_version = cur.fetchone()[0]
    con.close()
    if user_version != 3:
        logging.error(f"Unsupported database version {user_version}, expected 3")
        return 1
    return None


def init_dirs_and_config() -> None:
    """create FHS directories, write default config, and create database if missing"""
    for d in [CONFIG_DIR, DATA_DIR, LOG_DIR, RUN_DIR, CACHE_DIR]:
        os.makedirs(d, exist_ok=True)
    config_path = os.path.join(CONFIG_DIR, "config.toml")
    if not os.path.exists(config_path):
        write_default_config(config_path)
    db_path = os.path.join(DATA_DIR, "picosnitch.db")
    if not os.path.exists(db_path):
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute(""" CREATE TABLE connections
                        (contime text, send integer, recv integer, exe text, name text, cmdline text, sha256 text, pexe text, pname text, pcmdline text, psha256 text, uid integer, lport integer, rport integer, laddr text, raddr text, domain text) """)
        cur.execute(""" PRAGMA user_version = 3 """)
        con.commit()
        con.close()
    apply_data_permissions(CONFIG_DIR, DATA_DIR, LOG_DIR, CACHE_DIR)


def main():
    """init picosnitch"""
    # master copy of config and state, all subprocesses only receive a static copy from this point in time
    config = load_config()
    state = load_state()
    # start picosnitch process monitor
    pid_file = os.path.join(RUN_DIR, "picosnitch.pid")
    with open(pid_file, "r") as f:
        pid = int(f.read().strip())
    if pid != os.getpid():
        logging.error(f"PID mismatch: pidfile has {pid}, current process is {os.getpid()}")
        sys.exit(1)
    sys.exit(run_main_loop(config, state))


def start_picosnitch():
    """command line interface, pre-startup checks, and run"""
    pid_file = os.path.join(RUN_DIR, "picosnitch.pid")

    class PicoDaemon(Daemon):
        def run(self):
            main()

    readme = textwrap.dedent(f"""    Monitor your system for applications that make network connections, track their
    bandwidth, verify hashes, and receive notifications.

    picosnitch comes with ABSOLUTELY NO WARRANTY. This is free software, and you
    are welcome to redistribute it under certain conditions. See version 3 of the
    GNU General Public License for details.

    website: https://github.com/elesiuta/picosnitch
    version: {VERSION}
    entrypoint: {os.path.abspath(sys.argv[0])}
    config: {CONFIG_DIR}
    data: {DATA_DIR}
    logs: {LOG_DIR}
    cache: {CACHE_DIR}

    usage:
        picosnitch dash|view|status|version|help
                    |    |    |      |       |--> this text
                    |    |    |      |--> version info
                    |    |    |--> show pid
                    |    |--> curses tui
                    |--> start web gui (http://{os.getenv("HOST", "localhost")}:{os.getenv("PORT", "5100")})

        sudo picosnitch init|start|stop|restart|start-no-daemon|systemd
                         |    |     |    |       |               |--> create service
                         |    |     |    |       |--> run without daemonizing
                         |    |_____|____|--> start/stop/restart daemon
                         |--> create directories and default config

        systemctl enable|disable|start|stop|restart|status picosnitch
                   |      |       |     |    |       |--> show status with systemd
                   |      |       |_____|____|--> start/stop/restart picosnitch
                   |______|--> enable/disable autostart on reboot

    * if systemctl isn't working, recreate the service with `sudo picosnitch systemd`
    * if you don't use systemd, you can use `sudo picosnitch start|stop|restart`
    * if the daemon isn't working, try `sudo picosnitch start-no-daemon`
    * if dash isn't working, try `picosnitch start-dash` to see any errors
    * available environment variables for dash: HOST, PORT, DASH_DEBUG
    """)
    systemd_service = textwrap.dedent(f"""    [Unit]
    Description=picosnitch

    [Service]
    Type=simple
    Restart=always
    RestartSec=5
    ExecStart={sys.executable} -m picosnitch start-no-daemon
    PIDFile={pid_file}

    # Hardening
    ProtectHome=read-only
    ProtectSystem=strict
    ReadWritePaths={DATA_DIR} {LOG_DIR} {RUN_DIR} {CACHE_DIR}
    PrivateTmp=yes
    NoNewPrivileges=yes
    CapabilityBoundingSet=CAP_SYS_ADMIN CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH
    ProtectKernelModules=yes
    ProtectKernelLogs=yes
    ProtectControlGroups=yes
    ProtectClock=yes
    RestrictRealtime=yes
    LockPersonality=yes
    RestrictSUIDSGID=yes

    [Install]
    WantedBy=multi-user.target
    """)
    if len(sys.argv) != 2:
        print(readme)
        return 2
    cmd = sys.argv[1]
    # nix platform checks
    if sys.executable.startswith("/nix/"):
        if cmd in ("start", "stop", "restart"):
            logging.warning("built in daemon mode is not supported on Nix, use picosnitch start-no-daemon or systemctl instead")
        if cmd == "systemd":
            logging.error("Command not supported on Nix, add `services.picosnitch.enable = true;` to your Nix configuration")
            return 2
    # command dispatch
    if cmd == "help":
        print(readme)
        return 0
    elif cmd == "version":
        print(f"version: {VERSION}")
        print(f"entrypoint: {os.path.abspath(sys.argv[0])}")
        print(f"config: {CONFIG_DIR}")
        print(f"data: {DATA_DIR}")
        print(f"logs: {LOG_DIR}")
        print(f"cache: {CACHE_DIR}")
        return 0
    elif cmd == "status":
        Daemon(pid_file).status()
        return 0
    elif cmd == "init":
        if err := check_root(cmd):
            return err
        init_dirs_and_config()
        logging.info("picosnitch initialized")
        return 0
    elif cmd == "systemd":
        if err := check_root(cmd):
            return err
        with open("/usr/lib/systemd/system/picosnitch.service", "w") as f:
            f.write(systemd_service)
        subprocess.run(["systemctl", "daemon-reload"])
        logging.info("Wrote /usr/lib/systemd/system/picosnitch.service\nYou can now run picosnitch using systemctl")
        return 0
    elif cmd == "stop":
        if err := check_root(cmd):
            return err
        if os.path.exists("/usr/lib/systemd/system/picosnitch.service") or os.path.exists("/etc/systemd/system/picosnitch.service"):
            logging.info("Found picosnitch.service but you are not using systemctl")
            if sys.stdin.isatty():
                confirm = input(f"Did you intend to run `systemctl {cmd} picosnitch` (y/N)? ")
                if confirm.lower().startswith("y"):
                    subprocess.run(["systemctl", cmd, "picosnitch"])
                    return 0
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
        # offer systemctl for start/restart
        if cmd in ("start", "restart"):
            if os.path.exists("/usr/lib/systemd/system/picosnitch.service") or os.path.exists("/etc/systemd/system/picosnitch.service"):
                logging.info("Found picosnitch.service but you are not using systemctl")
                if sys.stdin.isatty():
                    confirm = input(f"Did you intend to run `systemctl {cmd} picosnitch` (y/N)? ")
                    if confirm.lower().startswith("y"):
                        subprocess.run(["systemctl", cmd, "picosnitch"])
                        return 0
        # optional remote database
        config = load_config()
        if sql_kwargs := dict(config.database.remote):
            sql_client = sql_kwargs.pop("client", "no client error")
            table_name = sql_kwargs.pop("table_name", "connections")
            sql = importlib.import_module(sql_client)
            if sql_client not in ["mariadb", "psycopg", "psycopg2", "pymysql"]:
                logging.warning(f'using {sql_client} for database.remote "client" may not be supported, ensure it implements PEP 249')
            try:
                con = sql.connect(**sql_kwargs)
                cur = con.cursor()
                cur.execute(f""" CREATE TABLE IF NOT EXISTS {table_name}
                                 (contime text, send integer, recv integer, exe text, name text, cmdline text, sha256 text, pexe text, pname text, pcmdline text, psha256 text, uid integer, lport integer, rport integer, laddr text, raddr text, domain text) """)
                con.commit()
                con.close()
            except Exception as e:
                logging.warning(f"{type(e).__name__}{e.args} on line {sys.exc_info()[2].tb_lineno}")
        apply_data_permissions(CONFIG_DIR, DATA_DIR, LOG_DIR, CACHE_DIR)
        # dispatch
        if cmd == "start":
            logging.info("starting picosnitch daemon")
            PicoDaemon(pid_file).start()
        elif cmd == "restart":
            logging.info("restarting picosnitch daemon")
            PicoDaemon(pid_file).restart()
        elif cmd == "start-no-daemon":
            if os.path.exists(pid_file):
                logging.error(f"pid file already exists: {pid_file}")
                return 1

            def delpid():
                try:
                    os.remove(pid_file)
                except FileNotFoundError:
                    pass

            atexit.register(delpid)
            os.makedirs(RUN_DIR, exist_ok=True)
            with open(pid_file, "w") as f:
                f.write(str(os.getpid()) + "\n")
            logging.info("starting picosnitch in simple mode")
            logging.info(f"config: {CONFIG_DIR}")
            logging.info(f"data: {DATA_DIR}")
            logging.info(f"logs: {LOG_DIR}")
            sys.exit(main())
        return 0
    elif cmd == "dash":
        if err := check_database():
            return err
        try:
            import dash
            import pandas
            import plotly

            _ = dash.__version__ and pandas.__version__ and plotly.__version__
        except ImportError as e:
            logging.error(f"Missing required package for web dashboard: {e.name}")
            return 1
        logging.info(f"serving web gui on http://{os.getenv('HOST', 'localhost')}:{os.getenv('PORT', '5100')}")
        logging.info("if this fails, try running `picosnitch start-dash` to see any errors")
        return web_dashboard()
    elif cmd == "start-dash":
        if err := check_database():
            return err
        return web_dashboard()
    elif cmd == "view":
        if err := check_database():
            return err
        return tui_init()
    else:
        print(readme)
        return 2


if __name__ == "__main__":
    sys.exit(start_picosnitch())
