#!/usr/bin/env python3
# picosnitch
# Copyright (C) 2020-2023 Eric Lesiuta

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
import importlib.util
import os
import site
import sqlite3
import subprocess
import sys
import textwrap

from .constants import BASE_PATH, VERSION
from .daemon import Daemon
from .main_process import main_process
from .user_interface import ui_dash, ui_init
from .utils import read_snitch


def main():
    """init picosnitch"""
    # master copy of the snitch dictionary, all subprocesses only receive a static copy of it from this point in time
    snitch = read_snitch()
    # start picosnitch process monitor
    with open("/run/picosnitch.pid", "r") as f:
        assert int(f.read().strip()) == os.getpid()
    if __name__ == "__main__" or sys.argv[1] == "start-no-daemon":
        sys.exit(main_process(snitch))
    print("Snitch subprocess init failed, __name__ != __main__", file=sys.stderr)
    sys.exit(1)


def start_picosnitch():
    """command line interface, pre-startup checks, and run"""
    readme = textwrap.dedent(f"""    Monitor your system for applications that make network connections, track their
    bandwidth, verify hashes, and receive notifications.

    picosnitch comes with ABSOLUTELY NO WARRANTY. This is free software, and you
    are welcome to redistribute it under certain conditions. See version 3 of the
    GNU General Public License for details.

    website: https://elesiuta.github.io/picosnitch
    version: {VERSION} ({os.path.abspath(__file__)})
    config and log files: {BASE_PATH}

    usage:
        picosnitch dash|view|status|version|help
                    |    |    |      |       |--> this text
                    |    |    |      |--> version info
                    |    |    |--> show pid
                    |    |--> curses tui
                    |--> start web gui (http://{os.getenv("HOST", "localhost")}:{os.getenv("PORT", "5100")})

        systemctl enable|disable|start|stop|restart|status picosnitch
                   |      |       |     |    |       |--> show status with systemd
                   |      |       |_____|____|--> start/stop/restart picosnitch
                   |______|--> enable/disable autostart on reboot

    * if systemctl isn't working, recreate the service with `picosnitch systemd`
    * if you don't use systemd, you can use `picosnitch start|stop|restart` instead
    * if the daemon isn't working, try `picosnitch start-no-daemon`
    * if dash isn't working, try `picosnitch start-dash` to see any errors
    * available environment variables for dash: HOST, PORT, DASH_DEBUG
    """)
    systemd_service = textwrap.dedent(f"""    [Unit]
    Description=picosnitch

    [Service]
    Type=simple
    Restart=always
    RestartSec=5
    Environment="SUDO_UID={os.getenv("SUDO_UID")}" "SUDO_USER={os.getenv("SUDO_USER")}" "DBUS_SESSION_BUS_ADDRESS={os.getenv("DBUS_SESSION_BUS_ADDRESS")}" "PYTHON_USER_SITE={site.USER_SITE}"
    ExecStart={sys.executable} "{os.path.abspath(__file__)}" start-no-daemon
    PIDFile=/run/picosnitch.pid

    [Install]
    WantedBy=multi-user.target
    """)
    if len(sys.argv) == 2:
        # platform checks
        if sys.executable.startswith("/snap/"):
            if sys.argv[1] in ["start", "stop", "restart", "systemd"]:
                print("Command not supported by picosnitch snap, use `snap <command> picosnitch` or `systemctl <command> snap.picosnitch.daemon`", file=sys.stderr)
                return 2
        elif sys.executable.startswith("/nix/"):
            if sys.argv[1] in ["start", "stop", "restart", "start-no-daemon"]:
                if sys.argv[1] in ["start", "stop", "restart"]:
                    print("WARNING: built in daemon mode is not supported on Nix, use picosnitch start-no-daemon or systemctl instead", file=sys.stderr)
                if os.getuid() != 0:
                    print("ERROR: picosnitch requires root privileges to run", file=sys.stderr)
                    return 1
            elif sys.argv[1] == "systemd":
                print("Command not supported on Nix, add `services.picosnitch.enable = true;` to your Nix configuration", file=sys.stderr)
                return 2
        # privelage checks if required or just show help and exit
        if sys.argv[1] == "help":
            print(readme)
            return 0
        elif sys.argv[1] in ["start", "stop", "restart", "start-no-daemon", "systemd"]:
            if os.getuid() != 0:
                args = ["sudo", "-E", sys.executable, os.path.abspath(__file__), sys.argv[1]]
                os.execvp("sudo", args)
            with open("/proc/self/status", "r") as f:
                proc_status = f.read()
                capeff = int(proc_status[proc_status.find("CapEff:")+8:].splitlines()[0].strip(), base=16)
                cap_sys_admin = 2**21
                assert capeff & cap_sys_admin, "Missing capability CAP_SYS_ADMIN"
            assert importlib.util.find_spec("bcc"), "Requires BCC https://github.com/iovisor/bcc/blob/master/INSTALL.md"
        # config and database checks and init
        tmp_snitch = read_snitch()
        assert os.path.exists(os.path.join(BASE_PATH, "snitch.db")) or os.getuid() == 0, "Requires root privileges to create database"
        con = sqlite3.connect(os.path.join(BASE_PATH, "snitch.db"))
        cur = con.cursor()
        cur.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='connections' ''')
        if cur.fetchone()[0] != 1:
            cur.execute(''' CREATE TABLE connections
                            (contime text, send integer, recv integer, exe text, name text, cmdline text, sha256 text, pexe text, pname text, pcmdline text, psha256 text, uid integer, lport integer, rport integer, laddr text, raddr text, domain text) ''')
            cur.execute(''' PRAGMA user_version = 3 ''')
            con.commit()
        else:
            cur.execute(''' PRAGMA user_version ''')
            user_version = cur.fetchone()[0]
            if user_version <= 2:
                assert not os.path.exists("/run/picosnitch.pid"), "cannot upgrade database while picosnitch daemon is running"
                print("Upgrading database, please wait...")
            if user_version == 0:
                cur.execute(''' ALTER TABLE connections RENAME COLUMN events TO conns ''')
                cur.execute(''' ALTER TABLE connections ADD COLUMN send integer DEFAULT 0 NOT NULL ''')
                cur.execute(''' ALTER TABLE connections ADD COLUMN recv integer DEFAULT 0 NOT NULL ''')
                cur.execute(''' PRAGMA user_version = 1 ''')
                con.commit()
            if user_version <= 1:
                cur.execute(''' ALTER TABLE connections RENAME TO tmp ''')
                cur.execute(''' CREATE TABLE connections
                                (exe text, name text, cmdline text, sha256 text, contime text, domain text, ip text, port integer, uid integer, pexe text DEFAULT "", pname text DEFAULT "", pcmdline text DEFAULT "", psha256 text DEFAULT "", conns integer, send integer, recv integer) ''')
                cur.execute(''' INSERT INTO connections
                                (exe, name, cmdline, sha256, contime, domain, ip, port, uid, conns, send, recv) SELECT exe, name, cmdline, sha256, contime, domain, ip, port, uid, conns, send, recv FROM tmp ''')
                cur.execute(''' DROP TABLE tmp ''')
                cur.execute(''' PRAGMA user_version = 2 ''')
                con.commit()
            if user_version <= 2:
                cur.execute(''' ALTER TABLE connections RENAME TO tmp ''')
                cur.execute(''' CREATE TABLE connections
                                (contime text, send integer, recv integer, exe text, name text, cmdline text, sha256 text, pexe text, pname text, pcmdline text, psha256 text, uid integer, lport integer, rport integer, laddr text, raddr text, domain text) ''')
                cur.execute(''' INSERT INTO connections
                                (contime, send, recv, exe, name, cmdline, sha256, pexe, pname, pcmdline, psha256, uid, lport, rport, laddr, raddr, domain) SELECT contime, send, recv, exe, name, cmdline, sha256, pexe, pname, pcmdline, psha256, uid, -1, port, "", ip, domain FROM tmp ''')
                cur.execute(''' DROP TABLE tmp ''')
                cur.execute(''' PRAGMA user_version = 3 ''')
                con.commit()
                con.execute(''' VACUUM ''')
                print("Database upgrade complete")
        con.close()
        # optional remote database
        if sql_kwargs := tmp_snitch["Config"]["DB sql server"]:
            sql_client = sql_kwargs.pop("client", "no client error")
            table_name = sql_kwargs.pop("table_name", "connections")
            sql = importlib.import_module(sql_client)
            if sql_client not in ["mariadb", "psycopg", "psycopg2", "pymysql"]:
                print(f"Warning, using {sql_client} for \"DB sql server\" \"client\" may not be supported, ensure it implements PEP 249", file=sys.stderr)
            try:
                con = sql.connect(**sql_kwargs)
                cur = con.cursor()
                cur.execute(f''' CREATE TABLE IF NOT EXISTS {table_name}
                                 (contime text, send integer, recv integer, exe text, name text, cmdline text, sha256 text, pexe text, pname text, pcmdline text, psha256 text, uid integer, lport integer, rport integer, laddr text, raddr text, domain text) ''')
                con.commit()
                con.close()
            except Exception as e:
                print("Warning: %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno), file=sys.stderr)
        # offer to use systemctl instead of built in daemon
        if sys.argv[1] in ["start", "stop", "restart"]:
            if os.path.exists("/usr/lib/systemd/system/picosnitch.service") or os.path.exists("/etc/systemd/system/picosnitch.service"):
                print("Found picosnitch.service but you are not using systemctl")
                if sys.stdin.isatty():
                    confirm = input(f"Did you intend to run `systemctl {sys.argv[1]} picosnitch` (y/N)? ")
                    if confirm.lower().startswith("y"):
                        subprocess.run(["systemctl", sys.argv[1], "picosnitch"])
                        return 0
        # init built in daemon control
        class PicoDaemon(Daemon):
            def run(self):
                main()
        daemon = PicoDaemon("/run/picosnitch.pid")
        # process command line arguments
        if sys.argv[1] == "start":
            print("starting picosnitch daemon")
            daemon.start()
        elif sys.argv[1] == "stop":
            print("stopping picosnitch daemon")
            daemon.stop()
        elif sys.argv[1] == "restart":
            print("restarting picosnitch daemon")
            daemon.restart()
        # daemon pid (for built in or systemd)
        elif sys.argv[1] == "status":
            daemon.status()
        # create systemd service file (intended for installing from PyPI or runnning script directly)
        elif sys.argv[1] == "systemd":
            with open("/usr/lib/systemd/system/picosnitch.service", "w") as f:
                f.write(systemd_service)
            subprocess.run(["systemctl", "daemon-reload"])
            print("Wrote /usr/lib/systemd/system/picosnitch.service\nYou can now run picosnitch using systemctl")
            return 0
        # simple mode (intended for running from systemd or debugging)
        elif sys.argv[1] == "start-no-daemon":
            assert not os.path.exists("/run/picosnitch.pid"), "pid file already exists"
            def delpid():
                os.remove("/run/picosnitch.pid")
            atexit.register(delpid)
            if sys.executable.startswith("/nix/"):
                os.makedirs("/run/picosnitch", exist_ok=True)
            with open("/run/picosnitch.pid", "w") as f:
                f.write(str(os.getpid()) + "\n")
            print("starting picosnitch in simple mode")
            print(f"using config and log files from: {BASE_PATH}")
            print(f"using DBUS_SESSION_BUS_ADDRESS: {os.getenv('DBUS_SESSION_BUS_ADDRESS')}")
            sys.exit(main())
        # web gui (launches browser and detaches from terminal on supported platforms (not snap or nix))
        elif sys.argv[1] == "dash":
            site.addsitedir(os.path.expanduser(f"~/.local/pipx/venvs/dash/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"))
            site.addsitedir(os.path.expandvars(f"$PIPX_HOME/venvs/dash/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"))
            import dash, pandas, plotly
            assert dash.__version__ and pandas.__version__ and plotly.__version__
            try:
                os.setgid(int(os.getenv("SUDO_UID")))
                os.setuid(int(os.getenv("SUDO_UID")))
            except Exception:
                pass
            print(f"serving web gui on http://{os.getenv('HOST', 'localhost')}:{os.getenv('PORT', '5100')}")
            print("if this fails, try running `picosnitch start-dash` to see any errors")
            if sys.executable.startswith("/snap/") or sys.executable.startswith("/nix/"):
                subprocess.Popen(["bash", "-c", f'/usr/bin/env python3 -m webbrowser -t http://{os.getenv("HOST", "localhost")}:{os.getenv("PORT", "5100")}'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return ui_dash()
            subprocess.Popen(["bash", "-c", f'let i=0; rm {BASE_PATH}/dash; while [[ ! -f {BASE_PATH}/dash || "$i" -gt 30 ]]; do let i++; sleep 1; done; rm {BASE_PATH}/dash && /usr/bin/env python3 -m webbrowser -t http://{os.getenv("HOST", "localhost")}:{os.getenv("PORT", "5100")}'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            args = ["bash", "-c", f"touch {BASE_PATH}/dash; nohup {sys.executable} \"{os.path.abspath(__file__)}\" start-dash > /dev/null 2>&1 &"]
            os.execvp("bash", args)
        # web gui without launching browser or detaching from terminal (intended for debugging)
        elif sys.argv[1] == "start-dash":
            return ui_dash()
        # terminal interface
        elif sys.argv[1] == "view":
            return ui_init()
        # show version or help if invalid argument and exit
        elif sys.argv[1] == "version":
            print(f"version: {VERSION} ({os.path.abspath(__file__)})\nconfig and log files: {BASE_PATH}")
            return 0
        else:
            print(readme)
            return 2
        return 0
    else:
        print(readme)
        return 2


if __name__ == "__main__":
    sys.exit(start_picosnitch())

