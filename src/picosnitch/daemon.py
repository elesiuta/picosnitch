# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

import atexit
import logging
import os
import signal
import sys
import time
from pathlib import Path


class Daemon:
    """A generic daemon class based on http://www.jejik.com/files/examples/daemon3x.py"""

    def __init__(self, pidfile: Path) -> None:
        self.pidfile = pidfile

    def daemonize(self) -> None:
        """Daemonize class. UNIX double fork mechanism."""
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as err:
            logging.error(f"fork #1 failed: {err}")
            sys.exit(1)
        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0o077)
        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError as err:
            logging.error(f"fork #2 failed: {err}")
            sys.exit(1)
        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(os.devnull, "r")
        so = open(os.devnull, "a+")
        se = open(os.devnull, "a+")
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
        # write pidfile (world-readable so non-root `picosnitch status` works)
        atexit.register(self.delpid)
        pid = str(os.getpid())
        with open(self.pidfile, "w+") as f:
            f.write(pid + "\n")
        try:
            os.chmod(self.pidfile, 0o644)
        except OSError:
            pass

    def delpid(self) -> None:
        self.pidfile.unlink(missing_ok=True)

    def getpid(self) -> int | None:
        """Get the pid from the pidfile"""
        try:
            with open(self.pidfile, "r") as f:
                pid = int(f.read().strip())
        except (IOError, ValueError):
            # missing, empty, or garbage pidfile
            pid = None
        return pid

    @staticmethod
    def _cmdline_is_picosnitch(cmdline: bytes) -> bool:
        """True only for a real picosnitch daemon cmdline, so a stale/recycled pid or a
        process that merely has 'picosnitch' somewhere in its argv is never mistaken for the
        daemon. Interpreter-agnostic (python, env, or a nix/bash wrapper are all fine):
        argv0 must be picosnitch or its interpreter, and picosnitch must appear as
        `-m picosnitch` or as a script path, together with a daemon subcommand."""
        parts = [part for part in cmdline.split(b"\0") if part]
        if not parts:
            return False
        daemon_cmds = {b"start", b"restart", b"start-no-daemon"}
        if not any(part in daemon_cmds for part in parts):
            return False

        def _is_picosnitch(part: bytes) -> bool:
            # nix runs the entry point as `.picosnitch-wrapped`; normalize before comparing
            return os.path.basename(part).lstrip(b".").split(b"-wrapped")[0] == b"picosnitch"

        # argv0 must be picosnitch itself or the interpreter/wrapper that launched it (python,
        # env, or a nix/bash wrapper), so a /path/to/picosnitch passed as a plain argument to an
        # unrelated program (e.g. `tail -f /var/backups/picosnitch start-no-daemon`) is not matched.
        argv0 = os.path.basename(parts[0])
        if not (_is_picosnitch(parts[0]) or argv0.startswith(b"python") or argv0 in (b"env", b"bash", b"sh", b"dash")):
            return False
        for i, part in enumerate(parts):
            if part == b"-m" and i + 1 < len(parts) and parts[i + 1] == b"picosnitch":
                return True
            if _is_picosnitch(part) and (b"/" in part or i == 0):
                return True
        return False

    def _pid_is_picosnitch(self, pid: int) -> bool:
        """True only if pid is a live picosnitch process, so a stale or recycled
        pid is never mistaken for the daemon (and never signalled)."""
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                return self._cmdline_is_picosnitch(f.read())
        except OSError:
            return False

    def start(self) -> None:
        """Start the daemon."""
        # Check for a pidfile to see if the daemon already runs
        pid = self.getpid()
        if pid and self._pid_is_picosnitch(pid):
            message = f"pidfile {self.pidfile} already exists. picosnitch already running?"
            logging.error(message)
            sys.exit(1)
        if pid:
            # stale pidfile left by a SIGKILL/OOM/crash (pid gone or recycled): clear it
            logging.warning(f"removing stale pidfile {self.pidfile} (pid {pid} is not picosnitch)")
            self.pidfile.unlink(missing_ok=True)
        # Start the daemon
        self.daemonize()
        self.run()

    def stop(self) -> None:
        """Stop the daemon."""
        pid = self.getpid()
        if not pid:
            message = f"pidfile {self.pidfile} does not exist. picosnitch not running?"
            logging.warning(message)
            return  # not an error in a restart
        if not self._pid_is_picosnitch(pid):
            # stale or recycled pid: clear the pidfile but never signal an unrelated process
            logging.warning(f"pidfile {self.pidfile} is stale (pid {pid} is not picosnitch), removing")
            self.pidfile.unlink(missing_ok=True)
            return
        # Signal until the process exits, bounded so a wedged process can't hang stop() forever
        deadline = time.time() + 60
        try:
            while time.time() < deadline:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
                if not self._pid_is_picosnitch(pid):
                    break
            else:
                logging.error(f"picosnitch (pid {pid}) did not exit within 60s of SIGTERM")
                return
        except OSError as err:
            if "No such process" not in str(err.args):
                logging.error(f"{err.args}")
                sys.exit(1)
        if self.pidfile.exists():
            self.pidfile.unlink()

    def restart(self) -> None:
        """Restart the daemon."""
        self.stop()
        self.start()

    def status(self) -> None:
        """Get daemon status."""
        pid = self.getpid()
        if pid:
            if self._pid_is_picosnitch(pid):
                logging.info(f"picosnitch is currently running with pid {pid}.")
            else:
                logging.info("pidfile exists but no picosnitch process is running.")
        else:
            logging.info("picosnitch does not appear to be running.")

    def run(self) -> None:
        """Subclass Daemon and override this method"""
