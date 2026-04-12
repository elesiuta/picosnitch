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

    def __init__(self, pidfile: Path):
        self.pidfile = pidfile

    def daemonize(self):
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
        os.umask(0)
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
        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        with open(self.pidfile, "w+") as f:
            f.write(pid + "\n")

    def delpid(self):
        self.pidfile.unlink(missing_ok=True)

    def getpid(self):
        """Get the pid from the pidfile"""
        try:
            with open(self.pidfile, "r") as f:
                pid = int(f.read().strip())
        except IOError:
            pid = None
        return pid

    def start(self):
        """Start the daemon."""
        # Check for a pidfile to see if the daemon already runs
        pid = self.getpid()
        if pid:
            message = f"pidfile {self.pidfile} already exist. picosnitch already running?"
            logging.error(message)
            sys.exit(1)
        # Start the daemon
        self.daemonize()
        self.run()

    def stop(self):
        """Stop the daemon."""
        pid = self.getpid()
        if not pid:
            message = f"pidfile {self.pidfile} does not exist. picosnitch not running?"
            logging.warning(message)
            return  # not an error in a restart
        # Try killing the daemon process
        try:
            while 1:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
        except OSError as err:
            e = str(err.args)
            if e.find("No such process") > 0:
                if self.pidfile.exists():
                    self.pidfile.unlink()
            else:
                logging.error(f"{err.args}")
                sys.exit(1)

    def restart(self):
        """Restart the daemon."""
        self.stop()
        self.start()

    def status(self):
        """Get daemon status."""
        pid = self.getpid()
        if pid:
            try:
                with open(f"/proc/{pid}/cmdline", "r") as f:
                    cmdline = f.read()
            except Exception:
                cmdline = ""
            if "picosnitch" in cmdline:
                logging.info(f"picosnitch is currently running with pid {pid}.")
            else:
                logging.info("pidfile exists however picosnitch was not detected.")
        else:
            logging.info("picosnitch does not appear to be running.")

    def run(self):
        """Subclass Daemon and override this method"""
