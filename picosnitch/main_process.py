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

import ctypes
import ctypes.util
import multiprocessing
import os
import signal
import subprocess
import sys
import time

from .constants import FD_CACHE
from .monitor_subprocess import monitor_subprocess
from .primary_subprocess import primary_subprocess
from .process_manager import ProcessManager
from .rfuse_subprocess import rfuse_subprocess
from .secondary_subprocess import secondary_subprocess
from .virustotal_subprocess import virustotal_subprocess


def main_process(snitch: dict):
    """coordinates all picosnitch subprocesses"""
    # init fanotify
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    _FAN_CLASS_CONTENT = 0x4
    _FAN_UNLIMITED_MARKS = 0x20
    flags = _FAN_CLASS_CONTENT if FD_CACHE < 8192 else _FAN_CLASS_CONTENT | _FAN_UNLIMITED_MARKS
    fan_fd = libc.fanotify_init(flags, os.O_RDONLY)
    assert fan_fd >= 0, "fanotify_init() failed"
    # start subprocesses
    snitch_pipes = [multiprocessing.Pipe(duplex=False) for i in range(5)]
    snitch_recv_pipes, snitch_send_pipes = zip(*snitch_pipes)
    secondary_recv_pipe, secondary_send_pipe = multiprocessing.Pipe(duplex=False)
    q_error = multiprocessing.Queue()
    p_monitor = ProcessManager(name="snitchmonitor", target=monitor_subprocess,
                               init_args=(snitch["Config"], fan_fd, snitch_send_pipes, q_error,))
    p_rfuse = ProcessManager(name="snitchrfuse", target=rfuse_subprocess,
                             init_args=(snitch["Config"], q_error,))
    p_virustotal = ProcessManager(name="snitchvirustotal", target=virustotal_subprocess,
                                  init_args=(snitch["Config"], q_error,))
    p_primary = ProcessManager(name="snitchprimary", target=primary_subprocess,
                               init_args=(snitch, snitch_recv_pipes, secondary_send_pipe, q_error,))
    p_secondary = ProcessManager(name="snitchsecondary", target=secondary_subprocess,
                           init_args=(snitch, fan_fd, p_rfuse, p_virustotal, secondary_recv_pipe, p_primary.q_in, q_error,))
    # set signals
    subprocesses = [p_monitor, p_rfuse, p_virustotal, p_primary, p_secondary]
    def clean_exit():
        _ = [p.terminate() for p in subprocesses]
        sys.exit(0)
    signal.signal(signal.SIGINT, lambda *args: clean_exit())
    signal.signal(signal.SIGTERM, lambda *args: clean_exit())
    # watch subprocesses
    suspend_check_last = time.time()
    try:
        while True:
            time.sleep(5)
            if not all(p.is_alive() for p in subprocesses):
                dead = " ".join([p.name for p in subprocesses if not p.is_alive()])
                q_error.put(f"picosnitch subprocess died, attempting restart, terminate by running `picosnitch stop` ({dead})")
                break
            if any(p.is_zombie() for p in subprocesses):
                zombies = " ".join([p.name for p in subprocesses if p.is_zombie()])
                q_error.put(f"picosnitch subprocess became a zombie, attempting restart ({zombies})")
                break
            if sum(p.memory() for p in subprocesses) > 4096000000:
                q_error.put("picosnitch memory usage exceeded 4096 MB, attempting restart")
                break
            suspend_check_now = time.time()
            if suspend_check_now - suspend_check_last > 20:
                p_monitor.q_in.put("terminate")
                p_monitor.terminate()
                _ = p_monitor.q_in.get()
                p_monitor.start()
            suspend_check_last = suspend_check_now
    except Exception as e:
        q_error.put("picosnitch subprocess exception: %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))
    if sys.argv[1] == "start-no-daemon":
        return 1
    # attempt to restart picosnitch (terminate by running `picosnitch stop`)
    time.sleep(5)
    _ = [p.terminate() for p in subprocesses]
    args = [sys.executable, os.path.abspath(__file__), "restart"]
    subprocess.Popen(args)
    return 0

