# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import ctypes
import ctypes.util
import logging
import multiprocessing
import os
import signal
import subprocess
import sys
import time

from .config import Config
from .constants import FD_CACHE
from .process_manager import ProcessManager
from .subprocesses.fuse import run_fuse
from .subprocesses.monitor import run_monitor
from .subprocesses.notifications import run_notifications
from .subprocesses.primary import run_primary
from .subprocesses.secondary import run_secondary
from .subprocesses.virustotal import run_virustotal
from .types import State


def run_main_loop(config: Config, state: State) -> int:
    """coordinates all picosnitch subprocesses"""
    # init fanotify
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    _FAN_CLASS_CONTENT = 0x4
    _FAN_UNLIMITED_MARKS = 0x20
    flags = _FAN_CLASS_CONTENT if FD_CACHE < 8192 else _FAN_CLASS_CONTENT | _FAN_UNLIMITED_MARKS
    fan_fd = libc.fanotify_init(flags, os.O_RDONLY)
    if fan_fd < 0:
        logging.error("fanotify_init() failed")
        sys.exit(1)
    # start subprocesses
    event_pipes = [multiprocessing.Pipe(duplex=False) for _ in range(5)]
    event_recv_pipes, event_send_pipes = zip(*event_pipes)
    secondary_recv_pipe, secondary_send_pipe = multiprocessing.Pipe(duplex=False)
    q_error: multiprocessing.Queue[str] = multiprocessing.Queue()
    p_notifications = ProcessManager(
        name="snitchnotify",
        target=run_notifications,
        init_args=(
            config,
            q_error,
        ),
    )
    p_monitor = ProcessManager(
        name="snitchmonitor",
        target=run_monitor,
        init_args=(
            config,
            fan_fd,
            event_send_pipes,
            q_error,
        ),
    )
    p_fuse = ProcessManager(
        name="snitchrfuse",
        target=run_fuse,
        init_args=(
            config,
            q_error,
        ),
    )
    p_virustotal = ProcessManager(
        name="snitchvirustotal",
        target=run_virustotal,
        init_args=(
            config,
            q_error,
        ),
    )
    p_primary = ProcessManager(
        name="snitchprimary",
        target=run_primary,
        init_args=(
            state,
            event_recv_pipes,
            secondary_send_pipe,
            q_error,
            p_notifications.q_in,
        ),
    )
    p_secondary = ProcessManager(
        name="snitchsecondary",
        target=run_secondary,
        init_args=(
            config,
            state,
            fan_fd,
            p_fuse,
            p_virustotal,
            secondary_recv_pipe,
            p_primary.q_in,
            q_error,
        ),
    )
    # set signals
    subprocesses = [p_monitor, p_fuse, p_virustotal, p_primary, p_secondary, p_notifications]

    def clean_exit() -> None:
        for p in subprocesses:
            p.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, lambda signum, frame: clean_exit())
    signal.signal(signal.SIGTERM, lambda signum, frame: clean_exit())
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
                p_monitor.q_in.get()
                p_monitor.start()
            suspend_check_last = suspend_check_now
    except Exception as e:
        tb = sys.exc_info()[2]
        q_error.put("picosnitch subprocess exception: %s%s on line %s" % (type(e).__name__, str(e.args), tb.tb_lineno if tb else "?"))
    if sys.argv[1] == "start-no-daemon":
        return 1
    # attempt to restart picosnitch (terminate by running `picosnitch stop`)
    time.sleep(5)
    for p in subprocesses:
        p.terminate()
    args = [sys.executable, "-m", "picosnitch", "restart"]
    subprocess.Popen(args)
    return 0
