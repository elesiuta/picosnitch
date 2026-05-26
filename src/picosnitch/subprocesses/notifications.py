# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import logging
import multiprocessing
import os
import queue
import shutil
import subprocess

from picosnitch.config import Config


def _send_notification(msg: str) -> None:
    """fire-and-forget desktop notification via libnotify's notify-send"""
    subprocess.run(
        ["notify-send", "--app-name=picosnitch", "--expire-time=2000", "picosnitch", msg],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def run_notifications(config: Config, fan_fd: int, q_error: multiprocessing.Queue[str], q_in: multiprocessing.Queue[str], _q_out: multiprocessing.Queue) -> int:
    """notification subprocess: drops root then sends desktop notifications via notify-send (libnotify)"""
    parent_process = multiprocessing.parent_process()
    assert parent_process is not None
    if config.desktop.user:
        from ..utils import drop_root_permanent, resolve_group, resolve_owner

        uid = resolve_owner(config.desktop.user)
        gid = resolve_group(config.desktop.user)
        drop_root_permanent(uid, gid)
    # fan_fd is inherited via fork() but this subprocess never uses it;
    # closing it prevents leaking a privileged fanotify handle into a
    # dropped-privilege security domain.
    try:
        os.close(fan_fd)
    except OSError:
        pass
    notifier_ready = bool(config.desktop.notifications) and shutil.which("notify-send") is not None
    last_notification = ""
    pending: list[str] = []
    while True:
        if not parent_process.is_alive():
            return 0
        try:
            msg = q_in.get(block=True, timeout=15)
            if notifier_ready:
                if msg != last_notification:
                    last_notification = msg
                    _send_notification(msg)
            else:
                logging.warning(msg)
                pending.append(msg)
                if config.desktop.notifications and shutil.which("notify-send") is not None:
                    notifier_ready = True
                    for queued_msg in pending:
                        try:
                            if queued_msg != last_notification:
                                last_notification = queued_msg
                                _send_notification(queued_msg)
                        except Exception:
                            pass
                    pending = []
        except queue.Empty:
            pass
        except Exception as e:
            q_error.put("notification subprocess %s%s on line %s" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?"))
