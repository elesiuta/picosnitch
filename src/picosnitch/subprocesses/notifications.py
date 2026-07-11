# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import multiprocessing
import os
import pwd
import queue
import shutil
import subprocess

from picosnitch.config import Config


def _set_desktop_session_env(uid: int) -> None:
    """point notify-send at the target user's D-Bus session bus

    After dropping to desktop.user, the inherited env still holds root's (or no)
    XDG_RUNTIME_DIR / DBUS_SESSION_BUS_ADDRESS, so notify-send can't reach the
    user's session bus and every notification fails. Set the systemd-logind
    standard paths for that uid; without a running session at /run/user/<uid>
    notify-send still fails, but that is the user's login state, not our env.
    """
    os.environ["XDG_RUNTIME_DIR"] = f"/run/user/{uid}"
    os.environ["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{uid}/bus"
    try:
        os.environ["HOME"] = pwd.getpwuid(uid).pw_dir
    except KeyError:
        pass


def _send_notification(msg: str) -> subprocess.CompletedProcess:
    """fire-and-forget desktop notification via libnotify's notify-send"""
    return subprocess.run(
        ["notify-send", "--app-name=picosnitch", "--expire-time=2000", "--", "picosnitch", msg],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=5,  # a wedged notify-send / D-Bus must not block the notifier forever
    )


def run_notifications(config: Config, fan_fd: int, q_error: multiprocessing.Queue[str], q_in: multiprocessing.Queue[str], _q_out: multiprocessing.Queue) -> int:
    """notification subprocess: drops root then sends desktop notifications via notify-send (libnotify).

    Behavior:
    - desktop.notifications = false: silently drain the queue, never emit errors.
    - desktop.notifications = true, notify-send missing: emit one tagged
      q_error explaining how to fix it, then keep silently draining until
      notify-send appears (re-checked every drained message).
    - desktop.notifications = true, notify-send present: forward each
      distinct message; if notify-send exits non-zero, emit one tagged
      q_error per distinct stderr signature."""
    parent_process = multiprocessing.parent_process()
    assert parent_process is not None
    from ..utils import drop_root_permanent, resolve_unprivileged_user

    # close the privileged fanotify handle before dropping: never used here, must not persist into
    # the dropped-privilege domain
    try:
        os.close(fan_fd)
    except OSError:
        pass
    uid, gid = resolve_unprivileged_user(config.desktop.user)
    drop_root_permanent(uid, gid)
    if config.desktop.user:
        _set_desktop_session_env(uid)
    notifications_enabled = bool(config.desktop.notifications)
    last_notification = ""
    notify_send_missing_reported = False
    reported_send_failures: set[str] = set()
    while True:
        if not parent_process.is_alive():
            return 0
        try:
            msg = q_in.get(block=True, timeout=15)
        except queue.Empty:
            continue
        except Exception as e:
            q_error.put("notifier: queue.get %s%s on line %s" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?"))
            continue
        if not notifications_enabled:
            # silently drop; this path exists so _toast() in primary.py
            # never blocks on a full queue when the user disabled desktop
            # notifications in config.toml.
            continue
        if msg == last_notification:
            continue
        if shutil.which("notify-send") is None:
            if not notify_send_missing_reported:
                q_error.put(
                    "notifier: notify-send not found in PATH but desktop.notifications=true; "
                    "install libnotify (e.g. apt install libnotify-bin) or set desktop.notifications=false in config.toml to silence this"
                )
                notify_send_missing_reported = True
            continue
        if notify_send_missing_reported:
            q_error.put("notifier: notify-send is now available, resuming desktop notifications")
            notify_send_missing_reported = False
        try:
            result = _send_notification(msg)
        except Exception as e:
            sig = "%s%s" % (type(e).__name__, str(e.args))
            if sig not in reported_send_failures:
                reported_send_failures.add(sig)
                q_error.put(f"notifier: notify-send invocation raised {sig}")
            continue
        last_notification = msg
        if result.returncode != 0:
            stderr_text = (result.stderr or b"").decode("utf-8", "replace").strip()
            sig = f"rc={result.returncode} {stderr_text}"
            if sig not in reported_send_failures:
                reported_send_failures.add(sig)
                q_error.put(f"notifier: notify-send exited rc={result.returncode}" + (f": {stderr_text}" if stderr_text else ""))
