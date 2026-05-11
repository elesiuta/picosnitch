# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import logging
import multiprocessing
import queue
import sys

from ..config import Config


def run_notifications(config: Config, q_error: multiprocessing.Queue[str], q_in: multiprocessing.Queue[str], _q_out: multiprocessing.Queue) -> int:
    """notification subprocess: drops root then sends desktop notifications via D-Bus"""
    parent_process = multiprocessing.parent_process()
    # drop root before importing dbus
    if config.desktop.user:
        from ..utils import drop_root_permanent, resolve_group, resolve_owner

        uid = resolve_owner(config.desktop.user)
        gid = resolve_group(config.desktop.user)
        drop_root_permanent(uid, gid)
    # try to set up dbus notifications
    dbus_ready = False
    system_notification = None
    if config.desktop.notifications:
        try:
            import dbus

            dbus_session_obj = dbus.SessionBus().get_object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
            interface = dbus.Interface(dbus_session_obj, "org.freedesktop.Notifications")

            def system_notification(msg):
                return interface.Notify("picosnitch", 0, "", "picosnitch", msg, [], [], 2000)

            dbus_ready = True
        except Exception:
            pass
    last_notification = ""
    pending = []
    while True:
        if not parent_process.is_alive():
            return 0
        try:
            msg = q_in.get(block=True, timeout=15)
            if dbus_ready:
                if msg != last_notification:
                    last_notification = msg
                    system_notification(msg)
            else:
                logging.warning(msg)
                pending.append(msg)
                if config.desktop.notifications:
                    try:
                        import dbus

                        dbus_session_obj = dbus.SessionBus().get_object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
                        interface = dbus.Interface(dbus_session_obj, "org.freedesktop.Notifications")

                        def system_notification(msg):
                            return interface.Notify("picosnitch", 0, "", "picosnitch", msg, [], [], 2000)

                        dbus_ready = True
                        for queued_msg in pending:
                            try:
                                if queued_msg != last_notification:
                                    last_notification = queued_msg
                                    system_notification(queued_msg)
                            except Exception:
                                pass
                        pending = []
                    except Exception:
                        pass
        except queue.Empty:
            pass
        except Exception as e:
            q_error.put("notification subprocess %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))
