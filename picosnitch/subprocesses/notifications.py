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

import logging
import multiprocessing
import queue
import sys

from ..config import Config


def run_notifications(config: Config, q_error, q_in, _q_out):
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
