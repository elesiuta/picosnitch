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

import os
import sys


class NotificationManager:
    """A singleton for creating system tray notifications, holds notifications in queue if fails, prints if disabled"""
    __instance = None
    dbus_notifications = False
    notifications_ready = False
    notification_queue = []
    last_notification = ""
    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            cls.__instance = super(NotificationManager, cls).__new__(cls, *args, **kwargs)
        return cls.__instance

    def enable_notifications(self):
        self.dbus_notifications = True
        try:
            import dbus
            os.seteuid(int(os.getenv("SUDO_UID")))
            dbus_session_obj = dbus.SessionBus().get_object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
            interface = dbus.Interface(dbus_session_obj, "org.freedesktop.Notifications")
            self.system_notification = lambda msg: interface.Notify("picosnitch", 0, "", "picosnitch", msg, [], [], 2000)
            self.notifications_ready = True
        except Exception:
            pass
        finally:
            os.seteuid(os.getuid())

    def toast(self, msg: str, file=sys.stdout) -> None:
        try:
            if self.notifications_ready:
                if self.last_notification != msg:
                    self.last_notification = msg
                    self.system_notification(msg)
            else:
                print(msg, file=file)
                self.notification_queue.append(msg)
                if self.dbus_notifications:
                    self.enable_notifications()
                    if self.notifications_ready:
                        for msg in self.notification_queue:
                            try:
                                if self.last_notification != msg:
                                    self.last_notification = msg
                                    self.system_notification(msg)
                            except Exception:
                                pass
                        self.notification_queue = []
        except Exception:
            self.notification_queue.append(msg)
            self.notifications_ready = False

