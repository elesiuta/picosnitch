# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""Tests for the notifier's desktop-session env setup (so notify-send can reach
the user's D-Bus session bus after dropping root to desktop.user)."""

import os
import pwd

from picosnitch.subprocesses.notifications import _set_desktop_session_env


def test_set_desktop_session_env(monkeypatch):
    """XDG_RUNTIME_DIR / DBUS_SESSION_BUS_ADDRESS point at the target uid's
    session bus (the canonical /run/user/<uid>/bus path), overriding whatever
    root's environment held; HOME follows the uid's passwd entry."""
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/0")  # root's -- must be overridden
    me = pwd.getpwuid(os.getuid())
    _set_desktop_session_env(me.pw_uid)
    assert os.environ["XDG_RUNTIME_DIR"] == f"/run/user/{me.pw_uid}"
    assert os.environ["DBUS_SESSION_BUS_ADDRESS"] == f"unix:path=/run/user/{me.pw_uid}/bus"
    assert os.environ["HOME"] == me.pw_dir


def test_set_desktop_session_env_unknown_uid(monkeypatch):
    """a uid with no passwd entry must not crash; HOME is left untouched."""
    monkeypatch.setenv("HOME", "/root")
    _set_desktop_session_env(4000000000)
    assert os.environ["XDG_RUNTIME_DIR"] == "/run/user/4000000000"
    assert os.environ["DBUS_SESSION_BUS_ADDRESS"] == "unix:path=/run/user/4000000000/bus"
    assert os.environ["HOME"] == "/root"  # unchanged
