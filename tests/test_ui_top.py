# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""Smoke tests for `picosnitch.ui.top._top_loop` driven inside a pty.

We can't connect to a real picosnitch daemon from a unit test, so we
build a stub `LiveFeedSubscriber` that yields a few synthetic events
and then signals StopIteration. The loop should render, accept `?`
(toggle help) and `q` (quit), and exit with status 0."""

import os
import pty
import time

import pytest


class _StubSub:
    """Mimic just enough of LiveFeedSubscriber for _top_loop."""

    def __init__(self, events: list[dict]) -> None:
        self._events = list(events)
        self._yielded = 0

    def settimeout(self, _t: float) -> None: ...

    def __iter__(self) -> "_StubSub":
        return self

    def __next__(self) -> dict:
        if self._yielded < len(self._events):
            ev = self._events[self._yielded]
            self._yielded += 1
            return ev
        raise BlockingIOError


def _run_top_in_pty(events: list[dict], keystrokes: bytes, deadline_s: float) -> int:
    """Run _top_loop under curses.wrapper inside a child pty, feed
    keystrokes, return the exit status."""
    pid, fd = pty.fork()
    if pid == 0:
        # child
        try:
            os.environ["TERM"] = "xterm-256color"
            import curses

            from picosnitch.ui.top import _top_loop

            sub = _StubSub(events)
            rc = curses.wrapper(_top_loop, sub)  # ty: ignore[invalid-argument-type]
            os._exit(0 if rc == 0 else 1)
        except SystemExit:
            raise
        except BaseException:
            os._exit(2)
    # parent: drive the pty
    # Tiny initial delay so curses has a chance to paint the first frame.
    time.sleep(0.1)
    try:
        os.write(fd, keystrokes)
    except OSError:
        pass
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        # Drain output until child exits.
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            break
    try:
        os.close(fd)
    except OSError:
        pass
    _waited, status = os.waitpid(pid, 0)
    return status


def test_top_loop_renders_and_quits() -> None:
    events: list[dict] = [
        {"name": "curl", "exe": "/usr/bin/curl", "send": 1024, "recv": 4096, "raddr": "1.2.3.4", "rport": 443, "lport": 51000, "domain": "example.com", "pname": "bash", "gpname": "sshd"},
        {"name": "nginx", "exe": "/usr/sbin/nginx", "send": 2048, "recv": 8192, "raddr": "5.6.7.8", "rport": 80, "lport": 80, "domain": None, "pname": "nginx", "gpname": "systemd"},
    ]
    # Send "?" to toggle help, then "q" to quit. Two short bursts so the
    # loop drains both.
    try:
        status = _run_top_in_pty(events, b"?q", deadline_s=5.0)
    except OSError as e:
        pytest.skip(f"pty not available: {e}")
    assert os.WIFEXITED(status), f"child did not exit cleanly (status={status})"
    assert os.WEXITSTATUS(status) == 0, f"child exit status = {os.WEXITSTATUS(status)}"


def test_top_loop_quits_on_esc() -> None:
    try:
        status = _run_top_in_pty([], b"\x1b", deadline_s=5.0)
    except OSError as e:
        pytest.skip(f"pty not available: {e}")
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 0
