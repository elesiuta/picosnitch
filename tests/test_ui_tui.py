# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""Tests for `picosnitch.ui.tui` -- helpers and the live-feed
unavailable path. The full `tui_loop` is skipped here because it
opens the production sqlite database; the focused tests below
exercise the new sidebar layout, key dispatch surface, and live-pane
chrome without needing a real DB."""

import curses
import os
import pty
import time

import pytest

from picosnitch.ui import _keys, tui

# ── pure helpers ────────────────────────────────────────────────────


def test_views_flatten_matches_sections() -> None:
    expected = sum(len(items) for _section, items in tui._SIDEBAR_SECTIONS)
    assert len(tui._VIEWS) == expected
    # live is a separate keybind, not a sidebar entry
    assert all(col != "__live__" for _s, _l, col in tui._VIEWS)
    # every sql column appears at most once
    cols = [col for _s, _l, col in tui._VIEWS]
    assert len(cols) == len(set(cols))


def test_tui_help_lines_extends_shared() -> None:
    # tui keeps the shared help lines as a prefix, then adds its own.
    assert tui._TUI_HELP_LINES[: len(_keys.HELP_LINES)] == _keys.HELP_LINES
    extras = tui._TUI_HELP_LINES[len(_keys.HELP_LINES) :]
    assert any("filter" in desc for _key, desc in extras)
    assert any("time" in desc for _key, desc in extras)
    assert any("byte units" in desc for _key, desc in extras)


def test_tui_status_hint_is_short() -> None:
    hint = tui._tui_status_hint()
    assert hint
    assert len(hint) < 60


# ── pty-driven smoke tests ──────────────────────────────────────────


def _run_in_pty(fn, keystrokes: bytes = b"", deadline_s: float = 5.0) -> int:
    """Run `fn(stdscr)` in a curses session attached to a pty.

    Returns the child's exit status. Sends `keystrokes` after a short
    delay so the function gets out of any blocking getch() calls.
    """
    if not hasattr(pty, "fork"):
        pytest.skip("pty.fork unavailable on this platform")
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.environ["TERM"] = "xterm-256color"
            rc = curses.wrapper(fn)
            os._exit(0 if rc in (None, 0) else int(rc))
        except SystemExit:
            raise
        except BaseException:
            os._exit(2)
    # parent: feed keys after a beat, then drain
    time.sleep(0.1)
    try:
        if keystrokes:
            os.write(fd, keystrokes)
    except OSError:
        pass
    deadline = time.monotonic() + deadline_s
    try:
        while time.monotonic() < deadline:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    _waited_pid, status = os.waitpid(pid, 0)
    return status


def _live_unavailable_target(stdscr: "curses.window") -> int:
    # _live_tab_loop() falls through to _live_tab_unavailable when the
    # events socket doesn't exist (true under pytest).
    result = tui._live_tab_loop(stdscr)
    return 0 if result == "quit" else 3


def test_live_tab_unavailable_quits_on_q() -> None:
    status = _run_in_pty(_live_unavailable_target, keystrokes=b"q")
    assert os.WIFEXITED(status), f"child did not exit: {status}"
    assert os.WEXITSTATUS(status) == 0


def _sidebar_render_target(stdscr: "curses.window") -> int:
    from picosnitch.ui import _chrome

    _chrome.init_colors()
    # render at a few different selections + focuses; just make sure
    # nothing raises curses.error on a small screen.
    for view_i in (0, 5, len(tui._VIEWS) - 1):
        for focus in ("sidebar", "main"):
            stdscr.erase()
            tui._draw_sidebar(stdscr, view_i, focus, sidebar_w=20, max_y=stdscr.getmaxyx()[0])
            stdscr.noutrefresh()
    curses.doupdate()
    return 0


def test_draw_sidebar_smoke() -> None:
    status = _run_in_pty(_sidebar_render_target, keystrokes=b"")
    assert os.WIFEXITED(status), f"child did not exit: {status}"
    assert os.WEXITSTATUS(status) == 0
