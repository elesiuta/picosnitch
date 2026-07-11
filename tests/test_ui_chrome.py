# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""Tests for the shared TUI primitives in `picosnitch.ui._keys` and
`picosnitch.ui._chrome`.

`_chrome` is exercised against a real curses screen via a pty so we
catch addnstr/init_pair failures, but we never actually display
anything to the user."""

import curses
import os
import pty

import pytest

from picosnitch.ui import _chrome, _keys

# ── _keys ────────────────────────────────────────────────────────────


def test_key_action_known_keys() -> None:
    assert _keys.key_action(ord("q")) == _keys.QUIT
    assert _keys.key_action(27) == _keys.QUIT
    assert _keys.key_action(ord("?")) == _keys.HELP
    assert _keys.key_action(ord("/")) == _keys.FILTER
    assert _keys.key_action(ord("p")) == _keys.PAUSE
    assert _keys.key_action(ord(" ")) == _keys.PAUSE
    assert _keys.key_action(ord("s")) == _keys.SORT
    assert _keys.key_action(ord("\t")) == _keys.NEXT_SECTION
    assert _keys.key_action(curses.KEY_BTAB) == _keys.PREV_SECTION
    assert _keys.key_action(curses.KEY_LEFT) == _keys.PREV_VIEW
    assert _keys.key_action(curses.KEY_RIGHT) == _keys.NEXT_VIEW
    assert _keys.key_action(curses.KEY_UP) == _keys.MOVE_UP
    assert _keys.key_action(curses.KEY_DOWN) == _keys.MOVE_DOWN
    assert _keys.key_action(curses.KEY_PPAGE) == _keys.PAGE_UP
    assert _keys.key_action(curses.KEY_NPAGE) == _keys.PAGE_DOWN
    assert _keys.key_action(curses.KEY_HOME) == _keys.JUMP_HOME
    assert _keys.key_action(curses.KEY_END) == _keys.JUMP_END
    assert _keys.key_action(ord("\n")) == _keys.DRILL_IN
    assert _keys.key_action(curses.KEY_BACKSPACE) == _keys.POP_OUT
    assert _keys.key_action(curses.KEY_RESIZE) == _keys.RESIZE


def test_key_action_unknown_returns_none() -> None:
    assert _keys.key_action(ord("z")) is None
    assert _keys.key_action(-1) is None


def test_help_lines_nonempty_and_well_formed() -> None:
    assert _keys.HELP_LINES
    for entry in _keys.HELP_LINES:
        assert len(entry) == 2
        key_label, desc = entry
        assert key_label and desc
        assert key_label.isprintable()
        assert desc.isprintable()


def test_format_status_hint_is_short() -> None:
    hint = _keys.format_status_hint()
    assert hint
    assert len(hint) < 60


# ── _chrome ──────────────────────────────────────────────────────────


def _run_in_pty(fn) -> None:
    """Run `fn(stdscr)` inside a curses session attached to a pty so it
    works under pytest. Re-raises any assertion / exception from fn."""
    pid, fd = pty.fork()
    if pid == 0:
        # child: take over, run curses.wrapper, exit with status
        try:
            os.environ["TERM"] = "xterm-256color"
            curses.wrapper(fn)
        except SystemExit:
            raise
        except BaseException:
            os._exit(2)
        os._exit(0)
    # parent: drain output, wait, check status
    try:
        while True:
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
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise AssertionError(f"curses child exited with status {status}")


def _chrome_smoke(stdscr: "curses.window") -> None:
    _chrome.init_colors()
    # idempotent
    _chrome.init_colors()
    _chrome.draw_status_bar(
        stdscr,
        left=[("picosnitch", "v2.0")],
        center=[("events", "1234"), ("rate", "312/s")],
        hint=_keys.format_status_hint(),
    )
    _chrome.draw_status_bar(
        stdscr,
        left=[("picosnitch", "v2.0")],
        center=[("events", "1234")],
        hint="paused",
        paused=True,
    )
    _chrome.draw_help_popup(stdscr, "picosnitch top", _keys.HELP_LINES)
    _chrome.draw_modal(
        stdscr,
        "Live feed unavailable",
        ["Daemon socket not found.", "Try `sudo picosnitch start`."],
    )
    stdscr.refresh()


def test_chrome_renders_without_crash() -> None:
    if not os.environ.get("DISPLAY", "") and not os.isatty(0):
        # works fine; just documenting that we use a pty regardless
        pass
    try:
        _run_in_pty(_chrome_smoke)
    except OSError as e:
        pytest.skip(f"pty not available: {e}")


def _chrome_tiny_screen(stdscr: "curses.window") -> None:
    """Even on absurdly small screens, draws must not raise."""
    _chrome.init_colors()
    # We can't actually resize the pty cleanly here, but the helpers
    # all guard against tiny dimensions internally; just call them.
    _chrome.draw_status_bar(stdscr, left=[], center=[], hint="")
    _chrome.draw_help_popup(stdscr, "x", [("a", "b")])
    _chrome.draw_modal(stdscr, "x", ["body"])
    stdscr.refresh()


def test_chrome_handles_minimal_inputs() -> None:
    try:
        _run_in_pty(_chrome_tiny_screen)
    except OSError as e:
        pytest.skip(f"pty not available: {e}")


def _chrome_ctrl_chars(stdscr: "curses.window") -> None:
    """A control char in an attacker-influenced name (curses acts on \\r \\n \\t \\b as
    cursor movement) must not overwrite or spoof another row -- it is neutralized to '?'."""
    _chrome.init_colors()
    _chrome._safe_addnstr(stdscr, 0, 0, "safe\r\nSPOOF\tx\bz\x9bq\u202eRTL\udc9b", 40)
    stdscr.refresh()
    row0 = stdscr.instr(0, 0, 40)
    row1 = stdscr.instr(1, 0, 40)
    assert b"SPOOF" in row0  # stayed on the intended row
    assert b"SPOOF" not in row1 and row1.strip() == b""  # the \n did not bleed onto row 1
    assert b"\r" not in row0 and b"\t" not in row0  # controls replaced, not acted on
    assert b"\x9b" not in row0 and b"q" in row0  # C1 CSI replaced, not passed to the terminal
    assert "\u202e" not in row0.decode("utf-8", "replace")


def test_chrome_sanitizes_control_chars() -> None:
    try:
        _run_in_pty(_chrome_ctrl_chars)
    except OSError as e:
        pytest.skip(f"pty not available: {e}")
