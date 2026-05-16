# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""Shared key map for the curses UIs (`picosnitch top` and `tui`).

A single source of truth for what each key does, so the two TUIs stay
cohesive. `key_action(ch)` returns the action name (e.g. "quit",
"scroll_down", "toggle_pause") for a curses key code, or `None` if the
key is unbound. Each TUI loop translates that action into its own
state mutation -- this module never touches state itself.

`HELP_LINES` powers the `?` popup. Keep it short; the popup is a quick
reference, not a manual.
"""

import curses

# ── action names (string constants for easy match/case) ──────────────
QUIT = "quit"
HELP = "help"
LIVE = "live"
FILTER = "filter"
PAUSE = "pause"
RESET = "reset"
SORT = "sort"
NEXT_SECTION = "next_section"
PREV_SECTION = "prev_section"
NEXT_VIEW = "next_view"
PREV_VIEW = "prev_view"
MOVE_UP = "move_up"
MOVE_DOWN = "move_down"
PAGE_UP = "page_up"
PAGE_DOWN = "page_down"
JUMP_HOME = "jump_home"
JUMP_END = "jump_end"
DRILL_IN = "drill_in"
POP_OUT = "pop_out"
RESIZE = "resize"


# Map curses key codes (and ord() of plain chars) to action names.
# Multiple keys can share an action (e.g. ESC and q both quit).
_KEYMAP: dict[int, str] = {
    ord("q"): QUIT,
    27: QUIT,  # ESC
    ord("?"): HELP,
    ord("l"): LIVE,
    ord("L"): LIVE,
    ord("/"): FILTER,
    ord("p"): PAUSE,
    ord(" "): PAUSE,
    ord("r"): RESET,
    ord("s"): SORT,
    ord("\t"): NEXT_SECTION,
    curses.KEY_BTAB: PREV_SECTION,
    curses.KEY_LEFT: PREV_VIEW,
    curses.KEY_RIGHT: NEXT_VIEW,
    curses.KEY_UP: MOVE_UP,
    curses.KEY_DOWN: MOVE_DOWN,
    curses.KEY_PPAGE: PAGE_UP,
    curses.KEY_NPAGE: PAGE_DOWN,
    curses.KEY_HOME: JUMP_HOME,
    curses.KEY_END: JUMP_END,
    curses.KEY_ENTER: DRILL_IN,
    ord("\n"): DRILL_IN,
    ord("\r"): DRILL_IN,
    curses.KEY_BACKSPACE: POP_OUT,
    127: POP_OUT,  # DEL on some terminals
    8: POP_OUT,  # ^H
    curses.KEY_RESIZE: RESIZE,
}


def key_action(ch: int) -> str | None:
    """Map a curses key code to an action name, or None if unbound."""
    return _KEYMAP.get(ch)


# Shown by the `?` popup. Order matters; group related keys together.
# Use plain ASCII so it renders on every terminal.
HELP_LINES: list[tuple[str, str]] = [
    ("q / ESC", "quit"),
    ("?", "toggle this help"),
    ("l", "jump to live feed"),
    ("/", "filter rows"),
    ("p / SPACE", "pause / resume"),
    ("r", "reset counters"),
    ("s", "cycle sort column"),
    ("TAB / S-TAB", "next / prev section"),
    ("LEFT/RIGHT", "previous / next view"),
    ("UP / DOWN", "move selection one row"),
    ("PgUp/PgDn", "scroll one page"),
    ("Home / End", "jump to top / bottom"),
    ("Enter", "drill into selection"),
    ("Backspace", "back / pop"),
]


def format_status_hint() -> str:
    """Compact one-line hint to embed in the status bar."""
    return "? help  q quit"
