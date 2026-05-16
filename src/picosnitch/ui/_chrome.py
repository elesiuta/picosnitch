# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""Shared curses chrome -- color pairs, status bar, modal popups.

Both `picosnitch top` and `picosnitch tui` use these so they look and
feel like one tool. Stdlib-only; never touches input or business state.
"""

import curses

# ── color pair IDs (1..8 -- safe everywhere, including 8-color terms) ─
CP_CHROME = 1  # status bar / header background strip
CP_SELECTION = 2  # currently-selected row
CP_ACCENT = 3  # accent text (links, active section title)
CP_OK = 4  # green status (recording, healthy)
CP_WARN = 5  # yellow status (paused, degraded)
CP_BAD = 6  # red status (error, blocked)
CP_MUTED = 7  # dim secondary text


def init_colors() -> None:
    """Initialise the shared color pairs. Safe to call multiple times."""
    try:
        curses.start_color()
    except curses.error:
        return
    try:
        curses.use_default_colors()
        bg = -1
    except curses.error:
        bg = curses.COLOR_BLACK
    pairs = (
        (CP_CHROME, curses.COLOR_WHITE, curses.COLOR_BLUE),
        (CP_SELECTION, curses.COLOR_BLACK, curses.COLOR_CYAN),
        (CP_ACCENT, curses.COLOR_CYAN, bg),
        (CP_OK, curses.COLOR_GREEN, bg),
        (CP_WARN, curses.COLOR_YELLOW, bg),
        (CP_BAD, curses.COLOR_RED, bg),
        (CP_MUTED, curses.COLOR_WHITE, bg),
    )
    for pid, fg, b in pairs:
        try:
            curses.init_pair(pid, fg, b)
        except curses.error:
            pass


def _safe_addnstr(win: "curses.window", y: int, x: int, s: str, n: int, attr: int = 0) -> None:
    """addnstr that never raises (e.g. drawing on the bottom-right cell)."""
    if n <= 0:
        return
    try:
        win.addnstr(y, x, s, n, attr)
    except curses.error:
        pass


def draw_status_bar(
    stdscr: "curses.window",
    left: list[tuple[str, str]],
    center: list[tuple[str, str]],
    hint: str,
    paused: bool = False,
) -> None:
    """Draw the top status bar: `left` segments, then `center` counters,
    then a right-aligned `hint`.

    Each segment is rendered as `label value` with the label dimmed and
    the value bright. If `paused` is True, the entire bar uses the WARN
    color instead of CHROME so it's obvious at a glance.
    """
    max_y, max_x = stdscr.getmaxyx()
    if max_y < 1 or max_x < 4:
        return
    pair = CP_WARN if paused else CP_CHROME
    bar_attr = curses.color_pair(pair) | curses.A_BOLD
    # Paint the whole row first so the segment writes layer cleanly.
    _safe_addnstr(stdscr, 0, 0, " " * (max_x - 1), max_x - 1, bar_attr)
    x = 1
    for label, value in left:
        seg = f"{label} {value}  " if label else f"{value}  "
        _safe_addnstr(stdscr, 0, x, seg, max_x - 1 - x, bar_attr)
        x += len(seg)
        if x >= max_x - 1:
            return
    if center and x < max_x - 1:
        _safe_addnstr(stdscr, 0, x, " | ", max_x - 1 - x, bar_attr)
        x += 3
    for label, value in center:
        seg = f"{label}:{value}  "
        _safe_addnstr(stdscr, 0, x, seg, max_x - 1 - x, bar_attr)
        x += len(seg)
        if x >= max_x - 1:
            return
    # Right-align the hint.
    if hint:
        room = max(0, max_x - 1 - x - 1)
        clipped = hint[:room]
        hx = max_x - 1 - len(clipped)
        if hx > x:
            _safe_addnstr(stdscr, 0, hx, clipped, len(clipped), bar_attr)


def draw_help_popup(
    stdscr: "curses.window",
    title: str,
    lines: list[tuple[str, str]],
) -> None:
    """Render the shared `?` help popup centered on the screen.

    `lines` is a sequence of (key_label, description) pairs (typically
    `_keys.HELP_LINES`). If the screen is too short to fit a single
    column of all the lines, the popup automatically splits into two
    side-by-side columns so the help is always visible."""
    max_y, max_x = stdscr.getmaxyx()
    fill_attr = curses.color_pair(CP_CHROME)
    title_attr = curses.color_pair(CP_CHROME) | curses.A_BOLD
    body_attr = curses.color_pair(CP_CHROME)
    footer = "press ? to close"

    # Decide one or two columns based on available height. The popup
    # always uses an even split so the column heights match.
    avail_h = max_y - 2  # leave room for status bar + bottom edge
    one_col_h = len(lines) + 6  # title + blank + lines + blank + footer + borders
    cols = 1 if one_col_h <= avail_h else 2
    if cols == 2:
        per_col = (len(lines) + 1) // 2
        col_lines = [lines[:per_col], lines[per_col:]]
    else:
        per_col = len(lines)
        col_lines = [lines]

    key_w = max((len(k) for k, _ in lines), default=8)
    desc_w = max((len(d) for _, d in lines), default=20)
    # row format below is `"  {key:<key_w}   {desc}"` -> 2 + key_w + 3 + desc_w
    col_w = key_w + desc_w + 5
    col_gap = 4
    body_w = col_w * cols + col_gap * (cols - 1)
    inner_w = max(body_w, len(title) + 4, len(footer) + 4)
    inner_h = per_col + 4  # title + blank + rows + blank + footer
    box_w = inner_w + 4
    box_h = inner_h + 2
    if box_h > max_y or box_w > max_x:
        # Last-ditch fallback: render only the title + footer so the
        # user at least sees the popup acknowledged the keypress.
        box_h = min(max_y, 5)
        box_w = min(max_x, max(len(title), len(footer)) + 6)
        col_lines = [[]]
        per_col = 0
        inner_w = box_w - 4
    y0 = (max_y - box_h) // 2
    x0 = (max_x - box_w) // 2
    for row in range(box_h):
        _safe_addnstr(stdscr, y0 + row, x0, " " * box_w, box_w, fill_attr)
    _safe_addnstr(stdscr, y0 + 1, x0 + 2, title.ljust(inner_w), inner_w, title_attr)
    for col_i, col in enumerate(col_lines):
        col_x = x0 + 2 + col_i * (col_w + col_gap)
        for i, (key, desc) in enumerate(col):
            line = f"  {key.ljust(key_w)}   {desc}"
            _safe_addnstr(stdscr, y0 + 3 + i, col_x, line.ljust(col_w), col_w, body_attr)
    _safe_addnstr(stdscr, y0 + box_h - 2, x0 + 2, footer.rjust(inner_w), inner_w, body_attr)


def draw_modal(
    stdscr: "curses.window",
    title: str,
    body_lines: list[str],
    footer: str = "press any key to dismiss",
) -> None:
    """Render a generic centered modal: title + body lines + footer.

    Used for "no data", "live feed unavailable", confirm prompts, etc."""
    max_y, max_x = stdscr.getmaxyx()
    inner_w = max(
        max((len(line) for line in body_lines), default=0),
        len(title),
        len(footer),
    )
    inner_w = min(inner_w, max(20, max_x - 8))
    inner_h = len(body_lines) + 4  # title + blank + body + blank + footer
    box_w = inner_w + 4
    box_h = inner_h + 2
    if box_h >= max_y or box_w >= max_x:
        return
    y0 = (max_y - box_h) // 2
    x0 = (max_x - box_w) // 2
    fill_attr = curses.color_pair(CP_CHROME)
    for row in range(box_h):
        _safe_addnstr(stdscr, y0 + row, x0, " " * box_w, box_w, fill_attr)
    _safe_addnstr(stdscr, y0 + 1, x0 + 2, title.ljust(inner_w), inner_w, curses.color_pair(CP_CHROME) | curses.A_BOLD)
    for i, line in enumerate(body_lines):
        _safe_addnstr(stdscr, y0 + 3 + i, x0 + 2, line[:inner_w].ljust(inner_w), inner_w, curses.color_pair(CP_CHROME))
    _safe_addnstr(stdscr, y0 + box_h - 2, x0 + 2, footer.rjust(inner_w), inner_w, curses.color_pair(CP_CHROME))


def prompt_input(
    stdscr: "curses.window",
    prompt: str = "/",
    initial: str = "",
) -> str | None:
    """Inline text prompt rendered on the bottom row.

    Returns the typed string (possibly empty) when the user presses
    Enter, or None if the user cancels with Esc. Backspace edits;
    Ctrl-U clears. The caller is responsible for any redraw afterward
    -- this helper does not modify any other state."""
    max_y, max_x = stdscr.getmaxyx()
    if max_y < 1 or max_x < len(prompt) + 2:
        return None
    buf = list(initial)
    row = max_y - 1
    bar_attr = curses.color_pair(CP_CHROME) | curses.A_BOLD
    try:
        prev_curs = curses.curs_set(1)
    except curses.error:
        prev_curs = 0
    stdscr.nodelay(False)
    stdscr.timeout(-1)
    try:
        while True:
            text = "".join(buf)
            line = f"{prompt}{text}"
            _safe_addnstr(stdscr, row, 0, " " * (max_x - 1), max_x - 1, bar_attr)
            _safe_addnstr(stdscr, row, 0, line[: max_x - 1], max_x - 1, bar_attr)
            try:
                stdscr.move(row, min(len(line), max_x - 2))
            except curses.error:
                pass
            stdscr.refresh()
            try:
                ch = stdscr.getch()
            except KeyboardInterrupt:
                # cancel the prompt instead of propagating out of curses.wrapper
                return None
            if ch in (10, 13, curses.KEY_ENTER):
                return "".join(buf)
            if ch == 27:  # ESC
                return None
            if ch in (curses.KEY_BACKSPACE, 127, 8):
                if buf:
                    buf.pop()
                continue
            if ch == 21:  # Ctrl-U
                buf = []
                continue
            if ch == curses.KEY_RESIZE:
                max_y, max_x = stdscr.getmaxyx()
                row = max_y - 1
                continue
            if 32 <= ch < 127:
                buf.append(chr(ch))
    finally:
        try:
            curses.curs_set(prev_curs)
        except curses.error:
            pass
