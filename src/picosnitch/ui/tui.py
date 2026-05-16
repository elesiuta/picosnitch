# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

import bisect
import collections
import csv
import curses
import datetime
import gzip
import ipaddress
import json
import logging
import pwd
import queue
import random
import sqlite3
import sys
import threading
import time
import urllib.request

from picosnitch.config import load_config
from picosnitch.constants import CACHE_DIR, DATA_DIR, DB_VERSION, RUN_DIR, VERSION
from picosnitch.live_feed import EVENTS_SOCKET_PATH, LiveFeedSubscriber
from picosnitch.ui import _chrome, _keys
from picosnitch.utils import connect_db_readonly

# ── sidebar layout ────────────────────────────────────────────────────
# (section_label, [(item_label, sql_column), ...]) -- the selected
# item drives the SQL group-by. The live event feed is reachable via
# the global 'l' keybind instead of being a sidebar entry.
_SIDEBAR_SECTIONS: list[tuple[str, list[tuple[str, str]]]] = [
    (
        "Process",
        [
            ("Executable", "e.exe"),
            ("Name", "e.name"),
            ("Command", "e.cmdline"),
            ("SHA256", "e.sha256"),
        ],
    ),
    (
        "Parent",
        [
            ("Executable", "p.exe"),
            ("Name", "p.name"),
            ("Command", "p.cmdline"),
            ("SHA256", "p.sha256"),
        ],
    ),
    (
        "Grandparent",
        [
            ("Executable", "g.exe"),
            ("Name", "g.name"),
            ("Command", "g.cmdline"),
            ("SHA256", "g.sha256"),
        ],
    ),
    (
        "Network",
        [
            ("User", "c.uid"),
            ("Local Port", "c.lport"),
            ("Remote Port", "c.rport"),
            ("Local Address", "la.addr"),
            ("Remote Address", "ra.addr"),
            ("Domain", "dom.domain"),
            ("Entry Time", "c.contime"),
        ],
    ),
]


def _flatten_views() -> list[tuple[str, str, str]]:
    """[(section, label, sql_col), ...] in display / index order."""
    out: list[tuple[str, str, str]] = []
    for section, items in _SIDEBAR_SECTIONS:
        for label, col in items:
            out.append((section, label, col))
    return out


_VIEWS: list[tuple[str, str, str]] = _flatten_views()
_SIDEBAR_WIDTH = 22


# Tui-specific extensions to the shared help popup.
_TUI_HELP_LINES: list[tuple[str, str]] = _keys.HELP_LINES + [
    ("", ""),
    ("f / Enter", "filter on selected row"),
    ("e", "exclude selected row"),
    ("F / Bksp", "pop last filter"),
    ("t / T", "next / prev time period"),
    ("h / H", "step back / forward in history"),
    ("u / U", "cycle byte units"),
]


def _tui_status_hint() -> str:
    """One-line hint shown right-aligned in the tui status bar."""
    return "? help  q quit"


def _draw_sidebar(stdscr: "curses.window", view_i: int, focus: str, sidebar_w: int, max_y: int) -> None:
    """Render the left sidebar: bold section headers and indented items."""
    y = 1
    flat_idx = 0
    for section, items in _SIDEBAR_SECTIONS:
        if y >= max_y - 1:
            return
        header = f" {section}"
        _chrome._safe_addnstr(
            stdscr,
            y,
            0,
            header.ljust(sidebar_w)[:sidebar_w],
            sidebar_w,
            curses.color_pair(_chrome.CP_ACCENT) | curses.A_BOLD,
        )
        y += 1
        for label, _col in items:
            if y >= max_y - 1:
                return
            selected = flat_idx == view_i
            if selected and focus == "sidebar":
                attr = curses.color_pair(_chrome.CP_SELECTION) | curses.A_BOLD
            elif selected:
                attr = curses.color_pair(_chrome.CP_ACCENT)
            else:
                attr = curses.color_pair(_chrome.CP_MUTED)
            row = f"   {label}"
            _chrome._safe_addnstr(
                stdscr,
                y,
                0,
                row.ljust(sidebar_w)[:sidebar_w],
                sidebar_w,
                attr,
            )
            y += 1
            flat_idx += 1


def init_geoip():
    """Init a country-code lookup callable; returns lookup_fn(ip)->str|None or None on failure.

    Uses the DB-IP Country Lite CSV (CC-BY 4.0, monthly, no account required).
    Cached gzipped under CACHE_DIR; ~3MB on disk, parsed on each launch.
    """
    config = load_config()
    if not config.desktop.geoip_lookup:
        return None
    try:
        cache_path = CACHE_DIR / "dbip-country-lite.csv.gz"
        now = datetime.datetime.now()
        stale = not cache_path.is_file() or datetime.datetime.fromtimestamp(cache_path.stat().st_mtime).strftime("%Y%m") != now.strftime("%Y%m")
        if stale:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            last_err: Exception | None = None
            for delta_days in (0, 30):
                # Try current month first, then last month if the new release isn't published yet.
                when = now - datetime.timedelta(days=delta_days)
                url = when.strftime("https://download.db-ip.com/free/dbip-country-lite-%Y-%m.csv.gz")
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(req, timeout=30) as resp, open(cache_path, "wb") as f:
                        f.write(resp.read())
                    last_err = None
                    break
                except Exception as exc:
                    last_err = exc
            if last_err is not None and not cache_path.is_file():
                raise Exception(f"Could not download GeoIP database: {last_err}")
            if last_err is not None:
                logging.warning("Could not update GeoIP database, using cached version (%s)", last_err)

        v4_starts: list[int] = []
        v4_ends: list[int] = []
        v4_cc: list[str] = []
        v6_starts: list[int] = []
        v6_ends: list[int] = []
        v6_cc: list[str] = []
        with gzip.open(cache_path, "rt", encoding="ascii", errors="replace") as fh:
            for row in csv.reader(fh):
                if len(row) != 3:
                    continue
                start_s, end_s, cc = row
                try:
                    start = int(ipaddress.ip_address(start_s))
                    end = int(ipaddress.ip_address(end_s))
                except ValueError:
                    continue
                if ":" in start_s:
                    v6_starts.append(start)
                    v6_ends.append(end)
                    v6_cc.append(cc)
                else:
                    v4_starts.append(start)
                    v4_ends.append(end)
                    v4_cc.append(cc)

        def lookup(ip: str) -> str | None:
            try:
                addr = ipaddress.ip_address(ip)
                v = int(addr)
                if isinstance(addr, ipaddress.IPv4Address):
                    starts, ends, ccs = v4_starts, v4_ends, v4_cc
                else:
                    starts, ends, ccs = v6_starts, v6_ends, v6_cc
                idx = bisect.bisect_right(starts, v) - 1
                if 0 <= idx < len(starts) and starts[idx] <= v <= ends[idx]:
                    return ccs[idx]
            except Exception:
                pass
            return None

        return lookup
    except Exception as exc:
        logging.warning("GeoIP lookup disabled: %s", exc)
        return None


def _format_bytes_short(n: int) -> str:
    for unit in ("B", "K", "M", "G"):
        if n < 1024:
            return f"{n:>5d}{unit}"
        n //= 1024
    return f"{n:>5d}T"


def _live_tab_unavailable(stdscr: "curses.window", lines: list[str]) -> str:
    """Show a centered modal explaining why the live feed is unavailable.

    Returns one of: "left", "right", "sidebar", "quit".
    """
    stdscr.clear()
    _chrome.draw_status_bar(
        stdscr,
        left=[("picosnitch tui", f"v{VERSION}")],
        center=[("view", "Live"), ("status", "unavailable")],
        hint=_tui_status_hint(),
        paused=True,
    )
    _chrome.draw_modal(
        stdscr,
        "Live feed unavailable",
        lines,
        footer="? help  q quit",
    )
    stdscr.refresh()
    stdscr.nodelay(False)
    while True:
        ch = stdscr.getch()
        action = _keys.key_action(ch)
        if action == _keys.QUIT:
            return "quit"
        if action == _keys.LIVE:
            return "back"
        if action == _keys.PREV_VIEW:
            return "left"
        if action == _keys.NEXT_VIEW:
            return "right"
        if action in (_keys.NEXT_SECTION, _keys.PREV_SECTION):
            return "sidebar"


def _live_tab_loop(stdscr: "curses.window") -> str:
    """Render the live event feed inside the TUI.

    Returns one of: "left", "right", "sidebar", "quit" so the caller
    can decide where to navigate after the user leaves this view.
    """
    if not EVENTS_SOCKET_PATH.exists():
        return _live_tab_unavailable(
            stdscr,
            [
                f"Live feed socket {EVENTS_SOCKET_PATH} does not exist.",
                "Start the daemon (sudo picosnitch start) or run",
                "`picosnitch top` for a standalone live monitor.",
            ],
        )

    sub = LiveFeedSubscriber(timeout=0.0)
    try:
        sub.connect()
    except PermissionError as e:
        return _live_tab_unavailable(
            stdscr,
            [
                f"Permission denied: {e}",
                "The live event socket is owned by the picosnitch daemon",
                "and only readable by root (or members of the configured",
                "picosnitch group). Re-run the TUI with sudo, or use",
                "`sudo picosnitch top` for a standalone live monitor.",
            ],
        )
    except OSError as e:
        return _live_tab_unavailable(
            stdscr,
            [f"Could not connect to live feed: {type(e).__name__}: {e}"],
        )

    recent: collections.deque[dict] = collections.deque(maxlen=10000)
    paused = False
    scroll_offset = 0
    total_events = 0
    show_help = False
    try:
        stdscr.nodelay(True)
        while True:
            sub.settimeout(0.0)
            try:
                for _ in range(500):
                    try:
                        event = next(sub)
                    except (BlockingIOError, TimeoutError):
                        break
                    except StopIteration:
                        return "quit"
                    if not isinstance(event, dict) or not event:
                        continue
                    event["_t"] = time.time()
                    total_events += 1
                    if not paused:
                        recent.appendleft(event)
            except Exception:
                pass

            stdscr.erase()
            max_y, max_x = stdscr.getmaxyx()
            _chrome.draw_status_bar(
                stdscr,
                left=[("picosnitch tui", f"v{VERSION}")],
                center=[
                    ("view", "Live"),
                    ("events", str(total_events)),
                    ("shown", str(len(recent))),
                ],
                hint=_tui_status_hint(),
                paused=paused,
            )
            hdr = f" {'TIME':<8} {'NAME':<16} {'PNAME':<14} {'GPNAME':<14} {'REMOTE':<28} {'SEND':>7} {'RECV':>7}"
            _chrome._safe_addnstr(
                stdscr,
                1,
                0,
                hdr.ljust(max_x - 1)[: max_x - 1],
                max_x - 1,
                curses.color_pair(_chrome.CP_ACCENT) | curses.A_UNDERLINE,
            )

            rec_rows = max(1, max_y - 3)
            recent_list = list(recent)
            max_offset = max(0, len(recent_list) - rec_rows)
            if scroll_offset > max_offset:
                scroll_offset = max_offset
            for i, event in enumerate(recent_list[scroll_offset : scroll_offset + rec_rows]):
                ts = event.get("_t", 0)
                t = time.strftime("%H:%M:%S", time.localtime(ts)) if ts else time.strftime("%H:%M:%S")
                raddr = event.get("raddr", "") or ""
                rport = event.get("rport", -1)
                remote = (event.get("domain") or raddr) + (f":{rport}" if rport and rport > 0 else "")
                row = (
                    f" {t:<8} "
                    f"{(event.get('name') or '')[:16]:<16} "
                    f"{(event.get('pname') or '')[:14]:<14} "
                    f"{(event.get('gpname') or '')[:14]:<14} "
                    f"{remote[:28]:<28} "
                    f"{_format_bytes_short(int(event.get('send', 0) or 0)):>7} "
                    f"{_format_bytes_short(int(event.get('recv', 0) or 0)):>7}"
                )
                _chrome._safe_addnstr(stdscr, 2 + i, 0, row, max_x - 1)

            if show_help:
                _chrome.draw_help_popup(stdscr, "picosnitch tui -- live", _TUI_HELP_LINES)
            stdscr.refresh()

            stdscr.timeout(200)
            ch = stdscr.getch()
            action = _keys.key_action(ch)
            if show_help:
                if ch != -1:
                    show_help = False
                continue
            if action == _keys.QUIT:
                return "quit"
            if action == _keys.LIVE:
                return "back"
            if action == _keys.HELP:
                show_help = True
            elif action in (_keys.NEXT_SECTION, _keys.PREV_SECTION):
                return "sidebar"
            elif action == _keys.PREV_VIEW:
                return "left"
            elif action == _keys.NEXT_VIEW:
                return "right"
            elif action == _keys.PAUSE:
                paused = not paused
            elif action == _keys.RESET:
                recent.clear()
                total_events = 0
                scroll_offset = 0
            elif action == _keys.MOVE_UP:
                scroll_offset = min(max_offset, scroll_offset + 1)
            elif action == _keys.MOVE_DOWN:
                scroll_offset = max(0, scroll_offset - 1)
            elif action == _keys.PAGE_UP:
                scroll_offset = min(max_offset, scroll_offset + max(1, rec_rows - 1))
            elif action == _keys.PAGE_DOWN:
                scroll_offset = max(0, scroll_offset - max(1, rec_rows - 1))
            elif action == _keys.JUMP_HOME:
                scroll_offset = 0
            elif action == _keys.JUMP_END:
                scroll_offset = max_offset
    finally:
        sub.close()


# ── splash art ───────────────────────────────────────────────────────
# Pine tree silhouette, 14 cols wide. The last 3 rows are the trunk
# (it sits above the ground line drawn by the background layer).
_SPLASH_TREE = [
    "      /\\      ",
    "     /  \\     ",
    "    / /\\ \\    ",
    "   / /  \\ \\   ",
    "  / /----\\ \\  ",
    " / /  \u00b7\u00b7  \\ \\ ",
    "/_/___||___\\_\\",
    "     ||||     ",
    "     ||||     ",
]
_SPLASH_TREE_GAP = "    "  # 4 spaces between trees

_SPLASH_WORDMARK = [
    "      _                _ _      _    ",
    " _ __(_)__ ___ ____ _ (_) |_ __| |_  ",
    "| '_ \\ / _/ _ (_-< ' \\| |  _/ _| ' \\ ",
    "| .__/_\\__\\___/__/_||_|_|\\__\\__|_||_|",
    "|_|                                  ",
]


def _render_splash(stdscr: "curses.window") -> None:
    """Draw the night-forest splash dynamically centered on the wordmark.

    Layers (bottom-up):
        1. starfield (cyan), denser higher in the sky
        2. distant pine silhouettes on the horizon (dim grey)
        3. ground line (green), full terminal width
        4. grass (green), denser near the ground line
        5. critters (dim grey)
        6. foreground art: three pines + wordmark + footer
    """
    cp_accent = curses.color_pair(_chrome.CP_ACCENT)  # cyan stars
    cp_warn = curses.color_pair(_chrome.CP_WARN)  # yellow fireflies
    cp_ok = curses.color_pair(_chrome.CP_OK)  # green ground/grass
    cp_muted = curses.color_pair(_chrome.CP_MUTED)  # dim silhouettes/footer

    rows, cols = stdscr.getmaxyx()
    if rows < 4 or cols < 20:
        stdscr.clear()
        stdscr.refresh()
        return

    # Each cell is one of:
    #   ("X", attr)    -- opaque glyph drawn over the background
    #   (" ", -1)      -- transparent space (background shows through)
    #   (" ", -2)      -- opaque space (clears background for readability)
    transparent = -1
    opaque_bg = -2

    def _from_text(text: str, attr: int, opaque_spaces: bool) -> list[tuple[str, int]]:
        space_marker = opaque_bg if opaque_spaces else transparent
        return [(ch, attr if ch != " " else space_marker) for ch in text]

    fg_rows: list[list[tuple[str, int]]] = []

    tree_lines = [_SPLASH_TREE_GAP.join(row) for row in zip(_SPLASH_TREE, _SPLASH_TREE, _SPLASH_TREE)]
    for line in tree_lines:
        fg_rows.append(_from_text(line, 0, opaque_spaces=False))
    # Two yellow firefly accents between the trunks (cols 15 and 33).
    if len(fg_rows[8]) > 33:
        fg_rows[8][15] = ("\u00b7", cp_warn)
        fg_rows[8][33] = ("\u00b7", cp_warn)

    # Ground row (handled entirely by the background).
    ground_fg_idx = len(fg_rows)
    fg_rows.append([])

    fg_rows.append([])

    # Wordmark, padded to align with the tree block (50-col band).
    block_w = 50
    word_w = max(len(w) for w in _SPLASH_WORDMARK)
    pad = max(0, (block_w - word_w) // 2)
    wm_start = len(fg_rows)
    for w in _SPLASH_WORDMARK:
        fg_rows.append(_from_text(" " * pad + w, 0, opaque_spaces=True))
    wordmark_center = wm_start + len(_SPLASH_WORDMARK) // 2

    fg_rows.append([])
    footer = "loading database ..."
    fpad = max(0, (block_w - len(footer)) // 2)
    fg_rows.append(_from_text(" " * fpad + footer, cp_muted, opaque_spaces=True))

    art_h = len(fg_rows)
    art_w = max((len(r) for r in fg_rows), default=0)

    if rows >= art_h:
        top = (rows - art_h) // 2
    else:
        top = rows // 2 - wordmark_center
    left = max(0, (cols - art_w) // 2)
    ground_y = top + ground_fg_idx
    horizon_y = ground_y - 1

    # Canvas: each cell is (char, color_pair_attr).
    grid: list[list[tuple[str, int]]] = [[(" ", 0) for _ in range(cols)] for _ in range(rows)]

    rng = random.Random(42)
    star_chars = (".", ".", ".", "\u00b7", "\u00b7", "*", "\u2726")
    grass_chars = (",", ",", ",", "'", "v", "w", ".", "`")

    # Layer 1: stars across the entire sky (denser higher up).
    for y in range(0, max(0, horizon_y)):
        dist = horizon_y - y
        density = min(0.030, 0.005 + dist * 0.0015)
        for x in range(cols):
            if rng.random() < density:
                grid[y][x] = (rng.choice(star_chars), cp_accent)

    # Layer 2: distant pine silhouettes on the horizon, left and right of
    # the foreground bbox.
    if 0 <= horizon_y < rows:
        x = 0
        while x < cols - 1:
            if left - 6 <= x <= left + art_w + 4:
                x += 1
                continue
            if rng.random() < 0.18:
                if rng.random() < 0.5 and x + 1 < cols:
                    grid[horizon_y][x] = ("/", cp_muted)
                    grid[horizon_y][x + 1] = ("\\", cp_muted)
                    x += 2
                else:
                    grid[horizon_y][x] = ("^", cp_muted)
                    x += 1
                x += rng.randint(2, 6)
            else:
                x += 1

    # Layer 3: ground line spanning the full terminal width.
    if 0 <= ground_y < rows:
        for x in range(cols):
            grid[ground_y][x] = ("_", cp_ok)

    # Layer 4: grass below the ground line, denser near the top.
    for y in range(ground_y + 1, rows):
        depth = y - ground_y
        density = max(0.04, 0.55 - depth * 0.10)
        for x in range(cols):
            if rng.random() < density:
                grid[y][x] = (rng.choice(grass_chars), cp_ok)

    # Layer 5: critters in the grass.
    if ground_y + 1 < rows:
        bunny = "(\\__/)"
        bx = max(0, left - len(bunny) - 4)
        if bx + len(bunny) < left:
            for i, ch in enumerate(bunny):
                if 0 <= bx + i < cols:
                    grid[ground_y + 1][bx + i] = (ch, cp_muted)
        mush = "_o_"
        mx = left + art_w + 4
        if mx + len(mush) < cols:
            for i, ch in enumerate(mush):
                if 0 <= mx + i < cols:
                    grid[ground_y + 1][mx + i] = (ch, cp_muted)

    # Layer 6: overlay the foreground (opaque/transparent per cell).
    for i, row in enumerate(fg_rows):
        y = top + i
        if not (0 <= y < rows):
            continue
        for j, (ch, marker) in enumerate(row):
            x = left + j
            if not (0 <= x < cols):
                continue
            if marker == transparent:
                continue  # background shows through
            if marker == opaque_bg:
                grid[y][x] = (" ", 0)  # clear background, leave a true blank
            else:
                grid[y][x] = (ch, marker)

    # Render: collect runs of identical attr per row to minimise addnstr calls.
    stdscr.clear()
    for y in range(rows):
        x = 0
        while x < cols:
            ch, attr = grid[y][x]
            run_x = x
            run = [ch]
            x += 1
            while x < cols and grid[y][x][1] == attr:
                run.append(grid[y][x][0])
                x += 1
            text = "".join(run)
            # curses raises if you write to (rows-1, cols-1)
            if y == rows - 1 and run_x + len(text) >= cols:
                text = text[: max(0, cols - 1 - run_x)]
                if not text:
                    break
            _chrome._safe_addnstr(stdscr, y, run_x, text, len(text), attr)
    stdscr.refresh()


def tui_loop(stdscr: curses.window) -> int:
    """Main curses loop for `picosnitch tui`.

    Layout:
        row 0           status bar (shared chrome)
        rows 1..max_y-2 sidebar | column header + data rows
        row max_y-1     filter breadcrumb / footer
    """
    # ── thread for querying the database ──────────────────────────
    file_path = DATA_DIR / "picosnitch.db"
    q_query_results: queue.Queue = queue.Queue()
    kill_thread_query = threading.Event()

    def fetch_query_results(current_query: str, query_params: tuple, q_query_results: queue.Queue, kill_thread_query: threading.Event) -> None:
        # connect once per fetch; sqlite3 connections are not thread-safe to share
        con = connect_db_readonly(file_path, timeout=1)
        try:
            cur = con.cursor()
            while True and not kill_thread_query.is_set():
                try:
                    cur.execute(current_query, query_params)
                    break
                except sqlite3.OperationalError:
                    time.sleep(0.5)
            results = cur.fetchmany(25)
            while results and not kill_thread_query.is_set():
                q_query_results.put(results)
                results = cur.fetchmany(25)
        finally:
            con.close()

    thread_query = threading.Thread()
    thread_query.start()

    # ── splash screen ─────────────────────────────────────────────
    curses.cbreak()
    curses.noecho()
    curses.curs_set(0)
    _chrome.init_colors()
    _render_splash(stdscr)

    # ── time period setup ─────────────────────────────────────────
    # time_i indexes the time period; time_j is how many periods back
    # we are (0 = current, 1+ = historical window).
    time_i = 0
    time_j = 0
    time_period = [
        "all",
        "1 minute",
        "3 minutes",
        "5 minutes",
        "10 minutes",
        "15 minutes",
        "30 minutes",
        "1 hour",
        "3 hours",
        "6 hours",
        "12 hours",
        "1 day",
        "3 days",
        "7 days",
        "30 days",
        "365 days",
    ]
    time_minutes = [0, 1, 3, 5, 10, 15, 30, 60, 180, 360, 720, 1440, 4320, 10080, 43200, 525600]
    time_deltas = [datetime.timedelta(minutes=x) for x in time_minutes]
    time_round_units = ["second"] + ["minute"] * 6 + ["hour"] * 4 + ["day"] * 3 + ["month"] + ["year"]
    time_round_functions = collections.OrderedDict(
        {
            "second": lambda x: x.replace(microsecond=0),
            "minute": lambda x: x.replace(microsecond=0, second=0),
            "hour": lambda x: x.replace(microsecond=0, second=0, minute=0),
            "day": lambda x: x.replace(microsecond=0, second=0, minute=0, hour=0),
            "month": lambda x: x.replace(microsecond=0, second=0, minute=0, hour=0, day=1),
            "year": lambda x: x.replace(microsecond=0, second=0, minute=0, hour=0, day=1, month=1),
        }
    )

    def time_round_func(resolution_index: int, t: datetime.datetime) -> datetime.datetime:
        return time_round_functions[time_round_units[resolution_index]](t)

    # ── geoip ─────────────────────────────────────────────────────
    geoip_lookup = init_geoip()

    def get_remote_label(ip: str) -> str:
        # 2-char ASCII prefixes line up with country codes ("US 1.1.1.1"):
        #   LO -- LOcal/private (RFC1918, loopback, link-local, ULA)
        #   ZZ -- DB-IP's "no associated country" placeholder
        #   ?? -- public IP not in the GeoIP database
        #   !! -- string did not parse as an IP address
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return f"!! {ip}"
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return f"LO {ip}"
        cc = geoip_lookup(ip) if geoip_lookup else None
        if cc:
            return f"{cc} {ip}"
        return f"?? {ip}"

    # ── view + query state ────────────────────────────────────────
    view_i = 0  # index into _VIEWS
    focus = "sidebar"  # "sidebar" or "main"
    show_help = False
    from_clause = (
        "connections c"
        " JOIN executables e ON c.exe_id = e.id"
        " JOIN executables p ON c.pexe_id = p.id"
        " JOIN executables g ON c.gpexe_id = g.id"
        " JOIN addresses la ON c.laddr_id = la.id"
        " JOIN addresses ra ON c.raddr_id = ra.id"
        " JOIN domains dom ON c.domain_id = dom.id"
    )
    view_stack: list[int] = []  # filter breadcrumb: list of view_i indices
    byte_units = 3

    def round_bytes(size: int, b: int) -> str:
        return f"{size if b == 0 else round(size / 10**b, 1)!s:>{8 if b == 0 else 7}} {'k' if b == 3 else 'M' if b == 6 else 'G' if b == 9 else ''}B"

    # ── ui state ──────────────────────────────────────────────────
    max_y, max_x = stdscr.getmaxyx()
    first_line = 2  # data rows start at row 2 (row 0 status, row 1 column header)
    cursor = first_line
    line = first_line
    filter_values: list = []
    filter_exclude: list[str] = []
    add_filter = False
    add_filter_exclude = False
    find_query = ""  # case-insensitive substring filter (set via `/`)
    update_time = True
    update_query = True
    execute_query = True
    running_query = False
    current_query, current_query_params, current_screen = "", (), [""]
    last_executed_query: tuple = (None, None)
    vt_status: dict = collections.defaultdict(str)
    sum_send = 0
    sum_recv = 0
    time_history: object = ""

    while True:
        view_i %= len(_VIEWS)
        section_now, col_label_now, col_sql_now = _VIEWS[view_i]

        time_i %= len(time_period)
        if time_j < 0 or time_i == 0:
            time_j = 0

        # ── build query ───────────────────────────────────────────
        if update_query:
            if time_j == 0:
                dt_start = datetime.datetime.now() - time_deltas[time_i]
                time_history = time_round_functions["second"](datetime.datetime.now())
                time_start_ts = int(dt_start.timestamp())
                time_end_ts = int(datetime.datetime.now().timestamp())
            elif time_i != 0:
                if update_time:
                    dt_start = time_round_func(time_i, datetime.datetime.now() - time_deltas[time_i] * (time_j - 1))
                    dt_end = time_round_func(time_i, datetime.datetime.now() - time_deltas[time_i] * (time_j - 2))
                    time_start_ts = int(dt_start.timestamp())
                    time_end_ts = int(dt_end.timestamp())
                    time_history = f"{dt_start:%Y-%m-%d %H:%M:%S} -> {dt_end:%Y-%m-%d %H:%M:%S}"
                    update_time = False
            if time_i == 0:
                time_query = ""
            elif view_stack:
                time_query = f" AND c.contime > {time_start_ts} AND c.contime < {time_end_ts}"
            else:
                time_query = f" WHERE c.contime > {time_start_ts} AND c.contime < {time_end_ts}"
            if view_stack:
                filter_query = " AND ".join(f"{_VIEWS[i][2]} IS {exclude}?" for i, exclude in zip(view_stack, filter_exclude))
                current_query = f"SELECT {col_sql_now}, SUM(c.send), SUM(c.recv) FROM {from_clause} WHERE {filter_query}{time_query} GROUP BY {col_sql_now}"
                current_query_params = tuple(filter_values)
            else:
                current_query = f"SELECT {col_sql_now}, SUM(c.send), SUM(c.recv) FROM {from_clause}{time_query} GROUP BY {col_sql_now}"
                current_query_params = ()
            update_query = False

        # ── execute query (threaded) ──────────────────────────────
        if execute_query:
            if (current_query, current_query_params) == last_executed_query and current_screen and current_screen != [""]:
                execute_query = False
            else:
                current_screen = []
                kill_thread_query.set()
                while not q_query_results.empty():
                    _ = q_query_results.get_nowait()
                q_query_results = queue.Queue()
                kill_thread_query = threading.Event()
                thread_query = threading.Thread(
                    target=fetch_query_results,
                    args=(current_query, current_query_params, q_query_results, kill_thread_query),
                    daemon=True,
                )
                thread_query.start()
                last_executed_query = (current_query, current_query_params)
            # update terminal title with daemon status
            try:
                with open(RUN_DIR / "picosnitch.pid", "r") as f:
                    run_status = "pid: " + f.read().strip()
            except Exception:
                run_status = "not running"
            print(f"\033]0;picosnitch v{VERSION} ({run_status})\a", end="", flush=True)
            # virustotal status check
            try:
                with open(DATA_DIR / "state.json", "r") as f:
                    sha256_record = json.load(f)["SHA256"]
                for _exe, hashes in sha256_record.items():
                    for sha256, status in hashes.items():
                        if sha256 not in vt_status and "harmless" in status:
                            suspicious = status.split("'suspicious': ")[1].split(",")[0]
                            malicious = status.split("'malicious': ")[1].split(",")[0]
                            if suspicious == "0" and malicious == "0":
                                vt_status[sha256] = " (clean)"
                            else:
                                vt_status[sha256] = " (suspicious)"
            except Exception:
                pass
            if not q_query_results.empty():
                current_screen += q_query_results.get_nowait()
            sum_send = sum(b for _, b, _ in current_screen)
            sum_recv = sum(b for _, _, b in current_screen)
            execute_query = False
            running_query = True

        # ── apply substring `find_query` filter on top of query results ──
        if find_query:
            fq = find_query.lower()
            display_screen = [row for row in current_screen if fq in str(row[0]).lower()]
            sum_send = sum(b for _, b, _ in display_screen)
            sum_recv = sum(b for _, _, b in display_screen)
        else:
            display_screen = current_screen

        # ── draw screen ───────────────────────────────────────────
        max_y, max_x = stdscr.getmaxyx()
        sidebar_w = min(_SIDEBAR_WIDTH, max(10, max_x // 4))
        main_x = sidebar_w + 1
        main_w = max(20, max_x - main_x - 1)

        stdscr.erase()
        # status bar (row 0, full width)
        _chrome.draw_status_bar(
            stdscr,
            left=[("picosnitch tui", f"v{VERSION}")],
            center=[
                ("view", col_label_now),
                ("time", time_period[time_i]),
                ("rows", f"{min(max(0, cursor - first_line + 1), len(display_screen))}/{len(display_screen)}"),
                ("sent", round_bytes(sum_send, byte_units).strip()),
                ("recv", round_bytes(sum_recv, byte_units).strip()),
            ],
            hint=_tui_status_hint(),
        )
        # sidebar (rows 1..max_y-2)
        _draw_sidebar(stdscr, view_i, focus, sidebar_w, max_y)
        # vertical separator
        for sep_y in range(1, max_y - 1):
            _chrome._safe_addnstr(stdscr, sep_y, sidebar_w, "|", 1, curses.color_pair(_chrome.CP_MUTED))
        # main pane column header (row 1)
        col_hdr_w = max(1, main_w - 30)
        col_hdr = f"{col_label_now:<{col_hdr_w}.{col_hdr_w}}     Sent       Received"
        _chrome._safe_addnstr(
            stdscr,
            1,
            main_x,
            col_hdr,
            main_w,
            curses.color_pair(_chrome.CP_ACCENT) | curses.A_BOLD | curses.A_UNDERLINE,
        )

        # data rows
        line = first_line
        cursor = min(cursor, len(display_screen) + first_line - 1)
        if cursor < first_line:
            cursor = first_line
        rows_avail = max(1, max_y - 1 - first_line)  # leave footer row free
        offset = max(0, cursor - first_line - rows_avail + 1)
        for name, send, recv in display_screen:
            if line == cursor:
                if focus == "main":
                    row_attr = curses.color_pair(_chrome.CP_SELECTION) | curses.A_BOLD
                else:
                    row_attr = curses.color_pair(_chrome.CP_ACCENT)
                if add_filter:
                    view_stack.append(view_i)
                    filter_values.append(name)
                    filter_exclude.append("NOT " if add_filter_exclude else "")
                    add_filter_exclude = False
                    break
            else:
                row_attr = 0
            screen_y = line - offset
            if first_line <= screen_y < max_y - 1:
                # special-case formatting for known columns
                if col_sql_now == "c.contime":
                    name = datetime.datetime.fromtimestamp(name).strftime("%Y-%m-%d %H:%M:%S")
                elif isinstance(name, str):
                    name = name.replace("\0", "")
                elif col_sql_now == "c.uid":
                    try:
                        name = f"{pwd.getpwuid(name).pw_name} ({name})"
                    except Exception:
                        name = f"??? ({name})"
                if col_sql_now == "ra.addr":
                    name = get_remote_label(name)
                if col_sql_now.endswith(".sha256"):
                    name = f"{name}{vt_status[name]}"
                value = f"{round_bytes(send, byte_units):>14.14} {round_bytes(recv, byte_units):>14.14}"
                name_w = max(1, main_w - 29)
                disp = f"{name!s:<{name_w}.{name_w}}{value}"
                _chrome._safe_addnstr(stdscr, screen_y, main_x, disp, main_w, row_attr)
            line += 1

        # filter breadcrumb / footer (row max_y-1)
        if view_stack:
            crumb = " > ".join(f"{_VIEWS[i][1]}{ex.replace('NOT ', '!')}={val!r}" for i, ex, val in zip(view_stack, filter_exclude, filter_values))
            footer = f"filter: {crumb}"
        else:
            footer = f"filter: none   |   history: {time_history}"
        if find_query:
            footer = f"find: /{find_query}/   |   {footer}"
        _chrome._safe_addnstr(
            stdscr,
            max_y - 1,
            0,
            footer,
            max_x - 1,
            curses.color_pair(_chrome.CP_MUTED),
        )

        if show_help:
            _chrome.draw_help_popup(stdscr, "picosnitch tui", _TUI_HELP_LINES)

        stdscr.refresh()

        # ── filter follow-through (set on previous iter) ──────────
        if add_filter:
            add_filter = False
            update_query = True
            execute_query = True
            cursor = first_line
            continue

        # ── input ─────────────────────────────────────────────────
        if running_query:
            if not thread_query.is_alive():
                running_query = False
            stdscr.nodelay(True)
            new_results = False
            while True:
                try:
                    current_screen += q_query_results.get(timeout=0.01)
                    new_results = True
                except queue.Empty:
                    ch = stdscr.getch()
                    if ch != -1:
                        break
                    if new_results:
                        sum_send = sum(b for _, b, _ in current_screen)
                        sum_recv = sum(b for _, _, b in current_screen)
                        break
            stdscr.nodelay(False)
        else:
            ch = stdscr.getch()

        # help popup eats most keys
        if show_help:
            if ch != -1:
                show_help = False
            continue

        action = _keys.key_action(ch)

        # global handlers (work regardless of focus)
        if action == _keys.QUIT:
            return 0
        if action == _keys.HELP:
            show_help = True
            continue
        if action == _keys.RESIZE:
            if curses.is_term_resized(max_y, max_x):
                max_y, max_x = stdscr.getmaxyx()
                stdscr.clear()
                curses.resizeterm(max_y, max_x)
                stdscr.refresh()
                cursor = first_line
            continue
        if action in (_keys.NEXT_SECTION, _keys.PREV_SECTION):
            focus = "main" if focus == "sidebar" else "sidebar"
            continue
        if action == _keys.LIVE:
            sub_action = _live_tab_loop(stdscr)
            if sub_action == "quit":
                return 0
            update_query = True
            execute_query = True
            cursor = first_line
            stdscr.clear()
            continue

        # tui-specific keys (apply globally — affect query state)
        if ch == ord("t"):
            time_j = 0
            time_i += 1
            update_query = True
            execute_query = True
            continue
        if ch == ord("T"):
            time_j = 0
            time_i -= 1
            update_query = True
            execute_query = True
            continue
        if ch == ord("h"):
            time_j += 1
            update_time = True
            update_query = True
            execute_query = True
            continue
        if ch == ord("H"):
            time_j -= 1
            update_time = True
            update_query = True
            execute_query = True
            continue
        if ch == ord("u"):
            byte_units = (byte_units + 3) % 12
            continue
        if ch == ord("U"):
            byte_units = (byte_units - 3) % 12
            continue
        if action == _keys.RESET:
            update_time = True
            update_query = True
            execute_query = True
            continue
        if action == _keys.FILTER:
            entered = _chrome.prompt_input(stdscr, prompt="/", initial=find_query)
            if entered is not None:
                find_query = entered
                cursor = first_line
            stdscr.clear()
            continue

        # focus-specific handlers
        if focus == "sidebar":
            if action == _keys.MOVE_UP:
                view_i = (view_i - 1) % len(_VIEWS)
                update_query = True
                execute_query = True
                cursor = first_line
            elif action == _keys.MOVE_DOWN:
                view_i = (view_i + 1) % len(_VIEWS)
                update_query = True
                execute_query = True
                cursor = first_line
            elif action == _keys.PREV_VIEW:
                view_i = (view_i - 1) % len(_VIEWS)
                update_query = True
                execute_query = True
                cursor = first_line
            elif action == _keys.NEXT_VIEW:
                view_i = (view_i + 1) % len(_VIEWS)
                update_query = True
                execute_query = True
                cursor = first_line
            elif action == _keys.JUMP_HOME:
                view_i = 0
                update_query = True
                execute_query = True
                cursor = first_line
            elif action == _keys.JUMP_END:
                view_i = len(_VIEWS) - 1
                update_query = True
                execute_query = True
                cursor = first_line
            elif action == _keys.DRILL_IN:
                focus = "main"
        else:  # focus == "main"
            if action == _keys.PREV_VIEW:
                view_i = (view_i - 1) % len(_VIEWS)
                update_query = True
                execute_query = True
                cursor = first_line
            elif action == _keys.NEXT_VIEW:
                view_i = (view_i + 1) % len(_VIEWS)
                update_query = True
                execute_query = True
                cursor = first_line
            elif action == _keys.MOVE_UP:
                cursor -= 1
                if cursor < first_line:
                    cursor = first_line
            elif action == _keys.MOVE_DOWN:
                cursor += 1
            elif action == _keys.PAGE_UP:
                cursor -= max(1, max_y - 4)
                if cursor < first_line:
                    cursor = first_line
            elif action == _keys.PAGE_DOWN:
                cursor += max(1, max_y - 4)
                if cursor >= line:
                    cursor = line - 1
            elif action == _keys.JUMP_HOME:
                cursor = first_line
            elif action == _keys.JUMP_END:
                cursor = len(display_screen) + first_line - 1
            elif action == _keys.DRILL_IN or ch == ord("f"):
                add_filter = True
            elif ch == ord("e"):
                add_filter = True
                add_filter_exclude = True
            elif action == _keys.POP_OUT or ch == ord("F") or ch == ord("E"):
                if view_stack:
                    view_i = view_stack.pop()
                    _ = filter_values.pop()
                    _ = filter_exclude.pop()
                update_query = True
                execute_query = True


def tui_init() -> int:
    """init curses ui"""
    # init sql connection
    file_path = DATA_DIR / "picosnitch.db"
    con = connect_db_readonly(file_path, timeout=15)
    # check for table
    cur = con.cursor()
    cur.execute(""" PRAGMA user_version """)
    db_version = cur.fetchone()[0]
    if db_version != DB_VERSION:
        logging.error(f"Incorrect database version of picosnitch.db for picosnitch v{VERSION}")
        sys.exit(1)
    con.close()
    # start curses
    for err_count in reversed(range(30)):
        try:
            return curses.wrapper(tui_loop)
        except KeyboardInterrupt:
            # Ctrl-C anywhere in the TUI (including the find prompt)
            # should look like a clean quit, not a Python traceback.
            return 0
        except curses.error:
            logging.warning(f"CURSES DISPLAY ERROR: try resizing your terminal, ui will close in {err_count + 1} seconds")
            time.sleep(1)
    return 1
