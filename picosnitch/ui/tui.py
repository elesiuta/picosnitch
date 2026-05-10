# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

import collections
import curses
import datetime
import ipaddress
import json
import logging
import pwd
import queue
import socket
import sqlite3
import sys
import textwrap
import threading
import time

from ..config import load_config
from ..constants import CACHE_DIR, DATA_DIR, DB_VERSION, RUN_DIR, VERSION
from ..live_feed import EVENTS_SOCKET_PATH, LiveFeedSubscriber
from ..utils import connect_db_readonly


def init_geoip():
    """init a geoip2 reader and return it (along with updating geoip db), or None if not available"""
    config = load_config()
    if not config.monitoring.geoip_lookup:
        return None
    try:
        import geoip2.database

        # download latest database if out of date or does not exist, then create geoip_reader
        geoip_mmdb = CACHE_DIR / "dbip-country-lite.mmdb"
        geoip_mmdb_gz = CACHE_DIR / "dbip-country-lite.mmdb.gz"
        geoip_url = datetime.datetime.now().strftime("https://download.db-ip.com/free/dbip-country-lite-%Y-%m.mmdb.gz")
        if not geoip_mmdb.is_file() or datetime.datetime.fromtimestamp(geoip_mmdb.stat().st_mtime).strftime("%Y%m") != datetime.datetime.now().strftime("%Y%m"):
            try:
                import urllib.request

                try:
                    request = urllib.request.Request(geoip_url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(request) as response, open(geoip_mmdb_gz, "wb") as f:
                        f.write(response.read())
                except Exception:
                    # try previous month if current month is not available
                    geoip_url = (datetime.datetime.now() - datetime.timedelta(days=30)).strftime("https://download.db-ip.com/free/dbip-country-lite-%Y-%m.mmdb.gz")
                    request = urllib.request.Request(geoip_url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(request) as response, open(geoip_mmdb_gz, "wb") as f:
                        f.write(response.read())
                import gzip

                with gzip.open(geoip_mmdb_gz, "rb") as f_in, open(geoip_mmdb, "wb") as f_out:
                    f_out.write(f_in.read())
                geoip_mmdb_gz.unlink()
            except Exception:
                if not geoip_mmdb.is_file():
                    raise Exception("Could not download GeoIP database")
                logging.warning("Could not update GeoIP database, using old version")
        return geoip2.database.Reader(geoip_mmdb)
    except Exception:
        return None


def _format_bytes_short(n: int) -> str:
    for unit in ("B", "K", "M", "G"):
        if n < 1024:
            return f"{n:>5d}{unit}"
        n //= 1024
    return f"{n:>5d}T"


def _live_tab_unavailable(stdscr: "curses.window", lines: list[str]) -> str:
    """Show an error message in the live tab and wait for navigation."""
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()
    for i, line in enumerate(lines):
        if 2 + i >= max_y:
            break
        try:
            stdscr.addnstr(2 + i, 2, line, max_x - 3)
        except curses.error:
            pass
    try:
        stdscr.addnstr(2 + len(lines) + 1, 2, "Press LEFT/RIGHT to switch tab, q to quit.", max_x - 3)
    except curses.error:
        pass
    stdscr.refresh()
    stdscr.nodelay(False)
    while True:
        ch = stdscr.getch()
        if ch == curses.KEY_LEFT:
            return "left"
        if ch == curses.KEY_RIGHT:
            return "right"
        if ch in (ord("q"), 27):
            return "quit"


def _live_tab_loop(stdscr: "curses.window") -> str:
    """Render the live event feed inside the TUI.

    Returns one of: "left", "right", "quit" so the caller can decide
    where to navigate after the user leaves this tab.
    """
    if not EVENTS_SOCKET_PATH.exists():
        return _live_tab_unavailable(
            stdscr,
            [
                f"Live feed unavailable -- {EVENTS_SOCKET_PATH} does not exist.",
                "Start the daemon (sudo picosnitch start) or run `picosnitch top` for a standalone live monitor.",
            ],
        )

    sub = LiveFeedSubscriber(timeout=0.0)
    try:
        sub.connect()
    except PermissionError as e:
        return _live_tab_unavailable(
            stdscr,
            [
                f"Live feed unavailable -- permission denied: {e}",
                "The live event socket is owned by the picosnitch daemon and only readable by root",
                "(or members of the configured picosnitch group). Re-run the TUI with sudo, or use",
                "`sudo picosnitch top` for a standalone live monitor.",
            ],
        )
    except OSError as e:
        return _live_tab_unavailable(
            stdscr,
            [
                f"Could not connect to live feed: {type(e).__name__}: {e}",
            ],
        )

    recent: collections.deque[dict] = collections.deque(maxlen=10000)
    paused = False
    scroll_offset = 0
    total_events = 0
    try:
        stdscr.nodelay(True)
        while True:
            sub.settimeout(0.0)
            try:
                for _ in range(500):
                    try:
                        event = next(sub)
                    except (BlockingIOError, socket.timeout):
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
            help_bar = " ←/→: tabs  ↑↓ PgUp/PgDn Home/End: scroll  p: pause  r: clear  q: quit "
            stdscr.attrset(curses.color_pair(3) | curses.A_BOLD)
            stdscr.addstr(0, 0, help_bar.ljust(max_x - 1)[: max_x - 1])
            status = f" Live feed -- events: {total_events}  shown: {len(recent)}  {'PAUSED' if paused else 'streaming'} "
            stdscr.addstr(1, 0, status.ljust(max_x - 1)[: max_x - 1])
            hdr = f" {'TIME':<8} {'NAME':<16} {'PNAME':<14} {'GPNAME':<14} {'REMOTE':<28} {'SEND':>7} {'RECV':>7}"
            stdscr.addstr(2, 0, hdr.ljust(max_x - 1)[: max_x - 1], curses.A_UNDERLINE)
            stdscr.attrset(0)

            rec_rows = max(1, max_y - 4)
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
                line = (
                    f" {t:<8} "
                    f"{(event.get('name') or '')[:16]:<16} "
                    f"{(event.get('pname') or '')[:14]:<14} "
                    f"{(event.get('gpname') or '')[:14]:<14} "
                    f"{remote[:28]:<28} "
                    f"{_format_bytes_short(int(event.get('send', 0) or 0)):>7} "
                    f"{_format_bytes_short(int(event.get('recv', 0) or 0)):>7}"
                )
                stdscr.addstr(3 + i, 0, line[: max_x - 1])
            stdscr.refresh()

            stdscr.timeout(200)
            ch = stdscr.getch()
            if ch == ord("q") or ch == 27:
                return "quit"
            elif ch == curses.KEY_LEFT:
                return "left"
            elif ch == curses.KEY_RIGHT:
                return "right"
            elif ch == ord("p"):
                paused = not paused
            elif ch == ord("r"):
                recent.clear()
                total_events = 0
                scroll_offset = 0
            elif ch == curses.KEY_UP:
                scroll_offset = min(max_offset, scroll_offset + 1)
            elif ch == curses.KEY_DOWN:
                scroll_offset = max(0, scroll_offset - 1)
            elif ch == curses.KEY_PPAGE:
                scroll_offset = min(max_offset, scroll_offset + max(1, rec_rows - 1))
            elif ch == curses.KEY_NPAGE:
                scroll_offset = max(0, scroll_offset - max(1, rec_rows - 1))
            elif ch == curses.KEY_HOME:
                scroll_offset = 0
            elif ch == curses.KEY_END:
                scroll_offset = max_offset
    finally:
        sub.close()


def tui_loop(stdscr: curses.window, splash: str) -> int:
    """for curses wrapper"""
    # thread for querying database
    file_path = DATA_DIR / "picosnitch.db"
    q_query_results = queue.Queue()
    kill_thread_query = threading.Event()

    def fetch_query_results(current_query: str, query_params: tuple, q_query_results: queue.Queue, kill_thread_query: threading.Event):
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
    # init and splash screen
    curses.cbreak()
    curses.noecho()
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_CYAN)  # selection
    curses.init_pair(2, curses.COLOR_YELLOW, -1)  # splash
    curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_MAGENTA)  # header
    curses.init_pair(4, curses.COLOR_WHITE, -1)  # splash
    splash_lines = splash.splitlines()
    stdscr.clear()
    for i in range(len(splash_lines)):
        if "\u001b[33m" in splash_lines[i]:
            part1 = splash_lines[i].split("\u001b[33m")
            part2 = part1[1].split("\033[0m")
            stdscr.addstr(i, 0, part1[0], curses.color_pair(4))
            stdscr.addstr(i, len(part1[0]), part2[0], curses.color_pair(2))
            stdscr.addstr(i, len(part1[0]) + len(part2[0]), part2[1], curses.color_pair(4))
        else:
            stdscr.addstr(i, 0, splash_lines[i])
    stdscr.refresh()
    # time lookup functions
    # time_i is the index of the time period, time_j is the number of time period steps to go back
    # time_i=0 means all records and time_j=0 means current time (no rounding), due to rounding for time_j>0, time_j=1 may extend partially into the future
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

    def time_round_func(resolution_index, time):
        return time_round_functions[time_round_units[resolution_index]](time)

    # geoip lookup
    geoip_reader = init_geoip()

    def get_geoip(ip: str) -> str:
        try:
            country_code = geoip_reader.country(ip).country.iso_code
            # base = 0x1F1E6 - ord("A")
            # country_flag = chr(base + ord(country_code[0].upper())) + chr(base + ord(country_code[1].upper()))  # flags aren't supported in most fonts and terminals, disable for now
            return f"{country_code} {ip}"
        except Exception:
            try:
                if ipaddress.ip_address(ip).is_private:
                    return f"{chr(0x1F3E0)}{chr(0x200B)} {ip}"  # home emoji + ZWSP so line length is counted correctly
                else:
                    return f"{chr(0x1F310)}{chr(0x200B)} {ip}"  # globe emoji + ZWSP so line length is counted correctly
            except Exception:
                return f"{chr(0x2753)}{chr(0x200B)} {ip}"  # question emoji + ZWSP so line length is counted correctly

    # screens from queries, columns from normalized schema with executables table joined as e (process) and p (parent)
    tab_i = 0
    tab_names = [
        "Executables",
        "Process Names",
        "Commands",
        "SHA256",
        "Parent Executables",
        "Parent Names",
        "Parent Commands",
        "Parent SHA256",
        "Grandparent Executables",
        "Grandparent Names",
        "Grandparent Commands",
        "Grandparent SHA256",
        "Users",
        "Local Ports",
        "Remote Ports",
        "Local Addresses",
        "Remote Addresses",
        "Domains",
        "Entry Time",
        "Live",
    ]
    col_names = [
        "Executable",
        "Process Name",
        "Command",
        "SHA256",
        "Parent Executable",
        "Parent Name",
        "Parent Command",
        "Parent SHA256",
        "Grandparent Executable",
        "Grandparent Name",
        "Grandparent Command",
        "Grandparent SHA256",
        "User",
        "Local Port",
        "Remote Port",
        "Local Address",
        "Remote Address",
        "Domain",
        "Entry Time",
        "Live",
    ]
    col_sql = [
        "e.exe",
        "e.name",
        "e.cmdline",
        "e.sha256",
        "p.exe",
        "p.name",
        "p.cmdline",
        "p.sha256",
        "g.exe",
        "g.name",
        "g.cmdline",
        "g.sha256",
        "c.uid",
        "c.lport",
        "c.rport",
        "c.laddr",
        "c.raddr",
        "c.domain",
        "c.contime",
        "__live__",
    ]
    from_clause = "connections c JOIN executables e ON c.exe_id = e.id JOIN executables p ON c.pexe_id = p.id JOIN executables g ON c.gpexe_id = g.id"
    tab_stack = []
    byte_units = 3

    def round_bytes(size, b):
        return f"{size if b == 0 else round(size / 10**b, 1)!s:>{8 if b == 0 else 7}} {'k' if b == 3 else 'M' if b == 6 else 'G' if b == 9 else ''}B"

    # ui loop
    max_y, max_x = stdscr.getmaxyx()
    first_line = 4
    cursor, line = first_line, first_line
    filter_values = []
    filter_exclude = []
    add_filter = False
    add_filter_exclude = False
    update_time = True
    update_query = True
    execute_query = True
    running_query = False
    current_query, current_query_params, current_screen = "", (), [""]
    last_executed_query: tuple = (None, None)
    vt_status = collections.defaultdict(str)
    while True:
        # adjust cursor
        tab_i %= len(col_sql)
        # Live tab takes over with its own input loop
        if tab_names[tab_i] == "Live":
            action = _live_tab_loop(stdscr)
            if action == "quit":
                return 0
            if action == "left":
                tab_i = (tab_i - 1) % len(col_sql)
            elif action == "right":
                tab_i = (tab_i + 1) % len(col_sql)
            update_query = True
            execute_query = True
            cursor = first_line
            line = first_line
            stdscr.clear()
            continue
        time_i %= len(time_period)
        if time_j < 0 or time_i == 0:
            time_j = 0
        cursor %= line
        if cursor < first_line:
            cursor = first_line
        # generate screen
        if update_query:
            if time_j == 0:
                dt_start = datetime.datetime.now() - time_deltas[time_i]
                time_history_start = dt_start.strftime("%Y-%m-%d %H:%M:%S")
                time_history_end = "now"
                time_history = time_round_functions["second"](datetime.datetime.now())
                time_start_ts = int(dt_start.timestamp())
                time_end_ts = int(datetime.datetime.now().timestamp())
            elif time_i != 0:
                if update_time:
                    dt_start = time_round_func(time_i, datetime.datetime.now() - time_deltas[time_i] * (time_j - 1))
                    dt_end = time_round_func(time_i, datetime.datetime.now() - time_deltas[time_i] * (time_j - 2))
                    time_history_start = dt_start.strftime("%Y-%m-%d %H:%M:%S")
                    time_history_end = dt_end.strftime("%Y-%m-%d %H:%M:%S")
                    time_start_ts = int(dt_start.timestamp())
                    time_end_ts = int(dt_end.timestamp())
                    time_history = f"{time_history_start} -> {time_history_end}"
                    update_time = False
            if time_i == 0:
                time_query = ""
            else:
                if tab_stack:
                    time_query = f" AND c.contime > {time_start_ts} AND c.contime < {time_end_ts}"
                else:
                    time_query = f" WHERE c.contime > {time_start_ts} AND c.contime < {time_end_ts}"
            if tab_stack:
                filter_query = " AND ".join(f"{col_sql[i]} IS {exclude}?" for i, exclude in zip(tab_stack, filter_exclude))
                current_query = f"SELECT {col_sql[tab_i]}, SUM(c.send), SUM(c.recv) FROM {from_clause} WHERE {filter_query}{time_query} GROUP BY {col_sql[tab_i]}"
                current_query_params = tuple(filter_values)
            else:
                current_query = f"SELECT {col_sql[tab_i]}, SUM(c.send), SUM(c.recv) FROM {from_clause}{time_query} GROUP BY {col_sql[tab_i]}"
                current_query_params = ()
            update_query = False
        if execute_query:
            # skip thread restart if query+params haven't changed (e.g. resize, units toggle)
            if (current_query, current_query_params) == last_executed_query and current_screen and current_screen != [""]:
                execute_query = False
            else:
                current_screen = []
                # kill old thread with flag, may still be executing current query so don't wait for join, just let gc handle it
                kill_thread_query.set()
                while not q_query_results.empty():
                    _ = q_query_results.get_nowait()
                # start new thread, reinitialize queue and kill flag
                q_query_results = queue.Queue()
                kill_thread_query = threading.Event()
                thread_query = threading.Thread(target=fetch_query_results, args=(current_query, current_query_params, q_query_results, kill_thread_query), daemon=True)
                thread_query.start()
                last_executed_query = (current_query, current_query_params)
            # check daemon pid for status bar
            try:
                with open(RUN_DIR / "picosnitch.pid", "r") as f:
                    run_status = "pid: " + f.read().strip()
            except Exception:
                run_status = "not running"
            print(f"\033]0;picosnitch v{VERSION} ({run_status})\a", end="", flush=True)
            # check if any new virustotal results
            try:
                with open(DATA_DIR / "state.json", "r") as f:
                    sha256_record = json.load(f)["SHA256"]
                for exe, hashes in sha256_record.items():
                    for sha256, status in hashes.items():
                        if sha256 not in vt_status:
                            if "harmless" in status:
                                suspicious = status.split("'suspicious': ")[1].split(",")[0]
                                malicious = status.split("'malicious': ")[1].split(",")[0]
                                if suspicious == "0" and malicious == "0":
                                    vt_status[sha256] = " (clean)"
                                else:
                                    vt_status[sha256] = " (suspicious)"
            except Exception:
                pass
            # check if any query results are ready
            if not q_query_results.empty():
                current_screen += q_query_results.get_nowait()
            sum_send = sum(b for _, b, _ in current_screen)
            sum_recv = sum(b for _, _, b in current_screen)
            execute_query = False
            running_query = True
        # update headers for screen
        help_bar = f"f/F: filter  e/E: exclude  h/H: history  t/T: time  u/U: units  r: refresh  q: quit {' ':<{curses.COLS}}"
        status_bar = f"history: {time_history}  time: {time_period[time_i]}  line: {min(cursor - first_line + 1, len(current_screen))}/{len(current_screen)}  totals: {round_bytes(sum_send, byte_units).strip()} / {round_bytes(sum_recv, byte_units).strip()}{' ':<{curses.COLS}}"
        if tab_stack:
            l_tabs = " | ".join(reversed([tab_names[tab_i - i] for i in range(1, len(tab_names))]))
            r_tabs = " | ".join([tab_names[(tab_i + i) % len(tab_names)] for i in range(1, len(tab_names))])
            c_tab = tab_names[tab_i]
            filter_query = " & ".join(f'{col_names[i].lower()} {exclude.replace("NOT ", "!")}= "{value}"' for i, exclude, value in zip(tab_stack, filter_exclude, filter_values))
            column_names = f"{f'{col_names[tab_i]} (where {filter_query})':<{curses.COLS - 29}.{curses.COLS - 29}}          Sent       Received"
        else:
            l_tabs = " | ".join(reversed([tab_names[tab_i - i] for i in range(1, len(tab_names))]))
            r_tabs = " | ".join([tab_names[(tab_i + i) % len(tab_names)] for i in range(1, len(tab_names))])
            c_tab = tab_names[tab_i]
            column_names = f"{col_names[tab_i]:<{curses.COLS - 29}}          Sent       Received"
        edges_width = len("<- ... |  | ... ->")
        l_width = (curses.COLS - len(c_tab) - edges_width) // 2
        r_width = curses.COLS - len(c_tab) - edges_width - l_width
        l_tabs = f" ...{l_tabs[-l_width:]:>{l_width}} | "
        r_tabs = f" | {r_tabs:<{r_width}.{r_width}}... "
        # display headers on screen
        stdscr.clear()
        stdscr.attrset(curses.color_pair(3) | curses.A_BOLD)
        stdscr.addstr(0, 0, help_bar)
        stdscr.addstr(1, 0, status_bar)
        stdscr.addstr(2, 0, "<-")
        stdscr.addstr(2, 2, l_tabs, curses.color_pair(3))
        stdscr.addstr(2, 2 + len(l_tabs), c_tab, curses.color_pair(3) | curses.A_BOLD | curses.A_UNDERLINE)
        stdscr.addstr(2, 2 + len(l_tabs) + len(c_tab), r_tabs, curses.color_pair(3))
        stdscr.addstr(2, 2 + len(l_tabs) + len(c_tab) + len(r_tabs), "->")
        stdscr.addstr(3, 0, column_names)
        # display query results on screen
        line = first_line
        cursor = min(cursor, len(current_screen) + first_line - 1)
        offset = max(0, cursor - curses.LINES + 3)
        for name, send, recv in current_screen:
            if line == cursor:
                stdscr.attrset(curses.color_pair(1) | curses.A_BOLD)
                # if space/enter was pressed on previous loop, check current line to update filter
                if add_filter:
                    tab_stack.append(tab_i)
                    filter_values.append(name)
                    if add_filter_exclude:
                        filter_exclude.append("NOT ")
                    else:
                        filter_exclude.append("")
                    add_filter_exclude = False
                    break
            else:
                stdscr.attrset(curses.color_pair(0))
            if first_line <= line - offset < curses.LINES - 1:
                # special cases (cmdline null chars, uid, ip, contime, sha256 and vt results)
                if col_sql[tab_i] == "c.contime":
                    name = datetime.datetime.fromtimestamp(name).strftime("%Y-%m-%d %H:%M:%S")
                elif isinstance(name, str):
                    name = name.replace("\0", "")
                elif col_sql[tab_i] == "c.uid":
                    try:
                        name = f"{pwd.getpwuid(name).pw_name} ({name})"
                    except Exception:
                        name = f"??? ({name})"
                if col_sql[tab_i] == "c.raddr":
                    name = get_geoip(name)
                if col_sql[tab_i].endswith(".sha256"):
                    name = f"{name}{vt_status[name]}"
                value = f"{round_bytes(send, byte_units):>14.14} {round_bytes(recv, byte_units):>14.14}"
                stdscr.addstr(line - offset, 0, f"{name!s:<{curses.COLS - 29}.{curses.COLS - 29}}{value}")
            line += 1
        stdscr.refresh()
        # if space/enter was pressed on previous loop, continue loop with updated filter to execute new query
        if add_filter:
            add_filter = False
            update_query = True
            execute_query = True
            continue
        # check for any new query results while waiting for user input
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
        # process user input
        if ch == ord("\n") or ch == ord(" ") or ch == ord("f"):
            add_filter = True
        if ch == ord("e"):
            add_filter = True
            add_filter_exclude = True
        elif ch == curses.KEY_BACKSPACE or ch == ord("F") or ch == ord("E"):
            if tab_stack:
                tab_i = tab_stack.pop()
                _ = filter_values.pop()
                _ = filter_exclude.pop()
            update_query = True
            execute_query = True
        elif ch == ord("r"):
            update_time = True
            update_query = True
            execute_query = True
        elif ch == ord("t"):
            time_j = 0
            time_i += 1
            update_query = True
            execute_query = True
        elif ch == ord("T"):
            time_j = 0
            time_i -= 1
            update_query = True
            execute_query = True
        elif ch == ord("h"):
            time_j += 1
            update_time = True
            update_query = True
            execute_query = True
        elif ch == ord("H"):
            time_j -= 1
            update_time = True
            update_query = True
            execute_query = True
        elif ch == ord("u"):
            byte_units = (byte_units + 3) % 12
        elif ch == ord("U"):
            byte_units = (byte_units - 3) % 12
        elif ch == curses.KEY_UP:
            cursor -= 1
            if cursor < first_line:
                cursor = -1
        elif ch == curses.KEY_DOWN:
            cursor += 1
        elif ch == curses.KEY_PPAGE:
            cursor -= curses.LINES
            if cursor < first_line:
                cursor = first_line
        elif ch == curses.KEY_NPAGE:
            cursor += curses.LINES
            if cursor >= line:
                cursor = line - 1
        elif ch == curses.KEY_HOME:
            cursor = first_line
        elif ch == curses.KEY_END:
            cursor = len(current_screen) + first_line - 1
        elif ch == curses.KEY_LEFT:
            tab_i -= 1
            update_query = True
            execute_query = True
        elif ch == curses.KEY_RIGHT:
            tab_i += 1
            update_query = True
            execute_query = True
        elif ch == curses.KEY_RESIZE and curses.is_term_resized(max_y, max_x):
            max_y, max_x = stdscr.getmaxyx()
            stdscr.clear()
            curses.resizeterm(max_y, max_x)
            stdscr.refresh()
            cursor = first_line
        elif ch == 27 or ch == ord("q"):
            return 0


def tui_init() -> int:
    """init curses ui"""
    splash = textwrap.dedent("""
        @@&@@                                                              @@@@,
      &&.,,. &&&&&&%&%&&&&&&&&(..                      ..&&%&%&&&&&&&&%&&&&  .,#&%
        ,,/%#/(....,.,/(.  ...*,,%%                  %#*,..,... // ...,..//#%*,
             @@@@@@#((      #(/    @@  %@@@@@@@@  /@@    #(,      ##@@&@@@@
                   %@&    #(  .      @@\u001b[33m/********\033[0m@@(        (((    @@
                     .@@((    ,    @@\u001b[33m.,*,,****,,,,\033[0m(@@      . .#(@@
                        @@@@@@&@@@@@@\u001b[33m,,*,,,,,,,,,,\033[0m(@@@@@@@@&@@@@
                                   @@\u001b[33m**/*/*,**///*\033[0m(@@
                                   @@\u001b[33m.****/*//,*,*\033[0m/@@
                                     @&\u001b[33m//*////,/\033[0m&&(
                                       ,*\u001b[33m,,,,,,\033[0m,

    Loading database ...
    """)
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
            return curses.wrapper(tui_loop, splash)
        except curses.error:
            logging.warning(f"CURSES DISPLAY ERROR: try resizing your terminal, ui will close in {err_count + 1} seconds")
            time.sleep(1)
    return 1
