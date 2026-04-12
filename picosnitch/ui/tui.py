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

import collections
import curses
import datetime
import ipaddress
import json
import logging
import pwd
import queue
import sqlite3
import sys
import textwrap
import threading
import time

from ..config import load_config
from ..constants import CACHE_DIR, DATA_DIR, RUN_DIR, VERSION


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


def tui_loop(stdscr: curses.window, splash: str) -> int:
    """for curses wrapper"""
    # thread for querying database
    file_path = DATA_DIR / "picosnitch.db"
    q_query_results = queue.Queue()
    kill_thread_query = threading.Event()

    def fetch_query_results(current_query: str, q_query_results: queue.Queue, kill_thread_query: threading.Event):
        con = sqlite3.connect(file_path, timeout=1)
        cur = con.cursor()
        while True and not kill_thread_query.is_set():
            try:
                cur.execute(current_query)
                break
            except sqlite3.OperationalError:
                time.sleep(0.5)
        results = cur.fetchmany(25)
        while results and not kill_thread_query.is_set():
            q_query_results.put(results)
            results = cur.fetchmany(25)
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

    # screens from queries (exe text, name text, cmdline text, sha256 text, contime text, domain text, ip text, port integer, uid integer)
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
        "Users",
        "Local Ports",
        "Remote Ports",
        "Local Addresses",
        "Remote Addresses",
        "Domains",
        "Entry Time",
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
        "User",
        "Local Port",
        "Remote Port",
        "Local Address",
        "Remote Address",
        "Domain",
        "Entry Time",
    ]
    col_sql = ["exe", "name", "cmdline", "sha256", "pexe", "pname", "pcmdline", "psha256", "uid", "lport", "rport", "laddr", "raddr", "domain", "contime"]
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
    current_query, current_screen = "", [""]
    vt_status = collections.defaultdict(str)
    while True:
        # adjust cursor
        tab_i %= len(col_sql)
        time_i %= len(time_period)
        if time_j < 0 or time_i == 0:
            time_j = 0
        cursor %= line
        if cursor < first_line:
            cursor = first_line
        # generate screen
        if update_query:
            if time_j == 0:
                time_history_start = (datetime.datetime.now() - time_deltas[time_i]).strftime("%Y-%m-%d %H:%M:%S")
                time_history_end = "now"
                time_history = time_round_functions["second"](datetime.datetime.now())
            elif time_i != 0:
                if update_time:
                    time_history_start = time_round_func(time_i, datetime.datetime.now() - time_deltas[time_i] * (time_j - 1)).strftime("%Y-%m-%d %H:%M:%S")
                    time_history_end = time_round_func(time_i, datetime.datetime.now() - time_deltas[time_i] * (time_j - 2)).strftime("%Y-%m-%d %H:%M:%S")
                    time_history = f"{time_history_start} -> {time_history_end}"
                    update_time = False
            if time_i == 0:
                time_query = ""
            else:
                if tab_stack:
                    time_query = f' AND contime > datetime("{time_history_start}") AND contime < datetime("{time_history_end}")'
                else:
                    time_query = f' WHERE contime > datetime("{time_history_start}") AND contime < datetime("{time_history_end}")'
            if tab_stack:
                filter_query = " AND ".join(f'{col_sql[i]} IS {exclude}"{value}"' for i, exclude, value in zip(tab_stack, filter_exclude, filter_values))
                current_query = f"SELECT {col_sql[tab_i]}, SUM(send), SUM(recv) FROM connections WHERE {filter_query}{time_query} GROUP BY {col_sql[tab_i]}"
            else:
                current_query = f"SELECT {col_sql[tab_i]}, SUM(send), SUM(recv) FROM connections{time_query} GROUP BY {col_sql[tab_i]}"
            update_query = False
        if execute_query:
            current_screen = []
            # kill old thread with flag, may still be executing current query so don't wait for join, just let gc handle it
            kill_thread_query.set()
            while not q_query_results.empty():
                _ = q_query_results.get_nowait()
            # start new thread, reinitialize queue and kill flag
            q_query_results = queue.Queue()
            kill_thread_query = threading.Event()
            thread_query = threading.Thread(target=fetch_query_results, args=(current_query, q_query_results, kill_thread_query), daemon=True)
            thread_query.start()
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
                # special cases (cmdline null chars, uid, ip, sha256 and vt results)
                if isinstance(name, str):
                    name = name.replace("\0", "")
                elif col_sql[tab_i] == "uid":
                    try:
                        name = f"{pwd.getpwuid(name).pw_name} ({name})"
                    except Exception:
                        name = f"??? ({name})"
                if col_sql[tab_i] == "raddr":
                    name = get_geoip(name)
                if col_sql[tab_i].endswith("sha256"):
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
    con = sqlite3.connect(file_path, timeout=15)
    # check for table
    cur = con.cursor()
    cur.execute(""" PRAGMA user_version """)
    db_version = cur.fetchone()[0]
    if db_version != 3:
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
