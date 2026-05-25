# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""
`picosnitch top` -- live curses view of network events as they happen.

Connects to the daemon's live event socket and displays a rolling list of
recent connections, plus a per-executable rate aggregate.

If no daemon is running, top spawns `picosnitch start-no-daemon` as a
subprocess in its own session/process group so a single killpg(SIGTERM)
on top exit tears down the monitor and all of its helper subprocesses.
Top requires root for this path (BPF needs CAP_SYS_ADMIN).
"""

import atexit
import collections
import curses
import logging
import os
import signal
import socket
import subprocess
import sys
import time

from picosnitch.constants import LOG_DIR, RUN_DIR, VERSION
from picosnitch.live_feed import EVENTS_SOCKET_PATH, LiveFeedSubscriber
from picosnitch.ui import _chrome, _keys


def _format_bytes(n: int) -> str:
    for unit in ("B", "K", "M", "G"):
        if n < 1024:
            return f"{n:>5d}{unit}"
        n //= 1024
    return f"{n:>5d}T"


def _scan_listening_ports() -> dict[str, set[int]]:
    """Map executable path -> set of locally-bound ports.

    Walks /proc/net/{tcp,tcp6,udp,udp6} for currently-bound sockets and
    resolves each socket inode back to its owning executable via
    /proc/<pid>/fd/. Best-effort: silently skips processes we cannot inspect."""
    inode_to_port: dict[int, int] = {}
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        try:
            with open(f"/proc/net/{proto}") as f:
                lines = f.readlines()[1:]
        except OSError:
            continue
        tcp_proto = proto.startswith("tcp")
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            # tcp: only LISTEN (state 0A). udp: any bound entry counts.
            if tcp_proto and parts[3] != "0A":
                continue
            try:
                port = int(parts[1].rsplit(":", 1)[1], 16)
                inode = int(parts[9])
            except (ValueError, IndexError):
                continue
            if inode and port:
                inode_to_port[inode] = port
    if not inode_to_port:
        return {}
    exe_to_ports: dict[str, set[int]] = {}
    try:
        pids = [name for name in os.listdir("/proc") if name.isdigit()]
    except OSError:
        return {}
    for pid in pids:
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            continue
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            if not target.startswith("socket:[") or not target.endswith("]"):
                continue
            try:
                inode = int(target[8:-1])
            except ValueError:
                continue
            port = inode_to_port.get(inode)
            if port is not None:
                exe_to_ports.setdefault(exe, set()).add(port)
    return exe_to_ports


def _stop_spawned(proc: subprocess.Popen) -> None:
    """SIGTERM the spawned monitor's whole process group, then SIGKILL if needed."""
    if proc.poll() is not None:
        return
    pgid = proc.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=10)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def _wait_for_socket(timeout: float, proc: subprocess.Popen) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if EVENTS_SOCKET_PATH.exists():
            return True
        if proc.poll() is not None:
            return False
        time.sleep(0.2)
    return False


def _top_loop(stdscr, sub: LiveFeedSubscriber) -> int:
    curses.cbreak()
    curses.noecho()
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.keypad(True)
    _chrome.init_colors()

    recent: collections.deque[dict] = collections.deque(maxlen=10000)
    totals: dict[tuple[str, str], list[int | float]] = {}
    listening: dict[str, set[int]] = {}
    last_listen_scan = 0.0
    listen_scan_interval = 5.0
    sort_by_recv = False
    paused = False
    scroll_offset = 0  # offset into recent (bottom panel)
    summary_offset = 0  # offset into totals ranking (top panel)
    focus_summary = False  # False = recent panel scrolls, True = summary
    show_help = False
    find_query = ""  # case-insensitive substring filter (set via `/`)
    total_events_seen = 0
    counters_reset_at = time.time()
    last_render = 0.0
    render_interval = 0.25  # min seconds between full repaints

    while True:
        sub.settimeout(0.0)
        new_events_this_tick = 0
        try:
            for _ in range(500):
                try:
                    event = next(sub)
                except (BlockingIOError, socket.timeout):
                    break
                except StopIteration:
                    return 0
                if not event or not isinstance(event, dict):
                    continue
                total_events_seen += 1
                event["_t"] = time.time()
                if not paused:
                    recent.appendleft(event)
                    new_events_this_tick += 1
                key = (event.get("name", ""), event.get("exe", ""))
                row = totals.setdefault(key, [0, 0, 0, time.time()])
                row[0] += int(event.get("send", 0) or 0)
                row[1] += int(event.get("recv", 0) or 0)
                row[2] += 1
                row[3] = time.time()
        except Exception:
            pass

        # Pin the scrolled view to the same items even when new events
        # are prepended to `recent` -- otherwise the user-visible rows
        # appear to scroll on their own.
        if scroll_offset > 0 and new_events_this_tick:
            scroll_offset = min(len(recent), scroll_offset + new_events_this_tick)

        now = time.time()
        if now - last_listen_scan >= listen_scan_interval:
            try:
                listening = _scan_listening_ports()
            except Exception:
                listening = {}
            last_listen_scan = now
        if now - last_render >= render_interval:
            last_render = now
            max_y, max_x = stdscr.getmaxyx()
            elapsed = max(1, int(now - counters_reset_at))
            sort_label = "recv" if sort_by_recv else "send"
            stdscr.erase()
            _chrome.draw_status_bar(
                stdscr,
                left=[("picosnitch top", f"v{VERSION}")],
                center=[
                    ("events", f"{total_events_seen}"),
                    ("window", f"{elapsed}s"),
                    ("sort", sort_label),
                    *([("find", find_query)] if find_query else []),
                ],
                hint=_keys.format_status_hint(),
                paused=paused,
            )

            # Clamp split so the layout has at least 1 row above and 2 below.
            split = max(2, min(max_y - 2, max_y // 2))
            sum_marker = "*" if focus_summary else " "
            col_hdr = f"{sum_marker}{'EXECUTABLE':<40} {'NAME':<16} {'COUNT':>7} {'SENT':>7} {'RECV':>7} {'LISTEN':<14}"
            sort_idx = 1 if sort_by_recv else 0
            ranked = sorted(totals.items(), key=lambda kv: kv[1][sort_idx], reverse=True)
            if find_query:
                fq = find_query.lower()
                ranked = [kv for kv in ranked if fq in kv[0][0].lower() or fq in kv[0][1].lower()]
            totals_rows = max(0, split - 2)
            sum_max_offset = max(0, len(ranked) - totals_rows)
            if summary_offset > sum_max_offset:
                summary_offset = sum_max_offset
            sum_indicator = ""
            if ranked:
                sv_top = summary_offset + 1
                sv_bot = min(len(ranked), summary_offset + totals_rows)
                sum_indicator = f"  [{sv_top}-{sv_bot} / {len(ranked)}]"
            _chrome._safe_addnstr(stdscr, 1, 0, (col_hdr + sum_indicator).ljust(max_x), max_x - 1, curses.A_UNDERLINE)
            for i, ((name, exe), (s, r, c, _ts)) in enumerate(ranked[summary_offset : summary_offset + totals_rows]):
                ports = listening.get(exe)
                ports_s = ",".join(str(p) for p in sorted(ports)) if ports else ""
                line = f" {exe[:40]:<40} {name[:16]:<16} {c:>7d} {_format_bytes(int(s)):>7} {_format_bytes(int(r)):>7} {ports_s}"
                _chrome._safe_addnstr(stdscr, 2 + i, 0, line, max_x - 1)

            rec_rows = max(1, max_y - split - 1)
            recent_list = list(recent)
            if find_query:
                fq = find_query.lower()
                recent_list = [
                    ev
                    for ev in recent_list
                    if fq in (ev.get("name") or "").lower() or fq in (ev.get("exe") or "").lower() or fq in (ev.get("domain") or "").lower() or fq in (ev.get("raddr") or "").lower()
                ]
            max_offset = max(0, len(recent_list) - rec_rows)
            if scroll_offset > max_offset:
                scroll_offset = max_offset
            scroll_indicator = ""
            if recent_list:
                visible_top = scroll_offset + 1
                visible_bot = min(len(recent_list), scroll_offset + rec_rows)
                scroll_indicator = f"  [{visible_top}-{visible_bot} / {len(recent_list)}]"
            rec_marker = "*" if not focus_summary else " "
            rec_hdr = f"{rec_marker}{'TIME':<8} {'NAME':<16} {'PNAME':<12} {'GPNAME':<12} {'LPORT':>5} {'REMOTE':<25} {'SEND':>7} {'RECV':>7}{scroll_indicator}"
            _chrome._safe_addnstr(stdscr, split, 0, rec_hdr.ljust(max_x), max_x - 1, curses.A_UNDERLINE)
            for i, event in enumerate(recent_list[scroll_offset : scroll_offset + rec_rows]):
                ts = event.get("_t", 0)
                t = time.strftime("%H:%M:%S", time.localtime(ts)) if ts else time.strftime("%H:%M:%S")
                raddr = event.get("raddr", "") or ""
                rport = event.get("rport", -1)
                remote = (event.get("domain") or raddr) + (f":{rport}" if rport and rport > 0 else "")
                lport = event.get("lport", -1)
                lport_s = f"{lport:d}" if lport and lport > 0 else ""
                line = (
                    f" {t:<8} "
                    f"{(event.get('name') or '')[:16]:<16} "
                    f"{(event.get('pname') or '')[:12]:<12} "
                    f"{(event.get('gpname') or '')[:12]:<12} "
                    f"{lport_s:>5} "
                    f"{remote[:25]:<25} "
                    f"{_format_bytes(int(event.get('send', 0) or 0)):>7} "
                    f"{_format_bytes(int(event.get('recv', 0) or 0)):>7}"
                )
                _chrome._safe_addnstr(stdscr, split + 1 + i, 0, line, max_x - 1)

            if show_help:
                _chrome.draw_help_popup(stdscr, "picosnitch top", _keys.HELP_LINES)

            stdscr.noutrefresh()
            curses.doupdate()
        else:
            # cheap re-derive for key handling without re-render
            max_y, _max_x = stdscr.getmaxyx()
            split = max(2, min(max_y - 2, max_y // 2))
            rec_rows = max(1, max_y - split - 1)
            max_offset = max(0, len(recent) - rec_rows)
            totals_rows = max(0, split - 2)
            sum_max_offset = max(0, len(totals) - totals_rows)

        # Drain all queued keypresses so a held arrow scrolls smoothly
        # instead of waiting one render-tick per repeat.
        try:
            stdscr.timeout(50)
            ch = stdscr.getch()
        except KeyboardInterrupt:
            return 0
        steps_up = steps_down = 0
        page_up = page_down = 0
        go_home = go_end = False
        toggle_sort = toggle_pause = do_reset = toggle_focus = toggle_help = False
        do_find = False
        quit_now = False
        while ch != -1:
            action = _keys.key_action(ch)
            if action == _keys.HELP:
                toggle_help = True
            elif action == _keys.QUIT:
                quit_now = True
                break
            elif show_help:
                # while help is visible, ignore everything else except resize
                if action == _keys.RESIZE:
                    last_render = 0.0
            elif action == _keys.SORT:
                toggle_sort = True
            elif action == _keys.PAUSE:
                toggle_pause = True
            elif action == _keys.RESET:
                do_reset = True
            elif action == _keys.FILTER:
                do_find = True
                break  # handle prompt outside the drain loop
            elif action in (_keys.NEXT_SECTION, _keys.PREV_SECTION):
                toggle_focus = True
            elif action == _keys.MOVE_UP:
                steps_up += 1
            elif action == _keys.MOVE_DOWN:
                steps_down += 1
            elif action == _keys.PAGE_UP:
                page_up += 1
            elif action == _keys.PAGE_DOWN:
                page_down += 1
            elif action == _keys.JUMP_HOME:
                go_home = True
            elif action == _keys.JUMP_END:
                go_end = True
            elif action == _keys.RESIZE:
                last_render = 0.0  # force immediate repaint
            stdscr.timeout(0)
            ch = stdscr.getch()
        if quit_now:
            return 0
        if toggle_help:
            show_help = not show_help
            last_render = 0.0
        if toggle_sort:
            sort_by_recv = not sort_by_recv
        if toggle_pause:
            paused = not paused
        if toggle_focus:
            focus_summary = not focus_summary
            last_render = 0.0
        if do_reset:
            totals.clear()
            recent.clear()
            total_events_seen = 0
            scroll_offset = 0
            summary_offset = 0
            counters_reset_at = time.time()
            last_render = 0.0
            continue
        if do_find:
            entered = _chrome.prompt_input(stdscr, prompt="/", initial=find_query)
            if entered is not None:
                find_query = entered
                scroll_offset = 0
                summary_offset = 0
            last_render = 0.0
            continue
        # Scroll direction: UP moves toward the top of the list
        # (smaller offset), DOWN moves toward the bottom (larger).
        delta_steps = steps_down - steps_up
        delta_pages = page_down - page_up
        if focus_summary:
            if go_home:
                summary_offset = 0
            if go_end:
                summary_offset = sum_max_offset
            if delta_steps:
                summary_offset = max(0, min(sum_max_offset, summary_offset + delta_steps))
            if delta_pages:
                page = max(1, totals_rows - 1)
                summary_offset = max(0, min(sum_max_offset, summary_offset + page * delta_pages))
        else:
            if go_home:
                scroll_offset = 0
            if go_end:
                scroll_offset = max_offset
            if delta_steps:
                scroll_offset = max(0, min(max_offset, scroll_offset + delta_steps))
            if delta_pages:
                page = max(1, rec_rows - 1)
                scroll_offset = max(0, min(max_offset, scroll_offset + page * delta_pages))
        # any user input -> render this frame
        if steps_up or steps_down or page_up or page_down or go_home or go_end or toggle_sort or toggle_pause or toggle_focus:
            last_render = 0.0


def top_init() -> int:
    """Entry point for `picosnitch top`."""
    spawned: subprocess.Popen | None = None
    daemon_pid_file = RUN_DIR / "picosnitch.pid"

    if not EVENTS_SOCKET_PATH.exists():
        if daemon_pid_file.exists():
            try:
                old_pid = int(daemon_pid_file.read_text().strip())
                os.kill(old_pid, 0)
                logging.error(f"Daemon pid file {daemon_pid_file} exists but socket {EVENTS_SOCKET_PATH} is missing — try `sudo picosnitch restart`.")
                return 1
            except (OSError, ValueError):
                # stale pidfile from a crashed picosnitch -- remove it
                try:
                    daemon_pid_file.unlink()
                except OSError:
                    pass
        if os.geteuid() != 0:
            # BPF needs CAP_SYS_ADMIN. Refuse to escalate privileges
            # ourselves (security audit: no implicit sudo re-exec).
            logging.error("picosnitch top needs root to spawn a private monitor; re-run with: sudo picosnitch top")
            return 1
        logging.info("No picosnitch daemon detected — launching a private monitor (will exit when top exits).")
        # Spawn start-no-daemon as its own session leader so a single
        # killpg(pgid, SIGTERM) on top exit reaches every helper subprocess.
        log_path = LOG_DIR / "picosnitch-top.log"
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            mon_log = open(log_path, "ab", buffering=0)
        except OSError:
            mon_log = open(os.devnull, "ab", buffering=0)
        try:
            spawned = subprocess.Popen(
                [sys.executable, "-m", "picosnitch", "start-no-daemon"],
                stdin=subprocess.DEVNULL,
                stdout=mon_log,
                stderr=mon_log,
                start_new_session=True,
                close_fds=True,
            )
        finally:
            mon_log.close()

        atexit.register(_stop_spawned, spawned)

        def _signal_cleanup(_signum: int, _frame) -> None:
            _stop_spawned(spawned)
            sys.exit(0)

        signal.signal(signal.SIGTERM, _signal_cleanup)
        signal.signal(signal.SIGHUP, _signal_cleanup)

        if not _wait_for_socket(timeout=20.0, proc=spawned):
            logging.error("Spawned monitor did not create the live event socket within 20s.")
            _stop_spawned(spawned)
            return 1

    sub = LiveFeedSubscriber(timeout=1.0)
    try:
        sub.connect()
    except PermissionError:
        logging.error(f"Live event socket {EVENTS_SOCKET_PATH} is not accessible (permission denied) — re-run with: sudo picosnitch top")
        if spawned is not None:
            _stop_spawned(spawned)
        return 1
    except OSError as e:
        logging.error(f"Could not connect to picosnitch live feed: {e}")
        if spawned is not None:
            _stop_spawned(spawned)
        return 1
    # While curses owns the tty, redirect stderr to a log file so any
    # in-process logging (LiveFeedSubscriber warnings, exceptions, etc.)
    # does not corrupt the screen. Save the original fd to restore on exit.
    saved_stderr_fd = os.dup(2)
    log_path = LOG_DIR / "picosnitch-top.log"
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    except OSError:
        log_fd = os.open(os.devnull, os.O_WRONLY)
    os.dup2(log_fd, 2)
    os.close(log_fd)
    try:
        return curses.wrapper(_top_loop, sub)
    except KeyboardInterrupt:
        return 0
    finally:
        os.dup2(saved_stderr_fd, 2)
        os.close(saved_stderr_fd)
        sub.close()
        if spawned is not None:
            _stop_spawned(spawned)


if __name__ == "__main__":
    sys.exit(top_init())
