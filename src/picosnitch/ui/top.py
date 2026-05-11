# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""
`picosnitch top` — live curses view of network events as they happen.

Connects to the daemon's live event socket and displays a rolling list of
recent connections, plus a per-executable rate aggregate.

If no daemon is running, top forks a `multiprocessing.Process` that runs
`run_main_loop` directly. The child sets PR_SET_PDEATHSIG=SIGTERM so it
also dies if top is killed with SIGKILL. On normal exit / Ctrl+C /
SIGTERM, top calls `child.terminate()` (SIGTERM) which trips the main
loop's shutdown handler and tears down all picosnitch subprocesses
cleanly. Top requires root for this path (BPF needs CAP_SYS_ADMIN);
if launched without root it exits with an error rather than escalating
privileges itself -- the user should re-run with `sudo`.
"""

import atexit
import collections
import ctypes
import curses
import logging
import multiprocessing
import os
import signal
import socket
import sys
import time

from picosnitch.constants import LOG_DIR, RUN_DIR, VERSION
from picosnitch.live_feed import EVENTS_SOCKET_PATH, LiveFeedSubscriber

PR_SET_PDEATHSIG = 1


def _format_bytes(n: int) -> str:
    for unit in ("B", "K", "M", "G"):
        if n < 1024:
            return f"{n:>5d}{unit}"
        n //= 1024
    return f"{n:>5d}T"


def _scan_listening_ports() -> dict[str, set[int]]:
    """Map executable path -> set of locally-bound ports.

    Picosnitch event records only carry the source port of the connection
    that triggered the event, so a listening service that has never been
    contacted (or whose contact was missed) won't show up via the live
    feed alone. Walk /proc/net/{tcp,tcp6,udp,udp6} for currently-bound
    sockets and resolve each socket inode back to its owning executable
    via /proc/<pid>/fd/. Best-effort: silently skips processes we cannot
    inspect (permission denied, races, etc.)."""
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


def _standalone_monitor_entry() -> None:
    """multiprocessing.Process target that runs the picosnitch main loop.

    Sets PR_SET_PDEATHSIG=SIGTERM so the kernel signals us when the
    parent (top) dies for any reason -- including SIGKILL. The main
    loop's SIGTERM handler then tears down all helper subprocesses
    cleanly.

    Critically, also redirects stdout/stderr (and reconfigures the
    root logger) to a log file so that warnings / errors emitted by
    the monitor and its helper subprocesses do not scribble onto
    top's curses display."""
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0)
    except Exception:
        pass
    # If top already died between fork and prctl, exit immediately.
    if os.getppid() == 1:
        return
    # Redirect stdout/stderr to a log file so monitor logging does not
    # corrupt top's curses screen. Fall back to /dev/null if the log
    # dir is not writable.
    log_path = LOG_DIR / "picosnitch-top.log"
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    except OSError:
        log_fd = os.open(os.devnull, os.O_WRONLY)
    os.dup2(log_fd, 1)
    os.dup2(log_fd, 2)
    os.close(log_fd)
    # Reconfigure the root logger -- it was set up at module import to
    # write to the inherited stderr (which we just replaced). Point it
    # at the new fd 2 explicitly via a fresh StreamHandler.
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(logging.StreamHandler(os.fdopen(2, "w", buffering=1)))
    root.setLevel(logging.INFO)
    # Imported lazily so importing picosnitch.ui.top stays cheap.
    from ..config import load_config
    from ..main_loop import run_main_loop
    from ..utils import load_state

    # main_loop checks sys.argv[1] -- emulate `start-no-daemon` so it
    # exits instead of trying to relaunch via subprocess on failure.
    sys.argv = [sys.argv[0], "start-no-daemon"]
    config = load_config()
    state = load_state()
    sys.exit(run_main_loop(config, state))


def _stop_spawned(child: multiprocessing.Process) -> None:
    """Best-effort clean shutdown of the spawned monitor process tree."""
    if not child.is_alive():
        return
    try:
        child.terminate()  # SIGTERM -- main_loop sets shutdown_event
    except (OSError, ValueError):
        pass
    child.join(timeout=10)
    if child.is_alive():
        try:
            child.kill()  # SIGKILL as a last resort
        except (OSError, ValueError):
            pass
        child.join(timeout=5)


def _wait_for_socket(timeout: float, child: multiprocessing.Process) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if EVENTS_SOCKET_PATH.exists():
            return True
        if not child.is_alive():
            return False
        time.sleep(0.2)
    return False


def _top_loop(stdscr, sub: LiveFeedSubscriber) -> int:
    curses.cbreak()
    curses.noecho()
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.keypad(True)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_MAGENTA)

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
            paused_label = " [paused]" if paused else ""
            header = f" picosnitch top v{VERSION}  events:{total_events_seen:>6d}  window:{elapsed}s  sort:{sort_label}{paused_label}   q:quit   ?:help "
            stdscr.erase()
            stdscr.attrset(curses.color_pair(1) | curses.A_BOLD)
            stdscr.addnstr(0, 0, header.ljust(max_x), max_x - 1)
            stdscr.attrset(0)

            if show_help:
                help_lines = [
                    "picosnitch top -- key bindings",
                    "",
                    "  q            quit",
                    "  ?            toggle this help",
                    "  TAB          switch focus between summary and event log",
                    "  UP / DOWN    scroll focused panel by 1 row",
                    "  PgUp / PgDn  scroll focused panel by 1 page",
                    "  Home / End   jump to top / bottom of focused panel",
                    "  s            toggle sort by sent / received bytes",
                    "  p            pause / resume the live event log",
                    "  r            reset all counters and clear the log",
                    "",
                    "  press ? to close",
                ]
                for i, line in enumerate(help_lines):
                    if 1 + i >= max_y:
                        break
                    stdscr.addnstr(1 + i, 0, line, max_x - 1)
                stdscr.noutrefresh()
                curses.doupdate()
                split = max(8, max_y // 2)
                rec_rows = max(1, max_y - split - 1)
                max_offset = max(0, len(recent) - rec_rows)
                totals_rows = max(0, split - 2)
                sum_max_offset = max(0, len(totals) - totals_rows)
                # skip rendering the live panels while help overlays the screen
                _skip_panels = True
            else:
                _skip_panels = False

            if not _skip_panels:
                split = max(8, max_y // 2)
                sum_marker = "*" if focus_summary else " "
                col_hdr = f"{sum_marker}{'EXECUTABLE':<40} {'NAME':<16} {'COUNT':>7} {'SENT':>7} {'RECV':>7} {'LISTEN':<14}"
                sort_idx = 1 if sort_by_recv else 0
                ranked = sorted(totals.items(), key=lambda kv: kv[1][sort_idx], reverse=True)
                totals_rows = max(0, split - 2)
                sum_max_offset = max(0, len(ranked) - totals_rows)
                if summary_offset > sum_max_offset:
                    summary_offset = sum_max_offset
                sum_indicator = ""
                if ranked:
                    sv_top = summary_offset + 1
                    sv_bot = min(len(ranked), summary_offset + totals_rows)
                    sum_indicator = f"  [{sv_top}-{sv_bot} / {len(ranked)}]"
                stdscr.addnstr(1, 0, (col_hdr + sum_indicator).ljust(max_x), max_x - 1, curses.A_UNDERLINE)
                for i, ((name, exe), (s, r, c, _ts)) in enumerate(ranked[summary_offset : summary_offset + totals_rows]):
                    ports = listening.get(exe)
                    ports_s = ",".join(str(p) for p in sorted(ports)) if ports else ""
                    line = f" {exe[:40]:<40} {name[:16]:<16} {c:>7d} {_format_bytes(int(s)):>7} {_format_bytes(int(r)):>7} {ports_s}"
                    stdscr.addnstr(2 + i, 0, line, max_x - 1)

                rec_rows = max(1, max_y - split - 1)
                recent_list = list(recent)
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
                stdscr.addnstr(split, 0, rec_hdr.ljust(max_x), max_x - 1, curses.A_UNDERLINE)
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
                    stdscr.addnstr(split + 1 + i, 0, line, max_x - 1)
                stdscr.noutrefresh()
                curses.doupdate()
        else:
            # cheap re-derive for key handling without re-render
            max_y, _max_x = stdscr.getmaxyx()
            split = max(8, max_y // 2)
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
        quit_now = False
        while ch != -1:
            if ch == ord("?"):
                toggle_help = True
            elif ch == ord("q"):
                quit_now = True
                break
            elif show_help:
                # while help is visible, ignore everything else except resize
                if ch == curses.KEY_RESIZE:
                    last_render = 0.0
            elif ch == ord("s"):
                toggle_sort = True
            elif ch == ord("p"):
                toggle_pause = True
            elif ch == ord("r"):
                do_reset = True
            elif ch == ord("\t"):
                toggle_focus = True
            elif ch == curses.KEY_UP:
                steps_up += 1
            elif ch == curses.KEY_DOWN:
                steps_down += 1
            elif ch == curses.KEY_PPAGE:
                page_up += 1
            elif ch == curses.KEY_NPAGE:
                page_down += 1
            elif ch == curses.KEY_HOME:
                go_home = True
            elif ch == curses.KEY_END:
                go_end = True
            elif ch == curses.KEY_RESIZE:
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
    spawned: multiprocessing.Process | None = None
    daemon_pid_file = RUN_DIR / "picosnitch.pid"

    if not EVENTS_SOCKET_PATH.exists():
        if daemon_pid_file.exists():
            logging.error(f"Daemon pid file {daemon_pid_file} exists but socket {EVENTS_SOCKET_PATH} is missing — try `sudo picosnitch restart`.")
            return 1
        if os.geteuid() != 0:
            # BPF needs CAP_SYS_ADMIN. Refuse to escalate privileges
            # ourselves (security audit: no implicit sudo re-exec).
            logging.error("picosnitch top needs root to spawn a private monitor; re-run with: sudo picosnitch top")
            return 1
        logging.info("No picosnitch daemon detected — launching a private monitor (will exit when top exits).")
        # `spawn` start method to avoid sharing curses-related state if the
        # caller has already done any tty I/O; fork would also work but
        # spawn is safer across the multiprocessing primitives the main
        # loop sets up.
        ctx = multiprocessing.get_context("fork")
        spawned = ctx.Process(target=_standalone_monitor_entry, name="picosnitch-monitor")
        spawned.start()

        atexit.register(_stop_spawned, spawned)

        def _signal_cleanup(_signum: int, _frame) -> None:
            _stop_spawned(spawned)
            sys.exit(0)

        signal.signal(signal.SIGTERM, _signal_cleanup)
        signal.signal(signal.SIGHUP, _signal_cleanup)

        if not _wait_for_socket(timeout=20.0, child=spawned):
            logging.error("Spawned monitor did not create the live event socket within 20s.")
            _stop_spawned(spawned)
            return 1

    sub = LiveFeedSubscriber(timeout=1.0)
    try:
        sub.connect()
    except (OSError, PermissionError) as e:
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
