#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
"""
Mock picosnitch live event publisher for offline screenshot capture.

Binds the same AF_UNIX socket path that the real daemon uses
(EVENTS_SOCKET_PATH from picosnitch.live_feed) and replays a canned JSONL
file on a loop, preserving the original inter-event timing via the per-line
't' field. The 't' key is stripped before sending so payloads match what
the real publisher emits.

Because PICOSNITCH_TEST=1 is set, the socket is created under
/tmp/picosnitch/run/picosnitch/events.sock -- no root needed.

Run as `python3 mock_feed.py [path/to/events.jsonl]` or import and use
MockFeed as a context manager.
"""

import json
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path

os.environ.setdefault("PICOSNITCH_TEST", "1")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "src"))
from picosnitch.live_feed import EVENTS_SOCKET_PATH  # noqa: E402

DEFAULT_FIXTURE = HERE / "fixtures" / "events.jsonl"


class MockFeed:
    def __init__(self, fixture: Path = DEFAULT_FIXTURE, loop: bool = True, speed: float = 1.0) -> None:
        self.fixture = Path(fixture)
        self.loop = loop
        self.speed = speed
        self._sock: socket.socket | None = None
        self._subs: list[socket.socket] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._accept_thread: threading.Thread | None = None
        self._publish_thread: threading.Thread | None = None

    def start(self) -> None:
        EVENTS_SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            EVENTS_SOCKET_PATH.unlink()
        except FileNotFoundError:
            pass
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(str(EVENTS_SOCKET_PATH))
        os.chmod(EVENTS_SOCKET_PATH, 0o660)
        self._sock.listen(8)
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        self._publish_thread = threading.Thread(target=self._publish_loop, daemon=True)
        self._publish_thread.start()

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            conn.settimeout(0.5)
            with self._lock:
                self._subs.append(conn)

    def _publish_loop(self) -> None:
        events: list[dict] = []
        with open(self.fixture) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                events.append(json.loads(line))
        if not events:
            return
        while not self._stop.is_set():
            t0_wall = time.time()
            t0_event = events[0].get("t", 0.0)
            for ev in events:
                if self._stop.is_set():
                    return
                wait = (ev.get("t", 0.0) - t0_event) / max(self.speed, 0.001) - (time.time() - t0_wall)
                if wait > 0:
                    if self._stop.wait(wait):
                        return
                payload_dict = {k: v for k, v in ev.items() if k != "t"}
                payload = (json.dumps(payload_dict) + "\n").encode("utf-8")
                self._broadcast(payload)
            if not self.loop:
                return

    def _broadcast(self, payload: bytes) -> None:
        dropped: list[socket.socket] = []
        with self._lock:
            for conn in self._subs:
                try:
                    conn.sendall(payload)
                except (OSError, socket.timeout):
                    dropped.append(conn)
            for conn in dropped:
                try:
                    conn.close()
                except OSError:
                    pass
                self._subs.remove(conn)

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            for conn in self._subs:
                try:
                    conn.close()
                except OSError:
                    pass
            self._subs.clear()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        try:
            EVENTS_SOCKET_PATH.unlink()
        except FileNotFoundError:
            pass

    def __enter__(self) -> "MockFeed":
        self.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.stop()


def main() -> int:
    fixture = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_FIXTURE
    feed = MockFeed(fixture=fixture, loop=True)
    feed.start()
    print(f"Mock feed publishing {fixture} on {EVENTS_SOCKET_PATH} (Ctrl-C to stop)")

    def _stop(_signum: int, _frame) -> None:
        feed.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main())
