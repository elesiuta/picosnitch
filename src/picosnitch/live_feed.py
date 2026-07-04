# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""
Live event feed published over a UNIX socket so external readers
(picosnitch top, tui Live tab, custom tools) can subscribe to network
events in real time without polling the database.
"""

import grp
import json
import os
import socket
import threading

from picosnitch.constants import RUN_DIR

EVENTS_SOCKET_PATH = RUN_DIR / "events.sock"


class LiveFeedPublisher:
    """Single-publisher, many-subscribers UNIX socket broadcaster.

    Runs an accept thread; per-subscriber writes are blocking-with-timeout
    and a slow subscriber is dropped instead of stalling the publisher.
    """

    def __init__(self, group: str | None = None) -> None:
        self._group = group
        self._sock: socket.socket | None = None
        self._subscribers: list[socket.socket] = []
        self._lock = threading.Lock()
        self._stopped = threading.Event()
        self._accept_thread: threading.Thread | None = None

    def start(self) -> None:
        try:
            EVENTS_SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
            try:
                EVENTS_SOCKET_PATH.unlink()
            except FileNotFoundError:
                pass
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.bind(str(EVENTS_SOCKET_PATH))
            os.chmod(EVENTS_SOCKET_PATH, 0o660)
            if self._group:
                try:
                    gid = grp.getgrnam(self._group).gr_gid
                    os.chown(EVENTS_SOCKET_PATH, -1, gid)
                except (KeyError, PermissionError):
                    pass
            self._sock.listen(8)
            self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
            self._accept_thread.start()
        except Exception:
            self._sock = None

    def _accept_loop(self) -> None:
        while not self._stopped.is_set():
            if self._sock is None:
                return
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            conn.settimeout(0.5)
            with self._lock:
                self._subscribers.append(conn)

    def publish(self, event: dict) -> None:
        if self._sock is None:
            return
        payload = (json.dumps(event, default=str) + "\n").encode("utf-8", "replace")
        dropped: list[socket.socket] = []
        with self._lock:
            for conn in self._subscribers:
                try:
                    conn.sendall(payload)
                except (OSError, socket.timeout):
                    dropped.append(conn)
            for conn in dropped:
                try:
                    conn.close()
                except OSError:
                    pass
                self._subscribers.remove(conn)

    def stop(self) -> None:
        self._stopped.set()
        with self._lock:
            for conn in self._subscribers:
                try:
                    conn.close()
                except OSError:
                    pass
            self._subscribers.clear()
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


class LiveFeedSubscriber:
    """Iterable line-delimited JSON reader for the live event socket."""

    def __init__(self, timeout: float | None = None) -> None:
        self._timeout = timeout
        self._sock: socket.socket | None = None
        self._buf = b""

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self._timeout is not None:
            sock.settimeout(self._timeout)
        sock.connect(str(EVENTS_SOCKET_PATH))
        self._sock = sock

    def settimeout(self, timeout: float | None) -> None:
        if self._sock is not None:
            self._sock.settimeout(timeout)
        self._timeout = timeout

    def __iter__(self) -> "LiveFeedSubscriber":
        return self

    def __next__(self) -> dict:
        if self._sock is None:
            raise StopIteration
        while b"\n" not in self._buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise StopIteration
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\n")
        try:
            return json.loads(line.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            return {}

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
