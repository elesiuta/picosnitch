"""Minimal stdlib WebSocket reader for little-snitch's ws://127.0.0.1:3031/stream.

little-snitch's web UI streams connection rows (each an app, keyed by rowId, with
a `title` = process name) plus periodic cumulative `statistics`
(bytesSent / bytesReceived). This runs a background thread that keeps a live map
of title -> cumulative bytes so the adapter can read a process's total. No
third-party dependency (the harness runs as root).
"""

from __future__ import annotations

import base64
import json
import os
import socket
import struct
import threading


def _connect(host, port, path):
    s = socket.create_connection((host, port), timeout=5)
    key = base64.b64encode(os.urandom(16)).decode()
    req = f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nOrigin: http://{host}:{port}\r\n\r\n"
    s.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = s.recv(4096)
        if not chunk:
            raise ConnectionError("ws handshake failed")
        resp += chunk
    if b"101" not in resp.split(b"\r\n", 1)[0]:
        raise ConnectionError("ws upgrade rejected: " + resp[:80].decode("latin1"))
    return s


def _recvexact(s, n):
    d = b""
    while len(d) < n:
        c = s.recv(n - len(d))
        if not c:
            raise EOFError
        d += c
    return d


def _read_frame(s):
    b1, b2 = _recvexact(s, 2)
    opcode = b1 & 0x0F
    ln = b2 & 0x7F
    if ln == 126:
        ln = struct.unpack(">H", _recvexact(s, 2))[0]
    elif ln == 127:
        ln = struct.unpack(">Q", _recvexact(s, 8))[0]
    masked = b2 & 0x80
    mask = _recvexact(s, 4) if masked else b""
    data = _recvexact(s, ln) if ln else b""
    if masked:
        data = bytes(c ^ mask[i % 4] for i, c in enumerate(data))
    return opcode, data


class LittleSnitchStream:
    """Background reader maintaining {rowId: {title, sent, recv}}."""

    def __init__(self, host="127.0.0.1", port=3031, path="/stream"):
        self.addr = (host, port, path)
        self.rows = {}  # rowId -> {"title","indent","sent","recv"}
        self.lock = threading.Lock()
        self._stop = False
        self._th = None

    def start(self):
        self._th = threading.Thread(target=self._run, daemon=True)
        self._th.start()

    def stop(self):
        self._stop = True

    def _apply(self, u):
        up = u.get("update")
        if up in ("insertConnectionRows", "updateConnectionRows"):
            for r in u.get("rows") or []:
                rid = r.get("id")
                st = r.get("statistics") or {}
                e = self.rows.setdefault(rid, {"title": None, "indent": 0, "sent": 0, "recv": 0})
                if r.get("title") is not None:
                    e["title"] = r.get("title")
                e["indent"] = r.get("indentationLevel", e["indent"])
                if st:
                    e["sent"] = st.get("bytesSent", e["sent"])
                    e["recv"] = st.get("bytesReceived", e["recv"])
            for sblock in u.get("statistics") or []:
                rid = sblock.get("id")
                st = sblock.get("statistics") or {}
                e = self.rows.setdefault(rid, {"title": None, "indent": 0, "sent": 0, "recv": 0})
                # the `statistics` block is the cumulative, byte-exact total (the
                # `trafficEvents` are only approximate increments) -> SET, never ADD.
                e["sent"] = st.get("bytesSent", e["sent"])
                e["recv"] = st.get("bytesReceived", e["recv"])
        elif up == "clearConnectionRows":
            self.rows.clear()

    def _run(self):
        try:
            s = _connect(*self.addr)
        except Exception:
            return
        s.settimeout(2)
        while not self._stop:
            try:
                op, data = _read_frame(s)
            except socket.timeout:
                continue
            except (EOFError, OSError):
                break
            if op == 0x8:
                break
            if op in (0x9, 0xA):
                continue
            try:
                j = json.loads(data.decode("utf-8", "replace"))
            except Exception:
                continue
            with self.lock:
                for u in j if isinstance(j, list) else [j]:
                    self._apply(u)
        try:
            s.close()
        except Exception:
            pass

    def find(self, name_substr):
        """Return (sent, recv) for the top-level app row whose title contains
        name_substr, or None if not seen."""
        with self.lock:
            best = None
            for e in self.rows.values():
                t = e.get("title") or ""
                if name_substr in t:
                    # prefer the top-level (indent 0) row = the app total
                    if best is None or e["indent"] < best["indent"] or (e["indent"] == best["indent"] and e["sent"] + e["recv"] > best["sent"] + best["recv"]):
                        best = e
            return (best["sent"], best["recv"]) if best else None
