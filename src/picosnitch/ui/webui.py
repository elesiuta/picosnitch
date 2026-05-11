# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""
Web UI: zero-dependency dashboard served from the standard library.

Uses only the Python standard library (http.server, sqlite3, json) and
ships a single-page HTML/JS/CSS bundle that renders inline SVG sparkline
charts plus aggregate tables. No external JS/CSS is loaded; the entire
asset payload is self-hosted under /static/.
"""

import http.server
import ipaddress
import json
import logging
import os
import socket
import threading
import time
import urllib.parse
from pathlib import Path

from picosnitch.constants import DATA_DIR, RUN_DIR, VERSION
from picosnitch.live_feed import LiveFeedSubscriber
from picosnitch.utils import connect_db_readonly

_DB_PATH = DATA_DIR / "picosnitch.db"
_STATIC_DIR = Path(__file__).parent / "static"

_DIM_SQL: dict[str, str] = {
    "exe": "e.exe",
    "name": "e.name",
    "cmdline": "e.cmdline",
    "sha256": "e.sha256",
    "uid": "c.uid",
    "lport": "c.lport",
    "rport": "c.rport",
    "laddr": "c.laddr",
    "raddr": "c.raddr",
    "domain": "c.domain",
    "pexe": "p.exe",
    "pname": "p.name",
    "pcmdline": "p.cmdline",
    "psha256": "p.sha256",
    "gpexe": "g.exe",
    "gpname": "g.name",
    "gpcmdline": "g.cmdline",
    "gpsha256": "g.sha256",
}

_DIM_LABELS: dict[str, str] = {
    "exe": "Executable",
    "name": "Process Name",
    "cmdline": "Command",
    "sha256": "SHA256",
    "uid": "User",
    "lport": "Local Port",
    "rport": "Remote Port",
    "laddr": "Local Address",
    "raddr": "Remote Address",
    "domain": "Domain",
    "pexe": "Parent Executable",
    "pname": "Parent Name",
    "pcmdline": "Parent Command",
    "psha256": "Parent SHA256",
    "gpexe": "Grandparent Executable",
    "gpname": "Grandparent Name",
    "gpcmdline": "Grandparent Command",
    "gpsha256": "Grandparent SHA256",
}

_FROM_CLAUSE = "connections c JOIN executables e ON c.exe_id = e.id JOIN executables p ON c.pexe_id = p.id JOIN executables g ON c.gpexe_id = g.id"

_TIME_RANGES: dict[str, int] = {
    "1m": 60,
    "5m": 300,
    "15m": 900,
    "1h": 3600,
    "6h": 6 * 3600,
    "1d": 86400,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
    "all": 0,
}


def _query_aggregate(dim: str, time_key: str, where: str | None, whereis: str | None, limit: int) -> dict:
    """Aggregate by (bucketed contime, dim) -> {send, recv}.

    Returns a series-per-dim-value structure so the client can render a
    sparkline per series and a totals table.
    """
    if dim not in _DIM_SQL:
        raise ValueError(f"unknown dim: {dim}")
    seconds = _TIME_RANGES.get(time_key, 0)
    now = int(time.time())
    params: list = []
    where_sql = ""
    if seconds:
        where_sql = " WHERE c.contime > ?"
        params.append(now - seconds)
    if where and where in _DIM_SQL and whereis is not None:
        where_sql += (" AND " if where_sql else " WHERE ") + f"{_DIM_SQL[where]} = ?"
        params.append(whereis)
    # bucket size based on range so a chart never has more than ~300 points
    bucket = max(1, seconds // 300) if seconds else 3600
    dim_col = _DIM_SQL[dim]
    bucket_expr = f"(c.contime / {bucket}) * {bucket}"
    sql = f"SELECT {dim_col} AS d, {bucket_expr} AS t, SUM(c.send) AS s, SUM(c.recv) AS r FROM {_FROM_CLAUSE}{where_sql} GROUP BY d, t ORDER BY t"

    con = connect_db_readonly(_DB_PATH)
    try:
        rows = con.execute(sql, params).fetchall()
    finally:
        con.close()

    series: dict = {}
    totals: dict = {}
    for d, t, s, r in rows:
        key = "" if d is None else str(d)
        bucket_arr = series.setdefault(key, {"t": [], "s": [], "r": []})
        bucket_arr["t"].append(int(t))
        bucket_arr["s"].append(int(s or 0))
        bucket_arr["r"].append(int(r or 0))
        tot = totals.setdefault(key, [0, 0])
        tot[0] += int(s or 0)
        tot[1] += int(r or 0)

    # rank by total (send + recv) descending and trim to limit
    ranked = sorted(totals.items(), key=lambda kv: kv[1][0] + kv[1][1], reverse=True)[:limit]
    keys = [k for k, _ in ranked]
    return {
        "dim": dim,
        "label": _DIM_LABELS[dim],
        "bucket": bucket,
        "now": now,
        "range_seconds": seconds,
        "series": {k: series[k] for k in keys if k in series},
        "totals": {k: {"send": v[0], "recv": v[1]} for k, v in ranked},
    }


def _query_distinct(dim: str, limit: int = 200) -> list[str]:
    if dim not in _DIM_SQL:
        return []
    sql = f"SELECT DISTINCT {_DIM_SQL[dim]} FROM {_FROM_CLAUSE} ORDER BY 1 LIMIT ?"
    con = connect_db_readonly(_DB_PATH)
    try:
        return [str(row[0]) for row in con.execute(sql, (limit,)).fetchall() if row[0] is not None]
    finally:
        con.close()


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = f"picosnitch-web/{VERSION}"

    def log_message(self, format: str, *args) -> None:
        # quiet by default; uncomment for debugging
        pass

    def _send(self, status: int, body: bytes, content_type: str, extra_headers: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self._send(status, body, "application/json")

    def _serve_static(self, name: str) -> None:
        # Strict whitelist — only files we ship
        allowed = {"index.html", "app.js", "style.css"}
        if name not in allowed:
            self._send(404, b"not found", "text/plain")
            return
        path = _STATIC_DIR / name
        try:
            data = path.read_bytes()
        except OSError:
            self._send(404, b"not found", "text/plain")
            return
        ctype = {"index.html": "text/html; charset=utf-8", "app.js": "application/javascript", "style.css": "text/css"}[name]
        self._send(200, data, ctype)

    def do_GET(self) -> None:
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            qs = urllib.parse.parse_qs(parsed.query)

            if path == "/" or path == "/index.html":
                self._serve_static("index.html")
                return
            if path.startswith("/static/"):
                self._serve_static(path[len("/static/") :])
                return
            if path == "/api/meta":
                pid_status = "not running"
                try:
                    with open(RUN_DIR / "picosnitch.pid", "r") as f:
                        pid_status = "pid: " + f.read().strip()
                except OSError:
                    pass
                self._send_json(200, {"version": VERSION, "status": pid_status, "db": str(_DB_PATH), "dims": _DIM_LABELS, "ranges": list(_TIME_RANGES.keys())})
                return
            if path == "/api/aggregate":
                dim = (qs.get("dim", ["exe"])[0]).strip()
                rng = (qs.get("range", ["1h"])[0]).strip()
                where = qs.get("where", [None])[0]
                whereis = qs.get("whereis", [None])[0]
                try:
                    limit = int(qs.get("limit", ["20"])[0])
                except ValueError:
                    limit = 20
                limit = max(1, min(200, limit))
                self._send_json(200, _query_aggregate(dim, rng, where, whereis, limit))
                return
            if path == "/api/distinct":
                dim = (qs.get("dim", ["exe"])[0]).strip()
                self._send_json(200, _query_distinct(dim))
                return
            if path == "/api/live":
                # Server-Sent Events stream of live picosnitch events.
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "keep-alive")
                self.send_header("X-Accel-Buffering", "no")
                self.end_headers()
                sub = LiveFeedSubscriber(timeout=2.0)
                try:
                    sub.connect()
                except (OSError, PermissionError) as e:
                    msg = f"live feed unavailable: {type(e).__name__}: {e}".encode("utf-8", "replace")
                    try:
                        self.wfile.write(b"event: error\ndata: " + msg + b"\n\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    return
                # initial hello so the client immediately sees the connection is alive
                try:
                    self.wfile.write(b": connected\n\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    sub.close()
                    return
                last_keepalive = time.time()
                try:
                    while True:
                        try:
                            event = next(sub)
                        except StopIteration:
                            break
                        except socket.timeout:
                            # idle: send an SSE comment as keepalive so proxies don't drop us
                            if time.time() - last_keepalive >= 15:
                                try:
                                    self.wfile.write(b": keepalive\n\n")
                                    self.wfile.flush()
                                except (BrokenPipeError, ConnectionResetError):
                                    break
                                last_keepalive = time.time()
                            continue
                        except OSError:
                            break
                        line = b"data: " + json.dumps(event, default=str).encode("utf-8") + b"\n\n"
                        try:
                            self.wfile.write(line)
                            self.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError):
                            break
                        last_keepalive = time.time()
                finally:
                    sub.close()
                return

            self._send(404, b"not found", "text/plain")
        except Exception as e:
            self._send(500, f"error: {type(e).__name__}: {e}".encode("utf-8"), "text/plain")


class _ThreadingServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def web_dashboard() -> int:
    """Entry point for `picosnitch webui`."""
    host = os.getenv("HOST", "localhost")
    try:
        port = int(os.getenv("PORT", "5100"))
    except ValueError:
        port = 5100
    try:
        addr = ipaddress.ip_address(host)
        if not addr.is_loopback:
            logging.warning(f"web dashboard binding to non-loopback address {host} - dashboard has no authentication")
    except ValueError:
        if host != "localhost":
            logging.warning(f"web dashboard binding to {host} - dashboard has no authentication")
    server = _ThreadingServer((host, port), _Handler)
    logging.info(f"picosnitch web UI on http://{host}:{port}")
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        while t.is_alive():
            t.join(1.0)
    except KeyboardInterrupt:
        server.shutdown()
        server.server_close()
    return 0
