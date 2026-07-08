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
    "laddr": "la.addr",
    "raddr": "ra.addr",
    "domain": "dom.domain",
    "pexe": "p.exe",
    "pname": "p.name",
    "pcmdline": "p.cmdline",
    "psha256": "p.sha256",
    "gpexe": "g.exe",
    "gpname": "g.name",
    "gpcmdline": "g.cmdline",
    "gpsha256": "g.sha256",
    "netns": "c.netns",
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
    "netns": "Network ns",
}

_FROM_CLAUSE = (
    "connections c"
    " JOIN executables e ON c.exe_id = e.id"
    " JOIN executables p ON c.pexe_id = p.id"
    " JOIN executables g ON c.gpexe_id = g.id"
    " JOIN addresses la ON c.laddr_id = la.id"
    " JOIN addresses ra ON c.raddr_id = ra.id"
    " JOIN domains dom ON c.domain_id = dom.id"
)

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


def _resolve_window(qs: dict) -> tuple[int, int, str]:
    """Resolve a time window from query string params.

    Accepts either ``range=<preset>`` (e.g. ``1h``, ``1d``, ``all``) or
    ``from=<unix_ts>&to=<unix_ts>`` for a custom window. Returns
    ``(since, until, label)`` where ``since == 0`` means no lower
    bound. ``label`` is what the UI should display for this window.
    """
    now = int(time.time())
    raw_from = qs.get("from", [""])[0]
    raw_to = qs.get("to", [""])[0]
    if raw_from or raw_to:
        try:
            # OverflowError: int(float("inf")); ValueError: int(float("nan"))/non-numeric
            since = int(float(raw_from)) if raw_from else 0
            until = int(float(raw_to)) if raw_to else now
        except (ValueError, OverflowError):
            since, until = 0, now
        if since < 0:
            since = 0
        if until <= 0:
            until = now
        if since and until and since > until:
            since, until = until, since
        label = f"{since}-{until}"
        return since, until, label
    rng = (qs.get("range", ["1h"])[0]).strip()
    seconds = _TIME_RANGES.get(rng, 0)
    since = now - seconds if seconds else 0
    return since, now, rng


def _query_aggregate(dim: str, since: int, until: int, label: str, where: str | None, whereis: str | None, limit: int) -> dict:
    """Aggregate by (bucketed contime, dim) -> {send, recv}.

    Returns a series-per-dim-value structure so the client can render a
    sparkline per series and a totals table.
    """
    if dim not in _DIM_SQL:
        raise ValueError(f"unknown dim: {dim}")
    seconds = max(0, until - since) if since else 0
    params: list = []
    where_parts: list[str] = []
    if since:
        where_parts.append("c.contime > ?")
        params.append(since)
    if until:
        where_parts.append("c.contime <= ?")
        params.append(until)
    if where and where in _DIM_SQL and whereis is not None:
        where_parts.append(f"{_DIM_SQL[where]} = ?")
        params.append(whereis)
    where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    # bucket size based on range so a chart never has more than ~300 points
    bucket = max(1, seconds // 300) if seconds else 3600
    dim_col = _DIM_SQL[dim]
    bucket_expr = f"(c.contime / {bucket}) * {bucket}"
    sql = f"SELECT {dim_col} AS d, {bucket_expr} AS t, SUM(c.send) AS s, SUM(c.recv) AS r, COUNT(*) AS n FROM {_FROM_CLAUSE}{where_sql} GROUP BY d, t ORDER BY t"

    con = connect_db_readonly(_DB_PATH)
    try:
        rows = con.execute(sql, params).fetchall()
    finally:
        con.close()

    series: dict = {}
    totals: dict = {}
    for d, t, s, r, n in rows:
        key = "" if d is None else str(d)
        bucket_arr = series.setdefault(key, {"t": [], "s": [], "r": []})
        bucket_arr["t"].append(int(t))
        bucket_arr["s"].append(int(s or 0))
        bucket_arr["r"].append(int(r or 0))
        tot = totals.setdefault(key, [0, 0, 0])
        tot[0] += int(s or 0)
        tot[1] += int(r or 0)
        tot[2] += int(n or 0)

    # rank by total (send + recv) descending and trim to limit
    ranked = sorted(totals.items(), key=lambda kv: kv[1][0] + kv[1][1], reverse=True)[:limit]
    keys = [k for k, _ in ranked]
    return {
        "dim": dim,
        "label": _DIM_LABELS[dim],
        "bucket": bucket,
        "now": until,
        "since": since,
        "until": until,
        "range": label,
        "range_seconds": seconds,
        "series": {k: series[k] for k in keys if k in series},
        "totals": {k: {"send": v[0], "recv": v[1], "connections": v[2]} for k, v in ranked},
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


def _query_summary(since: int, until: int, label: str) -> dict:
    """Top-level KPIs for the chosen window: total bytes, connection
    count, distinct active executables and netns count."""
    where_parts: list[str] = []
    params: list = []
    if since:
        where_parts.append("c.contime > ?")
        params.append(since)
    if until:
        where_parts.append("c.contime <= ?")
        params.append(until)
    where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    sql = f"SELECT COALESCE(SUM(c.send), 0), COALESCE(SUM(c.recv), 0), COUNT(*), COUNT(DISTINCT c.exe_id), COUNT(DISTINCT c.netns) FROM connections c{where_sql}"
    con = connect_db_readonly(_DB_PATH)
    try:
        row = con.execute(sql, params).fetchone()
    finally:
        con.close()
    sent, recv, conns, exes, netns = row or (0, 0, 0, 0, 0)
    return {
        "range": label,
        "since": since,
        "until": until,
        "now": until,
        "sent": int(sent),
        "recv": int(recv),
        "connections": int(conns),
        "executables": int(exes),
        "netns": int(netns),
    }


def _query_drilldown(dim: str, value: str, since: int, until: int, label: str) -> dict:
    """Drilldown payload for a single (dim, value) selection: KPIs,
    a sparkline of received bytes over time, the top remote
    destinations and the most recent connections.

    Empty `value` is matched as the dim-NULL case so the user can drill
    into rows that have no domain / cmdline / etc."""
    if dim not in _DIM_SQL:
        raise ValueError(f"unknown dim: {dim}")
    seconds = max(0, until - since) if since else 0
    dim_col = _DIM_SQL[dim]
    where_parts: list[str] = []
    params: list = []
    if since:
        where_parts.append("c.contime > ?")
        params.append(since)
    if until:
        where_parts.append("c.contime <= ?")
        params.append(until)
    if value == "" or value is None:
        where_parts.append(f"({dim_col} IS NULL OR {dim_col} = '')")
    else:
        where_parts.append(f"{dim_col} = ?")
        params.append(value)
    where_sql = " WHERE " + " AND ".join(where_parts)
    bucket = max(60, seconds // 120) if seconds else 3600

    con = connect_db_readonly(_DB_PATH)
    try:
        # KPIs in one round trip.
        row = con.execute(
            "SELECT COALESCE(SUM(c.send), 0), COALESCE(SUM(c.recv), 0),"
            " COUNT(*), COUNT(DISTINCT c.domain_id), COUNT(DISTINCT c.raddr_id),"
            " COUNT(DISTINCT c.uid), COUNT(DISTINCT c.netns),"
            " MIN(c.contime), MAX(c.contime)"
            f" FROM {_FROM_CLAUSE}{where_sql}",
            params,
        ).fetchone() or (0, 0, 0, 0, 0, 0, 0, None, None)
        sent, recv, conns, dom_n, addr_n, uid_n, ns_n, first_t, last_t = row

        # Sparkline (received bytes per bucket).
        bucket_expr = f"(c.contime / {bucket}) * {bucket}"
        spark_rows = con.execute(
            f"SELECT {bucket_expr} AS t, SUM(c.send), SUM(c.recv) FROM {_FROM_CLAUSE}{where_sql} GROUP BY t ORDER BY t",
            params,
        ).fetchall()

        # Recent connections (latest first).
        recent_rows = con.execute(
            f"SELECT c.contime, ra.addr, c.rport, COALESCE(dom.domain, ''), c.send, c.recv, e.name FROM {_FROM_CLAUSE}{where_sql} ORDER BY c.contime DESC LIMIT 12",
            params,
        ).fetchall()

        # Process info: distinct {name, cmdline, exe, sha256} for e/p/g
        # across every connection that matched the drilldown filter.
        def _process_info(alias: str, limit: int = 8) -> dict:
            out: dict[str, list[str]] = {}
            for field in ("name", "cmdline", "exe", "sha256"):
                col = f"{alias}.{field}"
                rows = con.execute(
                    f"SELECT {col} AS v, COUNT(*) AS n FROM {_FROM_CLAUSE}{where_sql} AND {col} IS NOT NULL AND {col} != '' GROUP BY v ORDER BY n DESC LIMIT {limit}",
                    params,
                ).fetchall()
                out[field] = [str(v) for v, _ in rows]
            return out

        process_info = {
            "e": _process_info("e"),
            "p": _process_info("p"),
            "g": _process_info("g"),
        }

        # Breakdowns: per-uid / per-netns / per-domain / per-address totals.
        def _breakdown(group_expr: str, limit: int = 25) -> list:
            rows = con.execute(
                f"SELECT {group_expr} AS k,"
                " COALESCE(SUM(c.send), 0), COALESCE(SUM(c.recv), 0), COUNT(*)"
                f" FROM {_FROM_CLAUSE}{where_sql}"
                f" GROUP BY k ORDER BY SUM(c.send) + SUM(c.recv) DESC LIMIT {limit}",
                params,
            ).fetchall()
            return [{"key": "" if k is None else str(k), "send": int(s or 0), "recv": int(r or 0), "count": int(n)} for k, s, r, n in rows]

        breakdowns = {
            "uid": _breakdown("c.uid"),
            "netns": _breakdown("c.netns"),
            "domain": _breakdown("COALESCE(NULLIF(dom.domain, ''), '(none)')"),
            "address": _breakdown("ra.addr"),
        }
    finally:
        con.close()

    return {
        "dim": dim,
        "label": _DIM_LABELS[dim],
        "value": value,
        "range": label,
        "since": since,
        "until": until,
        "now": until,
        "bucket": bucket,
        "totals": {
            "sent": int(sent),
            "recv": int(recv),
            "connections": int(conns),
            "domains": int(dom_n),
            "addresses": int(addr_n),
            "uids": int(uid_n),
            "netns": int(ns_n),
            "first_seen": int(first_t) if first_t else 0,
            "last_seen": int(last_t) if last_t else 0,
        },
        "sparkline": [{"t": int(t), "s": int(s or 0), "r": int(r or 0)} for t, s, r in spark_rows],
        "recent": [
            {
                "t": int(t),
                "raddr": addr or "",
                "rport": int(rport or 0),
                "domain": dom,
                "send": int(s or 0),
                "recv": int(r or 0),
                "name": name or "",
            }
            for t, addr, rport, dom, s, r, name in recent_rows
        ],
        "breakdowns": breakdowns,
        "process_info": process_info,
    }


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
        ctypes_by_name = {
            "index.html": "text/html; charset=utf-8",
            "app.js": "application/javascript",
            "style.css": "text/css",
            "favicon.svg": "image/svg+xml",
        }
        if name not in ctypes_by_name:
            self._send(404, b"not found", "text/plain")
            return
        path = _STATIC_DIR / name
        try:
            data = path.read_bytes()
        except OSError:
            self._send(404, b"not found", "text/plain")
            return
        ctype = ctypes_by_name[name]
        self._send(200, data, ctype)

    def _host_allowed(self) -> bool:
        """reject a request whose Host header isn't a loopback name (DNS-rebinding guard).
        only enforced on a loopback bind; a missing Host is a non-browser client (rebinding
        always carries the attacker's Host, which browsers set and page JS cannot override)."""
        if not getattr(self.server, "loopback_only", False):
            return True
        host_header = self.headers.get("Host", "")
        if not host_header:
            return True
        return host_header.lower() in getattr(self.server, "allowed_hosts", frozenset())

    def do_GET(self) -> None:
        try:
            if not self._host_allowed():
                self._send(403, b"forbidden: Host header not allowed", "text/plain")
                return
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
                # status_state: "running" (green), "stopped" (red), "unknown" (yellow)
                pid_path = RUN_DIR / "picosnitch.pid"
                status_state = "unknown"
                status_text = "unknown"
                uptime_seconds = 0
                start_ts = 0
                try:
                    pid_str = pid_path.read_text().strip()
                    try:
                        pid_int = int(pid_str)
                    except ValueError:
                        pid_int = 0
                    if pid_int and (Path("/proc") / str(pid_int)).exists():
                        status_state = "running"
                        status_text = "running (pid " + pid_str + ")"
                        try:
                            mtime = pid_path.stat().st_mtime
                            uptime_seconds = max(0, int(time.time() - mtime))
                            start_ts = int(mtime)
                        except OSError:
                            pass
                    else:
                        status_state = "stopped"
                        status_text = "not running (stale pid file)"
                except PermissionError:
                    status_state = "unknown"
                    status_text = "unknown (insufficient permission to read pid file)"
                except FileNotFoundError:
                    status_state = "stopped"
                    status_text = "not running"
                except OSError:
                    status_state = "unknown"
                    status_text = "unknown"
                db_size = 0
                try:
                    db_size = _DB_PATH.stat().st_size
                except OSError:
                    pass
                self._send_json(
                    200,
                    {
                        "version": VERSION,
                        "status": status_text,
                        "status_state": status_state,
                        "db": str(_DB_PATH),
                        "db_size_bytes": db_size,
                        "uptime_seconds": uptime_seconds,
                        "start_ts": start_ts,
                        "dims": _DIM_LABELS,
                        "ranges": list(_TIME_RANGES.keys()),
                    },
                )
                return
            if path == "/api/summary":
                since, until, label = _resolve_window(qs)
                self._send_json(200, _query_summary(since, until, label))
                return
            if path == "/api/aggregate":
                dim = (qs.get("dim", ["exe"])[0]).strip()
                since, until, label = _resolve_window(qs)
                where = qs.get("where", [None])[0]
                whereis = qs.get("whereis", [None])[0]
                try:
                    limit = int(qs.get("limit", ["1000"])[0])
                except ValueError:
                    limit = 1000
                limit = max(1, min(5000, limit))
                try:
                    self._send_json(200, _query_aggregate(dim, since, until, label, where, whereis, limit))
                except ValueError as e:
                    # unknown dim: 400 JSON, matching /api/drilldown (not a 500)
                    self._send_json(400, {"error": str(e)})
                return
            if path == "/api/distinct":
                dim = (qs.get("dim", ["exe"])[0]).strip()
                self._send_json(200, _query_distinct(dim))
                return
            if path == "/api/drilldown":
                dim = (qs.get("dim", ["exe"])[0]).strip()
                value = qs.get("value", [""])[0]
                since, until, label = _resolve_window(qs)
                try:
                    self._send_json(200, _query_drilldown(dim, value, since, until, label))
                except ValueError as e:
                    self._send_json(400, {"error": str(e)})
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
        except (BrokenPipeError, ConnectionResetError):
            # client hung up mid-response; nothing left to send
            return
        except Exception as e:
            # best-effort 500; swallow a secondary failure if the response already started
            try:
                self._send(500, f"error: {type(e).__name__}: {e}".encode("utf-8"), "text/plain")
            except OSError:
                pass


class _ThreadingServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    # set in web_dashboard(): reject non-allowlisted Host headers on a loopback bind
    loopback_only = False
    allowed_hosts: frozenset[str] = frozenset()


def web_dashboard() -> int:
    """Entry point for `picosnitch webui`."""
    host = os.getenv("PICOSNITCH_HOST", "localhost")
    try:
        port = int(os.getenv("PICOSNITCH_PORT", "5100"))
    except ValueError:
        logging.warning(f"invalid PICOSNITCH_PORT {os.getenv('PICOSNITCH_PORT')!r}, using 5100")
        port = 5100
    try:
        loopback_only = ipaddress.ip_address(host).is_loopback
    except ValueError:
        # not an IP literal; "localhost" resolves to loopback, a custom hostname is the user's call
        loopback_only = host == "localhost"
    if not loopback_only:
        logging.warning(f"web dashboard binding to {host} - dashboard has no authentication")
    try:
        server = _ThreadingServer((host, port), _Handler)
    except OSError as e:
        logging.error(f"could not start web dashboard on {host}:{port}: {e}")
        return 1
    # on a loopback bind, only accept requests whose Host is a loopback name, so a remote
    # page can't reach the dashboard via DNS rebinding (the victim's browser always sends
    # the attacker's Host); a non-loopback bind already warned it has no auth
    server.loopback_only = loopback_only
    allowed = set()
    for h in ("localhost", "127.0.0.1", "::1", "[::1]", host):
        allowed.add(h.lower())
        allowed.add(f"{h}:{port}".lower())
    server.allowed_hosts = frozenset(allowed)
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
