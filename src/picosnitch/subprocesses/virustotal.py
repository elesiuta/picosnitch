# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import pickle
import queue
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from picosnitch.config import Config
from picosnitch.utils import get_fstat

VT_UPLOAD_MAX_BYTES = 32 * 1024 * 1024
VT_JSON_MAX_BYTES = 4 * 1024 * 1024


def _validate_url(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "www.virustotal.com":
        raise ValueError(f"unexpected VirusTotal URL: {url}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "VirusTotal redirect refused", headers, fp)


_OPENER = urllib.request.build_opener(_NoRedirect)


def _read_json(resp) -> dict:
    data = resp.read(VT_JSON_MAX_BYTES + 1)
    if len(data) > VT_JSON_MAX_BYTES:
        raise ValueError("VirusTotal JSON response is too large")
    return json.loads(data.decode("utf-8", "replace"))


def _http_get_json(url: str, headers: dict, timeout: int = 60) -> dict:
    _validate_url(url)
    req = urllib.request.Request(url, headers=headers, method="GET")
    with _OPENER.open(req, timeout=timeout) as resp:
        return _read_json(resp)


def _http_post_multipart_file_json(url: str, headers: dict, file_obj, filename: str, expected_sha256: str = "", timeout: int = 300) -> dict:
    """POST a single file as multipart/form-data with field name 'file'.

    Streams the file in 64K chunks built into a single bytes payload (VT
    file uploads are bounded by their API limits anyway, so a single
    bytes blob is acceptable and avoids needing chunked transfer).
    """
    _validate_url(url)
    boundary = uuid.uuid4().hex
    crlf = b"\r\n"
    safe_filename = os.path.basename(filename).replace("\\", "_").replace('"', "_").replace("\r", "_").replace("\n", "_")
    head = crlf.join(
        (
            f"--{boundary}".encode(),
            f'Content-Disposition: form-data; name="file"; filename="{safe_filename}"'.encode(),
            b"Content-Type: application/octet-stream",
            b"",
            b"",
        )
    )
    tail = crlf + f"--{boundary}--".encode() + crlf
    body_chunks = [head]
    size = 0
    digest = hashlib.sha256()
    while True:
        chunk = file_obj.read(65536)
        if not chunk:
            break
        size += len(chunk)
        if size > VT_UPLOAD_MAX_BYTES:
            raise ValueError("VirusTotal direct uploads are limited to 32 MiB")
        digest.update(chunk)
        body_chunks.append(chunk)
    if expected_sha256 and digest.hexdigest() != expected_sha256:
        raise ValueError("VirusTotal upload hash mismatch")
    body_chunks.append(tail)
    body = b"".join(body_chunks)
    post_headers = dict(headers)
    post_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    post_headers["Content-Length"] = str(len(body))
    req = urllib.request.Request(url, data=body, headers=post_headers, method="POST")
    with _OPENER.open(req, timeout=timeout) as resp:
        return _read_json(resp)


def run_virustotal(config: Config, fan_fd: int, q_error: multiprocessing.Queue[str], q_vt_pending: multiprocessing.Queue[bytes], q_vt_results: multiprocessing.Queue[bytes]) -> int:
    """get virustotal results of process executable"""
    parent_process = multiprocessing.parent_process()
    assert parent_process is not None
    from ..utils import drop_root_permanent, resolve_unprivileged_user

    # close the privileged fanotify handle before dropping: never used here, must not persist into
    # the dropped-privilege domain
    try:
        os.close(fan_fd)
    except OSError:
        pass
    # always drop root: this subprocess makes HTTPS requests and parses JSON, which must not run as
    # root even when [desktop].user is unset (matches run_remote_sql / run_notifications)
    uid, gid = resolve_unprivileged_user(config.desktop.user)
    drop_root_permanent(uid, gid)
    request_limit = config.virustotal.request_limit_seconds if config.virustotal.api_key else 0
    headers = {"x-apikey": config.virustotal.api_key} if config.virustotal.api_key else {}

    def get_analysis(analysis_id: dict, sha256: str) -> dict:
        api_url = "https://www.virustotal.com/api/v3/analyses/" + analysis_id["data"]["id"]
        for _ in range(90):
            time.sleep(max(5, request_limit))
            response = _http_get_json(api_url, headers)
            if response["data"]["attributes"]["status"] == "completed":
                return response["data"]["attributes"]["stats"]
        return {"timeout": api_url, "sha256": sha256}

    while True:
        if not parent_process.is_alive():
            return 0
        try:
            time.sleep(request_limit)
            proc, analysis = None, None
            proc, sha256 = pickle.loads(q_vt_pending.get(block=True, timeout=15))
            suspicious = False
            if config.virustotal.api_key:
                try:
                    analysis = _http_get_json("https://www.virustotal.com/api/v3/files/" + sha256, headers)
                    analysis = analysis["data"]["attributes"]["last_analysis_stats"]
                except Exception as e:
                    # only HTTP 404 means the file is genuinely absent from VT and worth
                    # uploading; a 401/429/timeout must not trigger an upload -- that worsens
                    # rate limits and would ship the binary to VT on a transient error
                    if not (isinstance(e, urllib.error.HTTPError) and e.code == 404):
                        # retryable marker (not a terminal verdict): resolve_hash in secondary and
                        # sync_vt_results re-query any state starting with "VT lookup error", so a
                        # rate-limited/offline/auth failure is retried instead of cached forever
                        q_vt_results.put(pickle.dumps((proc, sha256, f"VT lookup error: {type(e).__name__}", suspicious)))
                        continue
                    if config.virustotal.file_upload:
                        try:
                            with open(proc["fd"], "rb") as f:
                                if (proc["dev"], proc["ino"]) != get_fstat(f.fileno()):
                                    raise ValueError("file stat mismatch")
                                analysis_id = _http_post_multipart_file_json("https://www.virustotal.com/api/v3/files", headers, f, proc["exe"], sha256)
                            analysis = get_analysis(analysis_id, sha256)
                        except Exception:
                            try:
                                with open(proc["exe"], "rb") as f:
                                    analysis_id = _http_post_multipart_file_json("https://www.virustotal.com/api/v3/files", headers, f, proc["exe"], sha256)
                                analysis = get_analysis(analysis_id, sha256)
                            except Exception:
                                q_vt_results.put(pickle.dumps((proc, sha256, "Failed to read process for upload", suspicious)))
                                continue
                    else:
                        # reached only for a genuine 404 (absent from VT) with uploads disabled;
                        # a 401/invalid key now takes the retryable branch above, not this one
                        q_vt_results.put(pickle.dumps((proc, sha256, "File not analyzed (analysis not found)", suspicious)))
                        continue
                if analysis.get("suspicious", 0) != 0 or analysis.get("malicious", 0) != 0:
                    suspicious = True
                q_vt_results.put(pickle.dumps((proc, sha256, str(analysis), suspicious)))
            else:
                q_vt_results.put(pickle.dumps((proc, sha256, "File not analyzed (no api key)", suspicious)))
        except queue.Empty:
            # have to timeout here to check whether to terminate otherwise this could stay hanging
            # daemon=True flag for multiprocessing.Process does not work after root privileges are dropped for parent
            pass
        except Exception as e:
            q_error.put("VT %s%s on line %s" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?"))
            try:
                analysis = str(analysis)
            except Exception:
                analysis = "unknown analysis"
            q_error.put("Last VT Exception on: %s with %s" % (str(proc), str(analysis)))
