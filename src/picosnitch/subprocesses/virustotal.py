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
import urllib.request
import uuid

from picosnitch.config import Config
from picosnitch.utils import get_fstat


def _http_get_json(url: str, headers: dict, timeout: int = 60) -> dict:
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - VirusTotal API only
        return json.loads(resp.read().decode("utf-8", "replace"))


def _http_post_multipart_file_json(url: str, headers: dict, file_obj, filename: str, timeout: int = 300) -> dict:
    """POST a single file as multipart/form-data with field name 'file'.

    Streams the file in 64K chunks built into a single bytes payload (VT
    file uploads are bounded by their API limits anyway, so a single
    bytes blob is acceptable and avoids needing chunked transfer).
    """
    boundary = uuid.uuid4().hex
    crlf = b"\r\n"
    head = (
        f"--{boundary}{crlf.decode()}"
        f'Content-Disposition: form-data; name="file"; filename="{os.path.basename(filename)}"{crlf.decode()}'
        f"Content-Type: application/octet-stream{crlf.decode()}{crlf.decode()}"
    ).encode("utf-8")
    tail = f"{crlf.decode()}--{boundary}--{crlf.decode()}".encode("utf-8")
    body_chunks = [head]
    while True:
        chunk = file_obj.read(65536)
        if not chunk:
            break
        body_chunks.append(chunk)
    body_chunks.append(tail)
    body = b"".join(body_chunks)
    post_headers = dict(headers)
    post_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    post_headers["Content-Length"] = str(len(body))
    req = urllib.request.Request(url, data=body, headers=post_headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - VirusTotal API only
        return json.loads(resp.read().decode("utf-8", "replace"))


def run_virustotal(config: Config, fan_fd: int, q_error: multiprocessing.Queue[str], q_vt_pending: multiprocessing.Queue[bytes], q_vt_results: multiprocessing.Queue[bytes]) -> int:
    """get virustotal results of process executable"""
    parent_process = multiprocessing.parent_process()
    assert parent_process is not None
    if config.desktop.user:
        from ..utils import drop_root_permanent, resolve_group, resolve_owner

        uid = resolve_owner(config.desktop.user)
        gid = resolve_group(config.desktop.user)
        drop_root_permanent(uid, gid)
    # fan_fd is inherited via fork() but this subprocess never uses it;
    # closing it prevents leaking a privileged fanotify handle into a
    # dropped-privilege security domain.
    try:
        os.close(fan_fd)
    except OSError:
        pass
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
                except Exception:
                    if config.virustotal.file_upload:
                        try:
                            with open(proc["fd"], "rb") as f:
                                if (proc["dev"], proc["ino"]) != get_fstat(f.fileno()):
                                    raise ValueError("file stat mismatch")
                                analysis_id = _http_post_multipart_file_json("https://www.virustotal.com/api/v3/files", headers, f, proc["exe"])
                            analysis = get_analysis(analysis_id, sha256)
                        except Exception:
                            try:
                                readlink_exe_sha256 = hashlib.sha256()
                                with open(proc["exe"], "rb") as f:
                                    while data := f.read(1048576):
                                        readlink_exe_sha256.update(data)
                                if readlink_exe_sha256.hexdigest() != sha256:
                                    raise ValueError("sha256 mismatch")
                                with open(proc["exe"], "rb") as f:
                                    analysis_id = _http_post_multipart_file_json("https://www.virustotal.com/api/v3/files", headers, f, proc["exe"])
                                analysis = get_analysis(analysis_id, sha256)
                            except Exception:
                                q_vt_results.put(pickle.dumps((proc, sha256, "Failed to read process for upload", suspicious)))
                                continue
                    else:
                        # could also be an invalid api key
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
