# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

import hashlib
import multiprocessing
import pickle
import queue
import sys
import time

from ..config import Config
from ..utils import get_fstat


def run_virustotal(config: Config, q_error, q_vt_pending, q_vt_results):
    """get virustotal results of process executable"""
    parent_process = multiprocessing.parent_process()
    if config.desktop.user:
        from ..utils import drop_root_permanent, resolve_group, resolve_owner

        uid = resolve_owner(config.desktop.user)
        gid = resolve_group(config.desktop.user)
        drop_root_permanent(uid, gid)
    try:
        import requests

        vt_enabled = True
    except ImportError:
        vt_enabled = False
    request_limit = config.virustotal.request_limit_seconds
    if not (config.virustotal.api_key and vt_enabled):
        request_limit = 0
    headers = {"x-apikey": config.virustotal.api_key}

    def get_analysis(analysis_id: dict, sha256: str) -> dict:
        api_url = "https://www.virustotal.com/api/v3/analyses/" + analysis_id["data"]["id"]
        for i in range(90):
            time.sleep(max(5, request_limit))
            response = requests.get(api_url, headers=headers).json()
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
            if config.virustotal.api_key and vt_enabled:
                try:
                    analysis = requests.get("https://www.virustotal.com/api/v3/files/" + sha256, headers=headers).json()
                    analysis = analysis["data"]["attributes"]["last_analysis_stats"]
                except Exception:
                    if config.virustotal.file_upload:
                        try:
                            with open(proc["fd"], "rb") as f:
                                if (proc["dev"], proc["ino"]) != get_fstat(f.fileno()):
                                    raise ValueError("file stat mismatch")
                                files = {"file": (proc["exe"], f)}
                                analysis_id = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files).json()
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
                                    files = {"file": (proc["exe"], f)}
                                    analysis_id = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files).json()
                                analysis = get_analysis(analysis_id, sha256)
                            except Exception:
                                q_vt_results.put(pickle.dumps((proc, sha256, "Failed to read process for upload", suspicious)))
                                continue
                    else:
                        # could also be an invalid api key
                        q_vt_results.put(pickle.dumps((proc, sha256, "File not analyzed (analysis not found)", suspicious)))
                        continue
                if analysis["suspicious"] != 0 or analysis["malicious"] != 0:
                    suspicious = True
                q_vt_results.put(pickle.dumps((proc, sha256, str(analysis), suspicious)))
            elif vt_enabled:
                q_vt_results.put(pickle.dumps((proc, sha256, "File not analyzed (no api key)", suspicious)))
            else:
                q_vt_results.put(pickle.dumps((proc, sha256, "File not analyzed (requests library not found)", suspicious)))
        except queue.Empty:
            # have to timeout here to check whether to terminate otherwise this could stay hanging
            # daemon=True flag for multiprocessing.Process does not work after root privileges are dropped for parent
            pass
        except Exception as e:
            q_error.put("VT %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))
            try:
                analysis = str(analysis)
            except Exception:
                analysis = "unknown analysis"
            q_error.put("Last VT Exception on: %s with %s" % (str(proc), str(analysis)))
