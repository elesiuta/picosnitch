#!/usr/bin/env python3
# picosnitch
# Copyright (C) 2020-2023 Eric Lesiuta

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# https://github.com/elesiuta/picosnitch

import hashlib
import multiprocessing
import pickle
import queue
import sys
import time

from .utils import get_fstat


def virustotal_subprocess(config: dict, q_error, q_vt_pending, q_vt_results):
    """get virustotal results of process executable"""
    parent_process = multiprocessing.parent_process()
    try:
        import requests
        vt_enabled = True
    except ImportError:
        vt_enabled = False
    if not (config["VT API key"] and vt_enabled):
        config["VT request limit (seconds)"] = 0
    headers = {"x-apikey": config["VT API key"]}
    def get_analysis(analysis_id: dict, sha256: str) -> dict:
        api_url = "https://www.virustotal.com/api/v3/analyses/" + analysis_id["data"]["id"]
        for i in range(90):
            time.sleep(max(5, config["VT request limit (seconds)"]))
            response = requests.get(api_url, headers=headers).json()
            if response["data"]["attributes"]["status"] == "completed":
                return response["data"]["attributes"]["stats"]
        return {"timeout": api_url, "sha256": sha256}
    while True:
        if not parent_process.is_alive():
            return 0
        try:
            time.sleep(config["VT request limit (seconds)"])
            proc, analysis = None, None
            proc, sha256 = pickle.loads(q_vt_pending.get(block=True, timeout=15))
            suspicious = False
            if config["VT API key"] and vt_enabled:
                try:
                    analysis = requests.get("https://www.virustotal.com/api/v3/files/" + sha256, headers=headers).json()
                    analysis = analysis["data"]["attributes"]["last_analysis_stats"]
                except Exception:
                    if config["VT file upload"]:
                        try:
                            with open(proc["fd"], "rb") as f:
                                assert (proc["dev"], proc["ino"]) == get_fstat(f.fileno())
                                files = {"file": (proc["exe"], f)}
                                analysis_id = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files).json()
                            analysis = get_analysis(analysis_id, sha256)
                        except Exception:
                            try:
                                readlink_exe_sha256 = hashlib.sha256()
                                with open(proc["exe"], "rb") as f:
                                    while data := f.read(1048576):
                                        readlink_exe_sha256.update(data)
                                assert readlink_exe_sha256.hexdigest() == sha256
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

