# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""A transient/auth VirusTotal lookup error (429/timeout/401) must be recorded as a retryable
state, not cached as a terminal verdict. Before the fix the "VT lookup error: ..." string was
matched by no retry path, so a rate-limited lookup permanently poisoned the cache for that hash."""

import hashlib
import io
import pickle

import pytest

from picosnitch.subprocesses import virustotal
from picosnitch.utils import sync_vt_results


class _FakeQueue:
    """check_pending only calls put(); no multiprocessing feeder-thread races."""

    def __init__(self):
        self.items = []

    def put(self, b):
        self.items.append(b)


def test_transient_vt_lookup_error_is_requeued_on_startup():
    state = {
        "SHA256": {
            "/usr/bin/curl": {
                "aaa": "VT lookup error: HTTPError",  # transient 429/timeout/401 -> retry
                "bbb": "VT Pending",  # already known-retryable
                "ccc": "{'malicious': 3}",  # terminal verdict -> keep, never re-query
            }
        },
        "Executables": {"/usr/bin/curl": ["curl"]},
        "Parent Executables": {},
    }
    q_in = _FakeQueue()
    sync_vt_results(state, q_in, _FakeQueue(), check_pending=True)  # ty: ignore[invalid-argument-type]
    requeued = {sha for _proc, sha in (pickle.loads(b) for b in q_in.items)}
    assert requeued == {"aaa", "bbb"}  # the lookup error is retried; the real verdict is not


def test_upload_rejects_oversize_file_before_request(monkeypatch):
    class OversizeFile:
        def __init__(self):
            self.read_bytes = 0

        def read(self, size):
            self.read_bytes += size
            return b"x" * size

    file_obj = OversizeFile()
    monkeypatch.setattr(virustotal, "VT_UPLOAD_MAX_BYTES", 1024)
    with pytest.raises(ValueError, match="32 MiB"):
        virustotal._http_post_multipart_file_json("https://www.virustotal.com/api/v3/files", {}, file_obj, 'bad"\r\nname')
    assert file_obj.read_bytes <= 1024 + 65536


def test_upload_verifies_exact_bytes_before_request(monkeypatch):
    data = b"reviewed executable"
    called = False

    def blocked_send(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("request must not start")

    monkeypatch.setattr(virustotal._OPENER, "open", blocked_send)
    with pytest.raises(ValueError, match="hash mismatch"):
        virustotal._http_post_multipart_file_json("https://www.virustotal.com/api/v3/files", {}, io.BytesIO(data), "app", "0" * 64)
    assert called is False
    assert hashlib.sha256(data).hexdigest() != "0" * 64


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v"])
