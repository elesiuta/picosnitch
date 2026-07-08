# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""A transient/auth VirusTotal lookup error (429/timeout/401) must be recorded as a retryable
state, not cached as a terminal verdict. Before the fix the "VT lookup error: ..." string was
matched by no retry path, so a rate-limited lookup permanently poisoned the cache for that hash."""

import pickle

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
    sync_vt_results(state, q_in, _FakeQueue(), check_pending=True)
    requeued = {sha for _proc, sha in (pickle.loads(b) for b in q_in.items)}
    assert requeued == {"aaa", "bbb"}  # the lookup error is retried; the real verdict is not


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v"])
