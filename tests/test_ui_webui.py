# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""Tests for the stdlib web dashboard's request-safety logic: the DNS-rebinding
Host allowlist and the time-window parser's numeric edge cases. Both are exercised
without opening a socket."""

import types

from picosnitch.ui import webui


def _handler(loopback_only, allowed_hosts, host_header):
    """A _Handler with just enough state for _host_allowed(), no socket/__init__."""
    h = object.__new__(webui._Handler)
    h.server = types.SimpleNamespace(loopback_only=loopback_only, allowed_hosts=allowed_hosts)
    h.headers = {} if host_header is None else {"Host": host_header}
    return h


def test_host_allowed_blocks_dns_rebinding():
    """On a loopback bind, only loopback Host headers pass -- a remote page reaching
    127.0.0.1 via DNS rebinding always carries the attacker's Host, so it is rejected."""
    allowed = frozenset({"localhost", "localhost:5100", "127.0.0.1", "127.0.0.1:5100"})
    assert _handler(True, allowed, "127.0.0.1:5100")._host_allowed() is True
    assert _handler(True, allowed, "localhost:5100")._host_allowed() is True
    assert _handler(True, allowed, "evil.com")._host_allowed() is False  # DNS rebinding
    assert _handler(True, allowed, "attacker.example:5100")._host_allowed() is False
    assert _handler(True, allowed, None)._host_allowed() is True  # non-browser client, no Host
    # a non-loopback bind already warned it has no auth; Host is not enforced there
    assert _handler(False, allowed, "evil.com")._host_allowed() is True


def test_resolve_window_handles_infinity_and_nan():
    """?from=inf raised OverflowError (HTTP 500) before the fix; inf/nan/garbage must
    fall back to (0, now), and a valid explicit window must be preserved."""
    since, until, _ = webui._resolve_window({"from": ["inf"], "to": ["1"]})
    assert since == 0 and until > 0  # OverflowError caught
    since, until, _ = webui._resolve_window({"from": ["nan"]})
    assert since == 0 and until > 0  # ValueError caught
    since, until, _ = webui._resolve_window({"from": ["notnumeric"]})
    assert since == 0 and until > 0
    assert webui._resolve_window({"from": ["100"], "to": ["200"]})[:2] == (100, 200)
