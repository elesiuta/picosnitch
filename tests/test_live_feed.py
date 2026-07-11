# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""Unit tests for picosnitch.live_feed (no root needed)."""

import os
import socket
import tempfile
import time

import pytest

# Force RUN_DIR to a tempdir before importing live_feed so the socket lands somewhere we can write.
_TMP_RUN = tempfile.mkdtemp(prefix="picosnitch-test-")
os.environ["PICOSNITCH_TEST"] = _TMP_RUN

from picosnitch import live_feed  # noqa: E402

# Patch the socket path to live under our temp dir
live_feed.EVENTS_SOCKET_PATH = type(live_feed.EVENTS_SOCKET_PATH)(os.path.join(_TMP_RUN, "events.sock"))


def test_publish_and_subscribe():
    pub = live_feed.LiveFeedPublisher(group=None)
    pub.start()
    assert pub._sock is not None, "publisher should have started"
    try:
        sub = live_feed.LiveFeedSubscriber(timeout=2.0)
        sub.connect()
        try:
            # give accept thread a tick to register the subscriber
            time.sleep(0.05)
            pub.publish({"name": "curl", "exe": "/usr/bin/curl", "send": 42, "recv": 0})
            event = next(sub)
            assert event["name"] == "curl"
            assert event["exe"] == "/usr/bin/curl"
            assert event["send"] == 42
        finally:
            sub.close()
    finally:
        pub.stop()


def test_slow_subscriber_dropped():
    pub = live_feed.LiveFeedPublisher(group=None)
    pub.start()
    try:
        # Connect but never read
        sub_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sub_sock.connect(str(live_feed.EVENTS_SOCKET_PATH))
        time.sleep(0.05)
        # Flood; some sends will eventually time out and the subscriber will be dropped.
        started = time.monotonic()
        for i in range(2000):
            pub.publish({"i": i, "blob": "x" * 1024})
        assert time.monotonic() - started < 2
        assert not pub._subscribers
        # Publisher should still be functional
        pub.publish({"final": True})
        sub_sock.close()
    finally:
        pub.stop()


def test_subscriber_count_is_bounded(monkeypatch):
    monkeypatch.setattr(live_feed, "MAX_SUBSCRIBERS", 2)
    pub = live_feed.LiveFeedPublisher(group=None)
    pub.start()
    clients = []
    try:
        for _ in range(3):
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(str(live_feed.EVENTS_SOCKET_PATH))
            clients.append(client)
        time.sleep(0.05)
        assert len(pub._subscribers) == 2
    finally:
        for client in clients:
            client.close()
        pub.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
