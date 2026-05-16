#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
"""
Seed a fresh, deterministic picosnitch.db for screenshot generation.

Writes to $PICOSNITCH_TEST/var/lib/picosnitch/picosnitch.db when
PICOSNITCH_TEST is set (default: 1, set by the wrapper script), so this
never touches a real installation. Schema matches whatever DB_VERSION is
current in src/picosnitch/constants.py -- if the schema drifts, this
script will refuse to run and tell you to update the fixtures.

Usage:
    PICOSNITCH_TEST=1 python3 seed_db.py
    sudo python3 seed_db.py --target /var/lib/picosnitch/picosnitch.db
"""

import argparse
import hashlib
import os
import random
import sqlite3
import sys
import time
from pathlib import Path

# Pre-parse --target so we can decide whether to enter test mode.
_pre = argparse.ArgumentParser(add_help=False)
_pre.add_argument("--target", default=None)
_pre_args, _ = _pre.parse_known_args()
if _pre_args.target is None:
    os.environ.setdefault("PICOSNITCH_TEST", "1")

# Import after env is set so DATA_DIR resolves under the test root.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "src"))
from picosnitch.constants import (  # noqa: E402
    DATA_DIR,
    DB_VERSION,
    SCHEMA_ADDRESSES,
    SCHEMA_CONNECTIONS,
    SCHEMA_DOMAINS,
    SCHEMA_EXECUTABLES,
)

# (exe, name, cmdline, parent_idx, grandparent_idx)
# index 0 must be the empty sentinel row picosnitch uses for "no value";
# no real connection should reference it as parent/grandparent or domain,
# so top-level processes (systemd & friends) point parent/grandparent
# back at themselves to keep the rendered views free of blank rows.
EXES: list[tuple[str, str, str, int | None, int | None]] = [
    ("", "", "", None, None),
    ("/usr/lib/systemd/systemd", "systemd", "/sbin/init splash", 1, 1),
    ("/usr/bin/bash", "bash", "/bin/bash", 1, 1),
    ("/usr/bin/firefox", "firefox", "/usr/lib/firefox/firefox", 2, 1),
    ("/usr/lib/firefox/firefox", "Web Content", "/usr/lib/firefox/firefox -contentproc -childID 7", 3, 2),
    ("/usr/bin/chromium", "chromium", "/usr/bin/chromium --enable-features=UseOzonePlatform", 2, 1),
    ("/usr/bin/curl", "curl", "curl -sSL https://api.github.com/repos/elesiuta/picosnitch", 2, 1),
    ("/usr/bin/wget", "wget", "wget -q https://example.com/release.tar.gz", 2, 1),
    ("/usr/bin/ssh", "ssh", "ssh user@build.example.com", 2, 1),
    ("/usr/sbin/sshd", "sshd", "sshd: user [priv]", 1, 1),
    ("/usr/lib/systemd/systemd-resolved", "systemd-resolve", "/lib/systemd/systemd-resolved", 1, 1),
    ("/usr/sbin/NetworkManager", "NetworkManager", "/usr/sbin/NetworkManager --no-daemon", 1, 1),
    ("/usr/bin/syncthing", "syncthing", "syncthing serve --no-browser --no-restart --logflags=0", 1, 1),
    ("/usr/bin/thunderbird", "thunderbird", "/usr/bin/thunderbird", 2, 1),
    ("/usr/share/code/code", "code", "/usr/share/code/code --type=renderer", 2, 1),
    ("/usr/bin/dockerd", "dockerd", "/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock", 1, 1),
    ("/usr/bin/containerd-shim-runc-v2", "containerd-shim", "/usr/bin/containerd-shim-runc-v2 -namespace moby -id abcd", 15, 1),
    ("/usr/bin/python3.12", "python3", "python3 -m http.server 8000", 2, 1),
    ("/usr/bin/apt", "apt", "apt update", 2, 1),
    ("/usr/lib/apt/methods/https", "https", "/usr/lib/apt/methods/https", 18, 2),
]


# Per-exe traffic profile: (rport, domain, sample_raddrs_v4, sample_raddrs_v6, send_mu, recv_mu, count_weight)
TRAFFIC: dict[int, list[tuple[int, str, list[str], list[str], int, int, int]]] = {
    3: [  # firefox
        (443, "www.mozilla.org", ["63.245.208.195"], ["2620:101:f000:7807::202"], 2_000, 60_000, 30),
        (443, "addons.mozilla.org", ["52.85.132.10"], [], 1_500, 18_000, 8),
    ],
    4: [  # firefox content
        (443, "www.youtube.com", ["142.250.72.110"], ["2607:f8b0:4005:80c::200e"], 5_000, 1_200_000, 60),
        (443, "i.ytimg.com", ["142.250.72.118"], [], 800, 250_000, 40),
        (443, "github.com", ["140.82.112.3"], ["2606:50c0:8000::153"], 1_200, 80_000, 25),
        (443, "raw.githubusercontent.com", ["185.199.108.133"], [], 800, 350_000, 18),
        (443, "news.ycombinator.com", ["209.216.230.207"], [], 600, 35_000, 10),
        (443, "duckduckgo.com", ["52.149.246.39"], [], 500, 40_000, 8),
    ],
    5: [  # chromium
        (443, "www.google.com", ["142.250.72.100"], ["2607:f8b0:4005:80c::2004"], 1_200, 90_000, 25),
        (443, "fonts.gstatic.com", ["142.250.72.131"], [], 200, 22_000, 12),
    ],
    6: [  # curl
        (443, "api.github.com", ["140.82.121.6"], [], 600, 18_000, 6),
        (80, "example.com", ["93.184.216.34"], [], 250, 1_500, 3),
    ],
    7: [  # wget
        (443, "example.com", ["93.184.216.34"], [], 400, 700_000, 4),
    ],
    8: [  # ssh
        (22, "build.example.com", ["198.51.100.42"], [], 12_000, 8_000, 5),
    ],
    9: [  # sshd (incoming session from a client host)
        (22, "laptop.lan", ["203.0.113.7"], [], 9_000, 14_000, 7),
    ],
    10: [  # systemd-resolved (upstream DNS resolvers)
        (53, "one.one.one.one", ["1.1.1.1", "1.0.0.1"], ["2606:4700:4700::1111"], 80, 220, 140),
        (53, "dns.google", ["8.8.8.8"], [], 80, 220, 60),
    ],
    11: [  # NetworkManager
        (67, "router.lan", ["192.168.1.1"], [], 600, 800, 8),
        (123, "pool.ntp.org", ["162.159.200.1"], [], 90, 90, 6),
    ],
    12: [  # syncthing
        (22000, "relay.syncthing.net", ["45.79.142.43"], [], 350_000, 220_000, 20),
        (8443, "discovery.syncthing.net", ["95.179.220.235"], [], 800, 1_500, 8),
    ],
    13: [  # thunderbird
        (993, "imap.fastmail.com", ["103.168.172.45"], [], 1_200, 18_000, 12),
        (587, "smtp.fastmail.com", ["103.168.172.46"], [], 5_000, 800, 4),
    ],
    14: [  # code (vscode)
        (443, "update.code.visualstudio.com", ["13.107.42.16"], [], 800, 22_000, 6),
        (443, "marketplace.visualstudio.com", ["13.107.42.20"], [], 1_200, 65_000, 9),
    ],
    15: [  # dockerd
        (443, "auth.docker.io", ["3.224.226.93"], [], 700, 4_500, 4),
        (443, "registry-1.docker.io", ["3.213.189.158"], [], 1_500, 220_000, 12),
    ],
    16: [  # containerd-shim
        (443, "registry-1.docker.io", ["3.213.189.158"], [], 600, 80_000, 7),
    ],
    17: [  # python3 -m http.server (incoming connection from a LAN client)
        (38271, "phone.lan", ["192.168.1.42"], [], 2_500, 3_000, 18),
    ],
    19: [  # apt https method
        (443, "deb.debian.org", ["199.232.18.132"], [], 900, 480_000, 10),
        (443, "security.debian.org", ["151.101.130.132"], [], 700, 220_000, 6),
    ],
}


def fake_sha256(seed: str) -> str:
    """Deterministic, obviously-fake SHA256 derived from the exe path."""
    return hashlib.sha256(f"picosnitch-screenshot-fixture::{seed}".encode()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed a deterministic picosnitch.db")
    parser.add_argument(
        "--target",
        default=None,
        help="path to picosnitch.db (default: $DATA_DIR/picosnitch.db under PICOSNITCH_TEST root)",
    )
    args = parser.parse_args()
    if args.target is not None:
        db_path = Path(args.target)
        db_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        db_path = DATA_DIR / "picosnitch.db"
        DATA_DIR.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()
    for sidecar in (db_path.with_suffix(".db-wal"), db_path.with_suffix(".db-shm")):
        if sidecar.exists():
            sidecar.unlink()

    rng = random.Random(0xC0DECAFE)
    con = sqlite3.connect(str(db_path))
    cur = con.cursor()
    cur.execute(f"CREATE TABLE executables ({SCHEMA_EXECUTABLES}) STRICT")
    cur.execute(f"CREATE TABLE domains ({SCHEMA_DOMAINS}) STRICT")
    cur.execute(f"CREATE TABLE addresses ({SCHEMA_ADDRESSES}) STRICT")
    cur.execute(f"CREATE TABLE connections ({SCHEMA_CONNECTIONS}) STRICT")
    cur.execute("CREATE INDEX idx_contime ON connections(contime)")
    cur.execute("CREATE INDEX idx_exe_id_contime ON connections(exe_id, contime)")
    cur.execute("CREATE INDEX idx_pexe_id_contime ON connections(pexe_id, contime)")
    cur.execute("CREATE INDEX idx_gpexe_id_contime ON connections(gpexe_id, contime)")
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute(f"PRAGMA user_version = {DB_VERSION}")

    for idx, (exe, name, cmdline, _pidx, _gidx) in enumerate(EXES):
        sha = "" if idx == 0 else fake_sha256(exe or name or str(idx))
        cur.execute(
            "INSERT INTO executables (id, exe, name, cmdline, sha256) VALUES (?, ?, ?, ?, ?)",
            (idx, exe, name, cmdline, sha),
        )
    cur.execute("INSERT INTO domains (id, domain) VALUES (0, '')")
    cur.execute("INSERT INTO addresses (id, addr) VALUES (0, '')")

    AF_INET, AF_INET6 = 2, 10
    IPPROTO_TCP, IPPROTO_UDP = 6, 17
    udp_ports = {53, 67, 68, 123, 5353}
    # Synthetic netns inodes: host (typical Linux value) + a couple of
    # container netns to demonstrate the dimension is populated.
    HOST_NETNS = 4026531840
    CONTAINER_NETNS = {15: 4026532500, 16: 4026532501, 19: 4026532502}

    domain_ids: dict[str, int] = {"": 0}
    addr_ids: dict[str, int] = {"": 0}

    def domain_id(value: str) -> int:
        if value not in domain_ids:
            cur.execute("INSERT INTO domains (domain) VALUES (?)", (value,))
            domain_ids[value] = cur.lastrowid
        return domain_ids[value]

    def addr_id(value: str) -> int:
        if value not in addr_ids:
            cur.execute("INSERT INTO addresses (addr) VALUES (?)", (value,))
            addr_ids[value] = cur.lastrowid
        return addr_ids[value]

    now = int(time.time())
    window = 24 * 3600  # last 24h
    rows: list[tuple] = []
    for exe_idx, profiles in TRAFFIC.items():
        pidx = EXES[exe_idx][3]
        gidx = EXES[exe_idx][4]
        assert pidx is not None and gidx is not None, f"exe {exe_idx} has unset parent/grandparent"
        for rport, domain, raddrs_v4, raddrs_v6, send_mu, recv_mu, weight in profiles:
            n_groups = max(2, int(weight * 4 * rng.uniform(0.7, 1.3)))
            for _ in range(n_groups):
                peak = rng.choice([0.15, 0.45, 0.7, 0.92])
                t = now - int((1.0 - max(0.0, min(1.0, peak + rng.gauss(0, 0.07)))) * window)
                t = max(now - window, min(now - 30, t))
                use_v6 = bool(raddrs_v6) and rng.random() < 0.25
                raddr = rng.choice(raddrs_v6 if use_v6 else raddrs_v4)
                send = max(0, int(rng.lognormvariate(0, 0.8) * send_mu))
                recv = max(0, int(rng.lognormvariate(0, 0.8) * recv_mu))
                lport = rng.randint(32768, 60999)
                laddr = "fd00::1" if use_v6 else "192.168.1.42"
                uid = 1000 if exe_idx not in (10, 11, 9, 15, 16) else 0
                family = AF_INET6 if use_v6 else AF_INET
                protocol = IPPROTO_UDP if rport in udp_ports else IPPROTO_TCP
                events = rng.randint(1, 6)
                ns_inode = CONTAINER_NETNS.get(exe_idx, HOST_NETNS)
                rows.append(
                    (
                        t,
                        send,
                        recv,
                        events,
                        exe_idx,
                        pidx,
                        gidx,
                        uid,
                        family,
                        protocol,
                        lport,
                        rport,
                        addr_id(laddr),
                        addr_id(raddr),
                        domain_id(domain),
                        ns_inode,
                    )
                )
    rng.shuffle(rows)
    cur.executemany(
        "INSERT INTO connections VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        rows,
    )
    con.commit()
    con.close()

    print(f"Seeded {db_path} ({len(EXES)} executables, {len(domain_ids)} domains, {len(addr_ids)} addresses, {len(rows)} connections, schema v{DB_VERSION})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
