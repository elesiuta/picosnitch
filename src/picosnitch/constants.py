# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

import logging
import os
import resource
import tomllib
import typing
from pathlib import Path

from picosnitch import __version__

# picosnitch version
VERSION: typing.Final[str] = __version__

# FHS standard paths (PICOSNITCH_TEST enables /tmp/picosnitch prefix for testing)
_root: str = "/tmp/picosnitch" if os.getenv("PICOSNITCH_TEST") else ""
CONFIG_DIR: typing.Final[Path] = Path(f"{_root}/etc/picosnitch")
DATA_DIR: typing.Final[Path] = Path(f"{_root}/var/lib/picosnitch")
LOG_DIR: typing.Final[Path] = Path(f"{_root}/var/log/picosnitch")
RUN_DIR: typing.Final[Path] = Path(f"{_root}/run/picosnitch")
if _root or os.getuid() == 0:
    _cache_dir = Path(f"{_root}/var/cache/picosnitch")
else:
    _xdg_cache = os.getenv("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))
    _cache_dir = Path(f"{_xdg_cache}/picosnitch")
CACHE_DIR: typing.Final[Path] = _cache_dir

# set RLIMIT_NOFILE if configured
try:
    file_path = CONFIG_DIR / "config.toml"
    with open(file_path, "rb") as toml_file:
        nofile = tomllib.load(toml_file).get("monitoring", {}).get("rlimit_nofile")
    if isinstance(nofile, int) and not isinstance(nofile, bool) and nofile >= 256:
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            if nofile > soft:
                resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, hard))
                logging.info(f"set RLIMIT_NOFILE to {nofile}")
        except Exception as e:
            logging.error(f"{type(e).__name__}{e.args}")
            logging.error("monitoring.rlimit_nofile was found in config.toml but it could not be set")
except Exception:
    pass
FD_CACHE: typing.Final[int] = max(1, resource.getrlimit(resource.RLIMIT_NOFILE)[0] - 128)
PID_CACHE: typing.Final[int] = max(8192, 2 * FD_CACHE)
st_dev_mask = 0xFFFFFFFF
try:
    # parse /proc/mounts to detect btrfs filesystems (replaces psutil.disk_partitions)
    with open("/proc/mounts", "r") as _mounts_file:
        for _line in _mounts_file:
            _parts = _line.split()
            if len(_parts) >= 3 and _parts[2] == "btrfs":
                st_dev_mask = 0
                if not (CONFIG_DIR / "config.toml").exists():
                    logging.warning(
                        "running picosnitch on btrfs weakens exe name resolution due to per-subvolume device numbers and inodes that aren't unique across subvolumes "
                        "(this is still fine for most use cases)"
                    )
                break
    file_path = CONFIG_DIR / "config.toml"
    with open(file_path, "rb") as toml_file:
        set_mask = tomllib.load(toml_file).get("monitoring", {}).get("st_dev_mask")
    if isinstance(set_mask, int) and not isinstance(set_mask, bool) and 0 <= set_mask <= 0xFFFFFFFF:
        st_dev_mask = set_mask
except Exception:
    pass
ST_DEV_MASK: typing.Final[int] = st_dev_mask

# database schema version and table definitions
# id 0 in each lookup table is the "empty/unknown" sentinel.
# `family` is AF_INET (2), AF_INET6 (10), or 0 when unknown.
# `protocol` is an IPPROTO_* value (TCP=6, UDP=17, ...) or 0 when unknown.
# `netns` is the inode of the socket's network namespace.
DB_VERSION: typing.Final[int] = 4
SCHEMA_EXECUTABLES: typing.Final[str] = """
    id INTEGER PRIMARY KEY,
    exe TEXT NOT NULL,
    name TEXT NOT NULL,
    cmdline TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    UNIQUE(exe, name, cmdline, sha256)"""
SCHEMA_DOMAINS: typing.Final[str] = """
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE"""
SCHEMA_ADDRESSES: typing.Final[str] = """
    id INTEGER PRIMARY KEY,
    addr TEXT NOT NULL UNIQUE"""
SCHEMA_CONNECTIONS: typing.Final[str] = """
    contime INTEGER NOT NULL,
    send INTEGER NOT NULL,
    recv INTEGER NOT NULL,
    events INTEGER NOT NULL,
    exe_id INTEGER NOT NULL REFERENCES executables(id),
    pexe_id INTEGER NOT NULL REFERENCES executables(id),
    gpexe_id INTEGER NOT NULL REFERENCES executables(id),
    uid INTEGER NOT NULL,
    family INTEGER NOT NULL,
    protocol INTEGER NOT NULL,
    lport INTEGER NOT NULL,
    rport INTEGER NOT NULL,
    laddr_id INTEGER NOT NULL REFERENCES addresses(id),
    raddr_id INTEGER NOT NULL REFERENCES addresses(id),
    domain_id INTEGER NOT NULL REFERENCES domains(id),
    netns INTEGER NOT NULL"""
