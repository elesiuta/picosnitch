# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

import logging
import os
import resource
import time
import tomllib
import typing
from pathlib import Path

import psutil

from . import __version__

# picosnitch version
VERSION: typing.Final[str] = __version__

# FHS standard paths (PICOSNITCH_ROOT is used as a prefix for testing)
_root: str = os.getenv("PICOSNITCH_ROOT", "")
CONFIG_DIR: typing.Final[Path] = Path(f"{_root}/etc/picosnitch")
DATA_DIR: typing.Final[Path] = Path(f"{_root}/var/lib/picosnitch")
LOG_DIR: typing.Final[Path] = Path(f"{_root}/var/log/picosnitch")
RUN_DIR: typing.Final[Path] = Path(f"{_root}/run/picosnitch")
CACHE_DIR: typing.Final[Path] = Path(f"{_root}/var/cache/picosnitch")

# set RLIMIT_NOFILE if configured
try:
    file_path = CONFIG_DIR / "config.toml"
    with open(file_path, "rb") as toml_file:
        nofile = tomllib.load(toml_file).get("monitoring", {}).get("rlimit_nofile")
    if isinstance(nofile, int):
        try:
            new_limit = (nofile, resource.getrlimit(resource.RLIMIT_NOFILE)[1])
            resource.setrlimit(resource.RLIMIT_NOFILE, new_limit)
            logging.info(f"set RLIMIT_NOFILE to {nofile}")
            time.sleep(0.5)
        except Exception as e:
            logging.error(f"{type(e).__name__}{e.args}")
            logging.error("monitoring.rlimit_nofile was found in config.toml but it could not be set")
except Exception:
    pass
FD_CACHE: typing.Final[int] = resource.getrlimit(resource.RLIMIT_NOFILE)[0] - 128
PID_CACHE: typing.Final[int] = max(8192, 2 * FD_CACHE)
st_dev_mask = 0xFFFFFFFF
try:
    for part in psutil.disk_partitions():
        if part.fstype == "btrfs":
            st_dev_mask = 0
            if not (CONFIG_DIR / "config.toml").exists():
                logging.warning("running picosnitch on systems with btrfs is not fully supported due to dev number strangeness and non-unique inodes (this is still fine for most use cases)")
            break
    file_path = CONFIG_DIR / "config.toml"
    with open(file_path, "rb") as toml_file:
        set_mask = tomllib.load(toml_file).get("monitoring", {}).get("st_dev_mask")
    if isinstance(set_mask, int):
        st_dev_mask = set_mask
except Exception:
    pass
ST_DEV_MASK: typing.Final[int] = st_dev_mask
