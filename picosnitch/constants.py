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

import json
import os
import pwd
import resource
import site
import sys
import time
import typing

# add site dirs for system and user installed packages (to import bcc with picosnitch installed via pipx/venv, or dependencies installed via user)
site.addsitedir("/usr/lib/python3/dist-packages")
site.addsitedir(os.path.expandvars("$PYTHON_USER_SITE"))
import psutil

# picosnitch version and supported platform
VERSION: typing.Final[str] = "1.0.1"
assert sys.version_info >= (3, 8), "Python version >= 3.8 is required"
assert sys.platform.startswith("linux"), "Did not detect a supported operating system"

# warning about -O (optimize) flag since asserts are disabled and some are critical
if sys.flags.optimize > 0:
    print("Warning: picosnitch does not function properly with the -O (optimize) flag", file=sys.stderr)

# set constants and RLIMIT_NOFILE if configured
if os.getuid() == 0:
    if os.getenv("SUDO_UID"):
        home_user = pwd.getpwuid(int(os.getenv("SUDO_UID"))).pw_name
    elif os.getenv("SUDO_USER"):
        home_user = os.getenv("SUDO_USER")
    else:
        for home_user in os.listdir("/home"):
            try:
                if pwd.getpwnam(home_user).pw_uid >= 1000:
                    break
            except Exception:
                pass
    home_dir = pwd.getpwnam(home_user).pw_dir
    if not os.getenv("SUDO_UID"):
        os.environ["SUDO_UID"] = str(pwd.getpwnam(home_user).pw_uid)
    if not os.getenv("DBUS_SESSION_BUS_ADDRESS"):
        os.environ["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{pwd.getpwnam(home_user).pw_uid}/bus"
else:
    home_dir = os.path.expanduser("~")
    if sys.executable.startswith("/snap/"):
        home_dir = home_dir.split("/snap/picosnitch")[0]
BASE_PATH: typing.Final[str] = os.path.join(home_dir, ".config", "picosnitch")
try:
    file_path = os.path.join(BASE_PATH, "config.json")
    with open(file_path, "r", encoding="utf-8", errors="surrogateescape") as json_file:
        nofile = json.load(json_file)["Set RLIMIT_NOFILE"]
    if type(nofile) == int:
        try:
            new_limit = (nofile, resource.getrlimit(resource.RLIMIT_NOFILE)[1])
            resource.setrlimit(resource.RLIMIT_NOFILE, new_limit)
            time.sleep(0.5)
        except Exception as e:
            print(type(e).__name__ + str(e.args), file=sys.stderr)
            print("Error: Set RLIMIT_NOFILE was found in config.json but it could not be set", file=sys.stderr)
except Exception:
    pass
FD_CACHE: typing.Final[int] = resource.getrlimit(resource.RLIMIT_NOFILE)[0] - 128
PID_CACHE: typing.Final[int] = max(8192, 2*FD_CACHE)
st_dev_mask = 0xffffffff
try:
    for part in psutil.disk_partitions():
        if part.fstype == "btrfs":
            st_dev_mask = 0
            if not os.path.exists(os.path.join(BASE_PATH, "config.json")):
                # only warn users about btrfs on first run (by checking for config.json)
                print("Warning: running picosnitch on systems with btrfs is not fully supported due to dev number strangeness and non-unique inodes (this is still fine for most use cases)", file=sys.stderr)
            break
    file_path = os.path.join(BASE_PATH, "config.json")
    with open(file_path, "r", encoding="utf-8", errors="surrogateescape") as json_file:
        set_mask = json.load(json_file)["Set st_dev mask"]
    if type(set_mask) == int:
        st_dev_mask = set_mask
except Exception:
    pass
ST_DEV_MASK: typing.Final[int] = st_dev_mask

