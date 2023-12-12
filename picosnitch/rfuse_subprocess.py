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

import multiprocessing
import os
import pickle
import queue
import sys

from .utils import get_sha256_fd, get_sha256_pid


def rfuse_subprocess(config: dict, q_error, q_in, q_out):
    """runs as user to read executables for FUSE/AppImage (since real, effective, and saved UID must match)"""
    parent_process = multiprocessing.parent_process()
    try:
        os.setgid(int(os.getenv("SUDO_UID")))
        os.setuid(int(os.getenv("SUDO_UID")))
    except Exception:
        pass
    while True:
        if not parent_process.is_alive():
            return 0
        try:
            path, pid, st_dev, st_ino = pickle.loads(q_in.get(block=True, timeout=15))
            sha256 = get_sha256_fd.__wrapped__(path, st_dev, st_ino, 0)
            if sha256.startswith("!"):
                sha256 = get_sha256_pid.__wrapped__(pid, st_dev, st_ino)
                if sha256.startswith("!"):
                    sha256 = "!!! FUSE Read Error"
            q_out.put(sha256)
        except queue.Empty:
            pass
        except Exception as e:
            q_error.put("rfuse subprocess %s%s on line %s" % (type(e).__name__, str(e.args), sys.exc_info()[2].tb_lineno))
