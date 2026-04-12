# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

import multiprocessing
import pickle
import queue
import sys

from ..config import Config
from ..utils import get_sha256_fd, get_sha256_pid


def run_fuse(config: Config, q_error, q_in, q_out):
    """runs as user to read executables for FUSE/AppImage (since real, effective, and saved UID must match)"""
    parent_process = multiprocessing.parent_process()
    if config.desktop.user:
        from ..utils import drop_root_permanent, resolve_group, resolve_owner

        uid = resolve_owner(config.desktop.user)
        gid = resolve_group(config.desktop.user)
        drop_root_permanent(uid, gid)
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
