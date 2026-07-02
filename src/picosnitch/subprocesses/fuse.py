# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import multiprocessing
import os
import pickle
import queue

from picosnitch.config import Config
from picosnitch.utils import get_sha256_fd, get_sha256_pid


def run_fuse(config: Config, fan_fd: int, q_error: multiprocessing.Queue[str], q_in: multiprocessing.Queue[bytes], q_out: multiprocessing.Queue[bytes]) -> int:
    """runs as user to read executables for FUSE/AppImage (since real, effective, and saved UID must match)"""
    parent_process = multiprocessing.parent_process()
    assert parent_process is not None
    if config.desktop.user:
        from ..utils import drop_root_permanent, resolve_group, resolve_owner

        uid = resolve_owner(config.desktop.user)
        gid = resolve_group(config.desktop.user)
        drop_root_permanent(uid, gid)
    # fan_fd is inherited via fork() but this subprocess never uses it;
    # closing it prevents leaking a privileged fanotify handle into a
    # dropped-privilege security domain.
    try:
        os.close(fan_fd)
    except OSError:
        pass
    while True:
        if not parent_process.is_alive():
            return 0
        try:
            key = pickle.loads(q_in.get(block=True, timeout=15))
            path, pid, st_dev, st_ino = key
            sha256 = get_sha256_fd.__wrapped__(path, st_dev, st_ino, 0)
            if sha256.startswith("!"):
                sha256 = get_sha256_pid.__wrapped__(pid, st_dev, st_ino)
                if sha256.startswith("!"):
                    sha256 = "!!! FUSE Read Error"
            # echo the request key so a late reply after a caller timeout can't be
            # mismatched to a later request (get_sha256_fuse discards non-matching replies)
            q_out.put(pickle.dumps((key, sha256)))
        except queue.Empty:
            pass
        except Exception as e:
            q_error.put("rfuse subprocess %s%s on line %s" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?"))
