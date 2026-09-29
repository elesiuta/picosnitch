# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""Unit tests for monitor exe-resolution and fd cache helpers."""

import collections
import os

import pytest

from picosnitch.constants import ST_DEV_MASK
from picosnitch.subprocesses.monitor import _classify_inode_fallback, _close_unlinked_fds


def _dev_ino(path: str) -> tuple[int, int]:
    stat = os.stat(path)
    return stat.st_dev & ST_DEV_MASK, stat.st_ino


def test_plain_binary_returns_its_own_path(tmp_path):
    real = tmp_path / "binary"
    real.write_bytes(b"#!/bin/true\n")
    dev, ino = _dev_ino(str(real))
    assert _classify_inode_fallback(dev, ino, str(real)) == str(real)


def test_symlink_alias_collapses_to_canonical(tmp_path):
    # busybox-style: many symlink names point at one ELF (nlink == 1)
    real = tmp_path / "busybox"
    real.write_bytes(b"ELF\n")
    sh = tmp_path / "sh"
    nc = tmp_path / "nc"
    sh.symlink_to(real)
    nc.symlink_to(real)
    dev, ino = _dev_ino(str(real))
    assert _classify_inode_fallback(dev, ino, str(sh)) == str(real)
    assert _classify_inode_fallback(dev, ino, str(nc)) == str(real)


def test_hardlink_multicall_returns_sentinel(tmp_path):
    # uutils-style: many hardlink names share one inode (nlink > 1), no
    # canonical name exists so we must not pick one
    a = tmp_path / "ls"
    a.write_bytes(b"ELF\n")
    b = tmp_path / "cat"
    os.link(str(a), str(b))
    dev, ino = _dev_ino(str(a))
    label = _classify_inode_fallback(dev, ino, str(a))
    assert label == f"<multi-call:dev={dev},ino={ino}>"
    # either hardlink name classifies identically
    assert _classify_inode_fallback(dev, ino, str(b)) == label


def test_inode_mismatch_returns_input_unchanged(tmp_path):
    real = tmp_path / "binary"
    real.write_bytes(b"x")
    dev, ino = _dev_ino(str(real))
    # a path whose inode no longer matches the event must not be attributed
    assert _classify_inode_fallback(dev, ino + 1, str(real)) == str(real)


def test_empty_and_sentinel_pass_through():
    assert _classify_inode_fallback(1, 2, "") == ""
    assert _classify_inode_fallback(1, 2, "<multi-call:dev=1,ino=2>") == "<multi-call:dev=1,ino=2>"


def _is_open(fd: int) -> bool:
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


@pytest.fixture
def exe_fd(tmp_path):
    """an fd cached the way get_fd caches it, closed at teardown if the sweep left it open"""
    exe = tmp_path / "binary"
    exe.write_bytes(b"ELF\n")
    fd = os.open(exe, os.O_RDONLY)
    yield exe, fd
    if _is_open(fd):
        os.close(fd)


def test_sweep_closes_fd_of_deleted_exe(exe_fd):
    exe, fd = exe_fd
    fd_dict: collections.OrderedDict[str, tuple] = collections.OrderedDict()
    fd_dict["tmp0"] = (0,)
    fd_dict["1 2"] = (fd, f"/proc/self/fd/{fd}", str(exe))
    used = {"3 4"}
    unmarked: list[int] = []
    exe.unlink()
    _close_unlinked_fds(fd_dict, used, unmarked.append)
    assert not _is_open(fd)
    assert unmarked == [fd]
    # the slot stays so the cache keeps its size, and the next lookup reopens
    assert list(fd_dict) == ["tmp0", "1 2"]
    assert fd_dict["1 2"] == (0, "", str(exe))
    assert used == set()


def test_sweep_keeps_fd_of_existing_exe(exe_fd):
    exe, fd = exe_fd
    fd_dict: collections.OrderedDict[str, tuple] = collections.OrderedDict({"1 2": (fd, f"/proc/self/fd/{fd}", str(exe))})
    unmarked: list[int] = []
    _close_unlinked_fds(fd_dict, set(), unmarked.append)
    assert _is_open(fd)
    assert unmarked == []
    assert fd_dict["1 2"] == (fd, f"/proc/self/fd/{fd}", str(exe))


def test_sweep_keeps_deleted_exe_used_since_last_sweep(exe_fd):
    # a live process running from a deleted binary, or one not hashed yet
    exe, fd = exe_fd
    fd_dict: collections.OrderedDict[str, tuple] = collections.OrderedDict({"1 2": (fd, f"/proc/self/fd/{fd}", str(exe))})
    used = {"1 2"}
    unmarked: list[int] = []
    exe.unlink()
    _close_unlinked_fds(fd_dict, used, unmarked.append)
    assert _is_open(fd)
    assert unmarked == []
    # unused by the next sweep, so it is closed then
    _close_unlinked_fds(fd_dict, used, unmarked.append)
    assert not _is_open(fd)
    assert unmarked == [fd]
