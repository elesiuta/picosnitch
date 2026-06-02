# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""Unit tests for monitor exe-resolution helpers."""

import os

from picosnitch.constants import ST_DEV_MASK
from picosnitch.subprocesses.monitor import _classify_inode_fallback


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
