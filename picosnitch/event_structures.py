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

import ctypes
import typing


class BpfEvent(typing.TypedDict):
    """Process and connection data for each event captured by the BPF program, and sent to the main & secondary processes"""
    pid: int
    name: str
    fd: int
    dev: int
    ino: int
    exe: str
    cmdline: str
    ppid: int
    pname: str
    pfd: int
    pdev: int
    pino: int
    pexe: str
    pcmdline: str
    uid: int
    send: int
    recv: int
    lport: int
    rport: int
    laddr: str
    raddr: str
    domain: str


class FanotifyEventMetadata(ctypes.Structure):
    """https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/fanotify.h"""
    _fields_ = [
        ("event_len", ctypes.c_uint32),
        ("vers", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("metadata_len", ctypes.c_uint16),
        ("mask", ctypes.c_uint64),
        ("fd", ctypes.c_int32),
        ("pid", ctypes.c_int32)
    ]

