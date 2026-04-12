# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

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
        ("pid", ctypes.c_int32),
    ]


class ProcessHashInfo(typing.TypedDict):
    """Subset of process fields needed for hashing and VirusTotal submission"""

    pid: int
    name: str
    fd: int
    dev: int
    ino: int
    exe: str


# functional form required because keys contain spaces
State = typing.TypedDict(
    "State",
    {
        "Error Log": list[str],
        "Exe Log": list[str],
        "Executables": dict[str, list[str]],
        "Names": dict[str, list[str]],
        "Parent Executables": dict[str, list[str]],
        "Parent Names": dict[str, list[str]],
        "SHA256": dict[str, dict[str, str]],
    },
)
