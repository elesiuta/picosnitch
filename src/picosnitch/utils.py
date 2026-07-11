# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import ctypes
import fcntl
import functools
import grp
import hashlib
import ipaddress
import json
import logging
import multiprocessing
import os
import pickle
import pwd
import queue
import socket
import sqlite3
import stat
import sys
import tempfile
import termios
import time
import unicodedata
import urllib.parse
from pathlib import Path

from picosnitch.config import Config, load_config
from picosnitch.constants import DATA_DIR, LOG_DIR, PID_CACHE, ST_DEV_MASK
from picosnitch.types import FanotifyEventMetadata, State

FUSE_HASH_TIMEOUT = 60


def relaunch_argv(cmd: str) -> list[str]:
    """argv to re-invoke picosnitch for `cmd` (used by `top` to spawn a monitor and by the
    main loop to restart after suspend). Re-exec argv[0] directly so its own shebang or nix
    bash wrapper (which sets LD_LIBRARY_PATH for libbpf) runs; prefixing sys.executable breaks
    nix, whose argv[0] is a bash wrapper the python interpreter can't parse. Fall back to
    `-m picosnitch` when we weren't launched from a picosnitch console script/wrapper."""
    argv0 = sys.argv[0]
    base = os.path.basename(argv0).lstrip(".").split("-wrapped")[0]
    # only re-exec argv0 directly if it's absolute; a bare/relative name would be resolved via
    # $PATH or cwd at exec time. otherwise use the interpreter (sys.executable is always absolute)
    if base == "picosnitch" and os.path.isabs(argv0) and os.access(argv0, os.X_OK):
        return [argv0, cmd]
    return [sys.executable, "-m", "picosnitch", cmd]


def sqlite_error_means_corrupt(e: sqlite3.Error) -> bool:
    """True when a sqlite error means picosnitch.db itself is unusable (quarantine+recreate);
    False for transient errors (locked by the live daemon, busy, disk I/O) where quarantining
    would destroy a healthy database. Shared by the cli boot check and the secondary purge."""
    msg = str(e).lower()
    return any(s in msg for s in ("malformed", "not a database", "no such table", "no such column", "encrypted"))


def drop_root_permanent(uid: int, gid: int) -> None:
    """Permanently drop root privileges. Cannot be reversed."""
    if os.getuid() != 0:
        return
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    if os.getuid() != uid or os.getgid() != gid:
        logging.error("Failed to drop root privileges")
        sys.exit(1)
    try:
        os.setuid(0)
    except PermissionError:
        return
    logging.error("FATAL: was able to regain root after dropping privileges")
    sys.exit(1)


def resolve_owner(owner: str) -> int:
    """Resolve a username or numeric string to a UID."""
    try:
        return int(owner)
    except ValueError:
        return pwd.getpwnam(owner).pw_uid


def resolve_group(group: str) -> int:
    """Resolve a group name or numeric string to a GID."""
    try:
        return int(group)
    except ValueError:
        return grp.getgrnam(group).gr_gid


def resolve_unprivileged_user(user: str) -> tuple[int, int]:
    """Resolve a user and primary group, falling back to nobody (also when uid or gid would be 0)."""
    if user:
        try:
            entry = pwd.getpwuid(int(user))
        except (ValueError, TypeError, OverflowError, KeyError):
            try:
                entry = pwd.getpwnam(user)
            except (KeyError, TypeError):
                entry = None
        if entry is not None and entry.pw_uid != 0 and entry.pw_gid != 0:
            return entry.pw_uid, entry.pw_gid
    try:
        entry = pwd.getpwnam("nobody")
        if entry.pw_uid != 0:
            return entry.pw_uid, entry.pw_gid
    except KeyError:
        pass
    return 65534, 65534


def connect_db_readonly(db_path: Path | str, timeout: float = 5.0) -> sqlite3.Connection:
    """Open a sqlite3 connection for read-only access.

    Tries `mode=ro`, then `mode=ro&immutable=1`. The immutable fallback is needed
    when the caller cannot write to the -shm / -wal sidecar files of a WAL database (e.g.
    a non-root user opening the picosnitch database written by the root
    daemon). Raises sqlite3.OperationalError if both attempts fail."""
    try:
        db_stat = os.lstat(db_path)
    except OSError as e:
        raise sqlite3.OperationalError(f"could not inspect {db_path}: {e}") from e
    if not stat.S_ISREG(db_stat.st_mode) or db_stat.st_nlink != 1:
        raise sqlite3.OperationalError(f"refusing non-regular or hardlinked database: {db_path}")
    quoted_path = urllib.parse.quote(os.fspath(db_path), safe="/")
    last_err: Exception | None = None
    for uri in (
        f"file:{quoted_path}?mode=ro",
        f"file:{quoted_path}?mode=ro&immutable=1",
    ):
        con = None
        try:
            con = sqlite3.connect(uri, uri=uri.startswith("file:"), timeout=timeout)
            # Force the connection to actually touch the file so we
            # surface "attempt to write a readonly database" here
            # instead of at the first user query.
            con.execute("PRAGMA user_version").fetchone()
            return con
        except sqlite3.OperationalError as e:
            if con is not None:
                con.close()
            last_err = e
            continue
    raise sqlite3.OperationalError(f"could not open {db_path} for reading: {last_err}")


def safe_log_open(path: Path | str, binary: bool = False, config: Config | None = None):
    """Open a log file for appending without following a symlink or blocking on a FIFO.

    `LOG_DIR` may be chown'd to a non-root account when `[data].owner` is
    overridden in config.toml, so that user could swap a log file for a
    symlink (redirect the root daemon's writes to an arbitrary path) or a
    FIFO (block the daemon forever on open). `O_NOFOLLOW` fails with ELOOP
    on a symlink; `O_NONBLOCK` plus an `S_ISREG` check rejects a FIFO/device
    instead of hanging. The file is still created if it does not exist.
    """
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(str(path), flags, 0o644)
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1:
            raise OSError(f"refusing non-regular or hardlinked log file: {path}")
        if config is not None:
            os.fchown(fd, resolve_owner(config.data.owner), resolve_group(config.data.group))
            os.fchmod(fd, int(config.data.mode, 8))
        os.set_blocking(fd, True)
    except BaseException:
        os.close(fd)
        raise
    if binary:
        return os.fdopen(fd, "ab", buffering=0)
    return os.fdopen(fd, "a", encoding="utf-8", errors="surrogateescape")


def apply_data_permissions(config_dir: Path, data_dir: Path, log_dir: Path, cache_dir: Path) -> None:
    """Apply the configured ownership and mode to the data, log, and cache FILES.

    The directories are kept root-owned and never group/other-writable. [data].owner may be a
    non-root account (to read or restrict access to the logs); a directory owned by that account
    would let it swap a file for a symlink or FIFO and attack the root daemon (chown/open/sqlite
    all target these paths). Only the FILES take [data].owner:group and the configured mode -- the
    daemon (root) writes them, and readers reach the db read-only (WAL immutable if they can't
    write the sidecars, as non-root readers already do). Live data comes from the events socket,
    not the db, so this does not affect live monitoring."""
    config_dir.chmod(0o755)
    os.chown(config_dir, 0, 0)
    config_path = config_dir / "config.toml"
    try:
        config_fd = os.open(config_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return
    try:
        config_stat = os.fstat(config_fd)
        if not stat.S_ISREG(config_stat.st_mode) or config_stat.st_nlink != 1:
            raise OSError(f"refusing non-regular or hardlinked config: {config_path}")
        os.fchown(config_fd, 0, 0)
        os.fchmod(config_fd, 0o600)
    finally:
        os.close(config_fd)
    config = load_config(config_dir)
    uid = resolve_owner(config.data.owner)
    gid = resolve_group(config.data.group)
    mode = int(config.data.mode, 8)
    dir_mode = (mode | 0o111) & ~0o022  # traversable, but writable only by root (never group/other)
    for d in [data_dir, log_dir, cache_dir]:
        d.chmod(dir_mode)
        os.chown(d, 0, gid)  # root-owned dir (with [data].group for traversal), not [data].owner
        for entry in d.iterdir():
            # fd-based with O_NOFOLLOW: [data].owner may own these dirs, so a symlink swapped
            # in after a path check could redirect the root chown/chmod to an arbitrary file
            # (e.g. /etc/sudoers); O_NONBLOCK so a planted fifo can't block the open
            try:
                fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            except OSError:
                continue
            try:
                st = os.fstat(fd)
                # nlink==1: O_NOFOLLOW stops a symlink swap but not a hardlink from the (untrusted)
                # [data].owner to a root-owned file, which fchown would hand them (LPE where
                # fs.protected_hardlinks=0); picosnitch's own data files are never hardlinked
                if stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
                    os.fchmod(fd, mode)
                    os.fchown(fd, uid, gid)
            finally:
                os.close(fd)


def load_state() -> State:
    """read data for the state dictionary from state.json or init new if not found"""
    data: State = {
        "Error Log": [],
        "Exe Log": [],
        "Executables": {},
        "Names": {},
        "Parent Executables": {},
        "Parent Names": {},
        "Grandparent Executables": {},
        "Grandparent Names": {},
        "SHA256": {},
    }
    state_path = DATA_DIR / "state.json"
    keys = ["Executables", "Names", "Parent Executables", "Parent Names", "Grandparent Executables", "Grandparent Names", "SHA256"]
    if state_path.exists() or state_path.is_symlink():
        try:
            state_fd = os.open(state_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            state_stat = os.fstat(state_fd)
            if not stat.S_ISREG(state_stat.st_mode) or state_stat.st_nlink != 1:
                os.close(state_fd)
                raise OSError("state.json is not a regular, singly linked file")
            if state_stat.st_size > 256 * 1024 * 1024:
                os.close(state_fd)
                raise OSError("state.json exceeds 256 MiB")
            os.set_blocking(state_fd, True)
            with os.fdopen(state_fd, "r", encoding="utf-8", errors="surrogateescape") as json_file:
                state_record = json.load(json_file)
            if not isinstance(state_record, dict):
                raise ValueError("state.json is not a JSON object")
            for key in keys:
                if key in state_record:
                    value = state_record[key]
                    if not isinstance(value, dict):
                        raise ValueError(f"state.json[{key!r}] is not an object")
                    # validate the inner shape too: SHA256 maps exe -> {sha256: result}, the rest
                    # map exe -> [name history]. a wrong-typed entry (e.g. a str/int) crashes
                    # sync_vt_results at startup (outside its subprocess try/except) -> crash-loop
                    inner_type = dict if key == "SHA256" else list
                    if not all(isinstance(v, inner_type) for v in value.values()):
                        raise ValueError(f"state.json[{key!r}] has a non-{inner_type.__name__} entry")
                    data[key] = value  # ty: ignore[invalid-key]
        except (OSError, ValueError) as e:
            # corrupt/unreadable state must not crash-loop the daemon (JSONDecodeError is a
            # ValueError): quarantine the bad file and start fresh instead of sys.exit(1)
            logging.error(f"invalid state.json, starting with empty state: {e}")
            try:
                state_path.rename(state_path.with_name("state.json.bad"))
            except OSError:
                pass
            for key in keys:
                data[key] = {}  # ty: ignore[invalid-key]
    return data


def sanitize_log_line(line: str) -> str:
    """Remove control characters from a log line to prevent terminal-escape / log injection."""
    return "".join(c for c in line if c == "\t" or unicodedata.category(c) not in ("Cc", "Cf", "Cs"))


def flush_logs(state: State, config: Config | None = None) -> None:
    """append pending error.log and exe.log entries, then clear the lists"""
    exe_log_path = LOG_DIR / "exe.log"
    error_log_path = LOG_DIR / "error.log"
    try:
        if state["Error Log"]:
            with safe_log_open(error_log_path, config=config) as f:
                f.write("\n".join(sanitize_log_line(line) for line in state["Error Log"]) + "\n")
            state["Error Log"] = []
    except Exception as e:
        logging.error(f"picosnitch write error (error.log): {type(e).__name__}{e.args}")
    try:
        if state["Exe Log"]:
            with safe_log_open(exe_log_path, config=config) as f:
                f.write("\n".join(sanitize_log_line(line) for line in state["Exe Log"]) + "\n")
            state["Exe Log"] = []
    except Exception as e:
        logging.error(f"picosnitch write error (exe.log): {type(e).__name__}{e.args}")


def save_state(state: State, write_record: bool = True, config: Config | None = None) -> None:
    """flush logs then atomically write state.json via tempfile + os.replace"""
    flush_logs(state, config)
    try:
        if write_record:
            state_path = DATA_DIR / "state.json"
            state_data = {k: state[k] for k in ("Executables", "Names", "Parent Executables", "Parent Names", "Grandparent Executables", "Grandparent Names", "SHA256")}
            # Preserve ownership and mode across atomic replacement.
            try:
                existing = state_path.lstat()
                attrs = (existing.st_uid, existing.st_gid, existing.st_mode & 0o777) if stat.S_ISREG(existing.st_mode) and existing.st_nlink == 1 else None
            except FileNotFoundError:
                attrs = None
            if attrs is None and config is not None:
                attrs = (resolve_owner(config.data.owner), resolve_group(config.data.group), int(config.data.mode, 8))
            fd = tempfile.NamedTemporaryFile(dir=DATA_DIR, mode="w", prefix=".state.", suffix=".tmp", delete=False, encoding="utf-8", errors="surrogateescape")
            try:
                json.dump(state_data, fd, indent=2, separators=(",", ": "), sort_keys=True, ensure_ascii=False)
                fd.flush()
                os.fsync(fd.fileno())
                if attrs is not None:
                    os.fchown(fd.fileno(), attrs[0], attrs[1])
                    os.fchmod(fd.fileno(), attrs[2])
                fd.close()
                os.replace(fd.name, state_path)
            except BaseException:
                fd.close()
                try:
                    os.unlink(fd.name)
                except OSError:
                    pass
                raise
    except Exception as e:
        logging.error(f"picosnitch write error (state.json): {type(e).__name__}{e.args}")


@functools.lru_cache(maxsize=131072)
def reverse_dns_lookup(ip: str) -> str:
    """do a reverse dns lookup, return original ip if fails"""
    try:
        host = socket.getnameinfo((ip, 0), 0)[0]
        try:
            ipaddress.ip_address(host)
            return ip
        except ValueError:
            return ".".join(reversed(host.split(".")))
    except Exception:
        return ip


@functools.lru_cache(maxsize=PID_CACHE)
def get_sha256_fd(path: str, st_dev: int, st_ino: int, _mod_cnt: int) -> str:
    """get sha256 of process executable from /proc/monitor_pid/fd/proc_exe_fd"""
    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            if not st_ino:
                return "!!! FD Stat Error"
            if (st_dev, st_ino) != get_fstat(f.fileno()):
                return "!!! FD Cache Error"
            while data := f.read(1048576):
                sha256.update(data)
        return sha256.hexdigest()
    except Exception:
        return "!!! FD Read Error"


@functools.lru_cache(maxsize=PID_CACHE)
def get_sha256_pid(pid: int, st_dev: int, st_ino: int, _mod_cnt: int = 0) -> str:
    """get sha256 of process executable from /proc/pid/exe"""
    try:
        sha256 = hashlib.sha256()
        with open(f"/proc/{pid}/exe", "rb") as f:
            if (st_dev, st_ino) != get_fstat(f.fileno()):
                return "!!! PID Recycled Error"
            while data := f.read(1048576):
                sha256.update(data)
        return sha256.hexdigest()
    except Exception:
        return "!!! PID Read Error"


@functools.lru_cache(maxsize=PID_CACHE)
def get_sha256_fuse(q_in: multiprocessing.Queue[bytes], q_out: multiprocessing.Queue[bytes], path: str, pid: int, st_dev: int, st_ino: int, _mod_cnt: int) -> str:
    """get sha256 of process executable from a fuse mount"""
    # _mod_cnt in the key so a post-modification re-hash isn't matched to a stale pre-mod reply
    key = (path, pid, st_dev, st_ino, _mod_cnt)
    q_in.put(pickle.dumps(key))
    # bounded so a dead/wedged fuse subprocess can't stall the pipeline forever; match
    # the reply to our request so a late reply after a timeout can't desync the queue
    deadline = time.monotonic() + FUSE_HASH_TIMEOUT
    while (remaining := deadline - time.monotonic()) > 0:
        try:
            reply = q_out.get(timeout=remaining)
        except queue.Empty:
            return "!!! FUSE Subprocess Timeout"
        except Exception:
            return "!!! FUSE Subprocess Error"
        try:
            rkey, sha256 = pickle.loads(reply)
        except Exception:
            return "!!! FUSE Subprocess Error"
        if rkey == key:  # discard any stale reply left over from a prior timed-out call
            return sha256
    return "!!! FUSE Subprocess Timeout"


def get_fstat(fd: int) -> tuple[int, int]:
    """get (st_dev, st_ino) or (0, 0) if fails"""
    try:
        stat = os.fstat(fd)
        return stat.st_dev & ST_DEV_MASK, stat.st_ino
    except Exception:
        return 0, 0


def get_fanotify_events(fan_fd: int, fan_mod_cnt: dict[str, int], q_error: multiprocessing.Queue[str]) -> None:
    """check if any watched executables were modified and increase count to trigger rehash"""
    sizeof_event = ctypes.sizeof(FanotifyEventMetadata)
    bytes_avail = ctypes.c_int()
    fcntl.ioctl(fan_fd, termios.FIONREAD, bytes_avail)
    for _ in range(0, bytes_avail.value, sizeof_event):
        event_fd = -1
        try:
            fanotify_event_metadata = FanotifyEventMetadata()
            buf = os.read(fan_fd, sizeof_event)
            if len(buf) != sizeof_event:
                raise OSError(f"short fanotify event: {len(buf)}/{sizeof_event}")
            ctypes.memmove(ctypes.addressof(fanotify_event_metadata), buf, sizeof_event)
            event_fd = fanotify_event_metadata.fd
            if fanotify_event_metadata.mask & 0x4000:  # FAN_Q_OVERFLOW
                fan_mod_cnt["*"] = fan_mod_cnt.get("*", 0) + 1
                q_error.put("fanotify queue overflowed; invalidating all cached executable hashes")
                continue
            if event_fd < 0:
                raise OSError(f"fanotify event has invalid fd {event_fd}")
            st_dev, st_ino = get_fstat(event_fd)
            fan_mod_cnt[f"{st_dev} {st_ino}"] += 1
        except Exception as e:
            q_error.put("Fanotify Event %s%s on line %s" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?"))
        finally:
            if event_fd >= 0:
                os.close(event_fd)


def sync_vt_results(state: State, q_vt: multiprocessing.Queue[bytes], q_out: multiprocessing.Queue[bytes], check_pending: bool = False) -> None:
    """get virustotal results from subprocess and update state, q_vt = q_in if check_pending else q_out"""
    if check_pending:
        for exe in state["SHA256"]:
            for sha256 in state["SHA256"][exe]:
                vt_state = state["SHA256"][exe][sha256]
                # re-query pending/unscanned states and transient/auth lookup errors (retried, not terminal)
                if vt_state in ["VT Pending", "File not analyzed (no api key)", "", None] or (isinstance(vt_state, str) and vt_state.startswith("VT lookup error")):
                    if exe in state["Executables"] and state["Executables"][exe]:
                        name = state["Executables"][exe][0]
                    elif exe in state["Parent Executables"] and state["Parent Executables"][exe]:
                        name = state["Parent Executables"][exe][0]
                    else:
                        name = exe
                    proc = {"exe": exe, "name": name}
                    q_vt.put(pickle.dumps((proc, sha256)))
    else:
        while not q_vt.empty():
            proc, sha256, result, suspicious = pickle.loads(q_vt.get())
            q_out.put(pickle.dumps({"type": "vt_result", "name": proc["name"], "exe": proc["exe"], "sha256": sha256, "result": result, "suspicious": suspicious}))
