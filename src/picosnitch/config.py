# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

import dataclasses
import grp
import ipaddress
import logging
import os
import pwd
import tomllib
from pathlib import Path

from picosnitch.constants import CONFIG_DIR


@dataclasses.dataclass
class DatabaseConfig:
    enabled: bool = True
    retention_days: int = 30
    write_limit_seconds: int = 10
    text_log: bool = False
    remote: dict = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class DataConfig:
    owner: str = "root"
    group: str = "root"
    mode: str = "0644"


@dataclasses.dataclass
class LogConfig:
    addresses: bool = True
    commands: bool = True
    ports: bool = True
    ignore_ports: list[int] = dataclasses.field(default_factory=list)
    ignore_domains: list[str] = dataclasses.field(default_factory=list)
    ignore_ips: list[str] = dataclasses.field(default_factory=list)
    ignore_sha256: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class DesktopConfig:
    user: str = ""
    notifications: bool = True
    geoip_lookup: bool = True


@dataclasses.dataclass
class MonitoringConfig:
    every_exe: bool = False
    perf_ring_buffer_pages: int = 256
    conn_map_max_entries: int = 65536
    rlimit_nofile: int | None = None
    st_dev_mask: int | None = None


@dataclasses.dataclass
class VirusTotalConfig:
    api_key: str = ""
    file_upload: bool = False
    request_limit_seconds: int = 15


@dataclasses.dataclass
class Config:
    database: DatabaseConfig = dataclasses.field(default_factory=DatabaseConfig)
    data: DataConfig = dataclasses.field(default_factory=DataConfig)
    log: LogConfig = dataclasses.field(default_factory=LogConfig)
    desktop: DesktopConfig = dataclasses.field(default_factory=DesktopConfig)
    monitoring: MonitoringConfig = dataclasses.field(default_factory=MonitoringConfig)
    virustotal: VirusTotalConfig = dataclasses.field(default_factory=VirusTotalConfig)


def _dump_toml(config: Config) -> str:
    """Serialize a Config dataclass to a TOML string."""
    lines: list[str] = []

    def _format_value(value: bool | int | str | list) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, int):
            return str(value)
        if isinstance(value, str):
            # escape backslashes and quotes
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'
        if isinstance(value, list):
            if not value:
                return "[]"
            items = ", ".join(_format_value(v) for v in value)
            return f"[{items}]"
        raise TypeError(f"Unsupported TOML value type: {type(value)}")

    def _write_section(section_name: str, obj) -> None:
        lines.append(f"[{section_name}]")
        sub_sections: list[tuple[str, dict]] = []
        for field in dataclasses.fields(obj):
            value = getattr(obj, field.name)
            if value is None:
                continue
            if isinstance(value, dict):
                sub_sections.append((field.name, value))
                continue
            lines.append(f"{field.name} = {_format_value(value)}")
        lines.append("")
        for sub_name, sub_dict in sub_sections:
            full_name = f"{section_name}.{sub_name}"
            if sub_dict:
                lines.append(f"[{full_name}]")
                for k, v in sub_dict.items():
                    lines.append(f"{k} = {_format_value(v)}")
                lines.append("")

    for field in dataclasses.fields(config):
        _write_section(field.name, getattr(config, field.name))

    return "\n".join(lines)


def load_config(config_dir: Path = CONFIG_DIR) -> Config:
    """Load config from config.toml, merging with defaults."""
    config_path = config_dir / "config.toml"
    config = Config()
    if config_path.exists():
        try:
            with open(config_path, "rb") as f:
                raw = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
            # never crash-loop the daemon on a malformed config; fall back to defaults
            logging.error(f"failed to read {config_path}, using defaults: {e}")
            raw = {}
        for section_field in dataclasses.fields(config):
            section_name = section_field.name
            if section_name not in raw:
                continue
            section_data = raw[section_name]
            if not isinstance(section_data, dict):
                # valid TOML but wrong shape (e.g. `monitoring = 5` instead of `[monitoring]`);
                # skip so `field.name in section_data` can't raise and crash-loop the daemon
                logging.warning(f"config.{section_name}: expected a table, got {type(section_data).__name__}, ignoring")
                continue
            section_obj = getattr(config, section_name)
            for field in dataclasses.fields(section_obj):
                if field.name in section_data:
                    value = section_data[field.name]
                    expected_type = field.type
                    if hasattr(expected_type, "__origin__"):
                        # parameterized generics (list[int]): enforce the container type, a
                        # scalar here would crash the secondary's filters every write cycle
                        if expected_type.__origin__ is list and not isinstance(value, list):
                            logging.warning(f"config.{section_name}.{field.name}: expected a list, got {type(value).__name__}, skipping")
                            continue
                    elif not isinstance(expected_type, type):
                        # field.type may be a forward-ref string under `from __future__ import annotations`
                        pass
                    elif not isinstance(value, expected_type) or (isinstance(value, bool) and expected_type is not bool):
                        type_name = getattr(expected_type, "__name__", str(expected_type))
                        logging.warning(f"config.{section_name}.{field.name}: expected {type_name}, got {type(value).__name__}, skipping")
                        continue
                    setattr(section_obj, field.name, value)
    # clamp values that would otherwise fail the perf mmap / BPF load and restart-loop the daemon;
    # bound both above too so an absurd (but power-of-two / positive) value can't crash-loop either
    pages = config.monitoring.perf_ring_buffer_pages
    if pages < 1 or pages > 16384 or (pages & (pages - 1)) != 0:
        logging.warning(f"monitoring.perf_ring_buffer_pages must be a power of two in [1, 16384], got {pages}, using 256")
        config.monitoring.perf_ring_buffer_pages = 256
    entries = config.monitoring.conn_map_max_entries
    if entries < 1 or entries > 1048576:
        logging.warning(f"monitoring.conn_map_max_entries must be in [1, 1048576], got {entries}, using 65536")
        config.monitoring.conn_map_max_entries = 65536
    nofile = config.monitoring.rlimit_nofile
    if nofile is not None and (isinstance(nofile, bool) or not isinstance(nofile, int) or nofile < 256):
        logging.warning(f"monitoring.rlimit_nofile must be an integer >= 256, got {nofile!r}, ignoring")
        config.monitoring.rlimit_nofile = None
    dev_mask = config.monitoring.st_dev_mask
    if dev_mask is not None and (isinstance(dev_mask, bool) or not isinstance(dev_mask, int) or not 0 <= dev_mask <= 0xFFFFFFFF):
        logging.warning(f"monitoring.st_dev_mask must be in [0, 4294967295], got {dev_mask!r}, ignoring")
        config.monitoring.st_dev_mask = None
    # reject only negatives (a negative retention makes the cutoff a future time -> wipes the db)
    retention = config.database.retention_days
    if retention < 0:
        logging.warning(f"database.retention_days must not be negative, got {retention}, using 30")
        config.database.retention_days = 30
    write_limit = config.database.write_limit_seconds
    if write_limit < 0:
        logging.warning(f"database.write_limit_seconds must not be negative, got {write_limit}, using 10")
        config.database.write_limit_seconds = 10
    request_limit = config.virustotal.request_limit_seconds
    if request_limit < 0:
        logging.warning(f"virustotal.request_limit_seconds must not be negative, got {request_limit}, using 15")
        config.virustotal.request_limit_seconds = 15

    # reset owner/group/user/mode that don't resolve to a real uid/gid/octal mode; otherwise a
    # typo'd name crash-loops the daemon at boot (apply_data_permissions and the subprocess
    # privilege drop resolve these outside any try/except). resolved inline with pwd/grp (mirroring
    # utils.resolve_owner/resolve_group) to avoid a config<->utils import cycle
    def _resolves(value, lookup) -> bool:
        try:
            numeric = int(value)
            return 0 <= numeric < 2**32 - 1
        except (ValueError, TypeError):
            pass
        try:
            lookup(value)
            return True
        except (KeyError, TypeError):
            return False

    if not _resolves(config.data.owner, pwd.getpwnam):
        logging.warning(f"config.data.owner: {config.data.owner!r} does not resolve, using 'root'")
        config.data.owner = "root"
    if not _resolves(config.data.group, grp.getgrnam):
        logging.warning(f"config.data.group: {config.data.group!r} does not resolve, using 'root'")
        config.data.group = "root"
    try:
        mode = int(config.data.mode, 8)
        if not 0 <= mode <= 0o7777:
            raise ValueError
    except ValueError:
        logging.warning(f"config.data.mode: {config.data.mode!r} is not an octal mode, using '0644'")
        config.data.mode = "0644"

    def _unprivileged_user(value: str) -> bool:
        try:
            entry = pwd.getpwuid(int(value))
        except (ValueError, TypeError, OverflowError):
            try:
                entry = pwd.getpwnam(value)
            except (KeyError, TypeError):
                return False
        except KeyError:
            return False
        return entry.pw_uid != 0 and entry.pw_gid != 0

    if config.desktop.user and not _unprivileged_user(config.desktop.user):
        logging.warning(f"config.desktop.user: {config.desktop.user!r} is not a valid non-root user, ignoring")
        config.desktop.user = ""
    # drop log.ignore_ips entries that aren't valid networks (strict=False accepts a host-bit CIDR);
    # otherwise secondary crashes building ignored_networks at boot outside its try/except
    valid_ignore_ips = []
    for ip_subnet in config.log.ignore_ips:
        try:
            ipaddress.ip_network(ip_subnet, strict=False)
        except (ValueError, TypeError):
            logging.warning(f"config.log.ignore_ips: {ip_subnet!r} is not a valid network, ignoring")
            continue
        valid_ignore_ips.append(ip_subnet)
    config.log.ignore_ips = valid_ignore_ips
    # drop ignore_domains entries that aren't non-empty strings: a non-str crashes secondary's
    # startswith() filter every write cycle (halting all logging), an empty string prefixes every
    # domain (silently dropping all connections) -- both outside the subprocess try/except
    valid_ignore_domains = []
    for domain_prefix in config.log.ignore_domains:
        if not isinstance(domain_prefix, str) or not domain_prefix:
            logging.warning(f"config.log.ignore_domains: {domain_prefix!r} is not a non-empty string, ignoring")
            continue
        valid_ignore_domains.append(domain_prefix)
    config.log.ignore_domains = valid_ignore_domains
    config.log.ignore_ports = [port for port in config.log.ignore_ports if isinstance(port, int) and not isinstance(port, bool) and -1 <= port <= 65535]
    config.log.ignore_sha256 = [digest.lower() for digest in config.log.ignore_sha256 if isinstance(digest, str) and len(digest) == 64 and all(c in "0123456789abcdefABCDEF" for c in digest)]
    sudo_uid = os.environ.get("SUDO_UID", "")
    if not config.desktop.user and sudo_uid.isdigit() and _unprivileged_user(sudo_uid):
        config.desktop.user = sudo_uid
    return config


def write_default_config(config_path: Path) -> None:
    """Write the default config to a TOML file."""
    fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(_dump_toml(Config()))
    logging.info(f"wrote default config to {config_path}")
