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
        except (OSError, tomllib.TOMLDecodeError) as e:
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
                    # skip type check for parameterized generics (e.g. list[int])
                    if hasattr(expected_type, "__origin__"):
                        pass
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

    # reset owner/group/user/mode that don't resolve to a real uid/gid/octal mode; otherwise a
    # typo'd name crash-loops the daemon at boot (apply_data_permissions and the subprocess
    # privilege drop resolve these outside any try/except). resolved inline with pwd/grp (mirroring
    # utils.resolve_owner/resolve_group) to avoid a config<->utils import cycle
    def _resolves(value, lookup) -> bool:
        try:
            int(value)
            return True
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
        int(config.data.mode, 8)
    except ValueError:
        logging.warning(f"config.data.mode: {config.data.mode!r} is not an octal mode, using '0644'")
        config.data.mode = "0644"
    if config.desktop.user and not (_resolves(config.desktop.user, pwd.getpwnam) and _resolves(config.desktop.user, grp.getgrnam)):
        logging.warning(f"config.desktop.user: {config.desktop.user!r} does not resolve, ignoring")
        config.desktop.user = ""
    # drop log.ignore_ips entries that aren't valid networks (strict=False accepts a host-bit CIDR);
    # otherwise secondary crashes building ignored_networks at boot outside its try/except
    if not isinstance(config.log.ignore_ips, list):
        config.log.ignore_ips = []
    valid_ignore_ips = []
    for ip_subnet in config.log.ignore_ips:
        try:
            ipaddress.ip_network(ip_subnet, strict=False)
        except (ValueError, TypeError):
            logging.warning(f"config.log.ignore_ips: {ip_subnet!r} is not a valid network, ignoring")
            continue
        valid_ignore_ips.append(ip_subnet)
    config.log.ignore_ips = valid_ignore_ips
    if not config.desktop.user and os.environ.get("SUDO_UID", "").isdigit():
        config.desktop.user = os.environ["SUDO_UID"]
    return config


def write_default_config(config_path: Path) -> None:
    """Write the default config to a TOML file."""
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(_dump_toml(Config()))
    logging.info(f"wrote default config to {config_path}")
