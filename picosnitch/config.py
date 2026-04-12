#!/usr/bin/env python3
# picosnitch
# Copyright (C) 2020 Eric Lesiuta

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

import dataclasses
import logging
import os
import tomllib
from pathlib import Path

from .constants import CONFIG_DIR


@dataclasses.dataclass
class DatabaseConfig:
    enabled: bool = True
    retention_days: int = 30
    write_limit_seconds: int = 10
    text_log: bool = False
    remote: dict = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class DashConfig:
    scroll_zoom: bool = True
    theme: str = ""


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


@dataclasses.dataclass
class MonitoringConfig:
    every_exe: bool = False
    geoip_lookup: bool = True
    perf_ring_buffer_pages: int = 256
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
    dash: DashConfig = dataclasses.field(default_factory=DashConfig)
    data: DataConfig = dataclasses.field(default_factory=DataConfig)
    log: LogConfig = dataclasses.field(default_factory=LogConfig)
    desktop: DesktopConfig = dataclasses.field(default_factory=DesktopConfig)
    monitoring: MonitoringConfig = dataclasses.field(default_factory=MonitoringConfig)
    virustotal: VirusTotalConfig = dataclasses.field(default_factory=VirusTotalConfig)


def _dump_toml(config: Config) -> str:
    """Serialize a Config dataclass to a TOML string."""
    lines: list[str] = []

    def _format_value(value) -> str:
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
        sub_sections: list[tuple[str, object]] = []
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
        with open(config_path, "rb") as f:
            raw = tomllib.load(f)
        for section_field in dataclasses.fields(config):
            section_name = section_field.name
            if section_name not in raw:
                continue
            section_data = raw[section_name]
            section_obj = getattr(config, section_name)
            for field in dataclasses.fields(section_obj):
                if field.name in section_data:
                    setattr(section_obj, field.name, section_data[field.name])
    if not config.desktop.user and os.environ.get("SUDO_UID"):
        config.desktop.user = os.environ["SUDO_UID"]
    return config


def write_default_config(config_path: Path) -> None:
    """Write the default config to a TOML file."""
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(_dump_toml(Config()))
    logging.info(f"wrote default config to {config_path}")
