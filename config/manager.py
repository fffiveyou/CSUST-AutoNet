"""JSON configuration management with validation and atomic writes."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping

from app.constants import (
    CONFIG_VERSION,
    DEFAULT_CHECK_INTERVAL,
    MIN_CHECK_INTERVAL,
    PROXY_TYPE_KEYS,
    config_path,
)


def default_config() -> dict[str, Any]:
    """Return a new mutable copy of the Phase 1 defaults."""

    return {
        "version": CONFIG_VERSION,
        "username": "",
        "auto_auth": False,
        "wifi_auto_connect": True,
        "wifi_profile": "CSUST-Student",
        "monitor_interval": DEFAULT_CHECK_INTERVAL,
        "proxy_management": True,
        "proxy_type": "clash_for_windows",
        "proxy_exe_path": "",
        "restore_proxy": True,
        "windows_autostart": False,
        "minimize_to_tray": True,
    }


def normalize_interval(value: object) -> int:
    """Coerce a monitor interval and enforce the hard 30-second minimum."""

    try:
        interval = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        interval = DEFAULT_CHECK_INTERVAL
    return max(MIN_CHECK_INTERVAL, interval)


def normalize_config(raw: Mapping[str, object] | None) -> dict[str, Any]:
    """Merge supported values over defaults and reject unknown/sensitive keys."""

    defaults = default_config()
    if not isinstance(raw, Mapping):
        return defaults

    username = raw.get("username")
    if isinstance(username, str):
        defaults["username"] = username.strip()

    defaults["monitor_interval"] = normalize_interval(raw.get("monitor_interval"))

    for key in (
        "auto_auth",
        "wifi_auto_connect",
        "proxy_management",
        "restore_proxy",
        "windows_autostart",
        "minimize_to_tray",
    ):
        if isinstance(raw.get(key), bool):
            defaults[key] = raw[key]

    proxy_type = raw.get("proxy_type")
    if isinstance(proxy_type, str) and proxy_type in PROXY_TYPE_KEYS:
        defaults["proxy_type"] = proxy_type

    proxy_path = raw.get("proxy_exe_path")
    if isinstance(proxy_path, str):
        defaults["proxy_exe_path"] = proxy_path

    wifi_profile = raw.get("wifi_profile")
    if isinstance(wifi_profile, str) and 0 < len(wifi_profile.strip()) <= 128:
        defaults["wifi_profile"] = wifi_profile.strip()

    return defaults


class ConfigManager:
    """Load and save the non-secret application configuration."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or config_path()

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return default_config()
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return default_config()
        return normalize_config(payload if isinstance(payload, dict) else None)

    def save(self, config: Mapping[str, object]) -> dict[str, Any]:
        normalized = normalize_config(config)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        text = json.dumps(normalized, ensure_ascii=False, indent=2) + "\n"
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, self.path)
        return normalized
