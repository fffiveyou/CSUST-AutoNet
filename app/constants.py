"""Application-wide constants and filesystem locations."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final


APP_NAME: Final = "CSUST AutoNet"
APP_ID: Final = "CSUSTAutoNet"
CONFIG_VERSION: Final = 2

MIN_CHECK_INTERVAL: Final = 30
DEFAULT_CHECK_INTERVAL: Final = 30
LOG_RETENTION_DAYS: Final = 5
MAX_AUTH_ATTEMPTS: Final = 3

PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
CONFIG_FILENAME: Final = "config.json"
KEYRING_SERVICE: Final = "CSUSTAutoNet.CampusNetwork"

PROXY_OPTIONS: Final[tuple[tuple[str, str, bool], ...]] = (
    ("none", "不处理代理软件", True),
    ("clash_for_windows", "Clash for Windows", True),
    ("flclash", "FlClash", True),
    ("clash_verge_rev", "Clash Verge Rev", True),
    ("mihomo", "Mihomo / GUI.for.Clash", True),
    ("gui_for_singbox", "GUI.for.SingBox", True),
    ("v2rayn", "v2rayN", True),
)
PROXY_TYPE_KEYS: Final = frozenset(item[0] for item in PROXY_OPTIONS)


def local_app_data_dir() -> Path:
    """Return the per-user application data directory without creating it."""

    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / APP_ID
    return Path.home() / "AppData" / "Local" / APP_ID


def config_path() -> Path:
    return local_app_data_dir() / CONFIG_FILENAME


def log_dir() -> Path:
    return local_app_data_dir() / "logs"
