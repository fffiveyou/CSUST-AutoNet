"""Safe Windows Wi-Fi reconnection through an existing WLAN profile."""

from __future__ import annotations

import os
import re
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum


PROFILE_NAME = re.compile(r"^[^\x00-\x1f]{1,128}$")
SSID_LINE = re.compile(r"^\s*SSID\s*:\s*(.*?)\s*$", re.IGNORECASE | re.MULTILINE)


class WifiConnectState(str, Enum):
    DISABLED = "DISABLED"
    ALREADY_CONNECTED = "ALREADY_CONNECTED"
    CONNECTED = "CONNECTED"
    CONNECT_REQUESTED = "CONNECT_REQUESTED"
    OTHER_NETWORK = "OTHER_NETWORK"
    FAILED = "FAILED"


@dataclass(frozen=True)
class WifiConnectResult:
    state: WifiConnectState
    message: str


Runner = Callable[..., subprocess.CompletedProcess[str]]


class WindowsWifiConnector:
    """Connect to a saved Windows WLAN profile without handling Wi-Fi secrets."""

    def __init__(
        self,
        *,
        runner: Runner = subprocess.run,
        sleeper: Callable[[float], None] = time.sleep,
        poll_delays: Sequence[float] = (0.5, 1.0, 1.5),
        clock: Callable[[], float] = time.monotonic,
        request_cooldown: float = 60.0,
    ) -> None:
        self.runner = runner
        self.sleeper = sleeper
        self.poll_delays = tuple(poll_delays)
        self.clock = clock
        self.request_cooldown = request_cooldown
        self._last_connect_request_at: float | None = None

    @staticmethod
    def _creation_flags() -> int:
        return int(getattr(subprocess, "CREATE_NO_WINDOW", 0)) if os.name == "nt" else 0

    def _run(self, arguments: list[str]) -> subprocess.CompletedProcess[str] | None:
        try:
            return self.runner(
                arguments,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=8,
                check=False,
                creationflags=self._creation_flags(),
            )
        except (OSError, subprocess.SubprocessError):
            return None

    def _current_ssid(self) -> str | None:
        completed = self._run(["netsh", "wlan", "show", "interfaces"])
        if completed is None or completed.returncode != 0:
            return None
        match = SSID_LINE.search(completed.stdout or "")
        return match.group(1).strip() if match else None

    def ensure_connected(self, profile_name: str, *, enabled: bool = True) -> WifiConnectResult:
        if not enabled:
            return WifiConnectResult(WifiConnectState.DISABLED, "Wi-Fi 自动连接未启用。")
        profile_name = profile_name.strip()
        if not PROFILE_NAME.fullmatch(profile_name):
            return WifiConnectResult(WifiConnectState.FAILED, "校园 Wi-Fi 配置名称无效。")

        current_ssid = self._current_ssid()
        if current_ssid == profile_name:
            return WifiConnectResult(WifiConnectState.ALREADY_CONNECTED, "校园 Wi-Fi 已连接。")
        if current_ssid:
            return WifiConnectResult(
                WifiConnectState.OTHER_NETWORK,
                "当前已连接其他 Wi-Fi，不自动切换网络。",
            )
        if (
            self._last_connect_request_at is not None
            and self.clock() - self._last_connect_request_at < self.request_cooldown
        ):
            return WifiConnectResult(
                WifiConnectState.CONNECT_REQUESTED,
                "已请求 Windows 连接校园 Wi-Fi，等待网络就绪。",
            )

        completed = self._run(
            ["netsh", "wlan", "connect", f"name={profile_name}", f"ssid={profile_name}"]
        )
        if completed is None or completed.returncode != 0:
            return WifiConnectResult(
                WifiConnectState.FAILED,
                "无法连接校园 Wi-Fi；请确认 Windows 已保存该网络配置。",
            )
        self._last_connect_request_at = self.clock()

        for delay in self.poll_delays:
            self.sleeper(delay)
            if self._current_ssid() == profile_name:
                return WifiConnectResult(WifiConnectState.CONNECTED, "校园 Wi-Fi 已自动连接。")
        return WifiConnectResult(
            WifiConnectState.CONNECT_REQUESTED,
            "已请求 Windows 连接校园 Wi-Fi，等待网络就绪。",
        )
