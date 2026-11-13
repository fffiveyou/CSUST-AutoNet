"""Exact snapshot, temporary disable, and restoration of Windows user proxy settings."""

from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import dataclass
from typing import Protocol


INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
MANAGED_VALUES = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect")
REG_DWORD = 4


@dataclass(frozen=True)
class RegistryValue:
    exists: bool
    value: object | None = None
    value_type: int | None = None


@dataclass(frozen=True)
class SystemProxySnapshot:
    values: dict[str, RegistryValue]


class ProxyRegistryBackend(Protocol):
    def read(self, name: str) -> RegistryValue: ...

    def write(self, name: str, value: object, value_type: int) -> None: ...

    def delete(self, name: str) -> None: ...

    def notify_changed(self) -> None: ...


class WindowsInternetSettingsRegistry:
    """HKCU WinINET backend; never touches WinHTTP or machine-wide keys."""

    @staticmethod
    def _winreg():
        if sys.platform != "win32":
            raise RuntimeError("Windows 系统代理仅支持 Windows")
        import winreg

        return winreg

    def read(self, name: str) -> RegistryValue:
        winreg = self._winreg()
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY) as key:
                value, value_type = winreg.QueryValueEx(key, name)
                return RegistryValue(True, value, value_type)
        except FileNotFoundError:
            return RegistryValue(False)

    def write(self, name: str, value: object, value_type: int) -> None:
        winreg = self._winreg()
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY) as key:
            winreg.SetValueEx(key, name, 0, value_type, value)

    def delete(self, name: str) -> None:
        winreg = self._winreg()
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                INTERNET_SETTINGS_KEY,
                0,
                winreg.KEY_SET_VALUE,
            ) as key:
                winreg.DeleteValue(key, name)
        except FileNotFoundError:
            return

    @staticmethod
    def notify_changed() -> None:
        if os.name != "nt":
            return
        internet_set_option = ctypes.windll.wininet.InternetSetOptionW
        internet_set_option(None, 39, None, 0)
        internet_set_option(None, 37, None, 0)


class WindowsSystemProxy:
    """Manage only the current user's WinINET manual/PAC proxy state."""

    def __init__(self, backend: ProxyRegistryBackend | None = None) -> None:
        self.backend = backend or WindowsInternetSettingsRegistry()

    def capture(self) -> SystemProxySnapshot:
        return SystemProxySnapshot({name: self.backend.read(name) for name in MANAGED_VALUES})

    @staticmethod
    def is_active_snapshot(snapshot: SystemProxySnapshot) -> bool:
        manual = snapshot.values["ProxyEnable"]
        pac = snapshot.values["AutoConfigURL"]
        manual_active = manual.exists and bool(manual.value)
        pac_active = pac.exists and bool(str(pac.value or "").strip())
        return manual_active or pac_active

    def is_active(self) -> bool:
        return self.is_active_snapshot(self.capture())

    def disable(self) -> bool:
        """Disable manual and PAC routing while retaining stored endpoint details."""

        self.backend.write("ProxyEnable", 0, REG_DWORD)
        self.backend.delete("AutoConfigURL")
        self.backend.notify_changed()
        return not self.is_active()

    def restore(self, snapshot: SystemProxySnapshot) -> bool:
        """Restore exact values, registry types, and originally missing values."""

        for name in MANAGED_VALUES:
            captured = snapshot.values[name]
            if captured.exists:
                assert captured.value_type is not None
                self.backend.write(name, captured.value, captured.value_type)
            else:
                self.backend.delete(name)
        self.backend.notify_changed()
        return self.capture() == snapshot
