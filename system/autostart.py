"""HKCU Run registration for background startup on Windows."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Protocol

from app.constants import APP_ID, PROJECT_ROOT


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


class RegistryBackend(Protocol):
    def read(self, name: str) -> str | None: ...

    def write(self, name: str, value: str) -> None: ...

    def delete(self, name: str) -> None: ...


class AutostartError(RuntimeError):
    """A sanitized autostart operation failure."""


class WindowsRunRegistry:
    def _winreg(self):
        if sys.platform != "win32":
            raise AutostartError("开机启动仅支持 Windows")
        import winreg

        return winreg

    def read(self, name: str) -> str | None:
        winreg = self._winreg()
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
                value, _ = winreg.QueryValueEx(key, name)
                return str(value)
        except FileNotFoundError:
            return None

    def write(self, name: str, value: str) -> None:
        winreg = self._winreg()
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)

    def delete(self, name: str) -> None:
        winreg = self._winreg()
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, name)
        except FileNotFoundError:
            return


def build_autostart_command(
    *,
    executable: str | None = None,
    frozen: bool | None = None,
    source_main: Path | None = None,
) -> str:
    """Build an argv-safe command for packaged and source development modes."""

    is_frozen = bool(getattr(sys, "frozen", False)) if frozen is None else frozen
    exe = executable or sys.executable
    if is_frozen:
        args = [exe, "--background"]
    else:
        # Source/development installs should start without a console window.
        # Keep python.exe only when the matching pythonw.exe is unavailable.
        executable_path = Path(exe)
        pythonw = executable_path.with_name("pythonw.exe")
        if executable_path.name.casefold() == "python.exe" and pythonw.is_file():
            exe = str(pythonw)
        args = [exe, str(source_main or (PROJECT_ROOT / "main.py")), "--background"]
    return subprocess.list2cmdline(args)


class AutostartManager:
    def __init__(self, backend: RegistryBackend | None = None) -> None:
        self.backend = backend or WindowsRunRegistry()

    def is_enabled(self) -> bool:
        try:
            return self.backend.read(APP_ID) == build_autostart_command()
        except Exception:
            return False

    def set_enabled(self, enabled: bool) -> None:
        try:
            if enabled:
                expected = build_autostart_command()
                self.backend.write(APP_ID, expected)
                if self.backend.read(APP_ID) != expected:
                    raise AutostartError("开机启动项写入后校验失败")
            else:
                self.backend.delete(APP_ID)
                if self.backend.read(APP_ID) is not None:
                    raise AutostartError("开机启动项删除后校验失败")
        except AutostartError:
            raise
        except Exception:
            raise AutostartError("无法更新 HKCU 开机启动项") from None
