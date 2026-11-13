"""Clash for Windows adapter that bypasses authentication via WinINET proxy state."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Callable, Iterable

import psutil

from proxy.base import ProxyAdapter, ProxyOperationError
from system.proxy_settings import SystemProxySnapshot, WindowsSystemProxy


class ClashForWindowsAdapter(ProxyAdapter):
    """Keep Clash running; temporarily disable and exactly restore system proxy."""

    PROCESS_NAMES = frozenset({"Clash for Windows.exe"})
    EXECUTABLE_NAME = "Clash for Windows.exe"

    def __init__(
        self,
        *,
        exe_path: str = "",
        process_service=None,
        system_proxy: WindowsSystemProxy | None = None,
        dry_run: bool = True,
        candidate_paths: Iterable[Path] | None = None,
        process_paths_provider: Callable[[], Iterable[Path]] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        # process_service is accepted for factory compatibility; process control is forbidden.
        self.configured_executable = Path(exe_path).expanduser() if exe_path else None
        self.system_proxy = system_proxy or WindowsSystemProxy()
        self.dry_run = dry_run
        self._candidate_paths_override = tuple(candidate_paths) if candidate_paths is not None else None
        self._process_paths_provider = process_paths_provider
        self.logger = logger or logging.getLogger("csust_autonet.proxy")
        self._last_snapshot: SystemProxySnapshot | None = None

    def _running_paths(self) -> tuple[Path, ...]:
        if self._process_paths_provider is not None:
            return tuple(self._process_paths_provider())
        wanted = {name.casefold() for name in self.PROCESS_NAMES}
        paths: list[Path] = []
        for process in psutil.process_iter(("name", "exe")):
            try:
                if str(process.info.get("name") or "").casefold() not in wanted:
                    continue
                executable = process.info.get("exe")
                if executable:
                    paths.append(Path(executable))
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
        return tuple(dict.fromkeys(paths))

    @staticmethod
    def _valid_executable(path: Path | None) -> bool:
        return bool(path and path.is_file() and path.suffix.casefold() == ".exe")

    def _known_candidates(self) -> tuple[Path, ...]:
        if self._candidate_paths_override is not None:
            return self._candidate_paths_override
        candidates: list[Path] = []
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            local = Path(local_app_data)
            candidates.extend(
                (
                    local / "Programs" / "Clash for Windows" / self.EXECUTABLE_NAME,
                    local / "Clash for Windows" / self.EXECUTABLE_NAME,
                )
            )
        for variable in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
            base = os.environ.get(variable)
            if base:
                candidates.append(Path(base) / "Clash for Windows" / self.EXECUTABLE_NAME)
        return tuple(dict.fromkeys(candidates))

    def detect(self) -> bool:
        return self.is_application_running() or self.locate_executable() is not None

    def is_application_running(self) -> bool:
        return bool(self._running_paths())

    def is_running(self) -> bool:
        """Return whether Windows user proxy routing is currently active."""

        return self.system_proxy.is_active()

    def locate_executable(self) -> Path | None:
        if self._valid_executable(self.configured_executable):
            return self.configured_executable
        for executable in self._running_paths():
            if self._valid_executable(executable):
                return executable
        for candidate in self._known_candidates():
            if self._valid_executable(candidate):
                return candidate
        return None

    def prepare_for_authentication(self, timeout_seconds: float = 10.0) -> SystemProxySnapshot:
        snapshot = self.system_proxy.capture()
        if self.dry_run:
            self.logger.info("DRY_RUN: Windows system proxy disable skipped")
            return snapshot
        if not self.system_proxy.disable():
            raise ProxyOperationError("Windows 系统代理关闭失败")
        self.logger.info("Windows system proxy disabled for campus authentication")
        return snapshot

    def restore_after_authentication(
        self,
        state: object,
        timeout_seconds: float = 10.0,
    ) -> bool:
        if not isinstance(state, SystemProxySnapshot):
            raise ProxyOperationError("系统代理快照无效")
        if self.dry_run:
            self.logger.info("DRY_RUN: Windows system proxy restoration skipped")
            return True
        restored = self.system_proxy.restore(state)
        if restored:
            self.logger.info("Windows system proxy state restored")
        return restored

    def stop(self, timeout_seconds: float = 10.0) -> bool:
        """Compatibility method: disable system proxy; never stop Clash."""

        self._last_snapshot = self.prepare_for_authentication(timeout_seconds)
        return True

    def start(self, timeout_seconds: float = 10.0) -> bool:
        """Compatibility method: restore the last system proxy snapshot."""

        if self._last_snapshot is None:
            return True
        snapshot = self._last_snapshot
        self._last_snapshot = None
        return self.restore_after_authentication(snapshot, timeout_seconds)
