"""Proxy-adapter contract, state preservation, and adapter factory."""

from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from app.constants import PROXY_OPTIONS


class ProxyAdapter(ABC):
    """Interface that every proxy integration must implement in Phase 2+."""

    @abstractmethod
    def detect(self) -> bool: ...

    @abstractmethod
    def is_running(self) -> bool: ...

    @abstractmethod
    def stop(self, timeout_seconds: float = 10.0) -> bool: ...

    @abstractmethod
    def start(self, timeout_seconds: float = 10.0) -> bool: ...

    @abstractmethod
    def locate_executable(self) -> Path | None: ...

    def restore(self, was_running: bool, timeout_seconds: float = 10.0) -> bool:
        """Restore exactly the running state captured before authentication."""

        running_now = self.is_running()
        if was_running and not running_now:
            return self.start(timeout_seconds)
        if not was_running and running_now:
            return self.stop(timeout_seconds)
        return True

    @contextmanager
    def authentication_bypass(self, timeout_seconds: float = 10.0) -> Iterator[object]:
        """Prepare direct access and always restore the exact captured proxy state."""

        state = self.prepare_for_authentication(timeout_seconds)

        body_failed = False
        try:
            yield state
        except BaseException:
            body_failed = True
            raise
        finally:
            restored = self.restore_after_authentication(state, timeout_seconds)
            if not restored and not body_failed:
                raise ProxyOperationError("系统代理原状态恢复失败")

    def prepare_for_authentication(self, timeout_seconds: float = 10.0) -> object:
        was_running = self.is_running()
        if was_running and not self.stop(timeout_seconds):
            raise ProxyOperationError("代理绕过准备失败")
        return was_running

    def restore_after_authentication(self, state: object, timeout_seconds: float = 10.0) -> bool:
        return self.restore(bool(state), timeout_seconds)


class ProxyOperationError(RuntimeError):
    """A sanitized proxy operation failure."""


class NoProxyAdapter(ProxyAdapter):
    """No-op implementation used when proxy management is disabled."""

    def detect(self) -> bool:
        return True

    def is_running(self) -> bool:
        return False

    def stop(self, timeout_seconds: float = 10.0) -> bool:
        return True

    def start(self, timeout_seconds: float = 10.0) -> bool:
        return True

    def locate_executable(self) -> Path | None:
        return None


class UnsupportedProxyAdapter(ProxyAdapter):
    """Explicit placeholder that cannot alter system proxy settings."""

    def __init__(self, display_name: str) -> None:
        self.display_name = display_name

    def detect(self) -> bool:
        return False

    def is_running(self) -> bool:
        return False

    def stop(self, timeout_seconds: float = 10.0) -> bool:
        raise ProxyOperationError(f"{self.display_name} 尚未支持")

    def start(self, timeout_seconds: float = 10.0) -> bool:
        raise ProxyOperationError(f"{self.display_name} 尚未支持")

    def locate_executable(self) -> Path | None:
        return None

    def prepare_for_authentication(self, timeout_seconds: float = 10.0) -> object:
        raise ProxyOperationError(f"{self.display_name} 尚未支持")

    def restore_after_authentication(self, state: object, timeout_seconds: float = 10.0) -> bool:
        raise ProxyOperationError(f"{self.display_name} 尚未支持")


def proxy_catalog() -> tuple[tuple[str, str, bool], ...]:
    """Return key, display label, and current adapter support flag."""

    return PROXY_OPTIONS


def create_proxy_adapter(
    proxy_type: str,
    *,
    exe_path: str = "",
    process_service=None,
    dry_run: bool = True,
    system_proxy=None,
) -> ProxyAdapter:
    """Create an adapter without leaking proxy-specific logic into callers."""

    if proxy_type == "none":
        from proxy.none import NoneProxyAdapter

        return NoneProxyAdapter()
    if proxy_type == "clash_for_windows":
        from proxy.clash_for_windows import ClashForWindowsAdapter

        return ClashForWindowsAdapter(
            exe_path=exe_path,
            process_service=process_service,
            dry_run=dry_run,
            system_proxy=system_proxy,
        )

    adapter_types = {
        "flclash": ("proxy.flclash", "FlClashAdapter"),
        "clash_verge_rev": ("proxy.clash_verge_rev", "ClashVergeRevAdapter"),
        "mihomo": ("proxy.mihomo", "MihomoAdapter"),
        "gui_for_singbox": ("proxy.gui_for_singbox", "GuiForSingBoxAdapter"),
        "v2rayn": ("proxy.v2rayn", "V2rayNAdapter"),
    }
    target = adapter_types.get(proxy_type)
    if target is None:
        raise ValueError(f"未知代理类型：{proxy_type}")
    module_name, class_name = target
    import importlib

    adapter_class = getattr(importlib.import_module(module_name), class_name)
    return adapter_class(
        exe_path=exe_path, process_service=process_service,
        dry_run=dry_run, system_proxy=system_proxy,
    )
