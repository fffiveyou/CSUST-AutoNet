from __future__ import annotations

from pathlib import Path

import pytest

from proxy.base import ProxyOperationError, create_proxy_adapter
from proxy.clash_for_windows import ClashForWindowsAdapter
from proxy.flclash import FlClashAdapter
from system.proxy_settings import (
    MANAGED_VALUES,
    REG_DWORD,
    RegistryValue,
    SystemProxySnapshot,
    WindowsSystemProxy,
)


REG_SZ = 1


class FakeRegistry:
    def __init__(self, values: dict[str, RegistryValue] | None = None) -> None:
        self.values = dict(values or {})
        self.writes: list[tuple[str, object, int]] = []
        self.deletes: list[str] = []
        self.notifications = 0

    def read(self, name: str) -> RegistryValue:
        return self.values.get(name, RegistryValue(False))

    def write(self, name: str, value: object, value_type: int) -> None:
        self.values[name] = RegistryValue(True, value, value_type)
        self.writes.append((name, value, value_type))

    def delete(self, name: str) -> None:
        self.values.pop(name, None)
        self.deletes.append(name)

    def notify_changed(self) -> None:
        self.notifications += 1


def manual_proxy_values() -> dict[str, RegistryValue]:
    return {
        "ProxyEnable": RegistryValue(True, 1, REG_DWORD),
        "ProxyServer": RegistryValue(True, "127.0.0.1:7890", REG_SZ),
        "ProxyOverride": RegistryValue(True, "<local>", REG_SZ),
        "AutoDetect": RegistryValue(True, 1, REG_DWORD),
    }


def fake_executable(tmp_path: Path) -> Path:
    path = tmp_path / "Clash for Windows.exe"
    path.write_bytes(b"test fixture, not executable")
    return path


def test_manual_proxy_disable_and_exact_restore() -> None:
    registry = FakeRegistry(manual_proxy_values())
    proxy = WindowsSystemProxy(registry)
    snapshot = proxy.capture()

    assert proxy.is_active() is True
    assert proxy.disable() is True
    assert proxy.is_active() is False
    assert registry.values["ProxyServer"].value == "127.0.0.1:7890"
    assert registry.values["ProxyOverride"].value == "<local>"
    assert registry.values["AutoDetect"].value == 1
    assert registry.notifications == 1

    assert proxy.restore(snapshot) is True
    assert proxy.capture() == snapshot
    assert registry.notifications == 2


def test_pac_proxy_is_removed_temporarily_and_restored() -> None:
    registry = FakeRegistry(
        {
            "ProxyEnable": RegistryValue(True, 0, REG_DWORD),
            "AutoConfigURL": RegistryValue(True, "http://127.0.0.1:7890/pac", REG_SZ),
        }
    )
    proxy = WindowsSystemProxy(registry)
    snapshot = proxy.capture()

    assert proxy.is_active() is True
    assert proxy.disable() is True
    assert registry.read("AutoConfigURL").exists is False
    assert proxy.restore(snapshot) is True
    assert registry.read("AutoConfigURL").value == "http://127.0.0.1:7890/pac"


def test_originally_missing_values_are_removed_again_on_restore() -> None:
    registry = FakeRegistry()
    proxy = WindowsSystemProxy(registry)
    snapshot = proxy.capture()

    assert all(not snapshot.values[name].exists for name in MANAGED_VALUES)
    assert proxy.disable() is True
    assert registry.read("ProxyEnable") == RegistryValue(True, 0, REG_DWORD)
    assert proxy.restore(snapshot) is True
    assert all(not registry.read(name).exists for name in MANAGED_VALUES)


def test_adapter_dry_run_never_writes_registry(tmp_path: Path) -> None:
    executable = fake_executable(tmp_path)
    registry = FakeRegistry(manual_proxy_values())
    proxy = WindowsSystemProxy(registry)
    adapter = ClashForWindowsAdapter(
        exe_path=str(executable),
        system_proxy=proxy,
        dry_run=True,
        process_paths_provider=lambda: (executable,),
    )

    with adapter.authentication_bypass() as snapshot:
        assert isinstance(snapshot, SystemProxySnapshot)
        assert proxy.is_active() is True

    assert registry.writes == []
    assert registry.deletes == []
    assert registry.notifications == 0


def test_proxy_state_restores_when_authentication_raises(tmp_path: Path) -> None:
    executable = fake_executable(tmp_path)
    registry = FakeRegistry(manual_proxy_values())
    proxy = WindowsSystemProxy(registry)
    original = proxy.capture()
    adapter = ClashForWindowsAdapter(
        exe_path=str(executable),
        system_proxy=proxy,
        dry_run=False,
        process_paths_provider=lambda: (executable,),
    )

    with pytest.raises(RuntimeError, match="authentication failed"):
        with adapter.authentication_bypass():
            assert proxy.is_active() is False
            raise RuntimeError("authentication failed")

    assert proxy.capture() == original


def test_stop_start_compatibility_toggles_system_proxy_not_process(tmp_path: Path) -> None:
    executable = fake_executable(tmp_path)
    registry = FakeRegistry(manual_proxy_values())
    proxy = WindowsSystemProxy(registry)
    process_queries = 0

    def running_paths():
        nonlocal process_queries
        process_queries += 1
        return (executable,)

    adapter = ClashForWindowsAdapter(
        exe_path=str(executable),
        system_proxy=proxy,
        dry_run=False,
        process_paths_provider=running_paths,
    )

    assert adapter.stop() is True
    assert proxy.is_active() is False
    assert adapter.start() is True
    assert proxy.is_active() is True
    assert process_queries == 0


def test_detects_application_and_manual_executable(tmp_path: Path) -> None:
    executable = fake_executable(tmp_path)
    proxy = WindowsSystemProxy(FakeRegistry())
    adapter = ClashForWindowsAdapter(
        exe_path=str(executable),
        system_proxy=proxy,
        process_paths_provider=lambda: (executable,),
    )

    assert adapter.detect() is True
    assert adapter.is_application_running() is True
    assert adapter.locate_executable() == executable
    assert adapter.is_running() is False


def test_known_path_discovery_without_running_application(tmp_path: Path) -> None:
    executable = fake_executable(tmp_path)
    adapter = ClashForWindowsAdapter(
        system_proxy=WindowsSystemProxy(FakeRegistry()),
        candidate_paths=(tmp_path / "missing.exe", executable),
        process_paths_provider=lambda: (),
    )

    assert adapter.detect() is True
    assert adapter.locate_executable() == executable
    assert adapter.is_application_running() is False


def test_invalid_snapshot_is_rejected(tmp_path: Path) -> None:
    executable = fake_executable(tmp_path)
    adapter = ClashForWindowsAdapter(
        exe_path=str(executable),
        system_proxy=WindowsSystemProxy(FakeRegistry()),
        dry_run=False,
    )
    with pytest.raises(ProxyOperationError, match="快照无效"):
        adapter.restore_after_authentication(object())


def test_factory_and_unsupported_boundaries(tmp_path: Path) -> None:
    executable = fake_executable(tmp_path)
    proxy = WindowsSystemProxy(FakeRegistry(manual_proxy_values()))
    adapter = create_proxy_adapter(
        "clash_for_windows",
        exe_path=str(executable),
        system_proxy=proxy,
    )
    assert isinstance(adapter, ClashForWindowsAdapter)
    assert adapter.dry_run is True
    assert create_proxy_adapter("none").is_running() is False

    unsupported = FlClashAdapter()
    with pytest.raises(ProxyOperationError, match="尚未支持"):
        unsupported.prepare_for_authentication()
    with pytest.raises(ValueError, match="未知代理类型"):
        create_proxy_adapter("not-a-proxy")
