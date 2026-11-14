from __future__ import annotations

import json
import logging
import os
from datetime import date, timedelta
from pathlib import Path

import pytest

from app.constants import APP_ID, KEYRING_SERVICE, MIN_CHECK_INTERVAL
from app.controller import AppController
from config.manager import ConfigManager, default_config, normalize_interval
from logutil.logger import SensitiveDataFilter, delete_logs_older_than, setup_logging
from proxy.base import NoProxyAdapter, ProxyAdapter, proxy_catalog
from system.autostart import AutostartError, AutostartManager, build_autostart_command
from system.credentials import CredentialStore


class FakeKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service_name: str, username: str) -> str | None:
        return self.values.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str) -> None:
        self.values[(service_name, username)] = password

    def delete_password(self, service_name: str, username: str) -> None:
        self.values.pop((service_name, username), None)


class FakeRegistry:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def read(self, name: str) -> str | None:
        return self.values.get(name)

    def write(self, name: str, value: str) -> None:
        self.values[name] = value

    def delete(self, name: str) -> None:
        self.values.pop(name, None)


class DroppingRegistry(FakeRegistry):
    def write(self, name: str, value: str) -> None:
        return


def test_interval_below_minimum_is_normalized() -> None:
    assert normalize_interval(10) == MIN_CHECK_INTERVAL
    assert normalize_interval("45") == 45


def test_config_roundtrip_excludes_password_and_unknown_keys(tmp_path: Path) -> None:
    manager = ConfigManager(tmp_path / "config.json")
    raw = default_config() | {"username": "20260001", "password": "secret", "unknown": 1}
    saved = manager.save(raw)
    text = manager.path.read_text(encoding="utf-8")
    assert saved["username"] == "20260001"
    assert "password" not in text
    assert "secret" not in text
    assert "unknown" not in text
    assert manager.load() == saved


def test_corrupt_config_falls_back_to_defaults(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text("{broken", encoding="utf-8")
    assert ConfigManager(path).load() == default_config()


def test_five_day_log_retention_boundary(tmp_path: Path) -> None:
    today = date(2026, 9, 22)
    retained = [today - timedelta(days=offset) for offset in range(5)]
    removed = [today - timedelta(days=5), today - timedelta(days=12)]
    for item in retained + removed:
        (tmp_path / f"{item.isoformat()}.log").write_text("x", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("keep", encoding="utf-8")

    deleted = delete_logs_older_than(tmp_path, 5, today=today)

    assert {path.name for path in deleted} == {f"{item.isoformat()}.log" for item in removed}
    assert all((tmp_path / f"{item.isoformat()}.log").exists() for item in retained)
    assert (tmp_path / "notes.txt").exists()


def test_sensitive_fields_are_redacted() -> None:
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "password=hunter2 token=abc", (), None)
    assert SensitiveDataFilter().filter(record)
    rendered = record.getMessage()
    assert "hunter2" not in rendered
    assert "abc" not in rendered
    assert rendered.count("[REDACTED]") == 2


def test_password_is_kept_in_keyring_not_config(tmp_path: Path) -> None:
    keyring = FakeKeyring()
    credentials = CredentialStore(keyring)
    config_manager = ConfigManager(tmp_path / "config.json")
    registry = FakeRegistry()
    logger = setup_logging(tmp_path / "logs", logger_name="test-password")
    controller = AppController(
        config_manager=config_manager,
        credential_store=credentials,
        autostart_manager=AutostartManager(registry),
        logs_path=tmp_path / "logs",
        logger=logger,
    )
    raw = default_config() | {"username": "student"}
    controller.save_settings(raw, "top-secret")

    assert keyring.values[(KEYRING_SERVICE, "student")] == "top-secret"
    assert "top-secret" not in config_manager.path.read_text(encoding="utf-8")
    assert all("top-secret" not in item.read_text(encoding="utf-8") for item in (tmp_path / "logs").glob("*.log"))


def test_proxy_adapter_contract_and_noop() -> None:
    assert ProxyAdapter.__abstractmethods__ == {"detect", "is_running", "stop", "start", "locate_executable"}
    adapter = NoProxyAdapter()
    assert adapter.detect() is True
    assert adapter.is_running() is False
    assert adapter.stop() is True
    assert adapter.start() is True
    assert adapter.locate_executable() is None


def test_proxy_catalog_marks_phase2_support_truthfully() -> None:
    items = proxy_catalog()
    assert len(items) == 7
    assert items[0] == ("none", "不处理代理软件", True)
    assert items[1] == ("clash_for_windows", "Clash for Windows", True)
    assert all(supported for _, _, supported in items[2:])
    assert all("待支持" not in label for _, label, _ in items[2:])


def test_autostart_command_for_packaged_exe() -> None:
    command = build_autostart_command(executable=r"C:\Program Files\CSUSTAutoNet.exe", frozen=True)
    assert command == '"C:\\Program Files\\CSUSTAutoNet.exe" --background'


def test_source_autostart_prefers_windowless_pythonw(tmp_path: Path) -> None:
    python = tmp_path / "python.exe"
    pythonw = tmp_path / "pythonw.exe"
    main = tmp_path / "main.py"
    python.touch()
    pythonw.touch()

    command = build_autostart_command(
        executable=str(python),
        frozen=False,
        source_main=main,
    )

    assert str(pythonw) in command
    assert str(python) not in command
    assert str(main) in command
    assert command.endswith(' --background')


def test_autostart_registry_enable_disable() -> None:
    registry = FakeRegistry()
    manager = AutostartManager(registry)
    manager.set_enabled(True)
    assert manager.is_enabled()
    assert registry.values[APP_ID].endswith("--background")
    manager.set_enabled(False)
    assert not manager.is_enabled()


def test_autostart_write_must_be_read_back() -> None:
    manager = AutostartManager(DroppingRegistry())

    with pytest.raises(AutostartError, match="校验失败"):
        manager.set_enabled(True)


def test_background_argument_parser() -> None:
    from main import build_parser, packaged_self_test

    assert build_parser().parse_args(["--background"]).background is True
    assert build_parser().parse_args([]).background is False
    assert build_parser().parse_args(["--self-test"]).self_test is True
    assert packaged_self_test() == 0


def test_pyside_window_smoke_and_background_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("PySide6")
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication, QLineEdit
    from ui.main_window import MainWindow

    application = QApplication.instance() or QApplication([])
    keyring = FakeKeyring()
    registry = FakeRegistry()
    config_manager = ConfigManager(tmp_path / "config.json")
    controller = AppController(
        config_manager=config_manager,
        credential_store=CredentialStore(keyring),
        autostart_manager=AutostartManager(registry),
        logs_path=tmp_path / "logs",
        logger=setup_logging(tmp_path / "logs", logger_name="test-ui"),
    )
    window = MainWindow(controller)
    window.username_edit.setText("ui-save-test")
    window.password_edit.setText("ui-test-secret")
    assert window.password_edit.echoMode() == QLineEdit.EchoMode.Password
    window.password_visibility_button.click()
    assert window.password_edit.echoMode() == QLineEdit.EchoMode.Normal
    assert window.password_visibility_button.text() == "隐藏"
    window.password_visibility_button.click()
    assert window.password_edit.echoMode() == QLineEdit.EchoMode.Password
    window.save_button.click()
    assert config_manager.load()["username"] == "ui-save-test"
    assert keyring.values[(KEYRING_SERVICE, "ui-save-test")] == "ui-test-secret"
    window.interval_spin.setValue(10)
    assert window.interval_spin.value() == 30
    assert window.proxy_combo.count() == 7
    window.start(background=True)
    application.processEvents()
    assert not window.isVisible()
    window.show_normal()
    application.processEvents()
    assert window.isVisible()
    window.close()
    application.processEvents()
    assert not window.isVisible()
    window.show_normal()
    application.processEvents()
    assert window.isVisible()
    assert controller.current_log_path().exists()
    assert window.view_log_button.text() == "查看今日日志"
    assert window.open_log_dir_button.text() == "打开日志文件夹"
    window.minimize_check.setChecked(False)
    window.close()
    assert window._allow_real_close is True
    assert not window.tray.isVisible()
