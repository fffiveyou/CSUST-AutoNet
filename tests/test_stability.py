"""Offline lifecycle regression: no real WLAN, credentials or proxy writes."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize("scenario", ["detect", "detect-error", "auth", "auth-error", "idle"])
def test_process_exits_after_worker_cleanup(scenario):
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), scenario],
        env=env, capture_output=True, text=True, timeout=15,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "CLEAN_EXIT" in completed.stdout


def test_monitor_history_is_bounded():
    from app.state_machine import AuthenticationStateMachine
    from network.csust_auth import MockAuthenticator
    from network.models import DetectionResult, NetworkStatus
    from proxy.base import NoProxyAdapter

    machine = AuthenticationStateMachine(authenticator=MockAuthenticator(), proxy_adapter=NoProxyAdapter())
    for _ in range(10000):
        result = machine.observe_detection(DetectionResult(NetworkStatus.CONNECTED, 0, "online"))
        assert len(result.transitions) == 1
    assert len(machine._history) == 1


def test_failed_wifi_check_invalidates_previous_portal():
    from app.controller import AppController
    from types import SimpleNamespace

    controller = AppController.__new__(AppController)
    controller._last_detection = object()
    controller._last_detection_at = 100
    controller.config = {}

    def fail(*args, **kwargs):
        raise RuntimeError("offline test")

    controller.wifi_connector = SimpleNamespace(ensure_connected=fail)
    with pytest.raises(RuntimeError):
        controller.check_network()
    assert controller._last_detection is None
    assert controller._last_detection_at is None


def test_authentication_releases_owned_session_and_credentials(monkeypatch):
    from types import SimpleNamespace
    from network import csust_auth

    closed = []
    session = SimpleNamespace(trust_env=True, proxies={}, close=lambda: closed.append(True))
    monkeypatch.setattr(csust_auth, "create_direct_session", lambda: session)
    auth = csust_auth.CsustAuthenticator(
        credential_provider=lambda: ("test-user", "test-password"),
        environment_provider=lambda: None,
    )
    auth.close()
    assert closed == [True]
    assert auth._credential_provider() == ("", "")


def run_lifecycle(scenario):
    import logging
    from threading import Event
    from types import SimpleNamespace
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication
    from app.state_machine import AppState, StateMachineResult
    from config.manager import default_config
    from network.models import DetectionResult, NetworkStatus
    from ui.main_window import MainWindow

    application = QApplication([])
    application.setQuitOnLastWindowClosed(False)
    started, release, restored = Event(), Event(), Event()
    calls = []

    def work():
        calls.append(scenario)
        started.set()
        try:
            assert release.wait(5), "UI blocked instead of releasing worker"
            if scenario.endswith("error"):
                raise RuntimeError("simulated worker failure")
            if scenario.startswith("auth"):
                return StateMachineResult(AppState.CONNECTED, 0, False, "done", ())
            return DetectionResult(NetworkStatus.AUTH_REQUIRED, 2, "portal")
        finally:
            restored.set()

    controller = SimpleNamespace(
        config=default_config(), logger=logging.getLogger("offline-lifecycle"),
        state_machine=SimpleNamespace(automatic_authentication_paused=False),
        load_password=lambda: ("", None), check_network=work,
        request_authentication=work,
    )
    # Even read-only host proxy access is unnecessary in this regression.
    MainWindow._refresh_system_proxy_status = lambda self: None
    window = MainWindow(controller)
    window.auto_auth_check.setChecked(True)
    if scenario.startswith("auth"):
        window._start_authentication(automatic=False)
    elif scenario != "idle":
        window._schedule_network_check(manual=False)

    heartbeat = []
    def request_exit():
        if scenario != "idle" and not started.is_set():
            QTimer.singleShot(10, request_exit)
            return
        window.quit_application()
        if scenario != "idle":
            assert window._closing
            assert not restored.is_set()
            # No new work may be scheduled during shutdown.
            window._scheduled_detect()
            window._manual_auth()
            QTimer.singleShot(30, lambda: heartbeat.append(True))
            QTimer.singleShot(100, release.set)

    QTimer.singleShot(0, request_exit)
    assert application.exec() == 0
    assert window._thread_pool.activeThreadCount() == 0
    assert not window._monitor_timer.isActive()
    if scenario != "idle":
        assert restored.is_set() and heartbeat and len(calls) == 1
    assert not window.tray.isVisible()
    print("CLEAN_EXIT")


if __name__ == "__main__":
    run_lifecycle(sys.argv[1])
