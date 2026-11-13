from __future__ import annotations

from dataclasses import dataclass
import logging
from types import SimpleNamespace

import requests

from network.detector import PUBLIC_PROBE_BODY, PUBLIC_PROBES, NetworkDetector, create_direct_session
from network.models import DetectionResult, NetworkStatus


@dataclass
class FakeResponse:
    status_code: int
    text: str
    url: str
    headers: dict[str, str] | None = None


class FakeSession:
    def __init__(self, outcomes: list[object], calls: list[tuple[str, dict]]) -> None:
        self.outcomes = outcomes
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def get(self, url: str, **kwargs):
        self.calls.append((url, kwargs))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def detector_for(outcomes: list[object]) -> tuple[NetworkDetector, list[tuple[str, dict]]]:
    calls: list[tuple[str, dict]] = []
    detector = NetworkDetector(session_factory=lambda: FakeSession(outcomes, calls))  # type: ignore[arg-type]
    return detector, calls


def connection_error() -> requests.ConnectionError:
    return requests.ConnectionError("simulated direct-connect failure")


def connected_probe_outcomes() -> list[object]:
    return [
        FakeResponse(200, PUBLIC_PROBE_BODY, PUBLIC_PROBES[0].url),
        FakeResponse(204, "", PUBLIC_PROBES[1].url),
    ]


def offline_probe_outcomes() -> list[object]:
    return [connection_error(), connection_error()]


def test_direct_session_ignores_environment_and_system_proxy() -> None:
    session = create_direct_session()
    try:
        assert session.trust_env is False
        assert session.proxies == {}
    finally:
        session.close()


def test_matching_public_probe_is_connected_and_does_not_check_portal() -> None:
    outcomes = connected_probe_outcomes()
    detector, calls = detector_for(outcomes)

    result = detector.check()

    assert result.status is NetworkStatus.CONNECTED
    assert result.consecutive_public_failures == 0
    assert len(calls) == 2
    assert calls[0][1]["allow_redirects"] is False


def test_first_public_failure_is_only_suspected_offline() -> None:
    detector, calls = detector_for(offline_probe_outcomes())

    result = detector.check()

    assert result.status is NetworkStatus.SUSPECTED_OFFLINE
    assert result.consecutive_public_failures == 1
    assert len(calls) == 2


def test_second_failure_with_confirmed_login_page_requires_authentication() -> None:
    outcomes: list[object] = [
        *offline_probe_outcomes(),
        *offline_probe_outcomes(),
        FakeResponse(200, '<form><input type="password"><button>登录</button></form>', "https://login.csust.edu.cn/"),
    ]
    detector, calls = detector_for(outcomes)

    assert detector.check().status is NetworkStatus.SUSPECTED_OFFLINE
    result = detector.check()

    assert result.status is NetworkStatus.AUTH_REQUIRED
    assert result.portal_url == "https://login.csust.edu.cn/"
    assert len(calls) == 5
    assert calls[-1][1]["allow_redirects"] is True


def test_second_failure_without_reachable_portal_is_network_unavailable() -> None:
    detector, _ = detector_for(
        [
            *offline_probe_outcomes(),
            *offline_probe_outcomes(),
            connection_error(),
            connection_error(),
        ]
    )

    detector.check()
    result = detector.check()

    assert result.status is NetworkStatus.NETWORK_UNAVAILABLE
    assert result.portal_url is None


def test_reachable_non_login_page_does_not_trigger_authentication() -> None:
    outcomes: list[object] = [
        *offline_probe_outcomes(),
        *offline_probe_outcomes(),
        FakeResponse(200, "campus status page", "https://login.csust.edu.cn/status"),
        connection_error(),
    ]
    detector, _ = detector_for(outcomes)

    detector.check()
    result = detector.check()

    assert result.status is NetworkStatus.NETWORK_UNAVAILABLE
    assert result.portal_url == "https://login.csust.edu.cn/status"


def test_success_resets_consecutive_failure_counter() -> None:
    outcomes: list[object] = [
        *offline_probe_outcomes(),
        *connected_probe_outcomes(),
        *offline_probe_outcomes(),
    ]
    detector, _ = detector_for(outcomes)

    assert detector.check().consecutive_public_failures == 1
    assert detector.check().status is NetworkStatus.CONNECTED
    result = detector.check()

    assert result.status is NetworkStatus.SUSPECTED_OFFLINE
    assert result.consecutive_public_failures == 1


def test_public_redirect_is_not_counted_as_connected() -> None:
    detector, _ = detector_for(
        [
            FakeResponse(302, "", PUBLIC_PROBES[0].url),
            connection_error(),
        ]
    )

    assert detector.check().status is NetworkStatus.SUSPECTED_OFFLINE


def test_whitelisted_ncsi_alone_is_not_enough_for_connected() -> None:
    detector, calls = detector_for(
        [
            FakeResponse(200, PUBLIC_PROBE_BODY, PUBLIC_PROBES[0].url),
            connection_error(),
            connection_error(),
        ]
    )

    result = detector.check()

    assert result.status is NetworkStatus.SUSPECTED_OFFLINE
    assert len(calls) == 3


def test_captive_redirect_url_is_preserved_for_portal_and_environment() -> None:
    captive_url = (
        "https://login.csust.edu.cn/?wlanuserip=10.0.0.8"
        "&wlanusermac=masked&wlanacip=10.0.0.1&wlanacname=masked-ac"
    )
    redirect = lambda: FakeResponse(
        302,
        "",
        PUBLIC_PROBES[0].url,
        {"Location": captive_url},
    )
    outcomes: list[object] = [
        redirect(),
        connection_error(),
        redirect(),
        connection_error(),
        FakeResponse(200, '<script src="/a41.js"></script>', captive_url),
    ]
    detector, calls = detector_for(outcomes)

    assert detector.check().status is NetworkStatus.SUSPECTED_OFFLINE
    result = detector.check()

    assert result.status is NetworkStatus.AUTH_REQUIRED
    assert result.portal_url == captive_url
    assert "10.0.0.8" not in repr(result)
    assert "masked" not in repr(result)
    assert calls[-1][0] == captive_url


def test_ui_receives_background_detection_result(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication

    from config.manager import default_config
    from ui.main_window import MainWindow

    class StubController:
        config = default_config()
        logger = logging.getLogger("phase3-ui-test")
        logs_path = tmp_path
        state_machine = SimpleNamespace(automatic_authentication_paused=False)

        @staticmethod
        def load_password():
            return "", None

        @staticmethod
        def check_network():
            return DetectionResult(NetworkStatus.CONNECTED, 0, "直连公网正常。")

        @staticmethod
        def process_detection(_detection):
            from app.state_machine import AppState

            return SimpleNamespace(
                state=AppState.CONNECTED,
                automatic_authentication_paused=False,
            )

    application = QApplication.instance() or QApplication([])
    window = MainWindow(StubController())  # type: ignore[arg-type]
    window.detect_button.click()
    for _ in range(100):
        application.processEvents()
        if not window._network_check_running:
            break
        QTest.qWait(10)

    assert window.status_label.text() == "● 已连接（检测已绕过代理）"
    assert window.detect_button.isEnabled()

    from app.state_machine import AppState, StateMachineResult

    automatic_calls: list[bool] = []
    window.auto_auth_check.setChecked(True)
    window.controller.process_detection = lambda _detection: SimpleNamespace(
        state=AppState.AUTH_REQUIRED,
        automatic_authentication_paused=False,
    )
    window._start_authentication = lambda *, automatic: automatic_calls.append(automatic)
    window._active_check_manual = False
    window._network_check_completed(
        DetectionResult(NetworkStatus.AUTH_REQUIRED, 2, "portal confirmed")
    )
    assert automatic_calls == [True]

    window._active_check_manual = True
    window._network_check_completed(
        DetectionResult(NetworkStatus.AUTH_REQUIRED, 2, "portal confirmed")
    )
    assert automatic_calls == [True]

    stopped = StateMachineResult(AppState.AUTH_STOPPED, 3, True, "mock stopped", ())
    window.controller.state_machine.automatic_authentication_paused = True
    window._apply_state_machine_result(stopped)
    window._configure_monitor_timer()
    assert window.retry_button.isEnabled()
    assert "网络监测继续运行" in window.monitor_label.text()

    not_authenticated = StateMachineResult(AppState.CONNECTED, 0, False, "already online", ())
    window.status_label.setText("● 已连接")
    window._apply_state_machine_result(not_authenticated, from_authentication=True)
    assert window.status_label.text() == "● 已连接"

    authenticated = StateMachineResult(
        AppState.CONNECTED,
        0,
        False,
        "verified",
        (AppState.AUTHENTICATING, AppState.VERIFYING, AppState.CONNECTED),
    )
    window._apply_state_machine_result(authenticated, from_authentication=True)
    assert "认证后直连验证通过" in window.status_label.text()

    window.minimize_check.setChecked(False)
    window.close()
