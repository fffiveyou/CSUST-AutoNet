from __future__ import annotations

import subprocess
import logging

from app.controller import AppController
from config.manager import default_config, normalize_config
from network.models import DetectionResult, NetworkStatus
from system.wifi import WifiConnectResult, WifiConnectState, WindowsWifiConnector


class SequenceRunner:
    def __init__(self, results) -> None:
        self.results = list(results)
        self.calls: list[list[str]] = []

    def __call__(self, arguments, **_kwargs):
        self.calls.append(list(arguments))
        return self.results.pop(0)


class FixedWifiConnector:
    def __init__(self, state: WifiConnectState, message: str) -> None:
        self.result = WifiConnectResult(state, message)

    def ensure_connected(self, _profile: str, *, enabled: bool = True):
        return self.result


class CountingDetector:
    def __init__(self) -> None:
        self.calls = 0
        self.consecutive_public_failures = 3

    def check(self) -> DetectionResult:
        self.calls += 1
        return DetectionResult(NetworkStatus.CONNECTED, 0, "直连公网正常。")


def build_controller(
    wifi_state: WifiConnectState,
    wifi_message: str,
    detector: CountingDetector,
) -> AppController:
    controller = AppController.__new__(AppController)
    controller.config = default_config()
    controller.logger = logging.getLogger(f"phase7-{wifi_state.value}-{id(detector)}")
    controller.wifi_connector = FixedWifiConnector(wifi_state, wifi_message)
    controller.network_detector = detector
    return controller


def completed(returncode: int, stdout: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="")


def interface_output(ssid: str | None) -> str:
    if ssid is None:
        return "State : disconnected\n"
    return f"State : connected\nSSID : {ssid}\nBSSID : redacted\n"


def test_already_connected_does_not_issue_reconnect() -> None:
    runner = SequenceRunner([completed(0, interface_output("CSUST-Student"))])
    connector = WindowsWifiConnector(runner=runner, sleeper=lambda _seconds: None)

    result = connector.ensure_connected("CSUST-Student")

    assert result.state is WifiConnectState.ALREADY_CONNECTED
    assert runner.calls == [["netsh", "wlan", "show", "interfaces"]]


def test_disconnected_saved_profile_is_connected_and_verified() -> None:
    runner = SequenceRunner(
        [
            completed(0, interface_output(None)),
            completed(0, "Connection request was completed successfully."),
            completed(0, interface_output("CSUST-Student")),
        ]
    )
    connector = WindowsWifiConnector(runner=runner, sleeper=lambda _seconds: None)

    result = connector.ensure_connected("CSUST-Student")

    assert result.state is WifiConnectState.CONNECTED
    assert runner.calls[1] == [
        "netsh",
        "wlan",
        "connect",
        "name=CSUST-Student",
        "ssid=CSUST-Student",
    ]


def test_successful_request_with_unavailable_query_is_reported_without_guessing() -> None:
    runner = SequenceRunner(
        [
            completed(1),
            completed(0),
            completed(1),
            completed(1),
            completed(1),
        ]
    )
    connector = WindowsWifiConnector(runner=runner, sleeper=lambda _seconds: None)

    result = connector.ensure_connected("CSUST-Student")

    assert result.state is WifiConnectState.CONNECT_REQUESTED


def test_failed_connect_and_invalid_profile_are_sanitized() -> None:
    runner = SequenceRunner([completed(0, interface_output(None)), completed(1, "raw error")])
    connector = WindowsWifiConnector(runner=runner, sleeper=lambda _seconds: None)

    failed = connector.ensure_connected("CSUST-Student")
    invalid = connector.ensure_connected("bad\nprofile")

    assert failed.state is WifiConnectState.FAILED
    assert "raw error" not in failed.message
    assert invalid.state is WifiConnectState.FAILED
    assert len(runner.calls) == 2


def test_other_connected_wifi_is_not_replaced() -> None:
    runner = SequenceRunner([completed(0, interface_output("Home-WiFi"))])
    connector = WindowsWifiConnector(runner=runner, sleeper=lambda _seconds: None)

    result = connector.ensure_connected("CSUST-Student")

    assert result.state is WifiConnectState.OTHER_NETWORK
    assert len(runner.calls) == 1


def test_wifi_auto_connect_defaults_and_normalization() -> None:
    defaults = default_config()
    assert defaults["auto_auth"] is False
    assert defaults["wifi_auto_connect"] is True
    assert defaults["wifi_profile"] == "CSUST-Student"

    normalized = normalize_config(
        defaults | {"wifi_auto_connect": False, "wifi_profile": " Campus-WiFi "}
    )
    assert normalized["wifi_auto_connect"] is False
    assert normalized["wifi_profile"] == "Campus-WiFi"


def test_controller_defers_probe_while_wifi_connect_is_pending() -> None:
    detector = CountingDetector()
    controller = build_controller(
        WifiConnectState.CONNECT_REQUESTED,
        "已请求 Windows 连接校园 Wi-Fi，等待网络就绪。",
        detector,
    )

    result = controller.check_network()

    assert result.status is NetworkStatus.SUSPECTED_OFFLINE
    assert "不要重复点击" in result.message
    assert result.consecutive_public_failures == 3
    assert detector.calls == 0


def test_controller_rejects_public_access_from_other_wifi() -> None:
    detector = CountingDetector()
    controller = build_controller(
        WifiConnectState.OTHER_NETWORK,
        "当前连接的是其他 Wi-Fi；不会自动切换。",
        detector,
    )

    result = controller.check_network()

    assert result.status is NetworkStatus.NETWORK_UNAVAILABLE
    assert "其他 Wi-Fi" in result.message
    assert detector.calls == 0


def test_controller_probes_after_campus_wifi_is_ready() -> None:
    detector = CountingDetector()
    controller = build_controller(
        WifiConnectState.ALREADY_CONNECTED,
        "校园 Wi-Fi 已连接。",
        detector,
    )

    result = controller.check_network()

    assert result.status is NetworkStatus.CONNECTED
    assert detector.calls == 1
