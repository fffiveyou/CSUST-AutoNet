"""Application services for settings, credentials, and direct network checks."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from app.state_machine import AppState, AuthenticationStateMachine, StateMachineResult
from config.manager import ConfigManager, normalize_config
from logutil.logger import setup_logging, today_log_path
from network.csust_auth import Authenticator, CsustAuthenticator, MockAuthenticator, PortalEnvironment
from network.detector import NetworkDetector
from network.models import DetectionResult, NetworkStatus
from proxy.base import create_proxy_adapter, proxy_catalog
from system.autostart import AutostartError, AutostartManager
from system.credentials import CredentialStore, CredentialStoreError
from system.wifi import WifiConnectState, WindowsWifiConnector


@dataclass(frozen=True)
class SaveResult:
    config: dict[str, Any]
    warnings: tuple[str, ...]


DETECTION_MAX_AGE_SECONDS = 120.0


class AppController:
    """Coordinate settings, credentials, logging, and Windows integration."""

    def __init__(
        self,
        *,
        config_manager: ConfigManager | None = None,
        credential_store: CredentialStore | None = None,
        autostart_manager: AutostartManager | None = None,
        logs_path: Path | None = None,
        logger: logging.Logger | None = None,
        network_detector: NetworkDetector | None = None,
        wifi_connector: WindowsWifiConnector | None = None,
        state_machine: AuthenticationStateMachine | None = None,
        real_authenticator_factory: Callable[..., Authenticator] = CsustAuthenticator,
        real_proxy_adapter_factory: Callable[..., Any] = create_proxy_adapter,
        clock: Callable[[], float] = time.monotonic,
        authentication_sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.config_manager = config_manager or ConfigManager()
        self.credential_store = credential_store or CredentialStore()
        self.autostart_manager = autostart_manager or AutostartManager()
        self.logger = logger or setup_logging(logs_path)
        self.logs_path = logs_path or Path(self.logger.handlers[0].directory)  # type: ignore[attr-defined]
        self.config = self.config_manager.load()
        self.network_detector = network_detector or NetworkDetector()
        self.wifi_connector = wifi_connector or WindowsWifiConnector()
        self.real_authenticator_factory = real_authenticator_factory
        self.real_proxy_adapter_factory = real_proxy_adapter_factory
        self.clock = clock
        self.authentication_sleeper = authentication_sleeper
        self._last_detection: DetectionResult | None = None
        self._last_detection_at: float | None = None
        self.state_machine = state_machine or AuthenticationStateMachine(
            authenticator=MockAuthenticator(),
            proxy_adapter=create_proxy_adapter(
                str(self.config["proxy_type"]),
                exe_path=str(self.config["proxy_exe_path"]),
                dry_run=True,
            ),
            sleeper=lambda _seconds: None,
        )
        self.logger.info("Application started")
        self.logger.info("Monitor interval: %s s", self.config["monitor_interval"])

    def load_password(self) -> tuple[str, str | None]:
        username = str(self.config.get("username", ""))
        try:
            return self.credential_store.get(username) or "", None
        except CredentialStoreError as exc:
            self.logger.warning("Credential store unavailable")
            return "", str(exc)

    def save_settings(self, raw: Mapping[str, object], password: str) -> SaveResult:
        previous_username = str(self.config.get("username", ""))
        normalized = normalize_config(raw)
        warnings: list[str] = []

        try:
            self.autostart_manager.set_enabled(bool(normalized["windows_autostart"]))
        except AutostartError as exc:
            warnings.append(str(exc))
            normalized["windows_autostart"] = self.autostart_manager.is_enabled()

        # Persist all non-secret settings even if Credential Manager is unavailable.
        self.config = self.config_manager.save(normalized)

        username = str(self.config["username"])
        try:
            if password:
                self.credential_store.set(username, password)
            else:
                self.credential_store.delete(username)
            if previous_username and previous_username != username:
                self.credential_store.delete(previous_username)
        except CredentialStoreError as exc:
            warnings.append(str(exc))

        self.logger.info("Settings saved")
        self.logger.info("Monitor interval: %s s", self.config["monitor_interval"])
        return SaveResult(dict(self.config), tuple(warnings))

    def current_log_path(self) -> Path:
        path = today_log_path(self.logs_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)
        return path

    def check_network(self) -> DetectionResult:
        # A failed/in-progress check must not leave old portal evidence usable.
        self.invalidate_detection()
        wifi_result = self.wifi_connector.ensure_connected(
            str(self.config.get("wifi_profile", "CSUST-Student")),
            enabled=bool(self.config.get("wifi_auto_connect", True)),
        )
        self.logger.info("Wi-Fi connection state: %s", wifi_result.state.value)

        # Do not mistake Internet access through another Wi-Fi for a working
        # campus connection, and do not count public-probe failures while
        # Windows is still associating with the requested campus profile.
        if wifi_result.state is WifiConnectState.OTHER_NETWORK:
            result = DetectionResult(
                NetworkStatus.NETWORK_UNAVAILABLE,
                getattr(self.network_detector, "consecutive_public_failures", 0),
                wifi_result.message,
            )
            self.logger.info(
                "Direct network status: %s; campus probe skipped",
                result.status.value,
            )
            return result
        if wifi_result.state is WifiConnectState.CONNECT_REQUESTED:
            result = DetectionResult(
                NetworkStatus.SUSPECTED_OFFLINE,
                getattr(self.network_detector, "consecutive_public_failures", 0),
                f"{wifi_result.message} 请等待连接完成，不要重复点击。",
            )
            self.logger.info(
                "Direct network status: %s; campus probe deferred",
                result.status.value,
            )
            return result
        if wifi_result.state is WifiConnectState.FAILED:
            result = DetectionResult(
                NetworkStatus.NETWORK_UNAVAILABLE,
                getattr(self.network_detector, "consecutive_public_failures", 0),
                wifi_result.message,
            )
            self.logger.info(
                "Direct network status: %s; campus probe skipped",
                result.status.value,
            )
            return result

        result = self.network_detector.check()
        self.logger.info(
            "Direct network status: %s; consecutive failures: %s",
            result.status.value,
            result.consecutive_public_failures,
        )
        if wifi_result.state not in {
            WifiConnectState.DISABLED,
            WifiConnectState.ALREADY_CONNECTED,
        }:
            result = DetectionResult(
                result.status,
                result.consecutive_public_failures,
                f"{wifi_result.message} {result.message}",
                result.portal_url,
            )
        return result

    def invalidate_detection(self) -> None:
        self._last_detection = None
        self._last_detection_at = None

    def process_detection(self, detection: DetectionResult) -> StateMachineResult:
        """Remember the latest evidence and update state without auto-login."""

        self._last_detection = detection
        self._last_detection_at = self.clock()
        result = self.state_machine.observe_detection(detection, run_authentication=False)
        self.logger.info(
            "Application state: %s; auth failures: %s",
            result.state.value,
            result.failure_count,
        )
        return result

    def retry_mock_authentication(self) -> StateMachineResult:
        """Run only the bounded Phase 4 mock cycle after an AUTH_STOPPED state."""

        result = self.state_machine.retry_authentication()
        self.logger.info(
            "Mock authentication retry state: %s; auth failures: %s",
            result.state.value,
            result.failure_count,
        )
        return result

    def request_network_check(self) -> str:
        """Compatibility wrapper; the UI uses check_network in a worker thread."""

        return self.check_network().message

    def _manual_result(self, message: str, state: AppState | None = None) -> StateMachineResult:
        return StateMachineResult(
            state or self.state_machine.state,
            self.state_machine.failure_count,
            False,
            message,
            (),
        )

    def request_authentication(self) -> StateMachineResult:
        """Run one user-triggered real authentication cycle after strict preflight."""

        detection = self._last_detection
        detected_at = self._last_detection_at
        if detection is None or detected_at is None:
            return self._manual_result("请先点击“立即检测”；未读取或提交凭据。")
        if self.clock() - detected_at > DETECTION_MAX_AGE_SECONDS:
            return self._manual_result("登录页检测结果已过期，请重新点击“立即检测”。")
        if detection.status is NetworkStatus.CONNECTED:
            return self._manual_result("直连公网已经可用，无需重复认证。", AppState.CONNECTED)
        if detection.status is not NetworkStatus.AUTH_REQUIRED:
            return self._manual_result("当前未确认校园网登录页，不会提交凭据。")

        environment = PortalEnvironment.from_url(detection.portal_url or "")
        if environment is None:
            return self._manual_result(
                "已确认登录页，但缺少当前网络环境参数；未读取或提交凭据。"
            )

        if bool(self.config.get("proxy_management")) and not bool(
            self.config.get("restore_proxy")
        ):
            return self._manual_result(
                "真实认证要求启用“认证完成后恢复系统代理原设置”；未读取或提交凭据。"
            )
        proxy_type = (
            str(self.config.get("proxy_type", "none"))
            if bool(self.config.get("proxy_management"))
            else "none"
        )
        supported = {key: enabled for key, _label, enabled in proxy_catalog()}
        if not supported.get(proxy_type, False):
            return self._manual_result(
                "所选代理适配器尚未支持真实认证；未读取或提交凭据。"
            )

        username = str(self.config.get("username", "")).strip()
        if not username:
            return self._manual_result("尚未保存校园网账号；未提交认证。")
        try:
            password = self.credential_store.get(username) or ""
        except CredentialStoreError:
            self.logger.warning("Credential store unavailable during authentication preflight")
            return self._manual_result("无法读取 Windows 凭据；未提交认证。")
        if not password:
            return self._manual_result("尚未在 Windows 凭据管理器中保存密码；未提交认证。")

        authenticator = None
        try:
            proxy_adapter = self.real_proxy_adapter_factory(
                proxy_type,
                exe_path=str(self.config.get("proxy_exe_path", "")),
                dry_run=False,
            )
            authenticator = self.real_authenticator_factory(
                credential_provider=lambda: (username, password),
                environment_provider=lambda: environment,
            )
            machine = AuthenticationStateMachine(
                authenticator=authenticator,
                proxy_adapter=proxy_adapter,
                sleeper=self.authentication_sleeper,
            )
            result = machine.observe_detection(
                detection,
                run_authentication=True,
                attempt_limit=1,
            )
            # Keep the active state machine in sync so a failed automatic
            # attempt remains fused until a later CONNECTED observation or an
            # explicit user retry.
            self.state_machine = machine
            outcome = str(getattr(authenticator, "last_outcome", "UNAVAILABLE"))
            if not outcome.replace("_", "").isalnum():
                outcome = "INVALID_DIAGNOSTIC_CODE"
            self.logger.info("Manual authentication outcome: %s", outcome)
            http_status = getattr(authenticator, "last_http_status", None)
            if type(http_status) is int and 100 <= http_status <= 599:
                self.logger.info("Manual authentication HTTP status: %s", http_status)

            if result.state is AppState.AUTH_STOPPED:
                diagnostic_messages = {
                    "TRANSPORT_ERROR": "认证请求未能到达校园网服务器；未自动重复提交。",
                    "HTTP_STATUS_REJECTED": "校园网服务器返回异常状态；未自动重复提交。",
                    "INVALID_JSONP_RESPONSE": "校园网服务器返回格式异常；未自动重复提交。",
                    "PORTAL_REJECTED": "校园网服务器拒绝本次登录；请检查账号密码后重试。",
                    "VERIFY_NOT_CONNECTED": "校园网服务器已接受登录，但直连联网验证未通过。",
                    "VERIFY_ERROR": "校园网服务器已接受登录，但联网验证发生异常。",
                }
                if (
                    outcome == "HTTP_STATUS_REJECTED"
                    and type(http_status) is int
                    and 100 <= http_status <= 599
                ):
                    diagnostic_messages[outcome] = (
                        f"校园网服务器返回 HTTP {http_status}；未自动重复提交。"
                    )
                if outcome in diagnostic_messages:
                    result = StateMachineResult(
                        result.state,
                        result.failure_count,
                        result.automatic_authentication_paused,
                        diagnostic_messages[outcome],
                        result.transitions,
                    )
        except Exception as exc:
            self.logger.error("Manual authentication setup failed: %s", type(exc).__name__)
            result = self._manual_result("认证准备失败；未确认有凭据提交。")
        finally:
            password = ""
            close = getattr(authenticator, "close", None)
            if close is not None:
                try:
                    close()
                except Exception:
                    self.logger.warning("Authentication session cleanup failed")

        self.logger.info(
            "Manual authentication state: %s; auth failures: %s",
            result.state.value,
            result.failure_count,
        )
        if result.state is AppState.CONNECTED:
            self._last_detection = None
            self._last_detection_at = None
        return result
