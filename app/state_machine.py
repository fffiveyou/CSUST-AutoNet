"""Authentication state machine with a strict three-attempt fuse."""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from app.constants import MAX_AUTH_ATTEMPTS
from network.csust_auth import Authenticator
from network.models import DetectionResult, NetworkStatus
from proxy.base import ProxyAdapter


RETRY_DELAYS_SECONDS = (10, 30)


class AppState(str, Enum):
    STARTING = "STARTING"
    CONNECTED = "CONNECTED"
    SUSPECTED_OFFLINE = "SUSPECTED_OFFLINE"
    CHECKING_PORTAL = "CHECKING_PORTAL"
    NETWORK_UNAVAILABLE = "NETWORK_UNAVAILABLE"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    PREPARING_PROXY = "PREPARING_PROXY"
    AUTHENTICATING = "AUTHENTICATING"
    VERIFYING = "VERIFYING"
    RESTORING_PROXY = "RESTORING_PROXY"
    AUTH_STOPPED = "AUTH_STOPPED"


@dataclass(frozen=True)
class StateMachineResult:
    state: AppState
    failure_count: int
    automatic_authentication_paused: bool
    message: str
    transitions: tuple[AppState, ...]


class AuthenticationStateMachine:
    """Coordinate detection, authentication, retries, and proxy restoration."""

    def __init__(
        self,
        *,
        authenticator: Authenticator,
        proxy_adapter: ProxyAdapter,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.authenticator = authenticator
        self.proxy_adapter = proxy_adapter
        self.sleeper = sleeper
        self.state = AppState.STARTING
        self.failure_count = 0
        self.automatic_authentication_paused = False
        self._last_detection_status: NetworkStatus | None = None
        self._history: list[AppState] = [self.state]

    def _transition(self, state: AppState) -> None:
        self.state = state
        self._history.append(state)

    def _result(self, message: str, start_index: int) -> StateMachineResult:
        return StateMachineResult(
            self.state,
            self.failure_count,
            self.automatic_authentication_paused,
            message,
            tuple(self._history[start_index:]),
        )

    def observe_detection(
        self,
        detection: DetectionResult,
        *,
        run_authentication: bool = False,
        attempt_limit: int = MAX_AUTH_ATTEMPTS,
    ) -> StateMachineResult:
        """Apply a detector result; credential submission is always explicit."""

        if not 1 <= attempt_limit <= MAX_AUTH_ATTEMPTS:
            raise ValueError("attempt_limit is outside the supported range")

        start_index = len(self._history)
        self._last_detection_status = detection.status

        if detection.status is NetworkStatus.CONNECTED:
            self.failure_count = 0
            self.automatic_authentication_paused = False
            self._transition(AppState.CONNECTED)
            return self._result("网络已恢复；认证失败计数已清零。", start_index)

        if detection.status is NetworkStatus.SUSPECTED_OFFLINE:
            self._transition(AppState.SUSPECTED_OFFLINE)
            return self._result(detection.message, start_index)

        if detection.status is NetworkStatus.NETWORK_UNAVAILABLE:
            self._transition(AppState.CHECKING_PORTAL)
            self._transition(AppState.NETWORK_UNAVAILABLE)
            return self._result("网络不可用；禁止提交认证。", start_index)

        if self.automatic_authentication_paused:
            self._transition(AppState.AUTH_STOPPED)
            return self._result("自动认证已暂停；未产生新的认证请求。", start_index)

        self._transition(AppState.CHECKING_PORTAL)
        self._transition(AppState.AUTH_REQUIRED)
        if not run_authentication:
            return self._result("需要认证；尚未自动发起登录。", start_index)
        return self._authenticate_cycle(start_index, attempt_limit=attempt_limit)

    def _authenticate_cycle(
        self,
        start_index: int,
        *,
        attempt_limit: int = MAX_AUTH_ATTEMPTS,
    ) -> StateMachineResult:
        self._transition(AppState.PREPARING_PROXY)
        succeeded = False
        operation_error: Exception | None = None
        try:
            with self.proxy_adapter.authentication_bypass():
                try:
                    while self.failure_count < attempt_limit:
                        self._transition(AppState.AUTHENTICATING)
                        login_ok = False
                        try:
                            login_ok = self.authenticator.login()
                        except Exception:
                            login_ok = False

                        verified = False
                        if login_ok:
                            self._transition(AppState.VERIFYING)
                            try:
                                verified = self.authenticator.verify_login()
                            except Exception:
                                verified = False

                        if verified:
                            succeeded = True
                            break

                        self.failure_count += 1
                        if self.failure_count < attempt_limit:
                            self.sleeper(RETRY_DELAYS_SECONDS[self.failure_count - 1])
                finally:
                    self._transition(AppState.RESTORING_PROXY)
        except Exception as exc:
            operation_error = exc

        if succeeded and operation_error is None:
            self.failure_count = 0
            self.automatic_authentication_paused = False
            self._transition(AppState.CONNECTED)
            if bool(getattr(self.authenticator, "is_mock", False)):
                message = "Mock 认证与验证成功；未发送真实登录请求。"
            else:
                message = "校园网认证与直连验证成功；Windows 系统代理已恢复。"
            return self._result(message, start_index)

        self.automatic_authentication_paused = True
        self._transition(AppState.AUTH_STOPPED)
        if operation_error is not None:
            return self._result("代理准备或恢复失败；自动认证已暂停。", start_index)
        if attempt_limit == 1:
            return self._result("本次手动认证失败；未自动重复提交。", start_index)
        return self._result("连续认证失败 3 次；自动认证已暂停。", start_index)

    def retry_authentication(self) -> StateMachineResult:
        """Reset the fuse and start one new bounded cycle on user request."""

        start_index = len(self._history)
        if not self.automatic_authentication_paused:
            return self._result("自动认证未处于暂停状态。", start_index)
        self.failure_count = 0
        self.automatic_authentication_paused = False
        self._transition(AppState.AUTH_REQUIRED)
        return self._authenticate_cycle(start_index)
