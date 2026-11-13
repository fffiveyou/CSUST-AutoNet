from __future__ import annotations

from contextlib import contextmanager

from app.state_machine import AppState, AuthenticationStateMachine
from network.csust_auth import MockAuthenticator
from network.models import DetectionResult, NetworkStatus
from proxy.none import NoneProxyAdapter


class TrackingProxy(NoneProxyAdapter):
    def __init__(self) -> None:
        self.prepared = 0
        self.restored = 0

    @contextmanager
    def authentication_bypass(self, timeout_seconds: float = 10.0):
        self.prepared += 1
        try:
            yield False
        finally:
            self.restored += 1


def auth_required() -> DetectionResult:
    return DetectionResult(NetworkStatus.AUTH_REQUIRED, 2, "portal confirmed")


def connected() -> DetectionResult:
    return DetectionResult(NetworkStatus.CONNECTED, 0, "connected")


def machine_for(login_outcomes, verify_outcomes=(True,)):
    delays: list[float] = []
    proxy = TrackingProxy()
    authenticator = MockAuthenticator(login_outcomes, verify_outcomes)
    machine = AuthenticationStateMachine(
        authenticator=authenticator,
        proxy_adapter=proxy,
        sleeper=delays.append,
    )
    return machine, authenticator, proxy, delays


def test_mock_authentication_success_follows_required_states() -> None:
    machine, authenticator, proxy, delays = machine_for([True])

    result = machine.observe_detection(auth_required(), run_authentication=True)

    assert result.state is AppState.CONNECTED
    assert result.failure_count == 0
    assert result.automatic_authentication_paused is False
    assert result.transitions == (
        AppState.CHECKING_PORTAL,
        AppState.AUTH_REQUIRED,
        AppState.PREPARING_PROXY,
        AppState.AUTHENTICATING,
        AppState.VERIFYING,
        AppState.RESTORING_PROXY,
        AppState.CONNECTED,
    )
    assert authenticator.login_calls == 1
    assert proxy.prepared == proxy.restored == 1
    assert delays == []


def test_first_failure_then_success_waits_ten_seconds() -> None:
    machine, authenticator, proxy, delays = machine_for([False, True])

    result = machine.observe_detection(auth_required(), run_authentication=True)

    assert result.state is AppState.CONNECTED
    assert authenticator.login_calls == 2
    assert delays == [10]
    assert proxy.prepared == proxy.restored == 1


def test_second_failure_then_success_uses_bounded_backoff() -> None:
    machine, authenticator, _, delays = machine_for([False, False, True])

    result = machine.observe_detection(auth_required(), run_authentication=True)

    assert result.state is AppState.CONNECTED
    assert authenticator.login_calls == 3
    assert delays == [10, 30]


def test_three_failures_enter_auth_stopped_without_fourth_attempt() -> None:
    machine, authenticator, proxy, delays = machine_for([False, False, False, True])

    stopped = machine.observe_detection(auth_required(), run_authentication=True)
    repeated = machine.observe_detection(auth_required(), run_authentication=True)

    assert stopped.state is AppState.AUTH_STOPPED
    assert stopped.failure_count == 3
    assert stopped.automatic_authentication_paused is True
    assert authenticator.login_calls == 3
    assert repeated.state is AppState.AUTH_STOPPED
    assert authenticator.login_calls == 3
    assert proxy.prepared == proxy.restored == 1
    assert delays == [10, 30]


def test_explicit_single_attempt_never_repeats_submission() -> None:
    machine, authenticator, proxy, delays = machine_for([False, True])

    result = machine.observe_detection(
        auth_required(),
        run_authentication=True,
        attempt_limit=1,
    )

    assert result.state is AppState.AUTH_STOPPED
    assert result.failure_count == 1
    assert result.automatic_authentication_paused is True
    assert "未自动重复提交" in result.message
    assert authenticator.login_calls == 1
    assert proxy.prepared == proxy.restored == 1
    assert delays == []


def test_user_retry_resets_count_and_starts_one_new_cycle() -> None:
    machine, authenticator, proxy, _ = machine_for([False, False, False, True])
    machine.observe_detection(auth_required(), run_authentication=True)

    result = machine.retry_authentication()

    assert result.state is AppState.CONNECTED
    assert result.failure_count == 0
    assert result.automatic_authentication_paused is False
    assert authenticator.login_calls == 4
    assert proxy.prepared == proxy.restored == 2


def test_network_self_recovery_clears_auth_stopped_fuse() -> None:
    machine, _, _, _ = machine_for([False, False, False])
    machine.observe_detection(auth_required(), run_authentication=True)

    result = machine.observe_detection(connected())

    assert result.state is AppState.CONNECTED
    assert result.failure_count == 0
    assert result.automatic_authentication_paused is False


def test_network_unavailable_never_calls_authenticator() -> None:
    machine, authenticator, proxy, _ = machine_for([True])
    detection = DetectionResult(NetworkStatus.NETWORK_UNAVAILABLE, 2, "offline")

    result = machine.observe_detection(detection, run_authentication=True)

    assert result.state is AppState.NETWORK_UNAVAILABLE
    assert authenticator.login_calls == 0
    assert proxy.prepared == proxy.restored == 0


def test_auth_required_observation_does_not_run_mock_by_default() -> None:
    machine, authenticator, proxy, _ = machine_for([True])

    result = machine.observe_detection(auth_required())

    assert result.state is AppState.AUTH_REQUIRED
    assert authenticator.login_calls == 0
    assert proxy.prepared == proxy.restored == 0
