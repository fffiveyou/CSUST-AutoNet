from __future__ import annotations

from contextlib import contextmanager

from app.controller import AppController
from app.state_machine import AppState
from config.manager import ConfigManager, default_config
from logutil.logger import setup_logging
from network.csust_auth import (
    ACCOUNT_PREFIX,
    JS_VERSION,
    LANGUAGE,
    LOGIN_URL,
    PORTAL_REQUEST_HEADERS,
    TERMINAL_TYPE,
    CsustAuthenticator,
    PortalEnvironment,
)
from network.models import DetectionResult, NetworkStatus
from proxy.none import NoneProxyAdapter
from system.credentials import CredentialStore


class FakeResponse:
    def __init__(self, text: str, status_code: int = 200) -> None:
        self.text = text
        self.status_code = status_code


class FakeSession:
    def __init__(self, response: FakeResponse | None = None) -> None:
        self.response = response or FakeResponse('dr1003({"result":1,"msg":"ok"})')
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.trust_env = True
        self.proxies = {"https": "http://proxy.invalid"}

    def get(self, url: str, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


class FakeKeyring:
    def __init__(self, password: str | None) -> None:
        self.password = password
        self.reads = 0

    def get_password(self, _service: str, _username: str) -> str | None:
        self.reads += 1
        return self.password

    def set_password(self, _service: str, _username: str, password: str) -> None:
        self.password = password

    def delete_password(self, _service: str, _username: str) -> None:
        self.password = None


class TrackingProxy(NoneProxyAdapter):
    def __init__(self) -> None:
        self.prepared = 0
        self.restored = 0

    @contextmanager
    def authentication_bypass(self, timeout_seconds: float = 10.0):
        self.prepared += 1
        try:
            yield None
        finally:
            self.restored += 1


class CapturingAuthenticator:
    is_mock = False

    def __init__(self, credential_provider, environment_provider) -> None:
        self.credential_provider = credential_provider
        self.environment_provider = environment_provider
        self.credentials: tuple[str, str] | None = None

    def login(self) -> bool:
        self.credentials = self.credential_provider()
        return self.environment_provider().ready

    def verify_login(self) -> bool:
        return True


def environment() -> PortalEnvironment:
    return PortalEnvironment(
        wlan_user_ip="10.0.0.8",
        wlan_user_ipv6="",
        wlan_user_mac="masked-mac-token",
        wlan_ac_ip="10.0.0.1",
        wlan_ac_name="masked-ac-name",
    )


def authenticator(
    session: FakeSession,
    *,
    environment_provider=lambda: environment(),
    verifier=lambda: True,
) -> CsustAuthenticator:
    return CsustAuthenticator(
        credential_provider=lambda: ("student", "test-password"),
        environment_provider=environment_provider,
        session=session,  # type: ignore[arg-type]
        verifier=verifier,
        token_factory=lambda: ("dr1003", "1234567890"),
    )


def test_confirmed_get_schema_and_direct_session_settings() -> None:
    session = FakeSession()
    auth = authenticator(session)

    assert auth.login() is True
    assert session.trust_env is False
    assert session.proxies == {}
    assert len(session.calls) == 1

    url, kwargs = session.calls[0]
    assert url == LOGIN_URL
    assert url == "https://login.csust.edu.cn:802/eportal/portal/login"
    assert kwargs["allow_redirects"] is False
    assert kwargs["headers"] == PORTAL_REQUEST_HEADERS
    assert auth.last_http_status == 200
    params = kwargs["params"]
    assert isinstance(params, dict)
    assert set(params) == {
        "callback",
        "login_method",
        "user_account",
        "user_password",
        "wlan_user_ip",
        "wlan_user_ipv6",
        "wlan_user_mac",
        "wlan_ac_ip",
        "wlan_ac_name",
        "jsVersion",
        "terminal_type",
        "lang",
        "v",
    }
    assert params["user_account"] == ACCOUNT_PREFIX + "student"
    assert params["user_password"] == "test-password"
    assert params["jsVersion"] == JS_VERSION
    assert params["terminal_type"] == TERMINAL_TYPE
    assert params["lang"] == LANGUAGE


def test_portal_environment_extracts_aliases_without_exposing_values() -> None:
    portal_url = (
        "https://login.csust.edu.cn/?wlanuserip=10.0.0.8"
        "&wlanusermac=secret-mac&wlanacip=10.0.0.1&wlanacname=secret-ac"
    )

    value = PortalEnvironment.from_url(portal_url)

    assert value is not None
    assert value.ready is True
    assert repr(value) == "PortalEnvironment(ready=True)"
    assert "10.0.0.8" not in repr(value)
    assert "secret-mac" not in repr(value)
    assert "secret-ac" not in repr(value)


def test_unknown_host_missing_fields_and_conflicts_fail_closed() -> None:
    complete_query = (
        "wlanuserip=10.0.0.8&wlanusermac=m&wlanacip=10.0.0.1&wlanacname=ac"
    )
    assert PortalEnvironment.from_url(f"https://example.invalid/?{complete_query}") is None
    assert PortalEnvironment.from_url("https://login.csust.edu.cn/?wlanuserip=10.0.0.8") is None
    assert (
        PortalEnvironment.from_url(
            f"https://login.csust.edu.cn/?{complete_query}&wlan_user_ip=10.0.0.9"
        )
        is None
    )


def test_missing_environment_never_reads_credentials_or_sends_request() -> None:
    session = FakeSession()
    credential_reads = 0

    def read_credentials() -> tuple[str, str]:
        nonlocal credential_reads
        credential_reads += 1
        return "student", "test-password"

    auth = CsustAuthenticator(
        credential_provider=read_credentials,
        environment_provider=lambda: None,
        session=session,  # type: ignore[arg-type]
        token_factory=lambda: ("dr1003", "123"),
    )

    assert auth.login() is False
    assert credential_reads == 0
    assert session.calls == []


def test_jsonp_success_variants_and_malformed_responses() -> None:
    for body, expected in (
        ('dr1003({"result":1})', True),
        ('dr1003({"result":"ok"})', True),
        ('dr1003({"result":0,"msg":"failed"})', False),
        ('dr1003({"result":true})', False),
        ('other({"result":1})', False),
        ('{"result":1}', False),
        ('dr1003(not-json)', False),
    ):
        session = FakeSession(FakeResponse(body))
        assert authenticator(session).login() is expected


def test_non_200_status_is_retained_without_response_content() -> None:
    auth = authenticator(FakeSession(FakeResponse("sensitive body", status_code=403)))

    assert auth.login() is False
    assert auth.last_outcome == "HTTP_STATUS_REJECTED"
    assert auth.last_http_status == 403


def test_invalid_callback_or_cache_buster_prevents_request() -> None:
    for tokens in (("bad-callback()", "123"), ("dr1003", "not-numeric")):
        session = FakeSession()
        auth = CsustAuthenticator(
            credential_provider=lambda: ("student", "test-password"),
            environment_provider=lambda: environment(),
            session=session,  # type: ignore[arg-type]
            token_factory=lambda tokens=tokens: tokens,
        )
        assert auth.login() is False
        assert session.calls == []


def test_transport_exceptions_are_suppressed_without_secret_text() -> None:
    class FailingSession(FakeSession):
        def get(self, url: str, **kwargs):
            raise RuntimeError("request contained test-password")

    assert authenticator(FailingSession()).login() is False


def test_verification_uses_injected_direct_connectivity_result() -> None:
    session = FakeSession()
    assert authenticator(session, verifier=lambda: True).verify_login() is True
    assert authenticator(session, verifier=lambda: False).verify_login() is False


def make_controller(
    tmp_path,
    *,
    portal_password: str | None = "saved-password",
    clock=lambda: 100.0,
    restore_proxy: bool = True,
):
    config_manager = ConfigManager(tmp_path / "config.json")
    config_manager.save(
        default_config()
        | {
            "username": "student",
            "proxy_type": "clash_for_windows",
            "proxy_management": True,
            "restore_proxy": restore_proxy,
        }
    )
    keyring = FakeKeyring(portal_password)
    proxy = TrackingProxy()
    created: list[CapturingAuthenticator] = []
    proxy_calls: list[tuple[str, dict[str, object]]] = []

    def auth_factory(**kwargs):
        value = CapturingAuthenticator(**kwargs)
        created.append(value)
        return value

    def proxy_factory(proxy_type: str, **kwargs):
        proxy_calls.append((proxy_type, kwargs))
        return proxy

    controller = AppController(
        config_manager=config_manager,
        credential_store=CredentialStore(keyring),
        logs_path=tmp_path / "logs",
        logger=setup_logging(tmp_path / "logs", logger_name=f"phase6-{id(tmp_path)}"),
        real_authenticator_factory=auth_factory,
        real_proxy_adapter_factory=proxy_factory,
        clock=clock,
        authentication_sleeper=lambda _seconds: None,
    )
    return controller, keyring, proxy, created, proxy_calls


def complete_portal_url() -> str:
    return (
        "https://login.csust.edu.cn/?wlanuserip=10.0.0.8"
        "&wlanusermac=masked&wlanacip=10.0.0.1&wlanacname=masked-ac"
    )


def test_controller_manual_auth_requires_fresh_confirmed_environment(tmp_path) -> None:
    controller, keyring, proxy, created, proxy_calls = make_controller(tmp_path)
    controller.process_detection(
        DetectionResult(NetworkStatus.AUTH_REQUIRED, 2, "portal", complete_portal_url())
    )

    result = controller.request_authentication()

    assert result.state is AppState.CONNECTED
    assert result.failure_count == 0
    assert keyring.reads == 1
    assert created[0].credentials == ("student", "saved-password")
    assert proxy.prepared == proxy.restored == 1
    assert proxy_calls == [
        (
            "clash_for_windows",
            {"exe_path": "", "dry_run": False},
        )
    ]


def test_controller_missing_environment_fails_before_credential_read(tmp_path) -> None:
    controller, keyring, proxy, created, _ = make_controller(tmp_path)
    controller.process_detection(
        DetectionResult(NetworkStatus.AUTH_REQUIRED, 2, "portal", "https://login.csust.edu.cn/")
    )

    result = controller.request_authentication()

    assert result.state is AppState.AUTH_REQUIRED
    assert "未读取或提交凭据" in result.message
    assert keyring.reads == 0
    assert created == []
    assert proxy.prepared == proxy.restored == 0


def test_controller_rejects_stale_detection(tmp_path) -> None:
    now = [100.0]
    controller, keyring, _, created, _ = make_controller(tmp_path, clock=lambda: now[0])
    controller.process_detection(
        DetectionResult(NetworkStatus.AUTH_REQUIRED, 2, "portal", complete_portal_url())
    )
    now[0] = 221.0

    result = controller.request_authentication()

    assert "已过期" in result.message
    assert keyring.reads == 0
    assert created == []


def test_controller_requires_exact_proxy_restoration(tmp_path) -> None:
    controller, keyring, _, created, _ = make_controller(tmp_path, restore_proxy=False)
    controller.process_detection(
        DetectionResult(NetworkStatus.AUTH_REQUIRED, 2, "portal", complete_portal_url())
    )

    result = controller.request_authentication()

    assert "恢复系统代理原设置" in result.message
    assert keyring.reads == 0
    assert created == []


def test_manual_auth_button_runs_worker_without_enabling_auto_auth(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication

    from ui.main_window import MainWindow

    controller, _, _, _, _ = make_controller(tmp_path)
    controller.process_detection(
        DetectionResult(NetworkStatus.AUTH_REQUIRED, 2, "portal", complete_portal_url())
    )
    application = QApplication.instance() or QApplication([])
    window = MainWindow(controller)

    assert window.auto_auth_check.isEnabled() is True
    assert window.auto_auth_check.isChecked() is False
    window.auth_button.click()
    for _ in range(100):
        application.processEvents()
        if not window._authentication_running:
            break
        QTest.qWait(10)

    assert window._authentication_running is False
    assert "认证后直连验证通过" in window.status_label.text()
    assert window.auth_button.isEnabled()
    window.minimize_check.setChecked(False)
    window.close()
