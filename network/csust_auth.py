"""CSUST ePortal authentication with fail-closed environment handling."""

from __future__ import annotations

import json
import re
import secrets
import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlparse

import requests

from network.detector import NetworkDetector, create_direct_session
from network.models import NetworkStatus


LOGIN_URL = "https://login.csust.edu.cn:802/eportal/portal/login"
PORTAL_HOSTS = frozenset({"login.csust.edu.cn", "192.168.7.221"})
ACCOUNT_PREFIX = ",0,"
JS_VERSION = "4.2.1"
LOGIN_METHOD = "1"
TERMINAL_TYPE = "1"
LANGUAGE = "zh"
PORTAL_REQUEST_HEADERS = {
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
    "Referer": "https://login.csust.edu.cn/",
    "Sec-Fetch-Dest": "script",
    "Sec-Fetch-Mode": "no-cors",
    "Sec-Fetch-Site": "same-site",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/153.0.0.0 Safari/537.36"
    ),
}
_JSONP_CALLBACK = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{0,63}$")


class Authenticator(Protocol):
    def login(self) -> bool: ...

    def verify_login(self) -> bool: ...


@dataclass(frozen=True, repr=False)
class PortalEnvironment:
    """Sensitive network routing values needed by ePortal.

    Values are deliberately omitted from repr so diagnostics cannot expose an
    IP address, MAC-derived value, or access-controller identifier.
    """

    wlan_user_ip: str
    wlan_user_ipv6: str
    wlan_user_mac: str
    wlan_ac_ip: str
    wlan_ac_name: str
    login_method: str = LOGIN_METHOD

    def __repr__(self) -> str:
        ready = bool(self.wlan_user_ip and self.wlan_user_mac and self.wlan_ac_ip and self.wlan_ac_name)
        return f"PortalEnvironment(ready={ready})"

    @property
    def ready(self) -> bool:
        return bool(
            self.wlan_user_ip
            and self.wlan_user_mac
            and self.wlan_ac_ip
            and self.wlan_ac_name
            and self.login_method
        )

    @classmethod
    def from_url(cls, url: str) -> PortalEnvironment | None:
        """Extract environment values from a trusted captive-portal URL.

        Several ePortal spellings are accepted. Conflicting duplicate values,
        unknown hosts, or missing required routing values fail closed.
        """

        parsed = urlparse(url)
        if parsed.scheme.casefold() not in {"http", "https"}:
            return None
        if (parsed.hostname or "").casefold() not in PORTAL_HOSTS:
            return None

        values: dict[str, list[str]] = {}
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            normalized = name.casefold().replace("-", "_")
            values.setdefault(normalized, []).append(value.strip())

        def pick(*aliases: str, default: str = "") -> str | None:
            found = {
                value
                for alias in aliases
                for value in values.get(alias.casefold(), ())
                if value
            }
            if len(found) > 1:
                return None
            return next(iter(found), default)

        user_ip = pick(
            "wlan_user_ip",
            "wlanuserip",
            "user_ip",
            "userip",
            "ip",
            "client_ip",
            "uip",
            "station_ip",
        )
        user_ipv6 = pick("wlan_user_ipv6", "wlanuseripv6", "user_ipv6", "useripv6", "ipv6")
        user_mac = pick(
            "wlan_user_mac",
            "wlanusermac",
            "user_mac",
            "usermac",
            "mac",
            "umac",
            "client_mac",
            "station_mac",
        )
        ac_ip = pick("wlan_ac_ip", "wlanacip", "nasip")
        ac_name = pick("wlan_ac_name", "wlanacname", "nasname")
        login_method = pick("login_method", default=LOGIN_METHOD)
        if None in {user_ip, user_ipv6, user_mac, ac_ip, ac_name, login_method}:
            return None

        environment = cls(
            wlan_user_ip=user_ip or "",
            wlan_user_ipv6=user_ipv6 or "",
            wlan_user_mac=user_mac or "",
            wlan_ac_ip=ac_ip or "",
            wlan_ac_name=ac_name or "",
            login_method=login_method or "",
        )
        return environment if environment.ready else None


CredentialProvider = Callable[[], tuple[str, str]]
EnvironmentProvider = Callable[[], PortalEnvironment | None]
Verifier = Callable[[], bool]
TokenFactory = Callable[[], tuple[str, str]]


def _default_tokens() -> tuple[str, str]:
    """Return a valid JSONP identifier and numeric cache buster."""

    callback = f"dr{secrets.randbelow(900_000) + 100_000}"
    cache_buster = str(time.time_ns())
    return callback, cache_buster


def _public_connectivity_verified() -> bool:
    return NetworkDetector().check().status is NetworkStatus.CONNECTED


def _parse_jsonp(text: str, expected_callback: str) -> dict[str, Any] | None:
    if not _JSONP_CALLBACK.fullmatch(expected_callback):
        return None
    match = re.fullmatch(
        rf"\s*{re.escape(expected_callback)}\s*\(\s*(\{{.*\}})\s*\)\s*;?\s*",
        text[:262_144],
        flags=re.DOTALL,
    )
    if match is None:
        return None
    try:
        value = json.loads(match.group(1))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


class CsustAuthenticator:
    """Submit one evidence-backed ePortal request and verify public access.

    This object never logs, returns, or embeds credentials in an exception. It
    refuses to send anything until a complete environment has been extracted
    from a trusted captive-portal URL by the caller.
    """

    is_mock = False

    def __init__(
        self,
        *,
        credential_provider: CredentialProvider,
        environment_provider: EnvironmentProvider,
        session: requests.Session | None = None,
        verifier: Verifier = _public_connectivity_verified,
        token_factory: TokenFactory = _default_tokens,
        timeout: tuple[float, float] = (3.0, 5.0),
    ) -> None:
        self._credential_provider = credential_provider
        self._environment_provider = environment_provider
        self._owns_session = session is None
        self._session = session if session is not None else create_direct_session()
        self._session.trust_env = False
        self._session.proxies.clear()
        self._verifier = verifier
        self._token_factory = token_factory
        self._timeout = timeout
        # Safe, fixed diagnostic codes only. Never store response text, URLs,
        # credentials, or portal environment values here.
        self.last_outcome = "NOT_ATTEMPTED"
        self.last_http_status: int | None = None

    def login(self) -> bool:
        self.last_http_status = None
        try:
            environment = self._environment_provider()
            if environment is None or not environment.ready:
                self.last_outcome = "INVALID_ENVIRONMENT"
                return False
            username, password = self._credential_provider()
            username = username.strip()
            if not username or not password:
                self.last_outcome = "MISSING_CREDENTIALS"
                return False
            callback, cache_buster = self._token_factory()
            if not _JSONP_CALLBACK.fullmatch(callback) or not cache_buster.isdecimal():
                self.last_outcome = "INVALID_CLIENT_TOKEN"
                return False

            account = username if username.startswith(ACCOUNT_PREFIX) else ACCOUNT_PREFIX + username
            params = {
                "callback": callback,
                "login_method": environment.login_method,
                "user_account": account,
                "user_password": password,
                "wlan_user_ip": environment.wlan_user_ip,
                "wlan_user_ipv6": environment.wlan_user_ipv6,
                "wlan_user_mac": environment.wlan_user_mac,
                "wlan_ac_ip": environment.wlan_ac_ip,
                "wlan_ac_name": environment.wlan_ac_name,
                "jsVersion": JS_VERSION,
                "terminal_type": TERMINAL_TYPE,
                "lang": LANGUAGE,
                "v": cache_buster,
            }
            response = self._session.get(
                LOGIN_URL,
                params=params,
                headers=dict(PORTAL_REQUEST_HEADERS),
                timeout=self._timeout,
                allow_redirects=False,
            )
            self.last_http_status = int(response.status_code)
            if response.status_code != 200:
                self.last_outcome = "HTTP_STATUS_REJECTED"
                return False
            payload = _parse_jsonp(response.text, callback)
            if payload is None:
                self.last_outcome = "INVALID_JSONP_RESPONSE"
                return False
            result = payload.get("result")
            accepted = (type(result) is int and result == 1) or result == "ok"
            self.last_outcome = "PORTAL_ACCEPTED" if accepted else "PORTAL_REJECTED"
            return accepted
        except Exception:
            # Requests may include the full credential-bearing URL in their
            # exception text, so nothing from this boundary is propagated.
            self.last_outcome = "TRANSPORT_ERROR"
            return False

    def close(self) -> None:
        self._credential_provider = lambda: ("", "")
        if self._owns_session:
            self._session.close()

    def verify_login(self) -> bool:
        try:
            verified = bool(self._verifier())
            self.last_outcome = "VERIFY_CONNECTED" if verified else "VERIFY_NOT_CONNECTED"
            return verified
        except Exception:
            self.last_outcome = "VERIFY_ERROR"
            return False


class MockAuthenticator:
    """Return predefined outcomes without reading or transmitting credentials."""

    is_mock = True

    def __init__(
        self,
        login_outcomes: Iterable[bool] = (True,),
        verify_outcomes: Iterable[bool] = (True,),
    ) -> None:
        self._login_outcomes = deque(login_outcomes)
        self._verify_outcomes = deque(verify_outcomes)
        self.login_calls = 0
        self.verify_calls = 0

    @staticmethod
    def _next_or_false(values: deque[bool]) -> bool:
        return bool(values.popleft()) if values else False

    def login(self) -> bool:
        self.login_calls += 1
        return self._next_or_false(self._login_outcomes)

    def verify_login(self) -> bool:
        self.verify_calls += 1
        return self._next_or_false(self._verify_outcomes)
