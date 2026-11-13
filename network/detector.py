"""Conservative direct-connectivity detector with a two-failure gate."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import parse_qsl, urljoin, urlparse

import requests

from network.models import DetectionResult, NetworkStatus


@dataclass(frozen=True)
class ConnectivityProbe:
    url: str
    status_code: int
    body: str | None = None


PUBLIC_PROBE_URL = "http://www.msftconnecttest.com/connecttest.txt"
PUBLIC_PROBE_BODY = "Microsoft Connect Test"
PUBLIC_PROBES = (
    ConnectivityProbe(PUBLIC_PROBE_URL, 200, PUBLIC_PROBE_BODY),
    ConnectivityProbe("https://connect.rom.miui.com/generate_204", 204),
    ConnectivityProbe("https://cp.cloudflare.com/generate_204", 204),
)
PUBLIC_PROBE_REQUIRED_SUCCESSES = 2
PORTAL_URLS = ("https://login.csust.edu.cn", "http://192.168.7.221")
PORTAL_HOSTS = frozenset({"login.csust.edu.cn", "192.168.7.221"})
PASSWORD_MARKERS = ("type=\"password\"", "type='password'", "name=\"password\"", "name='password'")
LOGIN_MARKERS = ("登录", "login", "userid", "用户名")
CAPTIVE_USER_IP_KEYS = frozenset(
    {"ip", "wlanuserip", "wlan_user_ip", "userip", "user_ip", "client_ip", "uip", "station_ip"}
)
CAPTIVE_ROUTE_KEYS = frozenset(
    {
        "mac",
        "usermac",
        "user_mac",
        "wlanusermac",
        "wlan_user_mac",
        "umac",
        "client_mac",
        "station_mac",
        "wlanacip",
        "wlan_ac_ip",
        "nasip",
    }
)


def create_direct_session() -> requests.Session:
    """Create a session that ignores OS and environment proxy configuration."""

    session = requests.Session()
    session.trust_env = False
    session.proxies.clear()
    session.headers.update({"User-Agent": "CSUST-AutoNet/0.1 network-detector"})
    return session


class NetworkDetector:
    """Classify direct connectivity without ever submitting credentials."""

    def __init__(
        self,
        *,
        session_factory: Callable[[], requests.Session] = create_direct_session,
        timeout: tuple[float, float] = (2.0, 3.0),
        failure_threshold: int = 2,
    ) -> None:
        if failure_threshold < 2:
            raise ValueError("failure_threshold must be at least 2")
        self.session_factory = session_factory
        self.timeout = timeout
        self.failure_threshold = failure_threshold
        self.consecutive_public_failures = 0
        self._portal_candidate: str | None = None

    @staticmethod
    def _trusted_portal_url(url: str) -> str | None:
        parsed = urlparse(url)
        if parsed.scheme.casefold() not in {"http", "https"}:
            return None
        if (parsed.hostname or "").casefold() not in PORTAL_HOSTS:
            return None
        return url

    @classmethod
    def _captive_redirect_from_response(
        cls,
        response: requests.Response,
        requested_url: str,
    ) -> str | None:
        if not 300 <= response.status_code < 400:
            return None
        location = (getattr(response, "headers", None) or {}).get("Location", "")
        return cls._trusted_portal_url(urljoin(requested_url, location)) if location else None

    def _public_internet_available(self, session: requests.Session) -> tuple[bool, str | None]:
        successes = 0
        remaining = len(PUBLIC_PROBES)
        portal_candidate: str | None = None
        for probe in PUBLIC_PROBES:
            remaining -= 1
            try:
                response = session.get(
                    probe.url,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            except requests.RequestException:
                response = None
            if response is not None:
                portal_candidate = (
                    self._captive_redirect_from_response(response, probe.url) or portal_candidate
                )
                status_matches = response.status_code == probe.status_code
                body_matches = probe.body is None or response.text.strip() == probe.body
                if status_matches and body_matches:
                    successes += 1
                    if successes >= PUBLIC_PROBE_REQUIRED_SUCCESSES:
                        return True, None
            if successes + remaining < PUBLIC_PROBE_REQUIRED_SUCCESSES:
                return False, portal_candidate
        return False, portal_candidate

    @staticmethod
    def _looks_like_login(response: requests.Response) -> bool:
        hostname = (urlparse(response.url).hostname or "").casefold()
        if hostname not in PORTAL_HOSTS or not 200 <= response.status_code < 400:
            return False
        body = response.text[:262_144].casefold()
        has_password_field = any(marker in body for marker in PASSWORD_MARKERS)
        has_login_marker = any(marker in body for marker in LOGIN_MARKERS)
        return has_password_field and has_login_marker

    @staticmethod
    def _looks_like_captive_url(url: str) -> bool:
        parsed = urlparse(url)
        if (parsed.hostname or "").casefold() not in PORTAL_HOSTS:
            return False
        names = {
            name.casefold().replace("-", "_")
            for name, _value in parse_qsl(parsed.query, keep_blank_values=True)
        }
        return bool(names & CAPTIVE_USER_IP_KEYS) and bool(names & CAPTIVE_ROUTE_KEYS)

    def _check_portal(
        self,
        session: requests.Session,
        portal_candidate: str | None = None,
    ) -> tuple[bool, str | None]:
        """Return confirmed-login-page status and the first reachable portal URL."""

        reachable_url: str | None = None
        urls = tuple(dict.fromkeys((portal_candidate, *PORTAL_URLS)))
        for url in urls:
            if not url:
                continue
            try:
                response = session.get(url, timeout=self.timeout, allow_redirects=True)
            except requests.RequestException:
                continue
            if response.status_code < 500 and reachable_url is None:
                reachable_url = response.url
            if self._looks_like_login(response):
                return True, url if self._looks_like_captive_url(url) else response.url
            if self._looks_like_captive_url(url) and 200 <= response.status_code < 400:
                body = response.text[:262_144].casefold()
                if "a41.js" in body or "eportal" in body or "login" in body:
                    return True, url
        return False, reachable_url

    def check(self) -> DetectionResult:
        """Run one detection cycle and apply the consecutive-failure gate."""

        with self.session_factory() as session:
            internet_available, portal_candidate = self._public_internet_available(session)
            if internet_available:
                self.consecutive_public_failures = 0
                self._portal_candidate = None
                return DetectionResult(NetworkStatus.CONNECTED, 0, "直连公网正常。")

            if portal_candidate is not None:
                self._portal_candidate = portal_candidate
            self.consecutive_public_failures += 1
            failures = self.consecutive_public_failures
            if failures < self.failure_threshold:
                return DetectionResult(
                    NetworkStatus.SUSPECTED_OFFLINE,
                    failures,
                    f"直连公网检测失败（{failures}/{self.failure_threshold}），等待再次确认。",
                )

            login_detected, portal_url = self._check_portal(session, self._portal_candidate)
            if login_detected:
                return DetectionResult(
                    NetworkStatus.AUTH_REQUIRED,
                    failures,
                    "连续两次直连公网失败，已确认校园网登录页面。",
                    portal_url,
                )
            return DetectionResult(
                NetworkStatus.NETWORK_UNAVAILABLE,
                failures,
                "连续两次直连公网失败，但未确认校园网登录页面；不会触发认证。",
                portal_url,
            )
