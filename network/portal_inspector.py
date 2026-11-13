"""Read-only, secret-minimizing inspection of the CSUST portal login surface."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

import requests

from network.detector import create_direct_session


ENDPOINT_HINTS = ("login", "auth", "portal", "eportal", "user", "online", "interfac")
QUOTED_URL = re.compile(
    r"[\"']((?:(?:https?://|/)[^\"'\\\s]{1,300}|(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.do(?:\?[^\"'\\\s]{0,240})?))[\"']",
    re.IGNORECASE,
)
SAFE_ROUTING_QUERY_KEYS = frozenset({"a", "c", "jsVersion", "ver", "method"})
SAFE_ROUTING_VALUE = re.compile(r"^[A-Za-z0-9_.-]{0,64}$")
PROTOCOL_FIELD_HINTS = (
    "queryString",
    "userId",
    "password",
    "service",
    "operatorPwd",
    "validcode",
    "passwordEncrypt",
    "userIndex",
    "wlanuserip",
    "wlanacip",
    "wlanacname",
    "mac",
)


def sanitize_url(url: str) -> str:
    """Retain route and query-field names, never query values or fragments."""

    parsed = urlparse(url)
    safe_pairs: list[tuple[str, str]] = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        if name in SAFE_ROUTING_QUERY_KEYS and SAFE_ROUTING_VALUE.fullmatch(value):
            safe_pairs.append((name, value))
        else:
            safe_pairs.append((name, "<redacted>"))
    safe_query = "&".join(f"{name}={value}" for name, value in sorted(set(safe_pairs)))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, safe_query, ""))


@dataclass(frozen=True)
class FormField:
    name: str
    field_type: str
    has_value: bool


@dataclass(frozen=True)
class FormSchema:
    method: str
    action: str
    enctype: str
    fields: tuple[FormField, ...]


@dataclass(frozen=True)
class PortalInspection:
    requested_url: str
    final_url: str
    status_code: int
    content_type: str
    title: str
    html_bytes: int
    html_sha256: str
    redirect_chain: tuple[str, ...]
    cookie_names: tuple[str, ...]
    forms: tuple[FormSchema, ...]
    script_urls: tuple[str, ...]
    endpoint_candidates: tuple[str, ...]
    protocol_field_hints: tuple[str, ...]


class _PortalHTMLParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.forms: list[dict[str, object]] = []
        self.scripts: list[str] = []
        self.inline_scripts: list[str] = []
        self._current_form: dict[str, object] | None = None
        self._inside_title = False
        self._inside_script = False
        self._title_parts: list[str] = []
        self._script_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        attributes = {str(name).casefold(): str(value or "") for name, value in attrs}
        normalized = tag.casefold()
        if normalized == "form":
            form = {
                "method": attributes.get("method", "get").upper(),
                "action": sanitize_url(urljoin(self.base_url, attributes.get("action", ""))),
                "enctype": attributes.get("enctype", "application/x-www-form-urlencoded"),
                "fields": [],
            }
            self.forms.append(form)
            self._current_form = form
        elif normalized in {"input", "select", "textarea"} and self._current_form is not None:
            name = attributes.get("name", "")
            if name:
                fields = self._current_form["fields"]
                assert isinstance(fields, list)
                fields.append(
                    FormField(
                        name=name,
                        field_type=attributes.get("type", normalized).casefold(),
                        has_value=bool(attributes.get("value", "")),
                    )
                )
        elif normalized == "script":
            source = attributes.get("src", "")
            if source:
                self.scripts.append(urljoin(self.base_url, source))
            else:
                self._inside_script = True
                self._script_parts = []
        elif normalized == "title":
            self._inside_title = True

    def handle_endtag(self, tag: str) -> None:
        normalized = tag.casefold()
        if normalized == "form":
            self._current_form = None
        elif normalized == "script" and self._inside_script:
            self.inline_scripts.append("".join(self._script_parts))
            self._inside_script = False
            self._script_parts = []
        elif normalized == "title":
            self._inside_title = False

    def handle_data(self, data: str) -> None:
        if self._inside_title:
            self._title_parts.append(data)
        if self._inside_script:
            self._script_parts.append(data)

    @property
    def title(self) -> str:
        return " ".join("".join(self._title_parts).split())


def _endpoint_candidates(text: str, base_url: str) -> set[str]:
    candidates: set[str] = set()
    for match in QUOTED_URL.finditer(text):
        value = match.group(1)
        if not any(hint in value.casefold() for hint in ENDPOINT_HINTS):
            continue
        candidates.add(sanitize_url(urljoin(base_url, value)))
    return candidates


class PortalInspector:
    """Inspect HTML and same-origin scripts using GET requests only."""

    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or create_direct_session()

    def inspect(self, url: str, *, inspect_scripts: bool = True) -> PortalInspection:
        response = self.session.get(url, timeout=(3.0, 5.0), allow_redirects=True)
        response.raise_for_status()
        if not response.encoding or response.encoding.casefold() in {"iso-8859-1", "ascii"}:
            response.encoding = response.apparent_encoding
        parser = _PortalHTMLParser(response.url)
        parser.feed(response.text)

        endpoints = set()
        inspected_text = [response.text]
        for script in parser.inline_scripts:
            endpoints.update(_endpoint_candidates(script, response.url))

        raw_scripts = tuple(dict.fromkeys(parser.scripts))
        safe_scripts = tuple(sanitize_url(item) for item in raw_scripts)
        if inspect_scripts:
            origin = urlparse(response.url).netloc.casefold()
            for script_url in raw_scripts[:12]:
                if urlparse(script_url).netloc.casefold() != origin:
                    continue
                try:
                    script_response = self.session.get(
                        script_url,
                        timeout=(3.0, 5.0),
                        allow_redirects=True,
                    )
                except requests.RequestException:
                    continue
                if script_response.status_code != 200:
                    continue
                script_text = script_response.text[:2_000_000]
                inspected_text.append(script_text)
                endpoints.update(_endpoint_candidates(script_text, response.url))

        combined_casefolded = "\n".join(inspected_text).casefold()
        field_hints = tuple(
            field for field in PROTOCOL_FIELD_HINTS if field.casefold() in combined_casefolded
        )

        forms = tuple(
            FormSchema(
                method=str(form["method"]),
                action=str(form["action"]),
                enctype=str(form["enctype"]),
                fields=tuple(form["fields"]),  # type: ignore[arg-type]
            )
            for form in parser.forms
        )
        return PortalInspection(
            requested_url=sanitize_url(url),
            final_url=sanitize_url(response.url),
            status_code=response.status_code,
            content_type=response.headers.get("Content-Type", "").split(";", 1)[0],
            title=parser.title,
            html_bytes=len(response.content),
            html_sha256=hashlib.sha256(response.content).hexdigest(),
            redirect_chain=tuple(sanitize_url(item.url) for item in response.history),
            cookie_names=tuple(sorted(self.session.cookies.keys())),
            forms=forms,
            script_urls=safe_scripts,
            endpoint_candidates=tuple(sorted(endpoints)),
            protocol_field_hints=field_hints,
        )


def main() -> int:
    inspection = PortalInspector().inspect("https://login.csust.edu.cn")
    print(json.dumps(asdict(inspection), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
