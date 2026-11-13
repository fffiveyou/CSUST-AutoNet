from __future__ import annotations

from network.portal_inspector import PortalInspector, sanitize_url


class FakeCookies:
    def keys(self):
        return ["SESSION", "route"]


class FakeResponse:
    def __init__(self, url: str, text: str, content_type: str) -> None:
        self.url = url
        self.text = text
        self.content = text.encode("utf-8")
        self.status_code = 200
        self.headers = {"Content-Type": content_type}
        self.history = []
        self.encoding = "utf-8"
        self.apparent_encoding = "utf-8"

    def raise_for_status(self) -> None:
        return None


class FakeSession:
    def __init__(self, responses) -> None:
        self.responses = list(responses)
        self.cookies = FakeCookies()
        self.requested_urls: list[str] = []

    def get(self, url: str, **_kwargs):
        self.requested_urls.append(url)
        return self.responses.pop(0)


def test_url_sanitizer_keeps_routes_but_redacts_sensitive_values() -> None:
    safe = sanitize_url(
        "https://login.csust.edu.cn/eportal/InterFace.do?method=login&userId=student&token=abc#x"
    )
    assert safe == (
        "https://login.csust.edu.cn/eportal/InterFace.do?"
        "method=login&token=<redacted>&userId=<redacted>"
    )
    assert "student" not in safe
    assert "abc" not in safe


def test_inspector_reports_schema_without_field_or_cookie_values() -> None:
    html = """
    <html><head><title>Campus Login</title></head><body>
      <form method="post" action="/eportal/InterFace.do?method=login&token=secret">
        <input name="userId" value="student">
        <input name="password" type="password" value="hidden">
        <input name="validcode" value="">
      </form>
      <script>const endpoint = '/eportal/InterFace.do?method=login&token=secret';</script>
      <script src="/login.js?v=private"></script>
    </body></html>
    """
    script = "const fields = ['queryString', 'service', 'operatorPwd'];"
    session = FakeSession(
        [
            FakeResponse("https://login.csust.edu.cn/", html, "text/html; charset=utf-8"),
            FakeResponse("https://login.csust.edu.cn/login.js?v=private", script, "text/javascript"),
        ]
    )

    result = PortalInspector(session).inspect("https://login.csust.edu.cn")  # type: ignore[arg-type]

    assert result.title == "Campus Login"
    assert result.cookie_names == ("SESSION", "route")
    assert result.forms[0].method == "POST"
    assert [field.name for field in result.forms[0].fields] == ["userId", "password", "validcode"]
    assert all(field.has_value for field in result.forms[0].fields[:2])
    assert result.forms[0].fields[2].has_value is False
    assert "student" not in repr(result)
    assert "hidden" not in repr(result)
    assert "secret" not in repr(result)
    assert result.script_urls == ("https://login.csust.edu.cn/login.js?v=<redacted>",)
    assert session.requested_urls[1] == "https://login.csust.edu.cn/login.js?v=private"
    assert set(result.protocol_field_hints) >= {"queryString", "userId", "password", "service", "operatorPwd", "validcode"}
