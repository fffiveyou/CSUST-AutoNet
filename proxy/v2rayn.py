"""v2rayN placeholder; intentionally unsupported in Phase 2."""

from proxy.base import UnsupportedProxyAdapter


class V2rayNAdapter(UnsupportedProxyAdapter):
    def __init__(self) -> None:
        super().__init__("v2rayN")

