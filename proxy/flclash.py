"""FlClash placeholder; intentionally unsupported in Phase 2."""

from proxy.base import UnsupportedProxyAdapter


class FlClashAdapter(UnsupportedProxyAdapter):
    def __init__(self) -> None:
        super().__init__("FlClash")

