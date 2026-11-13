"""Mihomo placeholder; intentionally unsupported in Phase 2."""

from proxy.base import UnsupportedProxyAdapter


class MihomoAdapter(UnsupportedProxyAdapter):
    def __init__(self) -> None:
        super().__init__("Mihomo 系列")

