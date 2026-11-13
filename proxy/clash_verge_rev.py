"""Clash Verge Rev placeholder; intentionally unsupported in Phase 2."""

from proxy.base import UnsupportedProxyAdapter


class ClashVergeRevAdapter(UnsupportedProxyAdapter):
    def __init__(self) -> None:
        super().__init__("Clash Verge Rev")

