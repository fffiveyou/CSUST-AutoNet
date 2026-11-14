"""Clash Verge Rev Windows system-proxy integration; no process or TUN control."""

from proxy.windows_system import WindowsSystemProxyAdapter


class ClashVergeRevAdapter(WindowsSystemProxyAdapter):
    PROCESS_NAMES = frozenset(["clash-verge.exe"])
    INSTALL_DIRECTORIES = ["Clash Verge","Clash Verge Rev"]

