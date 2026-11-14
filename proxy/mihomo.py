"""Mihomo 系列 Windows system-proxy integration; no process or TUN control."""

from proxy.windows_system import WindowsSystemProxyAdapter


class MihomoAdapter(WindowsSystemProxyAdapter):
    PROCESS_NAMES = frozenset(["mihomo.exe","GUI.for.Clash.exe"])
    INSTALL_DIRECTORIES = ["mihomo","GUI.for.Clash"]

