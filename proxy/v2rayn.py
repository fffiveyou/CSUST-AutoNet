"""v2rayN Windows system-proxy integration; no process or TUN control."""

from proxy.windows_system import WindowsSystemProxyAdapter


class V2rayNAdapter(WindowsSystemProxyAdapter):
    PROCESS_NAMES = frozenset(["v2rayN.exe"])
    INSTALL_DIRECTORIES = ["v2rayN"]

