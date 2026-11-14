"""FlClash Windows system-proxy integration; no process or TUN control."""

from proxy.windows_system import WindowsSystemProxyAdapter


class FlClashAdapter(WindowsSystemProxyAdapter):
    PROCESS_NAMES = frozenset(["FlClash.exe"])
    INSTALL_DIRECTORIES = ["FlClash"]

