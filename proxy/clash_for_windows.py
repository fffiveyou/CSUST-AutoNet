"""Clash for Windows system-proxy integration."""
from proxy.windows_system import WindowsSystemProxyAdapter


class ClashForWindowsAdapter(WindowsSystemProxyAdapter):
    PROCESS_NAMES = frozenset({"Clash for Windows.exe"})
    EXECUTABLE_NAME = "Clash for Windows.exe"
    INSTALL_DIRECTORIES = ("Clash for Windows",)
