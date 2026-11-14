"""GUI.for.SingBox Windows system-proxy integration; no process or TUN control."""

from proxy.windows_system import WindowsSystemProxyAdapter


class GuiForSingBoxAdapter(WindowsSystemProxyAdapter):
    PROCESS_NAMES = frozenset(["GUI.for.SingBox.exe"])
    INSTALL_DIRECTORIES = ["GUI.for.SingBox"]

