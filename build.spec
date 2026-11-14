# PyInstaller onedir specification for the Windows portable release.
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules("keyring.backends") + collect_submodules("win32ctypes") + collect_submodules("proxy")

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

# Qt6Core on this Windows build imports the system ICU API. PyInstaller can
# accidentally discover Poppler/Anaconda's incompatible ICU 78 through PATH,
# which makes QtGui fail with an entry-point error at startup. The application
# must use the Windows System32 ICU instead.
incompatible_icu = {"icuuc.dll", "icudt78.dll"}
a.binaries = [
    entry for entry in a.binaries if Path(entry[0]).name.casefold() not in incompatible_icu
]

pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CSUSTAutoNet",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="CSUSTAutoNet",
)
