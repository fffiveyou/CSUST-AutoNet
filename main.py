"""CSUST AutoNet desktop entry point."""

from __future__ import annotations

import argparse
import sys

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

from app.constants import APP_ID, APP_NAME
from app.controller import AppController
from ui.main_window import MainWindow


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=APP_ID, description=APP_NAME)
    parser.add_argument(
        "--background",
        action="store_true",
        help="后台启动：不显示主窗口，直接进入系统托盘",
    )
    parser.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    return parser


def packaged_self_test() -> int:
    """Validate packaged Qt imports and the Windows Credential backend."""

    try:
        from keyring.backends.Windows import WinVaultKeyring
        from proxy.base import create_proxy_adapter, proxy_catalog

        for key, _label, supported in proxy_catalog():
            if supported:
                create_proxy_adapter(key, dry_run=True)
        return 0 if WinVaultKeyring.priority > 0 else 1
    except Exception:
        return 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.self_test:
        return packaged_self_test()
    app = QApplication([sys.argv[0], *(argv or sys.argv[1:])])
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("CSUST AutoNet")
    app.setQuitOnLastWindowClosed(False)
    if sys.platform == "win32":
        app.setFont(QFont("Microsoft YaHei UI", 9))

    controller = AppController()
    window = MainWindow(controller)
    window.start(background=args.background)
    exit_code = app.exec()
    controller.logger.info("Application exited")
    return int(exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
