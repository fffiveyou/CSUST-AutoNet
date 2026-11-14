"""PySide6 main window, tray integration, and non-blocking network checks."""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, QThreadPool, QTimer, QUrl, Signal, Slot
from PySide6.QtGui import QAction, QCloseEvent, QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QStyle,
    QSystemTrayIcon,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from app.constants import APP_NAME, MIN_CHECK_INTERVAL
from app.controller import AppController
from app.state_machine import AppState, StateMachineResult
from network.models import DetectionResult, NetworkStatus
from proxy.base import create_proxy_adapter, proxy_catalog
from system.proxy_settings import WindowsSystemProxy


class NetworkCheckSignals(QObject):
    completed = Signal(object)
    failed = Signal(str)


class NetworkCheckWorker(QRunnable):
    """Run one potentially slow direct-network check outside the UI thread."""

    def __init__(self, controller: AppController) -> None:
        super().__init__()
        self.controller = controller
        self.signals = NetworkCheckSignals()

    @Slot()
    def run(self) -> None:
        try:
            self.signals.completed.emit(self.controller.check_network())
        except Exception as exc:
            self.controller.logger.error("Network check failed: %s", type(exc).__name__)
            self.signals.failed.emit(f"网络检测执行异常：{type(exc).__name__}")


class AuthenticationSignals(QObject):
    completed = Signal(object)
    failed = Signal(str)


class AuthenticationWorker(QRunnable):
    """Run one explicit authentication cycle outside the UI thread."""

    def __init__(self, controller: AppController) -> None:
        super().__init__()
        self.controller = controller
        self.signals = AuthenticationSignals()

    @Slot()
    def run(self) -> None:
        try:
            self.signals.completed.emit(self.controller.request_authentication())
        except Exception as exc:
            self.controller.logger.error("Authentication worker failed: %s", type(exc).__name__)
            self.signals.failed.emit(f"认证执行异常：{type(exc).__name__}")


class MainWindow(QMainWindow):
    def __init__(self, controller: AppController) -> None:
        super().__init__()
        self.controller = controller
        self._allow_real_close = False
        self._closing = False
        self._shutdown_timer = QTimer(self)
        self._shutdown_timer.setInterval(50)
        self._shutdown_timer.timeout.connect(self._finish_shutdown)
        self._tray_hint_shown = False
        self._network_check_running = False
        self._active_check_manual = False
        self._authentication_running = False
        self._authentication_automatic = False
        self._resume_monitor_after_auth = False
        self._thread_pool = QThreadPool(self)
        self._thread_pool.setMaxThreadCount(1)
        self._monitor_timer = QTimer(self)
        self._monitor_timer.timeout.connect(self._scheduled_detect)
        self.setWindowTitle(APP_NAME)
        self.resize(700, 760)
        self._build_ui()
        self._build_tray()
        self._load_settings()

    def _group(self, title: str, layout) -> QGroupBox:
        group = QGroupBox(title)
        group.setLayout(layout)
        return group

    def _build_ui(self) -> None:
        content = QWidget(self)
        root = QVBoxLayout(content)

        status_layout = QFormLayout()
        self.status_label = QLabel("● 尚未检测")
        self.system_proxy_status_label = QLabel("● 尚未读取")
        self.monitor_label = QLabel("● 准备启动无代理直连监测")
        status_layout.addRow("校园网状态：", self.status_label)
        status_layout.addRow("Windows 系统代理：", self.system_proxy_status_label)
        status_layout.addRow("自动监测：", self.monitor_label)
        root.addWidget(self._group("校园网状态", status_layout))

        auth_layout = QFormLayout()
        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        password_row = QHBoxLayout()
        password_row.addWidget(self.password_edit, 1)
        self.password_visibility_button = QToolButton()
        self.password_visibility_button.setText("显示")
        self.password_visibility_button.setCheckable(True)
        self.password_visibility_button.setToolTip("显示或隐藏密码")
        password_row.addWidget(self.password_visibility_button)
        self.auto_auth_check = QCheckBox("启用自动认证")
        self.auto_auth_check.setEnabled(True)
        self.auto_auth_check.setToolTip(
            "连续检测确认校园网登录页后自动提交一次；失败即暂停，不会连续重试。"
        )
        auth_layout.addRow("账号：", self.username_edit)
        auth_layout.addRow("密码：", password_row)
        auth_layout.addRow("", self.auto_auth_check)
        root.addWidget(self._group("校园网认证", auth_layout))

        monitor_layout = QFormLayout()
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(MIN_CHECK_INTERVAL, 86400)
        self.interval_spin.setSuffix(" 秒")
        self.wifi_auto_connect_check = QCheckBox("检测前自动连接校园 Wi-Fi")
        self.wifi_profile_edit = QLineEdit()
        self.wifi_profile_edit.setPlaceholderText("CSUST-Student")
        monitor_layout.addRow("检测间隔：", self.interval_spin)
        monitor_layout.addRow("", self.wifi_auto_connect_check)
        monitor_layout.addRow("Wi-Fi 配置：", self.wifi_profile_edit)
        monitor_layout.addRow("", QLabel("最低 30 秒；较小输入会自动纠正为 30。"))
        root.addWidget(self._group("网络监测", monitor_layout))

        proxy_layout = QFormLayout()
        self.proxy_management_check = QCheckBox("校园网重新认证时临时关闭 Windows 系统代理")
        self.proxy_combo = QComboBox()
        for key, label, supported in proxy_catalog():
            self.proxy_combo.addItem(label, {"key": key, "supported": supported})
        self.proxy_notice = QLabel()
        self.proxy_notice.setWordWrap(True)
        self.restore_proxy_check = QCheckBox("认证完成后恢复 Windows 系统代理原设置")
        proxy_file_row = QHBoxLayout()
        self.proxy_path_edit = QLineEdit()
        self.proxy_path_edit.setReadOnly(True)
        self.proxy_browse_button = QPushButton("选择代理程序")
        self.proxy_detect_button = QPushButton("自动检测")
        proxy_file_row.addWidget(self.proxy_path_edit, 1)
        proxy_file_row.addWidget(self.proxy_detect_button)
        proxy_file_row.addWidget(self.proxy_browse_button)
        proxy_layout.addRow("", self.proxy_management_check)
        proxy_layout.addRow("代理软件：", self.proxy_combo)
        proxy_layout.addRow("支持状态：", self.proxy_notice)
        proxy_layout.addRow("代理程序：", proxy_file_row)
        proxy_layout.addRow("", self.restore_proxy_check)
        root.addWidget(self._group("代理软件", proxy_layout))

        windows_layout = QVBoxLayout()
        self.autostart_check = QCheckBox("Windows 开机自动运行")
        self.minimize_check = QCheckBox("关闭窗口时最小化到系统托盘")
        windows_layout.addWidget(self.autostart_check)
        windows_layout.addWidget(self.minimize_check)
        root.addWidget(self._group("Windows", windows_layout))

        action_layout = QHBoxLayout()
        self.save_button = QPushButton("保存设置")
        self.detect_button = QPushButton("立即检测")
        self.auth_button = QPushButton("立即认证")
        self.retry_button = QPushButton("重新尝试认证")
        self.retry_button.setEnabled(False)
        self.exit_button = QPushButton("退出程序")
        for button in (
            self.save_button,
            self.detect_button,
            self.auth_button,
            self.retry_button,
            self.exit_button,
        ):
            action_layout.addWidget(button)
        root.addWidget(self._group("操作", action_layout))

        log_layout = QVBoxLayout()
        log_layout.addWidget(QLabel("日志保留：5 天（固定）"))
        log_buttons = QHBoxLayout()
        self.view_log_button = QPushButton("查看今日日志")
        self.open_log_dir_button = QPushButton("打开日志文件夹")
        log_buttons.addWidget(self.view_log_button)
        log_buttons.addWidget(self.open_log_dir_button)
        log_layout.addLayout(log_buttons)
        self.recent_events = QTextEdit()
        self.recent_events.setReadOnly(True)
        self.recent_events.document().setMaximumBlockCount(500)
        self.recent_events.setMaximumHeight(100)
        self.recent_events.setPlainText("应用已启动。当前不执行网络检测、认证或系统代理写入。")
        log_layout.addWidget(QLabel("最近事件："))
        log_layout.addWidget(self.recent_events)
        root.addWidget(self._group("日志", log_layout))

        root.addStretch(1)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(content)
        self.setCentralWidget(scroll)

        self.proxy_combo.currentIndexChanged.connect(self._update_proxy_notice)
        self.password_visibility_button.toggled.connect(self._toggle_password_visibility)
        self.proxy_detect_button.clicked.connect(self._detect_proxy)
        self.proxy_browse_button.clicked.connect(self._select_proxy_executable)
        self.save_button.clicked.connect(self._save)
        self.detect_button.clicked.connect(self._manual_detect)
        self.auth_button.clicked.connect(self._manual_auth)
        self.retry_button.clicked.connect(self._retry_authentication)
        self.view_log_button.clicked.connect(self._view_today_log)
        self.open_log_dir_button.clicked.connect(self._open_log_dir)
        self.exit_button.clicked.connect(self.quit_application)

    def _build_tray(self) -> None:
        icon = self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
        self.setWindowIcon(icon)
        self.tray = QSystemTrayIcon(icon, self)
        self.tray.setToolTip(APP_NAME)
        menu = QMenu()
        open_action = QAction("打开主界面", self)
        detect_action = QAction("立即检测网络", self)
        auth_action = QAction("立即认证", self)
        self.pause_action = QAction("暂停自动认证", self)
        self.pause_action.setCheckable(True)
        logs_action = QAction("打开日志文件夹", self)
        exit_action = QAction("退出程序", self)
        open_action.triggered.connect(self.show_normal)
        detect_action.triggered.connect(self._manual_detect)
        auth_action.triggered.connect(self._manual_auth)
        self.pause_action.toggled.connect(self._toggle_pause)
        logs_action.triggered.connect(self._open_log_dir)
        exit_action.triggered.connect(self.quit_application)
        for action in (open_action, detect_action, auth_action, self.pause_action, logs_action):
            menu.addAction(action)
        menu.addSeparator()
        menu.addAction(exit_action)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._tray_activated)

    def _load_settings(self) -> None:
        config = self.controller.config
        self.username_edit.setText(str(config["username"]))
        password, warning = self.controller.load_password()
        self.password_edit.setText(password)
        if warning:
            self._event(warning)
        auto_auth_enabled = bool(config.get("auto_auth", False))
        self.auto_auth_check.setChecked(auto_auth_enabled)
        self.pause_action.blockSignals(True)
        self.pause_action.setChecked(not auto_auth_enabled)
        self.pause_action.setText("暂停自动认证" if auto_auth_enabled else "恢复自动认证")
        self.pause_action.blockSignals(False)
        self.interval_spin.setValue(int(config["monitor_interval"]))
        self.wifi_auto_connect_check.setChecked(bool(config.get("wifi_auto_connect", True)))
        self.wifi_profile_edit.setText(str(config.get("wifi_profile", "CSUST-Student")))
        self.proxy_management_check.setChecked(bool(config["proxy_management"]))
        for index in range(self.proxy_combo.count()):
            if self.proxy_combo.itemData(index)["key"] == config["proxy_type"]:
                self.proxy_combo.setCurrentIndex(index)
                break
        self.proxy_path_edit.setText(str(config["proxy_exe_path"]))
        self.restore_proxy_check.setChecked(bool(config["restore_proxy"]))
        self.autostart_check.setChecked(bool(config["windows_autostart"]))
        self.minimize_check.setChecked(bool(config["minimize_to_tray"]))
        self._update_proxy_notice()
        self._refresh_system_proxy_status()
        self._configure_monitor_timer()

    def _settings_from_ui(self) -> dict[str, object]:
        proxy_data = self.proxy_combo.currentData()
        return {
            "username": self.username_edit.text(),
            "auto_auth": self.auto_auth_check.isChecked(),
            "wifi_auto_connect": self.wifi_auto_connect_check.isChecked(),
            "wifi_profile": self.wifi_profile_edit.text(),
            "monitor_interval": self.interval_spin.value(),
            "proxy_management": self.proxy_management_check.isChecked(),
            "proxy_type": proxy_data["key"],
            "proxy_exe_path": self.proxy_path_edit.text(),
            "restore_proxy": self.restore_proxy_check.isChecked(),
            "windows_autostart": self.autostart_check.isChecked(),
            "minimize_to_tray": self.minimize_check.isChecked(),
        }

    def _save(self) -> None:
        try:
            result = self.controller.save_settings(self._settings_from_ui(), self.password_edit.text())
        except Exception as exc:
            self.controller.logger.error("Settings save failed: %s", type(exc).__name__)
            message = f"设置保存失败：{exc}"
            self._event(message)
            self.statusBar().showMessage(message, 8000)
            QMessageBox.critical(self, APP_NAME, message)
            return
        self.interval_spin.setValue(int(result.config["monitor_interval"]))
        self._configure_monitor_timer()
        self.autostart_check.setChecked(bool(result.config["windows_autostart"]))
        if result.warnings:
            message = "；".join(result.warnings)
            self._event(message)
            QMessageBox.warning(self, APP_NAME, f"设置已保存，但：{message}")
        else:
            self._event("设置已保存；密码未写入 config.json 或日志。")
            self.statusBar().showMessage("设置已保存", 5000)

    def _toggle_password_visibility(self, visible: bool) -> None:
        mode = QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
        self.password_edit.setEchoMode(mode)
        self.password_visibility_button.setText("隐藏" if visible else "显示")

    def _select_proxy_executable(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择代理程序", "", "Windows 程序 (*.exe)")
        if path:
            self.proxy_path_edit.setText(path)

    def _detect_proxy(self) -> None:
        data = self.proxy_combo.currentData()
        if not data["supported"]:
            message = "该代理适配器尚未支持。"
        elif data["key"] == "none":
            message = "当前选择不处理代理软件。"
        else:
            client_name = self.proxy_combo.currentText()
            adapter = create_proxy_adapter(
                data["key"],
                exe_path=self.proxy_path_edit.text(),
                dry_run=True,
            )
            executable = adapter.locate_executable()
            app_running = bool(getattr(adapter, "is_application_running", adapter.is_running)())
            proxy_active = adapter.is_running()
            if executable is not None:
                self.proxy_path_edit.setText(str(executable))
            if app_running:
                state_text = "开启" if proxy_active else "关闭"
                message = f"{client_name} 正在运行；Windows 系统代理当前{state_text}。仅只读检测。"
            elif executable is not None:
                message = f"已找到 {client_name} 程序；应用当前未运行。仅只读检测。"
            else:
                message = "未自动找到代理程序，可手工选择 EXE；系统代理管理不依赖程序路径。"
        self.proxy_notice.setText(message)
        self._refresh_system_proxy_status()
        self._event(message)
        self.statusBar().showMessage(message, 6000)

    def _update_proxy_notice(self) -> None:
        data = self.proxy_combo.currentData()
        if data["key"] == "none":
            self.proxy_notice.setText("可用：不执行任何代理软件操作。")
        elif data["supported"]:
            self.proxy_notice.setText(
                "支持 Windows 系统代理模式：保持代理软件运行，认证前后临时关闭并恢复系统代理。TUN／增强模式需在客户端关闭；不自动切换。"
            )
        else:
            self.proxy_notice.setText("待支持：本轮仅保存选择，不修改代理软件或 Windows 系统代理。")

    def _manual_detect(self) -> None:
        self._schedule_network_check(manual=True)

    def _scheduled_detect(self) -> None:
        self._schedule_network_check(manual=False)

    def _configure_monitor_timer(self) -> None:
        interval_seconds = max(MIN_CHECK_INTERVAL, int(self.interval_spin.value()))
        self._monitor_timer.setInterval(interval_seconds * 1000)
        if self.controller.state_machine.automatic_authentication_paused:
            self.monitor_label.setText(
                f"● 自动认证已暂停；网络监测继续运行（每 {interval_seconds} 秒）"
            )
        else:
            self.monitor_label.setText(f"● 运行中（每 {interval_seconds} 秒，无代理直连）")

    def _schedule_network_check(self, *, manual: bool) -> None:
        if self._closing:
            return
        if self._authentication_running:
            if manual:
                self._event("手动认证正在进行，请等待系统代理恢复。")
            return
        if self._network_check_running:
            if manual:
                self._event("网络检测正在进行，请稍候。")
            return
        self._network_check_running = True
        self._active_check_manual = manual
        self.detect_button.setEnabled(False)
        self.monitor_label.setText("● 正在后台检测（无代理直连）")
        worker = NetworkCheckWorker(self.controller)
        worker.signals.completed.connect(self._network_check_completed)
        worker.signals.failed.connect(self._network_check_failed)
        self._thread_pool.start(worker)

    @Slot(object)
    def _network_check_completed(self, result: DetectionResult) -> None:
        if self._closing:
            return
        check_was_manual = self._active_check_manual
        self._network_check_running = False
        self._active_check_manual = False
        self.detect_button.setEnabled(True)
        labels = {
            NetworkStatus.CONNECTED: "● 已连接（检测已绕过代理）",
            NetworkStatus.SUSPECTED_OFFLINE: "● 疑似离线",
            NetworkStatus.AUTH_REQUIRED: "● 需要认证",
            NetworkStatus.NETWORK_UNAVAILABLE: "● 网络不可用",
        }
        self.status_label.setText(labels[result.status])
        machine_result = self.controller.process_detection(result)
        self._apply_state_machine_result(machine_result)
        self._refresh_system_proxy_status()
        self._event(result.message)
        self.statusBar().showMessage(result.message, 8000)
        self._configure_monitor_timer()
        if (
            not check_was_manual
            and result.status is NetworkStatus.AUTH_REQUIRED
            and self.auto_auth_check.isChecked()
            and not machine_result.automatic_authentication_paused
        ):
            self._start_authentication(automatic=True)

    @Slot(str)
    def _network_check_failed(self, message: str) -> None:
        if self._closing:
            return
        self.controller.invalidate_detection()
        self._network_check_running = False
        self._active_check_manual = False
        self.detect_button.setEnabled(True)
        self.status_label.setText("● 检测异常")
        self._refresh_system_proxy_status()
        self._event(message)
        self.statusBar().showMessage(message, 8000)
        self._configure_monitor_timer()

    def _refresh_system_proxy_status(self) -> None:
        try:
            active = WindowsSystemProxy().is_active()
        except Exception:
            self.system_proxy_status_label.setText("● 读取失败")
            return
        if active:
            self.system_proxy_status_label.setText("● 开启（网络检测仍会主动绕过）")
        else:
            self.system_proxy_status_label.setText("● 关闭")

    def _manual_auth(self) -> None:
        self._start_authentication(automatic=False)

    def _start_authentication(self, *, automatic: bool) -> None:
        if self._closing:
            return
        if self._authentication_running:
            if not automatic:
                self._event("认证正在进行，请勿重复提交。")
            return
        if self._network_check_running:
            if not automatic:
                self._event("网络检测正在进行，请等待检测完成后再认证。")
            return
        self._authentication_running = True
        self._authentication_automatic = automatic
        self._resume_monitor_after_auth = self._monitor_timer.isActive()
        self._monitor_timer.stop()
        self.save_button.setEnabled(False)
        self.detect_button.setEnabled(False)
        self.auth_button.setEnabled(False)
        self.retry_button.setEnabled(False)
        if automatic:
            self.monitor_label.setText("● 已确认登录页，正在自动认证一次")
            self._event("已连续确认校园网登录页，开始单次自动认证。")
        else:
            self.monitor_label.setText("● 正在执行单次手动认证")
        worker = AuthenticationWorker(self.controller)
        worker.signals.completed.connect(self._authentication_completed)
        worker.signals.failed.connect(self._authentication_failed)
        self._thread_pool.start(worker)

    def _retry_authentication(self) -> None:
        self._manual_auth()

    def _finish_authentication_worker(self) -> None:
        self._authentication_running = False
        self._authentication_automatic = False
        self.save_button.setEnabled(True)
        self.detect_button.setEnabled(True)
        self.auth_button.setEnabled(True)
        if self._resume_monitor_after_auth:
            self._monitor_timer.start()
        self._resume_monitor_after_auth = False
        self._configure_monitor_timer()
        self._refresh_system_proxy_status()

    @Slot(object)
    def _authentication_completed(self, result: StateMachineResult) -> None:
        if self._closing:
            return
        self._finish_authentication_worker()
        self._apply_state_machine_result(result, from_authentication=True)
        self._event(result.message)
        self.statusBar().showMessage(result.message, 10000)

    @Slot(str)
    def _authentication_failed(self, message: str) -> None:
        if self._closing:
            return
        self._finish_authentication_worker()
        self.status_label.setText("● 认证执行异常")
        self._event(message)
        self.statusBar().showMessage(message, 10000)

    def _apply_state_machine_result(
        self,
        result: StateMachineResult,
        *,
        from_authentication: bool = False,
    ) -> None:
        self.retry_button.setEnabled(result.automatic_authentication_paused)
        if result.state is AppState.AUTH_STOPPED:
            self.status_label.setText("● 认证失败（已停止重试）")
            self.monitor_label.setText("● 自动认证保持关闭；可手动重新尝试")
        elif (
            result.state is AppState.CONNECTED
            and from_authentication
            and AppState.AUTHENTICATING in result.transitions
            and AppState.VERIFYING in result.transitions
        ):
            self.status_label.setText("● 已连接（认证后直连验证通过）")

    def _toggle_pause(self, paused: bool) -> None:
        self.pause_action.setText("恢复自动认证" if paused else "暂停自动认证")
        self.auto_auth_check.setChecked(not paused)
        self._event("自动认证已暂停。" if paused else "自动认证已恢复；请保存设置以便下次启动继续生效。")

    def _view_today_log(self) -> None:
        self._open_path(self.controller.current_log_path())

    def _open_log_dir(self) -> None:
        self.controller.logs_path.mkdir(parents=True, exist_ok=True)
        self._open_path(self.controller.logs_path)

    @staticmethod
    def _open_path(path: Path) -> None:
        if os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        else:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _event(self, text: str) -> None:
        self.recent_events.append(text)

    def _tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self.show_normal()

    def show_normal(self) -> None:
        self.show()
        self.raise_()
        self.activateWindow()

    def start(self, *, background: bool) -> None:
        self.tray.show()
        self._configure_monitor_timer()
        self._monitor_timer.start()
        if background:
            self.hide()
        else:
            self.show_normal()

    def closeEvent(self, event: QCloseEvent) -> None:
        if not self._allow_real_close and self.minimize_check.isChecked():
            event.ignore()
            self.hide()
            if not self._tray_hint_shown:
                self.tray.showMessage(APP_NAME, "程序仍在系统托盘运行。", QSystemTrayIcon.MessageIcon.Information, 2500)
                self._tray_hint_shown = True
            return
        self._allow_real_close = True
        if self._thread_pool.activeThreadCount():
            event.ignore()
            if not self._closing:
                self._closing = True
                self._monitor_timer.stop()
                self.centralWidget().setEnabled(False)
                self.tray.contextMenu().setEnabled(False)
                self._event("正在退出：等待后台任务结束及系统代理恢复，请稍候。")
                self._shutdown_timer.start()
            return
        self._closing = True
        self._monitor_timer.stop()
        self._shutdown_timer.stop()
        self.tray.hide()
        event.accept()
        QApplication.quit()

    def _finish_shutdown(self) -> None:
        # Keep Qt's event loop alive while workers finish, including proxy
        # restoration in authentication_bypass. Never destroy a live pool.
        if not self._thread_pool.activeThreadCount():
            self.close()

    def quit_application(self) -> None:
        self._allow_real_close = True
        self.close()
