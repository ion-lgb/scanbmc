#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ScanBMC GUI —— 局域网 BMC 扫描器图形界面（PySide6）

扫描核心完全复用 scanbmc.py：后台 QThread 中调用 scan()，
通过 Qt 信号（跨线程自动 QueuedConnection）回传进度与结果。

用法：
    .venv/bin/python scanbmc_gui.py            # 开发运行
    ./build_app.sh                             # 打包成 macOS .app（dist/ScanBMC.app）
"""
from __future__ import annotations

import os
import sys
import threading
import time
from typing import List, Optional

from PySide6.QtCore import QThread, QTimer, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

import scanbmc as core
from scanbmc import HostResult, ProbeStats, ScanConfig

DEFAULT_TCP_PORTS_STR = ",".join(str(p) for p in core.DEFAULT_TCP_PORTS)
MAX_HOSTS = 8192

# 置信度 -> 文字颜色（确认=绿、可能=橙、疑似=灰）
CONF_COLORS = {
    core.CONF_CONFIRMED: QColor("#1a7f37"),
    core.CONF_LIKELY: QColor("#9a6700"),
    core.CONF_POSSIBLE: QColor("#57606a"),
}
WARN_BG = QColor("#fff3cd")  # 弱配置（匿名登录/空用户名）警示行底色


class ScanWorker(QThread):
    """后台扫描线程：参数校验与扫描都在这里跑，绝不阻塞界面。

    run() 中调用 scanbmc.scan()；scan() 的 cancel_event 检查点让
    “停止”按钮能及时打断，进度通过 progress_cb 回流为 Qt 信号。
    """

    progress = Signal(int, int, str)            # (done, total, phase)
    finished_scan = Signal(list, bool, float)   # (results, degraded, elapsed)
    failed = Signal(str)                        # 参数错误等
    cancelled = Signal(list)                    # 用户主动停止，附部分结果
    notice = Signal(str)                        # 提示信息（如并发收敛）

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.cancel_event = threading.Event()
        self.targets_spec = ""
        self.exclude_spec = ""
        self.ports_spec = DEFAULT_TCP_PORTS_STR
        self.workers = 256
        self.timeout = 1.0
        self.retries = 0
        self.udp = True
        self.web = True
        self.redfish = True
        self.arp_only = False

    def stop(self) -> None:
        """协作式停止：scan() 在批次间检查该标志。"""
        self.cancel_event.set()

    def run(self) -> None:  # noqa: D401 - QThread 入口
        # 参数解析与 CLI main() 保持一致
        try:
            specs = [s.strip() for s in self.targets_spec.split(",") if s.strip()]
            if not specs:
                nets = core.detect_local_networks()
                if not nets:
                    self.failed.emit("无法自动检测本机网段，请在“目标”里手动指定（如 192.168.1.0/24）。")
                    return
                specs = [str(n) for n in nets]
            excludes = [s.strip() for s in self.exclude_spec.split(",") if s.strip()]

            if self.arp_only:
                neighbors = core.filter_to_specs(core.arp_neighbors(), specs)
                if not neighbors:
                    self.failed.emit("ARP 表中没有落在目标范围内的地址，请去掉“ARP 快速模式”或更换目标。")
                    return
                targets = core.build_targets(neighbors, excludes)
            else:
                targets = core.build_targets(specs, excludes)
            tcp_ports = core.parse_ports(self.ports_spec)
        except ValueError as exc:
            self.failed.emit(f"参数错误：{exc}")
            return

        if not targets:
            self.failed.emit("目标列表为空，请检查“目标 / 排除”设置。")
            return
        if len(targets) > MAX_HOSTS:
            self.failed.emit(f"目标数 {len(targets)} 超过上限 {MAX_HOSTS}，请缩小网段范围。")
            return

        # 每个并发探测占一个句柄：先尝试抬升，抬不动就收敛并发数
        requested = max(1, self.workers)
        soft, _ = core.ensure_fd_limit(requested + core.FD_HEADROOM)
        workers = core.cap_workers(requested, soft)
        if workers < requested:
            self.notice.emit(
                f"本进程文件句柄上限为 {soft}，并发数已从 {requested} 收敛到 {workers}。"
            )

        cfg = ScanConfig(
            tcp_ports=tcp_ports,
            workers=workers,
            timeout=max(0.1, self.timeout),
            retries=max(0, self.retries),
            udp=self.udp,
            web=self.web,
            redfish=self.redfish,
            progress=False,  # GUI 用 progress_cb，不需要文本进度条
            cancel_event=self.cancel_event,
            progress_cb=self.progress.emit,
        )

        stats = ProbeStats()
        started = time.monotonic()
        try:
            results = core.scan(targets, cfg, stats=stats)
        except Exception as exc:  # noqa: BLE001 - 任何异常都回传界面而非崩溃
            self.failed.emit(f"扫描过程出错：{exc}")
            return
        elapsed = time.monotonic() - started

        if self.cancel_event.is_set():
            self.cancelled.emit(results)
            return

        # 与 CLI 一致的“结果不可信”判定（CLI 中对应退出码 3）
        systemic = stats.systemic_ratio()
        degraded = systemic >= 0.5 and stats.systemic_failures > 0
        self.finished_scan.emit(results, degraded, elapsed)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"ScanBMC {core.__version__} — 局域网 BMC 扫描器")
        self.resize(1240, 720)
        self.worker: Optional[ScanWorker] = None
        self._build_ui()

    # ---------- 界面搭建 ----------

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        # 参数区
        form_box = QGroupBox("扫描参数")
        form = QFormLayout(form_box)

        self.targets_edit = QLineEdit()
        self.targets_edit.setMinimumHeight(36)
        self.targets_edit.setMinimumWidth(560)
        self.targets_edit.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self.targets_edit.setPlaceholderText("例：192.168.1.0/24、10.0.0.1-99、192.168.1.50，逗号分隔；留空自动检测本机网段")
        self.targets_edit.setToolTip(
            "扫描目标，支持：\n"
            "· CIDR 网段：192.168.1.0/24\n"
            "· IP 区间：10.0.0.1-99\n"
            "· 单个 IP：192.168.1.50\n"
            "· 多个目标用英文逗号分隔\n"
            "留空 = 自动检测本机所在网段"
        )
        self.exclude_edit = QLineEdit()
        self.exclude_edit.setMinimumHeight(36)
        self.exclude_edit.setMinimumWidth(560)
        self.exclude_edit.setPlaceholderText("例：192.168.1.50（格式同“目标”，可选）")
        self.exclude_edit.setToolTip("从扫描中排除的地址，格式同“目标”。")

        self.ports_edit = QLineEdit(DEFAULT_TCP_PORTS_STR)
        self.ports_edit.setMinimumHeight(36)
        self.ports_edit.setMinimumWidth(560)
        self.ports_edit.setToolTip(
            "要探测的 TCP 端口，支持：\n"
            "· 80,443,623\n"
            "· 区间：5900-5910\n"
            f"默认：{DEFAULT_TCP_PORTS_STR}"
        )
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, 1024)
        self.workers_spin.setValue(256)
        self.workers_spin.setToolTip("同时进行的探测数。越大越快，但更吃句柄/带宽；程序会自动收敛到句柄上限内。")
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.1, 10.0)
        self.timeout_spin.setSingleStep(0.1)
        self.timeout_spin.setValue(1.0)
        self.timeout_spin.setToolTip("单次探测超时（秒）。越小越快，但丢包环境下会漏报。")
        self.retries_spin = QSpinBox()
        self.retries_spin.setRange(0, 5)
        self.retries_spin.setValue(0)
        self.retries_spin.setToolTip("超时重试次数。局域网稳定时 0 即可；丢包严重可调大（耗时成倍增加）。")

        form.addRow("目标（留空=自动检测）", self.targets_edit)
        form.addRow("排除（可选）", self.exclude_edit)
        form.addRow("TCP 端口", self.ports_edit)
        form.addRow("并发数", self.workers_spin)
        form.addRow("超时（秒）", self.timeout_spin)
        form.addRow("重试次数", self.retries_spin)

        self.udp_cb = QCheckBox("UDP/623 IPMI")
        self.udp_cb.setChecked(True)
        self.web_cb = QCheckBox("Web 指纹")
        self.web_cb.setChecked(True)
        self.redfish_cb = QCheckBox("Redfish")
        self.redfish_cb.setChecked(True)
        self.arp_cb = QCheckBox("ARP 快速模式")
        self.all_cb = QCheckBox("显示所有存活主机")
        opts = QHBoxLayout()
        for cb in (self.udp_cb, self.web_cb, self.redfish_cb, self.arp_cb, self.all_cb):
            opts.addWidget(cb)
        opts.addStretch(1)
        form.addRow("探测项", opts)

        root.addWidget(form_box)

        # 按钮行
        btn_row = QHBoxLayout()
        self.start_btn = QPushButton("开始扫描")
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setEnabled(False)
        self.clear_btn = QPushButton("清空结果")
        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.stop_btn)
        btn_row.addStretch(1)
        btn_row.addWidget(self.clear_btn)
        root.addLayout(btn_row)

        # 进度
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1000)
        self.progress_bar.setValue(0)
        self.status_label = QLabel("就绪")
        root.addWidget(self.progress_bar)
        root.addWidget(self.status_label)

        # 结果表格
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["IP 地址", "置信度", "设备类型", "开放端口", "判定依据"])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        for col in range(4):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        root.addWidget(self.table)

        self.statusBar().showMessage("就绪")

        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.clear_btn.clicked.connect(lambda: self.table.setRowCount(0))

    # ---------- 扫描流程 ----------

    def start_scan(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            return
        w = ScanWorker(self)
        w.targets_spec = self.targets_edit.text().strip()
        w.exclude_spec = self.exclude_edit.text().strip()
        w.ports_spec = self.ports_edit.text().strip() or DEFAULT_TCP_PORTS_STR
        w.workers = self.workers_spin.value()
        w.timeout = self.timeout_spin.value()
        w.retries = self.retries_spin.value()
        w.udp = self.udp_cb.isChecked()
        w.web = self.web_cb.isChecked()
        w.redfish = self.redfish_cb.isChecked()
        w.arp_only = self.arp_cb.isChecked()
        self.worker = w

        w.progress.connect(self.on_progress)
        w.finished_scan.connect(self.on_finished)
        w.failed.connect(self.on_failed)
        w.cancelled.connect(self.on_cancelled)
        w.notice.connect(self.statusBar().showMessage)
        w.finished.connect(self.on_worker_finished)  # 线程结束统一复位

        self.table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.status_label.setText("准备中…")
        self._set_busy(True)
        w.start()

    def stop_scan(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            self.status_label.setText("正在停止…")
            self.worker.stop()

    def _set_busy(self, busy: bool) -> None:
        self.start_btn.setEnabled(not busy)
        self.stop_btn.setEnabled(busy)
        for wdg in (
            self.targets_edit,
            self.exclude_edit,
            self.ports_edit,
            self.workers_spin,
            self.timeout_spin,
            self.retries_spin,
            self.udp_cb,
            self.web_cb,
            self.redfish_cb,
            self.arp_cb,
        ):
            wdg.setEnabled(not busy)

    # ---------- 信号槽 ----------

    def on_progress(self, done: int, total: int, phase: str) -> None:
        name = "端口发现" if phase == "probe" else "指纹识别"
        self.progress_bar.setMaximum(max(total, 1))
        self.progress_bar.setValue(done)
        self.status_label.setText(f"{name}：{done}/{total}")

    def on_finished(self, results: List[HostResult], degraded: bool, elapsed: float) -> None:
        self._populate_table(results)
        alive, bmc = len(results), sum(1 for r in results if r.is_bmc)
        self.status_label.setText(f"完成：耗时 {elapsed:.1f}s，存活主机 {alive} 台，判定为 BMC {bmc} 台")
        if degraded:
            QMessageBox.warning(
                self,
                "扫描结果不可信",
                "大量探测在本机侧就失败了（网卡未连接 / 目标网段无路由 / 并发过高耗尽句柄），\n"
                "本次结果不可信，请检查网络后重试，或降低并发数。",
            )

    def on_cancelled(self, results: List[HostResult]) -> None:
        self._populate_table(results)
        self.status_label.setText(f"已停止，显示已完成的 {len(results)} 台存活主机。")

    def on_failed(self, message: str) -> None:
        self.status_label.setText("失败")
        QMessageBox.critical(self, "错误", message)

    def on_worker_finished(self) -> None:
        self._set_busy(False)
        self.worker = None

    # ---------- 表格渲染 ----------

    def _populate_table(self, results: List[HostResult]) -> None:
        show_all = self.all_cb.isChecked()
        rows = [r for r in results if show_all or r.is_bmc]
        self.table.setRowCount(len(rows))
        for i, host in enumerate(rows):
            warned = any(e.startswith("⚠") for e in host.evidence)

            def item(text: str) -> QTableWidgetItem:
                it = QTableWidgetItem(text)
                if warned:
                    it.setBackground(WARN_BG)
                return it

            self.table.setItem(i, 0, item(host.ip))
            conf_item = item(host.confidence or "—")
            color = CONF_COLORS.get(host.confidence)
            if color is not None:
                conf_item.setForeground(color)
            self.table.setItem(i, 1, conf_item)
            self.table.setItem(i, 2, item(host.vendor or "—"))
            self.table.setItem(i, 3, item(host.open_ports_str()))
            self.table.setItem(i, 4, item("；".join(host.evidence)))

    # ---------- 收尾 ----------

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        if self.worker is not None and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(3000)
        event.accept()


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("ScanBMC")
    window = MainWindow()
    window.show()
    # 冒烟测试钩子：SCANBMC_GUI_SMOKE=1 时 2 秒后自动退出，用于 CI/打包验证
    if os.environ.get("SCANBMC_GUI_SMOKE"):
        QTimer.singleShot(2000, app.quit)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
