#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ScanBMC GUI —— 局域网 BMC 扫描器图形界面（PySide6）

扫描核心完全复用 scanbmc.py：后台 QThread 中调用 scan()，
通过 Qt 信号（跨线程自动 QueuedConnection）回传进度与结果。

界面视觉按 claude.ai/design 项目「软件UI设计方向」里的
`ScanBMC 扫描器.dc.html` 设计稿实现：浅色/深色主题、四角刻度装饰卡片、
置信度徽章、细进度条、空状态插图。

用法：
    .venv/bin/python scanbmc_gui.py            # 开发运行
    ./build_app.sh                             # 打包成 macOS .app（dist/ScanBMC.app）
"""
from __future__ import annotations

import os
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import QPointF, QRectF, Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QDoubleSpinBox,
    QFileDialog,
    QFrame,
    QGridLayout,
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
    QStyledItemDelegate,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

import scanbmc as core
from scanbmc import HostResult, ProbeStats, ScanConfig

DEFAULT_TCP_PORTS_STR = ",".join(str(p) for p in core.DEFAULT_TCP_PORTS)
MAX_HOSTS = 8192


# --------------------------------------------------------------------------- #
# 主题配色（对应设计稿 renderVals() 里的浅色/深色 token）
# --------------------------------------------------------------------------- #


def _c(r: int, g: int, b: int, a: int = 255) -> QColor:
    color = QColor(r, g, b)
    color.setAlpha(a)
    return color


def _css(color: QColor) -> str:
    """QColor -> QSS 可用的 rgba() 字符串（Qt 的 alpha 是 0-255，不是 CSS 的 0-1）。"""
    return f"rgba({color.red()},{color.green()},{color.blue()},{color.alpha()})"


LIGHT_THEME: Dict[str, QColor] = {
    "bg": _c(0xF2, 0xF2, 0xF3),
    "surface": _c(0xE9, 0xE9, 0xEA),
    "text": _c(0x1D, 0x1F, 0x20),
    "text_muted": _c(29, 31, 32, 140),
    "text_muted70": _c(29, 31, 32, 179),
    "divider": _c(29, 31, 32, 41),
    "divider_soft": _c(29, 31, 32, 20),
    "accent": _c(0x59, 0x80, 0xA6),
    "accent_tint": _c(0xEE, 0xF6, 0xFF),
    "accent_tint_text": _c(0x2C, 0x45, 0x5D),
    "neutral_tint": _c(0xF5, 0xF5, 0xF8),
    "neutral_tint_text": _c(0x42, 0x42, 0x44),
    "warn_row_bg": _c(89, 128, 166, 20),
    "mark_color": _c(29, 31, 32, 140),
}

DARK_THEME: Dict[str, QColor] = {
    "bg": _c(0x1D, 0x1F, 0x20),
    "surface": _c(0x26, 0x28, 0x2A),
    "text": _c(0xF2, 0xF2, 0xF3),
    "text_muted": _c(242, 242, 243, 140),
    "text_muted70": _c(242, 242, 243, 179),
    "divider": _c(242, 242, 243, 46),
    "divider_soft": _c(242, 242, 243, 26),
    "accent": _c(0x7E, 0xA0, 0xC2),
    "accent_tint": _c(0x1D, 0x2D, 0x3D),
    "accent_tint_text": _c(0xD6, 0xEB, 0xFF),
    "neutral_tint": _c(0x2B, 0x2B, 0x2D),
    "neutral_tint_text": _c(0xE7, 0xE7, 0xEA),
    "warn_row_bg": _c(126, 160, 194, 36),
    "mark_color": _c(242, 242, 243, 140),
}

THEMES = {"light": LIGHT_THEME, "dark": DARK_THEME}

TRANSPARENT = QColor(0, 0, 0, 0)


def _confidence_style(theme: Dict[str, QColor], confidence: str) -> Tuple[QColor, QColor, Optional[QColor]]:
    """返回 (背景色, 文字色, 边框色或 None)，对应设计稿里的置信度徽章样式。"""
    if confidence == core.CONF_CONFIRMED:
        return theme["accent_tint"], theme["accent_tint_text"], None
    if confidence == core.CONF_LIKELY:
        return TRANSPARENT, theme["accent"], theme["accent"]
    if confidence == core.CONF_POSSIBLE:
        return theme["neutral_tint"], theme["neutral_tint_text"], None
    return TRANSPARENT, theme["text_muted"], None


# --------------------------------------------------------------------------- #
# 自定义绘制控件：四角刻度卡片 / 品牌小方块 / 空状态雷达图标 / 置信度徽章
# --------------------------------------------------------------------------- #


class CornerTickFrame(QFrame):
    """带四角十字刻度的边框卡片，呼应设计稿里的蓝图风格装饰边角。"""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("cornerTickFrame")
        self._mark_color = QColor(0, 0, 0, 140)

    def set_mark_color(self, color: QColor) -> None:
        self._mark_color = color
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setPen(QPen(self._mark_color, 1))
        rect = self.rect().adjusted(0, 0, -1, -1)
        half = 5
        for x, y in (
            (rect.left(), rect.top()),
            (rect.right(), rect.top()),
            (rect.left(), rect.bottom()),
            (rect.right(), rect.bottom()),
        ):
            painter.drawLine(x - half, y, x + half, y)
            painter.drawLine(x, y - half, x, y + half)
        painter.end()


class BrandMark(QWidget):
    """左上角的品牌小图标：方框 + 居中实心方点。"""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._color = QColor(0x59, 0x80, 0xA6)
        self.setFixedSize(20, 20)

    def set_color(self, color: QColor) -> None:
        self._color = color
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(self._color, 1.5))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRect(self.rect().adjusted(1, 1, -2, -2))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(self._color)
        cx, cy = self.width() / 2.0, self.height() / 2.0
        painter.drawRect(QRectF(cx - 3, cy - 3, 6, 6))
        painter.end()


class RadarIcon(QWidget):
    """空状态插图：呼应设计稿里的雷达扫描图标。"""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._color = QColor(0x59, 0x80, 0xA6)
        self.setFixedSize(40, 40)

    def set_color(self, color: QColor) -> None:
        self._color = color
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        scale = self.width() / 24.0
        painter.scale(scale, scale)
        painter.setPen(QPen(self._color, 1.5))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(QPointF(12, 12), 9, 9)
        painter.drawEllipse(QPointF(12, 12), 4, 4)
        painter.drawLine(QPointF(12, 12), QPointF(19, 6))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(self._color)
        painter.drawEllipse(QPointF(12, 12), 1.4, 1.4)
        painter.end()


class ConfidenceDelegate(QStyledItemDelegate):
    """把置信度列画成圆角徽章，而不是纯色文字（对应设计稿的 pill 样式）。"""

    def __init__(self, window: "MainWindow", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._window = window

    def paint(self, painter: QPainter, option, index) -> None:  # noqa: N802
        text = index.data() or ""
        bg, fg, border = _confidence_style(self._window.theme, text)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(option.rect).adjusted(6, 6, -6, -6)
        painter.setBrush(bg)
        painter.setPen(QPen(border, 1) if border is not None else Qt.PenStyle.NoPen)
        painter.drawRoundedRect(rect, 3, 3)
        painter.setPen(QPen(fg))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)
        painter.restore()


class ResultsTable(QTableWidget):
    """结果表格：IP 地址列可点击，悬停时切换成手型光标，提示可以点击访问。"""

    def mouseMoveEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        index = self.indexAt(event.pos())
        if index.isValid() and index.column() == 0:
            self.viewport().setCursor(Qt.CursorShape.PointingHandCursor)
        else:
            self.viewport().unsetCursor()
        super().mouseMoveEvent(event)


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

        # 每个并发探测占一个句柄，UDP 探测阶段每个目标还会额外多占 2 个
        # （见 core.udp_fd_reserve）：先尝试抬升，抬不动就收敛并发数
        requested = max(1, self.workers)
        headroom = core.FD_HEADROOM + core.udp_fd_reserve(requested, len(targets), self.udp)
        soft, _ = core.ensure_fd_limit(requested + headroom)
        workers = core.cap_workers(requested, soft, headroom)
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
        self.resize(1240, 760)
        self.worker: Optional[ScanWorker] = None
        self.theme_name = "light"
        self.theme: Dict[str, QColor] = LIGHT_THEME
        self._last_results: List[HostResult] = []
        self._last_meta: dict = {}
        self._displayed_rows: List[HostResult] = []
        self._build_ui()
        self.set_theme("light")

    # ---------- 界面搭建 ----------

    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("central")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(20, 14, 20, 20)
        root.setSpacing(14)

        # ---- 头部：品牌标识 + 主题切换 ----
        header = QHBoxLayout()
        header.setSpacing(13)
        self.brand_mark = BrandMark()
        header.addWidget(self.brand_mark)

        self.title_label = QLabel("ScanBMC")
        title_font = QFont("Barlow Condensed")
        title_font.setPixelSize(18)
        title_font.setWeight(QFont.Weight.DemiBold)
        self.title_label.setFont(title_font)
        header.addWidget(self.title_label)

        self.version_badge = QLabel(f"v{core.__version__}")
        self.version_badge.setObjectName("versionBadge")
        header.addWidget(self.version_badge)

        self.subtitle_label = QLabel("局域网 BMC 扫描器")
        self.subtitle_label.setObjectName("subtitle")
        header.addWidget(self.subtitle_label)
        header.addStretch(1)

        self.light_btn = QPushButton("浅色")
        self.dark_btn = QPushButton("深色")
        for btn in (self.light_btn, self.dark_btn):
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setFlat(True)
        theme_group = QButtonGroup(self)
        theme_group.setExclusive(True)
        theme_group.addButton(self.light_btn)
        theme_group.addButton(self.dark_btn)
        self._theme_group = theme_group
        self.light_btn.clicked.connect(lambda: self.set_theme("light"))
        self.dark_btn.clicked.connect(lambda: self.set_theme("dark"))
        seg = QHBoxLayout()
        seg.setSpacing(0)
        seg.addWidget(self.light_btn)
        seg.addWidget(self.dark_btn)
        header.addLayout(seg)
        root.addLayout(header)

        header_sep = QFrame()
        header_sep.setObjectName("headerSep")
        header_sep.setFixedHeight(1)
        root.addWidget(header_sep)

        # ---- 扫描参数卡片 ----
        self.params_card = CornerTickFrame()
        params_layout = QVBoxLayout(self.params_card)
        params_layout.setContentsMargins(20, 20, 20, 20)
        params_layout.setSpacing(14)

        self.section_label = QLabel("扫描参数")
        self.section_label.setObjectName("sectionLabel")
        params_layout.addWidget(self.section_label)

        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(6)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        def labeled(text: str, widget: QWidget) -> QVBoxLayout:
            box = QVBoxLayout()
            box.setSpacing(5)
            lbl = QLabel(text)
            lbl.setObjectName("fieldLabel")
            box.addWidget(lbl)
            box.addWidget(widget)
            return box

        self.targets_edit = QLineEdit()
        self.targets_edit.setMinimumHeight(36)
        self.targets_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.targets_edit.setPlaceholderText("192.168.1.0/24、10.0.0.1-99")
        self.targets_edit.setToolTip(
            "扫描目标，支持：\n"
            "· CIDR 网段：192.168.1.0/24\n"
            "· IP 区间：10.0.0.1-99\n"
            "· 单个 IP：192.168.1.50\n"
            "· 多个目标用英文逗号分隔\n"
            "留空 = 自动检测本机所在网段"
        )
        grid.addLayout(labeled("目标（留空 = 自动检测本机网段）", self.targets_edit), 0, 0)

        self.exclude_edit = QLineEdit()
        self.exclude_edit.setMinimumHeight(36)
        self.exclude_edit.setPlaceholderText("192.168.1.50")
        self.exclude_edit.setToolTip("从扫描中排除的地址，格式同“目标”。")
        grid.addLayout(labeled("排除（可选）", self.exclude_edit), 0, 1)

        self.ports_edit = QLineEdit(DEFAULT_TCP_PORTS_STR)
        self.ports_edit.setMinimumHeight(36)
        self.ports_edit.setToolTip(
            "要探测的 TCP 端口，支持：\n"
            "· 80,443,623\n"
            "· 区间：5900-5910\n"
            f"默认：{DEFAULT_TCP_PORTS_STR}"
        )
        grid.addLayout(labeled("TCP 端口", self.ports_edit), 1, 0)

        sub = QHBoxLayout()
        sub.setSpacing(14)
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, 1024)
        self.workers_spin.setValue(256)
        self.workers_spin.setMinimumHeight(36)
        self.workers_spin.setToolTip("同时进行的探测数。越大越快，但更吃句柄/带宽；程序会自动收敛到句柄上限内。")
        sub.addLayout(labeled("并发数", self.workers_spin))
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.1, 10.0)
        self.timeout_spin.setSingleStep(0.1)
        self.timeout_spin.setValue(1.0)
        self.timeout_spin.setMinimumHeight(36)
        self.timeout_spin.setToolTip("单次探测超时（秒）。越小越快，但丢包环境下会漏报。")
        sub.addLayout(labeled("超时（秒）", self.timeout_spin))
        self.retries_spin = QSpinBox()
        self.retries_spin.setRange(0, 5)
        self.retries_spin.setValue(0)
        self.retries_spin.setMinimumHeight(36)
        self.retries_spin.setToolTip("超时重试次数。局域网稳定时 0 即可；丢包严重可调大（耗时成倍增加）。")
        sub.addLayout(labeled("重试次数", self.retries_spin))
        grid.addLayout(sub, 1, 1)

        params_layout.addLayout(grid)

        self.probe_label = QLabel("探测项")
        self.probe_label.setObjectName("fieldLabel")
        params_layout.addWidget(self.probe_label)

        opts = QHBoxLayout()
        opts.setSpacing(20)
        self.udp_cb = QCheckBox("UDP/623 IPMI")
        self.udp_cb.setChecked(True)
        self.web_cb = QCheckBox("Web 指纹")
        self.web_cb.setChecked(True)
        self.redfish_cb = QCheckBox("Redfish")
        self.redfish_cb.setChecked(True)
        self.arp_cb = QCheckBox("ARP 快速模式")
        self.all_cb = QCheckBox("显示所有存活主机")
        for cb in (self.udp_cb, self.web_cb, self.redfish_cb, self.arp_cb, self.all_cb):
            opts.addWidget(cb)
        opts.addStretch(1)
        params_layout.addLayout(opts)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.start_btn = QPushButton("▶  开始扫描")
        self.start_btn.setObjectName("primaryBtn")
        self.start_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.stop_btn = QPushButton("■  停止")
        self.stop_btn.setObjectName("secondaryBtn")
        self.stop_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.stop_btn.setEnabled(False)
        self.clear_btn = QPushButton("清空结果")
        self.clear_btn.setObjectName("textBtn")
        self.clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.stop_btn)
        btn_row.addWidget(self.clear_btn)
        btn_row.addStretch(1)

        self.progress_widget = QWidget()
        prog_layout = QHBoxLayout(self.progress_widget)
        prog_layout.setContentsMargins(0, 0, 0, 0)
        prog_layout.setSpacing(10)
        self.status_label = QLabel("")
        self.status_label.setObjectName("statusLabel")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1000)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setFixedWidth(180)
        prog_layout.addWidget(self.status_label)
        prog_layout.addWidget(self.progress_bar)
        self.progress_widget.setVisible(False)
        btn_row.addWidget(self.progress_widget)

        params_layout.addLayout(btn_row)
        root.addWidget(self.params_card)

        # ---- 结果区：表头 + 表格 / 空状态卡片 ----
        self.results_header = QWidget()
        rh_layout = QHBoxLayout(self.results_header)
        rh_layout.setContentsMargins(0, 0, 0, 0)
        self.results_title = QLabel("扫描结果")
        self.results_title.setObjectName("resultsTitle")
        rh_layout.addWidget(self.results_title)
        rh_layout.addStretch(1)
        self.summary_label = QLabel("")
        self.summary_label.setObjectName("summaryLabel")
        rh_layout.addWidget(self.summary_label)
        self.export_btn = QPushButton("导出 JSON")
        self.export_btn.setObjectName("textBtn")
        self.export_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        rh_layout.addWidget(self.export_btn)
        root.addWidget(self.results_header)

        self.table = ResultsTable(0, 5)
        self.table.setHorizontalHeaderLabels(["IP 地址", "置信度", "设备类型", "开放端口", "判定依据"])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setMouseTracking(True)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        for col in range(4):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._confidence_delegate = ConfidenceDelegate(self, self.table)
        self.table.setItemDelegateForColumn(1, self._confidence_delegate)
        self.table.cellClicked.connect(self.on_cell_clicked)
        root.addWidget(self.table, 1)

        self.empty_card = CornerTickFrame()
        empty_layout = QVBoxLayout(self.empty_card)
        empty_layout.setContentsMargins(40, 54, 40, 54)
        empty_layout.setSpacing(8)
        self.radar_icon = RadarIcon()
        empty_layout.addWidget(self.radar_icon, 0, Qt.AlignmentFlag.AlignHCenter)
        self.empty_title = QLabel("还没有扫描结果")
        self.empty_title.setObjectName("emptyTitle")
        self.empty_title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        empty_layout.addWidget(self.empty_title)
        self.empty_body = QLabel()
        self.empty_body.setObjectName("emptyBody")
        self.empty_body.setWordWrap(True)
        self.empty_body.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.empty_body.setMaximumWidth(420)
        empty_layout.addWidget(self.empty_body, 0, Qt.AlignmentFlag.AlignHCenter)
        self.empty_footnote = QLabel("默认探测 80、443、623 等常用端口，纯只读，不会尝试登录或爆破。")
        self.empty_footnote.setObjectName("emptyFootnote")
        self.empty_footnote.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        empty_layout.addWidget(self.empty_footnote)
        root.addWidget(self.empty_card, 1)

        self.statusBar().showMessage("就绪")

        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.clear_btn.clicked.connect(self.clear_results)
        self.export_btn.clicked.connect(self.export_results)

        self._set_empty_text(scanning=False)
        self._show_results(False)

    # ---------- 主题 ----------

    def set_theme(self, name: str) -> None:
        self.theme_name = name
        self.theme = THEMES[name]
        self.light_btn.setChecked(name == "light")
        self.dark_btn.setChecked(name == "dark")
        self._apply_theme()

    def _apply_theme(self) -> None:
        t = self.theme
        self.setStyleSheet(f"""
            QWidget#central {{ background: {_css(t['bg'])}; }}
            QMainWindow {{ background: {_css(t['bg'])}; }}
            QLabel {{ color: {_css(t['text'])}; }}
            QLabel#fieldLabel {{ color: {_css(t['text_muted70'])}; font-size: 12px; }}
            QLabel#sectionLabel {{ color: {_css(t['accent'])}; font-size: 10px; font-weight: 600; letter-spacing: 1px; }}
            QLabel#versionBadge {{ background: {_css(t['neutral_tint'])}; color: {_css(t['neutral_tint_text'])};
                font-size: 11px; padding: 3px 8px; border-radius: 3px; }}
            QLabel#subtitle {{ color: {_css(t['text_muted'])}; font-size: 13px; }}
            QLabel#resultsTitle {{ font-size: 16px; font-weight: 600; }}
            QLabel#summaryLabel {{ color: {_css(t['accent_tint_text'])}; font-size: 13px; }}
            QLabel#statusLabel {{ color: {_css(t['text_muted'])}; font-size: 12px; }}
            QLabel#emptyTitle {{ font-size: 18px; font-weight: 600; }}
            QLabel#emptyBody {{ color: {_css(t['text_muted70'])}; font-size: 14px; }}
            QLabel#emptyFootnote {{ color: {_css(t['text_muted'])}; font-size: 12px; }}
            QFrame#headerSep {{ background: {_css(t['divider'])}; border: none; }}
            QFrame#cornerTickFrame {{ border: 1px solid {_css(t['divider'])}; background: transparent; }}
            QLineEdit, QSpinBox, QDoubleSpinBox {{
                background: {_css(t['surface'])}; color: {_css(t['text'])};
                border: 1px solid {_css(t['divider'])}; border-radius: 4px;
                padding: 6px 10px; font-size: 14px;
            }}
            QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus {{ border: 1px solid {_css(t['accent'])}; }}
            QCheckBox {{ font-size: 14px; spacing: 7px; }}
            QCheckBox::indicator {{
                width: 15px; height: 15px; border: 1px solid {_css(t['divider'])};
                border-radius: 3px; background: {_css(t['surface'])};
            }}
            QCheckBox::indicator:checked {{ background: {_css(t['accent'])}; border: 1px solid {_css(t['accent'])}; }}
            QPushButton#primaryBtn {{
                background: {_css(t['accent'])}; color: {_css(t['bg'])};
                border: 1px solid {_css(t['accent'])}; border-radius: 4px;
                padding: 8px 16px; font-size: 14px; font-weight: 600;
            }}
            QPushButton#primaryBtn:disabled {{
                background: {_css(t['divider_soft'])}; color: {_css(t['text_muted'])}; border: 1px solid {_css(t['divider'])};
            }}
            QPushButton#secondaryBtn {{
                background: transparent; color: {_css(t['text'])};
                border: 1px solid {_css(t['divider'])}; border-radius: 4px;
                padding: 8px 16px; font-size: 14px; font-weight: 600;
            }}
            QPushButton#secondaryBtn:disabled {{ color: {_css(t['text_muted'])}; border: 1px solid {_css(t['divider_soft'])}; }}
            QPushButton#textBtn {{
                background: transparent; color: {_css(t['accent'])};
                border: none; padding: 6px 10px; font-size: 13px; font-weight: 600;
            }}
            QPushButton#textBtn:disabled {{ color: {_css(t['text_muted'])}; }}
            QTableWidget {{
                background: {_css(t['bg'])}; color: {_css(t['text'])}; border: none;
                gridline-color: {_css(t['divider_soft'])}; font-size: 14px;
            }}
            QTableWidget::item {{ padding: 4px; }}
            QHeaderView::section {{
                background: {_css(t['bg'])}; color: {_css(t['text_muted'])}; border: none;
                border-bottom: 1px solid {_css(t['divider'])}; padding: 6px; font-size: 11px;
            }}
            QProgressBar {{ background: {_css(t['divider_soft'])}; border: none; border-radius: 3px; }}
            QProgressBar::chunk {{ background: {_css(t['accent'])}; border-radius: 3px; }}
            QStatusBar {{ color: {_css(t['text_muted'])}; }}
        """)

        seg_base = f"border: 1px solid {_css(t['divider'])}; padding: 6px 13px; font-size: 13px;"
        for btn, active in ((self.light_btn, self.theme_name == "light"), (self.dark_btn, self.theme_name == "dark")):
            if active:
                btn.setStyleSheet(seg_base + f"background: {_css(t['accent'])}; color: {_css(t['bg'])};")
            else:
                btn.setStyleSheet(seg_base + f"background: transparent; color: {_css(t['text'])};")

        self.params_card.set_mark_color(t["mark_color"])
        self.empty_card.set_mark_color(t["mark_color"])
        self.radar_icon.set_color(t["accent"])
        self.brand_mark.set_color(t["accent"])
        self._repopulate_row_colors()
        self.table.viewport().update()

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
        self.progress_widget.setVisible(True)
        self._show_results(False)
        self._set_empty_text(scanning=True)
        self._set_busy(True)
        w.start()

    def stop_scan(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            self.status_label.setText("正在停止…")
            self.worker.stop()

    def clear_results(self) -> None:
        self.table.setRowCount(0)
        self._last_results = []
        self._last_meta = {}
        self._show_results(False)
        self._set_empty_text(scanning=False)

    def export_results(self) -> None:
        if not self._last_results:
            QMessageBox.information(self, "导出 JSON", "还没有可导出的扫描结果，先运行一次扫描。")
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出 JSON", "scanbmc-results.json", "JSON (*.json)")
        if not path:
            return
        show_all = self.all_cb.isChecked()
        try:
            text = core.render_json(self._last_results, show_all, self._last_meta)
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        except OSError as exc:
            QMessageBox.critical(self, "导出失败", f"写入文件失败：{exc}")
            return
        self.statusBar().showMessage(f"已导出到 {path}", 5000)

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

    def _show_results(self, show: bool) -> None:
        self.results_header.setVisible(show)
        self.table.setVisible(show)
        self.empty_card.setVisible(not show)

    def _set_empty_text(self, scanning: bool, found_none: bool = False) -> None:
        if scanning:
            self.empty_title.setText("正在扫描…")
            self.empty_body.setText("正在探测目标主机的开放端口与协议应答，完成后会在这里列出识别到的 BMC 设备。")
        elif found_none:
            self.empty_title.setText("未发现符合条件的设备")
            self.empty_body.setText("本次扫描没有找到匹配的存活主机，可以尝试勾选“显示所有存活主机”或调整目标范围。")
        else:
            self.empty_title.setText("还没有扫描结果")
            self.empty_body.setText("点击「开始扫描」即可自动检测本机所在网段，或在上方填写目标网段 / IP 区间后开始。")

    # ---------- 信号槽 ----------

    def on_progress(self, done: int, total: int, phase: str) -> None:
        name = "端口发现" if phase == "probe" else "指纹识别"
        self.progress_bar.setMaximum(max(total, 1))
        self.progress_bar.setValue(done)
        self.status_label.setText(f"{name}：{done}/{total}")

    def on_finished(self, results: List[HostResult], degraded: bool, elapsed: float) -> None:
        self.progress_widget.setVisible(False)
        self._last_results = results
        alive = len(results)
        bmc = sum(1 for r in results if r.is_bmc)
        self._last_meta = {
            "version": core.__version__,
            "elapsed_seconds": round(elapsed, 2),
            "alive": alive,
            "bmc": bmc,
            "degraded": degraded,
        }
        self._populate_table(results)
        rows_shown = self.table.rowCount()
        self._show_results(rows_shown > 0)
        if rows_shown == 0:
            self._set_empty_text(scanning=False, found_none=True)
        self.summary_label.setText(f"完成：耗时 {elapsed:.1f}s，存活主机 {alive} 台，判定为 BMC {bmc} 台")
        self.statusBar().showMessage(f"完成：存活 {alive} 台，判定为 BMC {bmc} 台", 5000)
        if degraded:
            QMessageBox.warning(
                self,
                "扫描结果不可信",
                "大量探测在本机侧就失败了（网卡未连接 / 目标网段无路由 / 并发过高耗尽句柄），\n"
                "本次结果不可信，请检查网络后重试，或降低并发数。",
            )

    def on_cancelled(self, results: List[HostResult]) -> None:
        self.progress_widget.setVisible(False)
        self._last_results = results
        self._last_meta = {"version": core.__version__, "alive": len(results)}
        self._populate_table(results)
        rows_shown = self.table.rowCount()
        self._show_results(rows_shown > 0)
        if rows_shown == 0:
            self._set_empty_text(scanning=False)
        self.statusBar().showMessage(f"已停止，显示已完成的 {len(results)} 台存活主机。", 5000)

    def on_failed(self, message: str) -> None:
        self.progress_widget.setVisible(False)
        self._set_empty_text(scanning=False)
        self.statusBar().showMessage("失败", 5000)
        QMessageBox.critical(self, "错误", message)

    def on_worker_finished(self) -> None:
        self._set_busy(False)
        self.worker = None

    # ---------- 表格渲染 ----------

    def _populate_table(self, results: List[HostResult]) -> None:
        show_all = self.all_cb.isChecked()
        rows = [r for r in results if show_all or r.is_bmc]
        self._displayed_rows = rows
        self.table.setRowCount(len(rows))
        mono = self.table.font()
        mono.setFamily("Menlo, Consolas, monospace")
        for i, host in enumerate(rows):
            warned = any(e.startswith("⚠") for e in host.evidence)
            bg = self.theme["warn_row_bg"] if warned else TRANSPARENT

            def item(text: str, monospace: bool = False) -> QTableWidgetItem:
                it = QTableWidgetItem(text)
                it.setBackground(bg)
                if monospace:
                    it.setFont(mono)
                return it

            ip_item = item(host.ip, monospace=True)
            ip_font = ip_item.font()
            ip_font.setUnderline(True)
            ip_item.setFont(ip_font)
            ip_item.setForeground(self.theme["accent"])
            ip_item.setToolTip(f"点击用浏览器打开 {self._preferred_url(host)}")
            self.table.setItem(i, 0, ip_item)
            self.table.setItem(i, 1, item(host.confidence or "—"))
            self.table.setItem(i, 2, item(host.vendor or "—"))
            self.table.setItem(i, 3, item(host.open_ports_str(), monospace=True))
            self.table.setItem(i, 4, item("；".join(host.evidence)))

    @staticmethod
    def _preferred_url(host: HostResult) -> str:
        """按开放端口猜测管理页协议：优先 HTTPS（BMC 常用自签证书），其次 HTTP。"""
        ports = {p.port for p in host.ports}
        if 443 in ports or 5989 in ports:
            return f"https://{host.ip}/"
        if 80 in ports or 5985 in ports or 5988 in ports:
            return f"http://{host.ip}/"
        return f"https://{host.ip}/"

    def on_cell_clicked(self, row: int, column: int) -> None:
        if column != 0 or not (0 <= row < len(self._displayed_rows)):
            return
        url = self._preferred_url(self._displayed_rows[row])
        QDesktopServices.openUrl(QUrl(url))
        self.statusBar().showMessage(f"已在浏览器中打开 {url}", 4000)

    def _repopulate_row_colors(self) -> None:
        """主题切换后重刷已有行的警示底色（置信度徽章由 delegate 自行取主题色）。"""
        if not self._last_results:
            return
        self._populate_table(self._last_results)

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
