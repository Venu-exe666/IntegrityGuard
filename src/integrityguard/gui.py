"""Tkinter desktop interface for IntegrityGuard GUI Phase 2."""

from __future__ import annotations

import ctypes
import os
import queue
import threading
import tkinter as tk
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from integrityguard.baseline import BaselineError, IncompleteScanError
from integrityguard.detector import ChangeStatus, DetectorError
from integrityguard.gui_service import (
    BaselineCreationResult,
    GuiBaselineExistsError,
    GuiBaselineNotFoundError,
    GuiIntegrationError,
    GuiMonitoringControl,
    GuiMonitoringState,
    GuiService,
    ScanOutcome,
)
from integrityguard.monitoring import (
    AlertEvent,
    MonitoringAssessment,
    MonitoringCycle,
    MonitoringFindingKind,
    MonitoringScanEvent,
    MonitoringSession,
    ScanEventHandler,
)

_BACKGROUND = "#07111f"
_SIDEBAR = "#091728"
_PANEL = "#0d1b2d"
_PANEL_RAISED = "#12243a"
_BORDER = "#274663"
_TEXT = "#f4f7fb"
_MUTED = "#a8b7ca"
_DISABLED = "#60748c"
_ACCENT = "#43b0ff"
_ACCENT_DARK = "#0878d1"
_SUCCESS = "#35d88a"
_SUCCESS_DARK = "#087f5b"
_WARNING = "#ffbe55"
_DANGER = "#ff6577"
_DANGER_DARK = "#a92d42"
_PURPLE = "#a98bff"
_MAX_LIVE_ALERT_ROWS = 1000


@dataclass(frozen=True, slots=True)
class _OperationMessage:
    operation_id: int
    outcome: str
    value: object


@dataclass(frozen=True, slots=True)
class _MonitoringCycleMessage:
    session_id: int
    cycle: MonitoringCycle


@dataclass(frozen=True, slots=True)
class _MonitoringFinishedMessage:
    session_id: int
    session: MonitoringSession


@dataclass(frozen=True, slots=True)
class _MonitoringErrorMessage:
    session_id: int
    error: BaseException


@dataclass(frozen=True, slots=True)
class _ScanActivityMessage:
    owner: str
    owner_id: int
    event: MonitoringScanEvent


class _ScanningIndicator(tk.Canvas):
    """Compact animated scanner beam used only during active filesystem scans."""

    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(
            parent,
            width=220,
            height=30,
            background=_BACKGROUND,
            highlightthickness=0,
            borderwidth=0,
            takefocus=0,
        )
        self._animation_job: str | None = None
        self._phase = 0

    @property
    def animation_running(self) -> bool:
        return self._animation_job is not None

    def start(self, interval: int = 55) -> None:
        if self._animation_job is not None:
            return
        self._phase = 0
        self._animate(max(interval, 30))

    def stop(self) -> None:
        if self._animation_job is not None:
            try:
                self.after_cancel(self._animation_job)
            except tk.TclError:
                pass
        self._animation_job = None
        self._phase = 0
        self.delete("all")

    def _animate(self, interval: int) -> None:
        self.delete("all")
        pulse = (self._phase % 16) / 15
        radius = 4 + int(pulse * 4)
        self.create_oval(
            12 - radius,
            15 - radius,
            12 + radius,
            15 + radius,
            outline=_ACCENT,
            width=2,
        )
        self.create_oval(9, 12, 15, 18, fill=_ACCENT, outline="")
        self.create_text(
            26,
            15,
            text="SCANNING",
            anchor="w",
            fill=_TEXT,
            font=("Segoe UI Semibold", 8),
        )

        track_start, track_end = 94, 216
        self.create_line(
            track_start,
            15,
            track_end,
            15,
            fill=_BORDER,
            width=5,
            capstyle=tk.ROUND,
        )
        travel = track_end - track_start + 30
        beam_x = track_start - 15 + (self._phase * 7) % travel
        for offset, color, width in (
            (-18, "#155a91", 4),
            (-9, _ACCENT_DARK, 5),
            (0, _ACCENT, 6),
            (9, "#8ed5ff", 4),
        ):
            x = beam_x + offset
            left = max(track_start, x - 8)
            right = min(track_end, x + 8)
            if left < right:
                self.create_line(
                    left,
                    15,
                    right,
                    15,
                    fill=color,
                    width=width,
                    capstyle=tk.ROUND,
                )
        self._phase += 1
        self._animation_job = self.after(interval, self._animate, interval)


class _MonitoringIndicator(tk.Canvas):
    """Subtle live indicator for an enabled polling session between scans."""

    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(
            parent,
            width=132,
            height=22,
            background=_PANEL,
            highlightthickness=0,
            borderwidth=0,
            takefocus=0,
        )
        self._animation_job: str | None = None
        self._phase = 0

    @property
    def animation_running(self) -> bool:
        return self._animation_job is not None

    def start(self) -> None:
        if self._animation_job is not None:
            return
        self._phase = 0
        self._animate()

    def stop(self) -> None:
        if self._animation_job is not None:
            try:
                self.after_cancel(self._animation_job)
            except tk.TclError:
                pass
        self._animation_job = None
        self._phase = 0
        self.delete("all")

    def _animate(self) -> None:
        self.delete("all")
        heights = (5, 9, 13, 9)
        for index in range(4):
            height = heights[(self._phase + index) % len(heights)]
            x = 5 + index * 5
            self.create_line(
                x,
                11 - height // 2,
                x,
                11 + height // 2,
                fill=_SUCCESS,
                width=3,
                capstyle=tk.ROUND,
            )
        self.create_text(
            31,
            11,
            text="MONITORING",
            anchor="w",
            fill=_ACCENT,
            font=("Segoe UI Semibold", 8),
        )
        self._phase += 1
        self._animation_job = self.after(140, self._animate)


class IntegrityGuardApp:
    """Responsive Tk application backed by the existing security engine."""

    def __init__(self, root: tk.Tk, service: GuiService | None = None) -> None:
        self.root = root
        self.service = service or GuiService()
        self.selected_folder: Path | None = None
        self._busy = False
        self._selected_has_baseline = False
        self._closing = False
        self._poll_scheduled = False
        self._operation_id = 0
        self._progress_visible = False
        self._operation_thread: threading.Thread | None = None
        self._monitor_thread: threading.Thread | None = None
        self._monitoring = GuiMonitoringControl()
        self._messages: queue.Queue[object] = queue.Queue()

        self.path_text = tk.StringVar(value="No folder selected")
        self.folder_help_text = tk.StringVar(
            value="Choose a folder to begin. IntegrityGuard will not modify its files."
        )
        self.results_caption_text = tk.StringVar(value="No assessment has been run yet.")
        self.status_text = tk.StringVar(value="STATUS  Ready — choose a folder")
        self.monitor_status_text = tk.StringVar(value="STATE  Stopped")
        self.monitor_interval = tk.StringVar(value="10")
        self.completed_scans_text = tk.StringVar(value="0")
        self.last_scan_text = tk.StringVar(value="Never")
        self.active_changes_text = tk.StringVar(value="0")
        self.summary_values = {
            name: tk.StringVar(value="0")
            for name in ("Added", "Modified", "Deleted", "Unknown", "Unchanged")
        }

        self._configure_window()
        self._configure_styles()
        self._build_layout()
        self._configure_bindings()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_window(self) -> None:
        self.root.title("IntegrityGuard")
        self.root.geometry("1380x900")
        self.root.minsize(1080, 720)
        self.root.configure(background=_BACKGROUND)
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        self.root.option_add("*TCombobox*Listbox.background", _PANEL_RAISED)
        self.root.option_add("*TCombobox*Listbox.foreground", _TEXT)
        self.root.option_add("*TCombobox*Listbox.selectBackground", _ACCENT_DARK)
        self.root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")

        style.configure(
            ".",
            background=_BACKGROUND,
            foreground=_TEXT,
            font=("Segoe UI", 10),
            bordercolor=_BORDER,
            darkcolor=_BORDER,
            lightcolor=_BORDER,
            focuscolor=_ACCENT,
        )
        style.configure("App.TFrame", background=_BACKGROUND)
        style.configure("Sidebar.TFrame", background=_SIDEBAR)
        style.configure(
            "Panel.TFrame",
            background=_PANEL,
            bordercolor=_BORDER,
            relief="solid",
            borderwidth=1,
        )
        style.configure("PanelBody.TFrame", background=_PANEL)
        style.configure("Raised.TFrame", background=_PANEL_RAISED)
        style.configure(
            "SidebarTitle.TLabel",
            background=_SIDEBAR,
            foreground=_TEXT,
            font=("Segoe UI Semibold", 14),
        )
        style.configure(
            "SidebarText.TLabel",
            background=_SIDEBAR,
            foreground=_MUTED,
            font=("Segoe UI", 9),
        )
        style.configure(
            "NavActive.TLabel",
            background="#10365b",
            foreground=_TEXT,
            padding=(18, 12),
            font=("Segoe UI Semibold", 10),
        )
        style.configure(
            "Title.TLabel",
            background=_BACKGROUND,
            foreground=_TEXT,
            font=("Segoe UI Semibold", 25),
        )
        style.configure(
            "Subtitle.TLabel",
            background=_BACKGROUND,
            foreground=_MUTED,
            font=("Segoe UI", 11),
        )
        style.configure(
            "PanelTitle.TLabel",
            background=_PANEL,
            foreground=_TEXT,
            font=("Segoe UI Semibold", 12),
        )
        style.configure(
            "PanelText.TLabel",
            background=_PANEL,
            foreground=_MUTED,
            font=("Segoe UI", 9),
        )
        style.configure(
            "CardLabel.TLabel",
            background=_PANEL_RAISED,
            foreground=_MUTED,
            font=("Segoe UI Semibold", 9),
        )
        style.configure(
            "MetricValue.TLabel",
            background=_PANEL_RAISED,
            foreground=_TEXT,
            font=("Segoe UI Semibold", 12),
        )
        style.configure(
            "Dark.TEntry",
            fieldbackground=_PANEL_RAISED,
            foreground=_TEXT,
            insertcolor=_TEXT,
            bordercolor=_BORDER,
            padding=(10, 8),
        )
        style.map(
            "Dark.TEntry",
            fieldbackground=[("readonly", _PANEL_RAISED)],
            foreground=[("readonly", _TEXT)],
            bordercolor=[("focus", _ACCENT)],
        )
        style.configure(
            "TButton",
            background=_PANEL_RAISED,
            foreground=_TEXT,
            bordercolor=_BORDER,
            focusthickness=1,
            focuscolor=_ACCENT,
            padding=(14, 9),
            font=("Segoe UI Semibold", 9),
        )
        style.map(
            "TButton",
            background=[
                ("disabled", _PANEL),
                ("pressed", _BORDER),
                ("active", "#293241"),
            ],
            foreground=[("disabled", _DISABLED)],
            bordercolor=[("focus", _ACCENT), ("disabled", _BORDER)],
        )
        self._configure_button_style(
            style, "Primary.TButton", _ACCENT_DARK, "#2f81f7"
        )
        self._configure_button_style(
            style, "Success.TButton", _SUCCESS_DARK, "#2ea043"
        )
        self._configure_button_style(
            style, "Danger.TButton", _DANGER_DARK, "#da3633"
        )
        style.configure(
            "Dark.TCombobox",
            fieldbackground=_PANEL_RAISED,
            background=_PANEL_RAISED,
            foreground=_TEXT,
            arrowcolor=_TEXT,
            bordercolor=_BORDER,
            padding=(8, 6),
        )
        style.map(
            "Dark.TCombobox",
            fieldbackground=[
                ("readonly", _PANEL_RAISED),
                ("disabled", _PANEL),
            ],
            foreground=[("readonly", _TEXT), ("disabled", _DISABLED)],
            arrowcolor=[("disabled", _DISABLED)],
            bordercolor=[("focus", _ACCENT)],
        )
        style.configure(
            "Horizontal.TProgressbar",
            background=_ACCENT,
            troughcolor=_PANEL,
            bordercolor=_BORDER,
            lightcolor=_ACCENT,
            darkcolor=_ACCENT,
        )
        style.configure(
            "Treeview",
            background=_PANEL,
            fieldbackground=_PANEL,
            foreground=_TEXT,
            bordercolor=_BORDER,
            rowheight=30,
            font=("Segoe UI", 9),
        )
        style.map(
            "Treeview",
            background=[("selected", _ACCENT_DARK)],
            foreground=[("selected", "#ffffff")],
        )
        style.configure(
            "Treeview.Heading",
            background=_PANEL_RAISED,
            foreground=_TEXT,
            bordercolor=_BORDER,
            relief="flat",
            padding=(10, 8),
            font=("Segoe UI Semibold", 9),
        )
        style.map(
            "Treeview.Heading",
            background=[("active", "#293241")],
            relief=[("pressed", "flat")],
        )
        style.configure(
            "Vertical.TScrollbar",
            background=_PANEL_RAISED,
            troughcolor=_PANEL,
            bordercolor=_BORDER,
            arrowcolor=_MUTED,
        )
        style.configure(
            "Horizontal.TScrollbar",
            background=_PANEL_RAISED,
            troughcolor=_PANEL,
            bordercolor=_BORDER,
            arrowcolor=_MUTED,
        )
        style.configure(
            "Sidebar.TButton",
            background=_SIDEBAR,
            foreground=_DISABLED,
            bordercolor=_SIDEBAR,
            padding=(18, 11),
            anchor="w",
        )
        style.map(
            "Sidebar.TButton",
            background=[("disabled", _SIDEBAR)],
            foreground=[("disabled", _DISABLED)],
            bordercolor=[("disabled", _SIDEBAR)],
        )

    @staticmethod
    def _configure_button_style(
        style: ttk.Style,
        name: str,
        background: str,
        active_background: str,
    ) -> None:
        style.configure(
            name,
            background=background,
            foreground="#ffffff",
            bordercolor=background,
        )
        style.map(
            name,
            background=[
                ("disabled", _PANEL),
                ("pressed", background),
                ("active", active_background),
            ],
            foreground=[("disabled", _DISABLED)],
            bordercolor=[("focus", _ACCENT), ("disabled", _BORDER)],
        )

    def _build_layout(self) -> None:
        shell = ttk.Frame(self.root, style="App.TFrame")
        shell.grid(row=0, column=0, sticky="nsew")
        shell.rowconfigure(0, weight=1)
        shell.columnconfigure(0, weight=0, minsize=205)
        shell.columnconfigure(1, weight=1)

        sidebar = ttk.Frame(
            shell,
            style="Sidebar.TFrame",
            padding=(18, 24, 18, 18),
        )
        sidebar.grid(row=0, column=0, sticky="nsw")
        sidebar.rowconfigure(8, weight=1)
        logo = tk.Canvas(
            sidebar,
            width=76,
            height=76,
            background=_SIDEBAR,
            highlightthickness=0,
        )
        logo.grid(row=0, column=0, pady=(0, 8))
        logo.create_polygon(
            38, 5, 65, 16, 61, 47, 38, 70, 15, 47, 11, 16,
            fill="#0d2946",
            outline=_ACCENT,
            width=3,
        )
        logo.create_polygon(
            38, 13, 57, 21, 52, 43, 38, 59, 38, 13,
            fill=_ACCENT,
            outline="",
        )
        ttk.Label(
            sidebar,
            text="IntegrityGuard",
            style="SidebarTitle.TLabel",
        ).grid(row=1, column=0)
        ttk.Label(
            sidebar,
            text="File Integrity Monitoring",
            style="SidebarText.TLabel",
        ).grid(row=2, column=0, pady=(2, 28))
        ttk.Label(
            sidebar,
            text="Monitoring Dashboard",
            style="NavActive.TLabel",
            anchor="w",
        ).grid(row=3, column=0, sticky="ew", pady=(0, 8))
        self.coming_soon_buttons: list[ttk.Button] = []
        for row, label in enumerate(("Settings", "Reports", "History"), start=4):
            button = ttk.Button(
                sidebar,
                text=f"{label}  —  Coming Soon",
                style="Sidebar.TButton",
                state="disabled",
                takefocus=False,
            )
            button.grid(row=row, column=0, sticky="ew", pady=2)
            self.coming_soon_buttons.append(button)
        ttk.Label(
            sidebar,
            text="LOCAL OPERATION\nNo network access or file uploads",
            style="SidebarText.TLabel",
            justify="left",
        ).grid(row=9, column=0, sticky="sw")

        outer = ttk.Frame(shell, style="App.TFrame", padding=(22, 18, 22, 20))
        outer.grid(row=0, column=1, sticky="nsew")
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(4, weight=1)

        header = ttk.Frame(outer, style="App.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        header.columnconfigure(0, weight=1)
        title_block = ttk.Frame(header, style="App.TFrame")
        title_block.grid(row=0, column=0, rowspan=2, sticky="w")
        title_accent = tk.Frame(
            title_block,
            width=5,
            height=58,
            background=_ACCENT,
        )
        title_accent.grid(row=0, column=0, rowspan=2, sticky="ns", padx=(0, 14))
        ttk.Label(title_block, text="IntegrityGuard", style="Title.TLabel").grid(
            row=0, column=1, sticky="w"
        )
        ttk.Label(
            title_block,
            text="File Integrity Monitoring",
            style="Subtitle.TLabel",
        ).grid(row=1, column=1, sticky="w", pady=(0, 1))
        self.status_label = tk.Label(
            header,
            textvariable=self.status_text,
            background=_PANEL_RAISED,
            foreground=_MUTED,
            font=("Segoe UI Semibold", 9),
            anchor="center",
            padx=16,
            pady=6,
            highlightthickness=1,
            highlightbackground=_BORDER,
        )
        self.status_label.grid(row=0, column=1, sticky="e")
        self.progress = _ScanningIndicator(header)
        self.progress.grid(row=0, column=2, sticky="e", padx=(18, 0))
        self.progress.grid_remove()

        workspace = ttk.Frame(outer, style="App.TFrame")
        workspace.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        workspace.columnconfigure(0, weight=3, uniform="workspace")
        workspace.columnconfigure(1, weight=2, uniform="workspace")

        selection = ttk.Frame(workspace, style="Panel.TFrame", padding=(16, 13))
        selection.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        selection.columnconfigure(0, weight=1)
        ttk.Label(selection, text="Monitored Folder", style="PanelTitle.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            selection,
            textvariable=self.folder_help_text,
            style="PanelText.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(2, 8))
        self.path_entry = ttk.Entry(
            selection,
            textvariable=self.path_text,
            state="readonly",
            style="Dark.TEntry",
        )
        self.path_entry.grid(row=2, column=0, sticky="ew")
        self.browse_button = ttk.Button(
            selection,
            text="Choose Folder",
            style="Primary.TButton",
            command=self._choose_folder,
        )
        self.browse_button.grid(row=2, column=1, padx=(12, 0))

        actions = ttk.Frame(workspace, style="Panel.TFrame", padding=(16, 13))
        actions.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        actions.columnconfigure(0, weight=1)
        actions.columnconfigure(1, weight=1)
        ttk.Label(actions, text="Quick Actions", style="PanelTitle.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w"
        )
        ttk.Label(
            actions,
            text=(
                "Create a trusted snapshot, scan on demand, or poll periodically. "
                "Changes are never accepted automatically."
            ),
            style="PanelText.TLabel",
            wraplength=390,
            justify="left",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 9))
        self.baseline_button = ttk.Button(
            actions,
            text="Create Baseline",
            style="Primary.TButton",
            command=self._create_baseline,
            state="disabled",
        )
        self.baseline_button.grid(row=2, column=0, sticky="ew", padx=(0, 4))
        self.scan_button = ttk.Button(
            actions,
            text="Scan Now",
            style="Primary.TButton",
            command=self._scan_now,
            state="disabled",
        )
        self.scan_button.grid(row=2, column=1, sticky="ew", padx=(4, 0))
        self.start_monitor_button = ttk.Button(
            actions,
            text="Start Monitoring",
            style="Success.TButton",
            command=self._start_monitoring,
            state="disabled",
        )
        self.start_monitor_button.grid(
            row=3, column=0, sticky="ew", padx=(0, 4), pady=(8, 0)
        )
        self.stop_monitor_button = ttk.Button(
            actions,
            text="Stop Monitoring",
            style="Danger.TButton",
            command=self._stop_monitoring,
            state="disabled",
        )
        self.stop_monitor_button.grid(
            row=3, column=1, sticky="ew", padx=(4, 0), pady=(8, 0)
        )

        monitoring = ttk.Frame(outer, style="Panel.TFrame", padding=(16, 13))
        monitoring.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        monitoring.columnconfigure(1, weight=1)
        ttk.Label(
            monitoring, text="Monitoring", style="PanelTitle.TLabel"
        ).grid(row=0, column=0, sticky="w")
        self.monitor_status_label = tk.Label(
            monitoring,
            textvariable=self.monitor_status_text,
            background=_PANEL,
            foreground=_MUTED,
            font=("Segoe UI Semibold", 9),
        )
        self.monitor_status_label.grid(row=0, column=1, padx=(12, 0), sticky="w")
        self.monitor_activity_label = _MonitoringIndicator(monitoring)
        self.monitor_activity_label.grid(row=0, column=2, padx=(16, 0), sticky="w")
        self.monitor_activity_label.grid_remove()
        ttk.Label(monitoring, text="Polling interval", style="PanelText.TLabel").grid(
            row=0, column=3, padx=(16, 7)
        )
        self.interval_box = ttk.Combobox(
            monitoring,
            textvariable=self.monitor_interval,
            values=("10", "30", "60"),
            state="readonly",
            style="Dark.TCombobox",
            width=5,
        )
        self.interval_box.grid(row=0, column=4)
        ttk.Label(monitoring, text="seconds", style="PanelText.TLabel").grid(
            row=0, column=5, padx=(5, 0)
        )

        metrics = ttk.Frame(monitoring, style="PanelBody.TFrame")
        metrics.grid(row=1, column=0, columnspan=6, sticky="ew", pady=(11, 0))
        for column, (label, variable) in enumerate(
            (
                ("Completed scans", self.completed_scans_text),
                ("Last scan (UTC)", self.last_scan_text),
                ("Active changes", self.active_changes_text),
            )
        ):
            metrics.columnconfigure(column, weight=1)
            item = ttk.Frame(metrics, style="Raised.TFrame", padding=(12, 8))
            item.grid(
                row=0,
                column=column,
                sticky="nsew",
                padx=(0 if column == 0 else 4, 0 if column == 2 else 4),
            )
            ttk.Label(item, text=label, style="CardLabel.TLabel").pack(anchor="w")
            ttk.Label(
                item,
                textvariable=variable,
                style="MetricValue.TLabel",
            ).pack(anchor="w")

        summary = ttk.Frame(outer, style="App.TFrame")
        summary.grid(row=3, column=0, sticky="ew", pady=(0, 10))
        card_colors = {
            "Added": ("#0b2a2b", "#1da878", _SUCCESS),
            "Modified": ("#0c2946", "#168ee0", _ACCENT),
            "Deleted": ("#321824", "#c33d55", _DANGER),
            "Unknown": ("#251d47", "#765bd1", _PURPLE),
            "Unchanged": ("#10272f", "#346070", _SUCCESS),
        }
        for index, name in enumerate(self.summary_values):
            summary.columnconfigure(index, weight=1)
            background, border, foreground = card_colors[name]
            card = tk.Frame(
                summary,
                background=background,
                highlightbackground=border,
                highlightthickness=1,
                padx=13,
                pady=9,
            )
            card.grid(
                row=0,
                column=index,
                sticky="nsew",
                padx=(0 if index == 0 else 4, 0 if index == 4 else 4),
            )
            tk.Label(
                card,
                text=name,
                background=background,
                foreground=_TEXT,
                font=("Segoe UI", 9),
            ).pack(anchor="w")
            tk.Label(
                card,
                textvariable=self.summary_values[name],
                background=background,
                foreground=foreground,
                font=("Segoe UI Semibold", 17),
            ).pack(anchor="w")

        results = ttk.Frame(outer, style="Panel.TFrame", padding=(16, 13))
        results.grid(row=4, column=0, sticky="nsew")
        results.columnconfigure(0, weight=1)
        results.rowconfigure(1, weight=1)
        result_header = ttk.Frame(results, style="PanelBody.TFrame")
        result_header.grid(row=0, column=0, sticky="ew", pady=(0, 9))
        result_header.columnconfigure(1, weight=1)
        ttk.Label(
            result_header, text="Results and Live Alerts", style="PanelTitle.TLabel"
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(
            result_header,
            textvariable=self.results_caption_text,
            style="PanelText.TLabel",
        ).grid(row=0, column=1, sticky="e", padx=(16, 0))

        table_frame = ttk.Frame(results, style="PanelBody.TFrame")
        table_frame.grid(row=1, column=0, sticky="nsew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self.table = ttk.Treeview(
            table_frame,
            columns=("status", "path", "size", "detail"),
            show="headings",
            selectmode="browse",
        )
        self.table.heading("status", text="Status")
        self.table.heading("path", text="Relative path")
        self.table.heading("size", text="Size")
        self.table.heading("detail", text="Details")
        self.table.column("status", width=105, minwidth=95, stretch=False)
        self.table.column("path", width=470, minwidth=220)
        self.table.column("size", width=100, minwidth=90, stretch=False, anchor="e")
        self.table.column("detail", width=270, minwidth=170)
        self.table.tag_configure(ChangeStatus.ADDED.value, foreground=_WARNING)
        self.table.tag_configure(ChangeStatus.MODIFIED.value, foreground=_WARNING)
        self.table.tag_configure(ChangeStatus.DELETED.value, foreground=_DANGER)
        self.table.tag_configure(ChangeStatus.UNKNOWN.value, foreground=_ACCENT)
        self.table.tag_configure("resolved", foreground=_ACCENT)
        self.table.tag_configure("scan_error", foreground=_DANGER)
        self.table.tag_configure("skipped_path", foreground=_MUTED)
        vertical_scrollbar = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.table.yview
        )
        horizontal_scrollbar = ttk.Scrollbar(
            table_frame, orient="horizontal", command=self.table.xview
        )
        self.table.configure(
            yscrollcommand=vertical_scrollbar.set,
            xscrollcommand=horizontal_scrollbar.set,
        )
        self.table.grid(row=0, column=0, sticky="nsew")
        vertical_scrollbar.grid(row=0, column=1, sticky="ns")
        horizontal_scrollbar.grid(row=1, column=0, sticky="ew")

    def _configure_bindings(self) -> None:
        self.root.bind("<Control-o>", lambda event: self._choose_folder())
        self.root.bind("<Control-b>", lambda event: self._create_baseline())
        self.root.bind("<F5>", lambda event: self._scan_now())
        self.root.bind("<Control-m>", lambda event: self._start_monitoring())
        self.root.bind("<Control-Shift-M>", lambda event: self._stop_monitoring())
        self.root.after_idle(self.browse_button.focus_set)

    def _choose_folder(self) -> None:
        if self._busy or self._monitoring.active:
            return
        selected = filedialog.askdirectory(
            parent=self.root,
            title="Choose a folder to monitor",
            mustexist=True,
        )
        if not selected:
            return
        self.selected_folder = Path(selected)
        self.path_text.set(str(self.selected_folder))
        self._clear_results()
        self._reset_monitoring_metrics()
        self.results_caption_text.set("No assessment has been run for this folder yet.")
        try:
            has_baseline = self.service.baseline_exists(self.selected_folder)
        except OSError as error:
            self._selected_has_baseline = False
            self._show_error(error)
            self._refresh_controls()
            return
        self._selected_has_baseline = has_baseline
        if has_baseline:
            self.folder_help_text.set(
                "Trusted baseline available. Scan now or start periodic monitoring."
            )
            self._set_status("Baseline available", _SUCCESS)
        else:
            self.folder_help_text.set(
                "Create a baseline to record this folder's current trusted state."
            )
            self._set_status("Folder selected — baseline required", _ACCENT)
        self._refresh_controls()

    def _create_baseline(self) -> None:
        if (
            self.selected_folder is None
            or self._busy
            or self._monitoring.active
        ):
            return
        selected_folder = self.selected_folder
        allow_new_version = False
        try:
            baseline_exists = self.service.baseline_exists(selected_folder)
        except OSError as error:
            self._show_error(error)
            return
        if baseline_exists:
            allow_new_version = messagebox.askyesno(
                "Create a new baseline version?",
                "A baseline already exists for this folder.\n\n"
                "Create a new version and keep the previous baseline?",
                parent=self.root,
                icon="warning",
            )
            if not allow_new_version:
                return
        self._start_operation(
            "Creating baseline…",
            lambda on_scan_event: self.service.create_for_root(
                selected_folder,
                allow_new_version=allow_new_version,
                on_scan_event=on_scan_event,
            ),
        )

    def _scan_now(self) -> None:
        if (
            self.selected_folder is None
            or self._busy
            or self._monitoring.active
        ):
            return
        selected_folder = self.selected_folder
        self._start_operation(
            "Scanning files…",
            lambda on_scan_event: self.service.scan_root(
                selected_folder,
                on_scan_event=on_scan_event,
            ),
        )

    def _start_operation(
        self,
        status: str,
        operation: Callable[[ScanEventHandler], object],
    ) -> None:
        if self._busy or self._monitoring.active:
            return
        self._busy = True
        self._operation_id += 1
        operation_id = self._operation_id
        self._set_status(status, _ACCENT)
        self._refresh_controls()

        def publish_scan_event(event: MonitoringScanEvent) -> None:
            self._messages.put(
                _ScanActivityMessage("operation", operation_id, event)
            )

        def worker() -> None:
            try:
                result = operation(publish_scan_event)
            except Exception as error:
                self._messages.put(
                    _OperationMessage(operation_id, "error", error)
                )
            else:
                self._messages.put(
                    _OperationMessage(operation_id, "success", result)
                )

        self._operation_thread = threading.Thread(
            target=worker,
            daemon=False,
            name="integrityguard-gui-operation",
        )
        self._operation_thread.start()
        self._ensure_message_poll()

    def _handle_operation_message(self, message: _OperationMessage) -> None:
        if message.operation_id != self._operation_id:
            return
        if self._operation_thread is not None:
            self._operation_thread.join()
            self._operation_thread = None
        self._busy = False
        self._set_progress_visible(False)
        self._refresh_controls()
        if message.outcome == "error":
            self._show_error(message.value)
        elif isinstance(message.value, BaselineCreationResult):
            self._show_baseline_created(message.value)
        elif isinstance(message.value, ScanOutcome):
            self._show_scan_outcome(message.value)

    def _show_baseline_created(self, result: BaselineCreationResult) -> None:
        self._clear_results()
        self._selected_has_baseline = True
        self.folder_help_text.set(
            "Trusted baseline recorded. Scan now or start periodic monitoring."
        )
        self.results_caption_text.set(
            "Baseline created; no comparison has been run yet."
        )
        self._refresh_controls()
        self._set_status("Baseline created", _SUCCESS)
        messagebox.showinfo(
            "Baseline created",
            f"Recorded files: {result.file_count}\n"
            f"Skipped link paths: {result.skipped_path_count}\n\n"
            f"Stored securely at:\n{result.baseline_path}",
            parent=self.root,
        )

    def _start_monitoring(self) -> None:
        if (
            self.selected_folder is None
            or self._busy
            or self._monitoring.active
            or not self._selected_has_baseline
        ):
            return
        selected_folder = self.selected_folder
        interval = float(self.monitor_interval.get())
        session_id, stop_event = self._monitoring.start()
        self._clear_results()
        self._reset_monitoring_metrics()
        self.results_caption_text.set("Waiting for the first polling assessment…")
        self._set_monitoring_state(GuiMonitoringState.RUNNING)
        self._set_status("Polling monitor running", _ACCENT)
        self._refresh_controls()

        def publish_cycle(cycle: MonitoringCycle) -> None:
            self._messages.put(_MonitoringCycleMessage(session_id, cycle))

        def publish_scan_event(event: MonitoringScanEvent) -> None:
            self._messages.put(
                _ScanActivityMessage("monitoring", session_id, event)
            )

        def worker() -> None:
            try:
                session = self.service.monitor_root(
                    selected_folder,
                    interval=interval,
                    stop_event=stop_event,
                    on_cycle=publish_cycle,
                    on_scan_event=publish_scan_event,
                )
            except Exception as error:
                self._messages.put(_MonitoringErrorMessage(session_id, error))
            else:
                self._messages.put(_MonitoringFinishedMessage(session_id, session))

        self._monitor_thread = threading.Thread(
            target=worker,
            daemon=False,
            name=f"integrityguard-monitor-{session_id}",
        )
        try:
            self._monitor_thread.start()
        except Exception as error:
            self._monitor_thread = None
            self._monitoring.finish(session_id, failed=True)
            self._set_progress_visible(False)
            self._set_monitoring_state(GuiMonitoringState.ERROR)
            self._refresh_controls()
            self._show_error(error)
            return
        self._ensure_message_poll()

    def _stop_monitoring(self) -> None:
        if not self._monitoring.request_stop():
            return
        self._set_monitoring_state(GuiMonitoringState.STOPPING)
        self._set_status("Stopping after the current scan…", _WARNING)
        self._set_progress_visible(False)
        self._refresh_controls()

    def _ensure_message_poll(self) -> None:
        if self._poll_scheduled:
            return
        self._poll_scheduled = True
        self.root.after(80, self._poll_messages)

    def _poll_messages(self) -> None:
        self._poll_scheduled = False
        while True:
            try:
                message = self._messages.get_nowait()
            except queue.Empty:
                break
            if isinstance(message, _OperationMessage):
                self._handle_operation_message(message)
            elif isinstance(message, _MonitoringCycleMessage):
                self._handle_monitoring_cycle(message)
            elif isinstance(message, _MonitoringFinishedMessage):
                self._handle_monitoring_finished(message)
            elif isinstance(message, _MonitoringErrorMessage):
                self._handle_monitoring_error(message)
            elif isinstance(message, _ScanActivityMessage):
                self._handle_scan_activity(message)
        if self._busy or self._monitoring.active or not self._messages.empty():
            self._ensure_message_poll()

    def _handle_scan_activity(self, message: _ScanActivityMessage) -> None:
        if message.owner == "operation":
            current = self._busy and message.owner_id == self._operation_id
        elif message.owner == "monitoring":
            current = (
                self._monitoring.active
                and self._monitoring.is_current(message.owner_id)
                and self._monitoring.state is GuiMonitoringState.RUNNING
            )
        else:
            return
        if not current:
            return
        self._set_progress_visible(
            message.event is MonitoringScanEvent.STARTED
        )

    def _handle_monitoring_cycle(self, message: _MonitoringCycleMessage) -> None:
        if (
            not self._monitoring.is_current(message.session_id)
            or not self._monitoring.active
        ):
            return
        cycle = message.cycle
        self.completed_scans_text.set(str(cycle.status.completed_scans))
        self.last_scan_text.set(
            cycle.scanned_at_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
        )
        self.active_changes_text.set(str(cycle.status.active_change_count))
        self._update_summary(cycle)
        self._append_monitoring_alerts(cycle)
        alert_count = len(cycle.new_alerts) + len(cycle.resolved_alerts)
        if alert_count:
            self.results_caption_text.set(
                f"Cycle {cycle.scan_number}: {alert_count} new or resolved alert"
                f"{'s' if alert_count != 1 else ''}."
            )
        elif cycle.repeated_finding_count:
            self.results_caption_text.set(
                f"Cycle {cycle.scan_number}: no duplicate alerts; "
                f"{cycle.repeated_finding_count} finding"
                f"{'s remain' if cycle.repeated_finding_count != 1 else ' remains'} active."
            )
        else:
            self.results_caption_text.set(
                f"Cycle {cycle.scan_number}: no active findings."
            )
        if cycle.status.current_assessment is MonitoringAssessment.INCONCLUSIVE:
            self._set_status(
                f"Cycle {cycle.scan_number} inconclusive — review alerts",
                _WARNING,
            )
        elif cycle.status.current_assessment is MonitoringAssessment.CHANGES_DETECTED:
            self._set_status(
                f"Cycle {cycle.scan_number} detected changes",
                _WARNING,
            )
        else:
            self._set_status(f"Cycle {cycle.scan_number} complete", _SUCCESS)

    def _handle_monitoring_finished(
        self,
        message: _MonitoringFinishedMessage,
    ) -> None:
        if not self._monitoring.finish(message.session_id):
            return
        self._join_monitor_thread()
        self._set_progress_visible(False)
        self._set_monitoring_state(GuiMonitoringState.STOPPED)
        self._set_status("Monitoring stopped", _MUTED)
        self._refresh_controls()
        if self._closing:
            self.root.destroy()

    def _handle_monitoring_error(self, message: _MonitoringErrorMessage) -> None:
        if not self._monitoring.finish(message.session_id, failed=True):
            return
        self._join_monitor_thread()
        self._set_progress_visible(False)
        self._set_monitoring_state(GuiMonitoringState.ERROR)
        self._refresh_controls()
        self._show_error(message.error)
        if self._closing:
            self.root.destroy()

    def _join_monitor_thread(self) -> None:
        if self._monitor_thread is not None:
            self._monitor_thread.join()
            self._monitor_thread = None

    def _update_summary(self, cycle: MonitoringCycle) -> None:
        counts = cycle.report.counts
        for name, value in (
            ("Added", counts.added),
            ("Modified", counts.modified),
            ("Deleted", counts.deleted),
            ("Unknown", counts.unknown),
            ("Unchanged", counts.unchanged),
        ):
            self.summary_values[name].set(str(value))

    def _append_monitoring_alerts(self, cycle: MonitoringCycle) -> None:
        for alert in cycle.new_alerts + cycle.resolved_alerts:
            if alert.event is AlertEvent.RESOLVED:
                label = "RESOLVED"
                tag = "resolved"
                detail = f"Previously {alert.kind.value.replace('_', ' ')}"
            else:
                label = {
                    MonitoringFindingKind.ADDED: "ADDED",
                    MonitoringFindingKind.MODIFIED: "MODIFIED",
                    MonitoringFindingKind.DELETED: "DELETED",
                    MonitoringFindingKind.UNKNOWN: "UNKNOWN",
                    MonitoringFindingKind.SCAN_ERROR: "ERROR",
                    MonitoringFindingKind.SKIPPED_PATH: "SKIPPED",
                }[alert.kind]
                tag = alert.kind.value
                detail = alert.detail or "New monitoring finding"
            self.table.insert(
                "",
                "end",
                values=(label, alert.relative_path, "—", detail.replace("_", " ")),
                tags=(tag,),
            )
        rows = self.table.get_children()
        overflow = len(rows) - _MAX_LIVE_ALERT_ROWS
        if overflow > 0:
            self.table.delete(*rows[:overflow])

    def _show_scan_outcome(self, outcome: ScanOutcome) -> None:
        self._populate_results(outcome)
        report = outcome.report
        if not report.assessment_conclusive:
            self._set_status("Inconclusive scan", _WARNING)
            messagebox.showwarning(
                "Scan incomplete",
                "The scan contains errors or excluded paths and must not be "
                "treated as clean. Review UNKNOWN rows and scan details.",
                parent=self.root,
            )
        elif report.has_confirmed_changes:
            self._set_status("Changes detected", _WARNING)
            messagebox.showwarning(
                "Integrity changes detected",
                "One or more files differ from the trusted baseline.",
                parent=self.root,
            )
        else:
            self._set_status("No changes detected", _SUCCESS)
            messagebox.showinfo(
                "Scan complete",
                "No integrity changes were detected.",
                parent=self.root,
            )

    def _populate_results(self, outcome: ScanOutcome) -> None:
        self._clear_results()
        summary = outcome.summary
        for name, value in (
            ("Added", summary.added),
            ("Modified", summary.modified),
            ("Deleted", summary.deleted),
            ("Unknown", summary.unknown),
            ("Unchanged", summary.unchanged),
        ):
            self.summary_values[name].set(str(value))
        for row in outcome.rows:
            size = "—" if row.size_bytes is None else f"{row.size_bytes:,} B"
            self.table.insert(
                "",
                "end",
                values=(
                    row.status.value.upper(),
                    row.relative_path,
                    size,
                    row.detail.replace("_", " "),
                ),
                tags=(row.status.value,),
            )
        if outcome.rows:
            self.results_caption_text.set(
                f"Showing {len(outcome.rows)} finding"
                f"{'s' if len(outcome.rows) != 1 else ''} from the latest scan."
            )
        elif not outcome.summary.assessment_conclusive:
            self.results_caption_text.set(
                "No file rows are available, but the scan remains inconclusive."
            )
        else:
            self.results_caption_text.set(
                "No findings to display from the latest conclusive scan."
            )

    def _show_error(self, value: object) -> None:
        if isinstance(value, GuiBaselineNotFoundError):
            self._set_status("Baseline required", _WARNING)
            messagebox.showwarning(
                "Baseline required", str(value), parent=self.root
            )
            return
        if isinstance(value, GuiBaselineExistsError):
            self._set_status("Baseline not replaced", _WARNING)
            messagebox.showwarning(
                "Baseline already exists", str(value), parent=self.root
            )
            return
        if isinstance(value, IncompleteScanError):
            self._set_status("Baseline not created", _WARNING)
            messagebox.showwarning(
                "Incomplete scan",
                "The baseline was not created because the scan was incomplete.\n\n"
                + str(value),
                parent=self.root,
            )
            return
        if isinstance(value, (BaselineError, DetectorError, GuiIntegrationError)):
            message = str(value)
        elif isinstance(value, OSError):
            message = "A filesystem operation failed. Check access and try again."
        else:
            message = "An unexpected error prevented the operation from completing."
        self._set_status("Operation failed", _DANGER)
        messagebox.showerror("IntegrityGuard error", message, parent=self.root)

    def _clear_results(self) -> None:
        for item in self.table.get_children():
            self.table.delete(item)
        for value in self.summary_values.values():
            value.set("0")

    def _set_status(self, text: str, color: str) -> None:
        self.status_text.set(f"STATUS  {text}")
        self.status_label.configure(foreground=color)

    def _set_progress_visible(self, visible: bool) -> None:
        """Show scan activity only while a worker reports an active scan."""
        if visible == self._progress_visible:
            return
        self._progress_visible = visible
        if visible:
            self.progress.grid()
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.grid_remove()

    def _set_monitoring_state(self, state: GuiMonitoringState) -> None:
        color = {
            GuiMonitoringState.RUNNING: _SUCCESS,
            GuiMonitoringState.STOPPING: _WARNING,
            GuiMonitoringState.STOPPED: _MUTED,
            GuiMonitoringState.ERROR: _DANGER,
        }[state]
        self.monitor_status_text.set(f"STATE  {state.value.title()}")
        self.monitor_status_label.configure(foreground=color)
        if state is GuiMonitoringState.RUNNING:
            self._start_monitoring_animation()
        else:
            self._stop_monitoring_animation()

    def _start_monitoring_animation(self) -> None:
        """Show subtle activity while periodic monitoring is enabled."""
        self.monitor_activity_label.grid()
        self.monitor_activity_label.start()

    def _stop_monitoring_animation(self) -> None:
        self.monitor_activity_label.stop()
        self.monitor_activity_label.grid_remove()

    def _reset_monitoring_metrics(self) -> None:
        self.completed_scans_text.set("0")
        self.last_scan_text.set("Never")
        self.active_changes_text.set("0")

    def _refresh_controls(self) -> None:
        manual_state = (
            "normal"
            if (
                self.selected_folder is not None
                and not self._busy
                and not self._monitoring.active
            )
            else "disabled"
        )
        self.baseline_button.configure(state=manual_state)
        self.scan_button.configure(state=manual_state)
        locked = self._busy or self._monitoring.active
        self.browse_button.configure(state="disabled" if locked else "normal")
        start_allowed = (
            manual_state == "normal" and self._selected_has_baseline
        )
        self.start_monitor_button.configure(
            state="normal" if start_allowed else "disabled"
        )
        self.stop_monitor_button.configure(
            state=(
                "normal"
                if self._monitoring.state is GuiMonitoringState.RUNNING
                else "disabled"
            )
        )
        self.interval_box.configure(state="disabled" if locked else "readonly")

    def _on_close(self) -> None:
        if self._busy:
            messagebox.showinfo(
                "Operation in progress",
                "Wait for the current filesystem operation to finish before closing.",
                parent=self.root,
            )
            return
        if self._monitoring.active:
            self._closing = True
            self._stop_monitoring()
            return
        self._stop_monitoring_animation()
        self.root.destroy()


def _enable_windows_dpi_awareness() -> None:
    """Request system-DPI-aware sizing before Tk creates the application window."""
    if os.name != "nt":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        # Tk remains usable when the host has already selected a DPI mode or
        # the legacy API is unavailable.
        pass


def main() -> None:
    """Launch the IntegrityGuard desktop application."""
    _enable_windows_dpi_awareness()
    root = tk.Tk()
    IntegrityGuardApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
