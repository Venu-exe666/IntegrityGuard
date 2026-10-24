"""Tkinter desktop interface for IntegrityGuard GUI Phase 2."""

from __future__ import annotations

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
    MonitoringSession,
)

_BACKGROUND = "#f4f7fb"
_PANEL = "#ffffff"
_TEXT = "#172033"
_MUTED = "#5f6b7a"
_ACCENT = "#2563eb"
_SUCCESS = "#15803d"
_WARNING = "#b45309"
_DANGER = "#b91c1c"
_MAX_LIVE_ALERT_ROWS = 1000


@dataclass(frozen=True, slots=True)
class _OperationMessage:
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
        self._operation_thread: threading.Thread | None = None
        self._monitor_thread: threading.Thread | None = None
        self._monitoring = GuiMonitoringControl()
        self._messages: queue.Queue[object] = queue.Queue()

        self.path_text = tk.StringVar(value="No folder selected")
        self.status_text = tk.StringVar(value="Ready")
        self.monitor_status_text = tk.StringVar(value="●  Stopped")
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
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_window(self) -> None:
        self.root.title("IntegrityGuard")
        self.root.geometry("1080x790")
        self.root.minsize(900, 680)
        self.root.configure(background=_BACKGROUND)

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("App.TFrame", background=_BACKGROUND)
        style.configure("Panel.TFrame", background=_PANEL)
        style.configure(
            "Title.TLabel",
            background=_BACKGROUND,
            foreground=_TEXT,
            font=("Segoe UI Semibold", 24),
        )
        style.configure(
            "Subtitle.TLabel",
            background=_BACKGROUND,
            foreground=_MUTED,
            font=("Segoe UI", 10),
        )
        style.configure(
            "PanelTitle.TLabel",
            background=_PANEL,
            foreground=_TEXT,
            font=("Segoe UI Semibold", 11),
        )
        style.configure(
            "Path.TLabel",
            background=_PANEL,
            foreground=_MUTED,
            font=("Segoe UI", 10),
        )
        style.configure("Primary.TButton", font=("Segoe UI Semibold", 10))
        style.configure("Action.TButton", font=("Segoe UI", 10))
        style.configure("Monitor.TLabel", font=("Segoe UI Semibold", 10))
        style.configure("Treeview", rowheight=28, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI Semibold", 9))

    def _build_layout(self) -> None:
        outer = ttk.Frame(self.root, style="App.TFrame", padding=24)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text="IntegrityGuard", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            outer,
            text="File integrity monitoring with trusted SHA-256 baselines",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(2, 18))

        selection = ttk.Frame(outer, style="Panel.TFrame", padding=16)
        selection.pack(fill="x")
        selection.columnconfigure(0, weight=1)
        ttk.Label(selection, text="Monitored folder", style="PanelTitle.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            selection,
            textvariable=self.path_text,
            style="Path.TLabel",
            anchor="w",
        ).grid(row=1, column=0, sticky="ew", pady=(7, 0))
        self.browse_button = ttk.Button(
            selection,
            text="Choose Folder",
            style="Action.TButton",
            command=self._choose_folder,
        )
        self.browse_button.grid(row=0, column=1, rowspan=2, padx=(16, 0))

        controls = ttk.Frame(outer, style="App.TFrame")
        controls.pack(fill="x", pady=14)
        self.baseline_button = ttk.Button(
            controls,
            text="Create Baseline",
            style="Primary.TButton",
            command=self._create_baseline,
            state="disabled",
        )
        self.baseline_button.pack(side="left")
        self.scan_button = ttk.Button(
            controls,
            text="Scan Now",
            style="Action.TButton",
            command=self._scan_now,
            state="disabled",
        )
        self.scan_button.pack(side="left", padx=(10, 0))
        self.progress = ttk.Progressbar(controls, mode="indeterminate", length=170)
        self.progress.pack(side="right")
        self.status_label = tk.Label(
            controls,
            textvariable=self.status_text,
            background=_BACKGROUND,
            foreground=_SUCCESS,
            font=("Segoe UI Semibold", 10),
        )
        self.status_label.pack(side="right", padx=(0, 14))

        monitoring = ttk.Frame(outer, style="Panel.TFrame", padding=16)
        monitoring.pack(fill="x", pady=(0, 14))
        monitoring.columnconfigure(6, weight=1)
        ttk.Label(
            monitoring, text="Live monitoring", style="PanelTitle.TLabel"
        ).grid(row=0, column=0, sticky="w")
        self.monitor_status_label = tk.Label(
            monitoring,
            textvariable=self.monitor_status_text,
            background=_PANEL,
            foreground=_MUTED,
            font=("Segoe UI Semibold", 10),
        )
        self.monitor_status_label.grid(row=0, column=1, padx=(14, 20), sticky="w")
        ttk.Label(monitoring, text="Interval", style="Path.TLabel").grid(
            row=0, column=2, padx=(0, 7)
        )
        self.interval_box = ttk.Combobox(
            monitoring,
            textvariable=self.monitor_interval,
            values=("10", "30", "60"),
            state="readonly",
            width=5,
        )
        self.interval_box.grid(row=0, column=3)
        ttk.Label(monitoring, text="seconds", style="Path.TLabel").grid(
            row=0, column=4, padx=(5, 18)
        )
        self.start_monitor_button = ttk.Button(
            monitoring,
            text="Start Monitoring",
            style="Primary.TButton",
            command=self._start_monitoring,
            state="disabled",
        )
        self.start_monitor_button.grid(row=0, column=5, padx=(0, 8))
        self.stop_monitor_button = ttk.Button(
            monitoring,
            text="Stop Monitoring",
            style="Action.TButton",
            command=self._stop_monitoring,
            state="disabled",
        )
        self.stop_monitor_button.grid(row=0, column=6, sticky="w")

        metrics = ttk.Frame(monitoring, style="Panel.TFrame")
        metrics.grid(row=1, column=0, columnspan=7, sticky="ew", pady=(13, 0))
        for column, (label, variable) in enumerate(
            (
                ("Completed scans", self.completed_scans_text),
                ("Last scan (UTC)", self.last_scan_text),
                ("Active changes", self.active_changes_text),
            )
        ):
            metrics.columnconfigure(column, weight=1)
            item = ttk.Frame(metrics, style="Panel.TFrame")
            item.grid(row=0, column=column, sticky="w", padx=(0, 40))
            ttk.Label(item, text=label, style="Path.TLabel").pack(anchor="w")
            tk.Label(
                item,
                textvariable=variable,
                background=_PANEL,
                foreground=_TEXT,
                font=("Segoe UI Semibold", 11),
            ).pack(anchor="w")

        summary = ttk.Frame(outer, style="App.TFrame")
        summary.pack(fill="x", pady=(0, 14))
        for index, name in enumerate(self.summary_values):
            summary.columnconfigure(index, weight=1)
            card = ttk.Frame(summary, style="Panel.TFrame", padding=(14, 10))
            card.grid(
                row=0,
                column=index,
                sticky="nsew",
                padx=(0 if index == 0 else 5, 0 if index == 4 else 5),
            )
            ttk.Label(card, text=name, style="Path.TLabel").pack(anchor="w")
            tk.Label(
                card,
                textvariable=self.summary_values[name],
                background=_PANEL,
                foreground=_TEXT,
                font=("Segoe UI Semibold", 18),
            ).pack(anchor="w")

        results = ttk.Frame(outer, style="Panel.TFrame", padding=16)
        results.pack(fill="both", expand=True)
        ttk.Label(results, text="Detected changes", style="PanelTitle.TLabel").pack(
            anchor="w", pady=(0, 10)
        )

        table_frame = ttk.Frame(results, style="Panel.TFrame")
        table_frame.pack(fill="both", expand=True)
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
        self.table.column("status", width=105, stretch=False)
        self.table.column("path", width=440, minwidth=220)
        self.table.column("size", width=100, stretch=False, anchor="e")
        self.table.column("detail", width=220, minwidth=150)
        self.table.tag_configure(ChangeStatus.ADDED.value, foreground=_SUCCESS)
        self.table.tag_configure(ChangeStatus.MODIFIED.value, foreground=_WARNING)
        self.table.tag_configure(ChangeStatus.DELETED.value, foreground=_DANGER)
        self.table.tag_configure(ChangeStatus.UNKNOWN.value, foreground=_MUTED)
        self.table.tag_configure("resolved", foreground=_ACCENT)
        self.table.tag_configure("scan_error", foreground=_DANGER)
        self.table.tag_configure("skipped_path", foreground=_MUTED)
        scrollbar = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.table.yview
        )
        self.table.configure(yscrollcommand=scrollbar.set)
        self.table.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

    def _choose_folder(self) -> None:
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
        try:
            has_baseline = self.service.baseline_exists(self.selected_folder)
        except OSError as error:
            self._selected_has_baseline = False
            self._show_error(error)
            self._refresh_controls()
            return
        self._selected_has_baseline = has_baseline
        self._set_status("Baseline available" if has_baseline else "Ready", _SUCCESS)
        self._refresh_controls()

    def _create_baseline(self) -> None:
        if self.selected_folder is None:
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
            lambda: self.service.create_for_root(
                selected_folder,
                allow_new_version=allow_new_version,
            ),
        )

    def _scan_now(self) -> None:
        if self.selected_folder is None:
            return
        selected_folder = self.selected_folder
        self._start_operation(
            "Scanning files…",
            lambda: self.service.scan_root(selected_folder),
        )

    def _start_operation(self, status: str, operation: Callable[[], object]) -> None:
        if self._busy or self._monitoring.active:
            return
        self._busy = True
        self._set_status(status, _ACCENT)
        self.progress.start(10)
        self._refresh_controls()

        def worker() -> None:
            try:
                result = operation()
            except Exception as error:
                self._messages.put(_OperationMessage("error", error))
            else:
                self._messages.put(_OperationMessage("success", result))

        self._operation_thread = threading.Thread(
            target=worker,
            daemon=False,
            name="integrityguard-gui-operation",
        )
        self._operation_thread.start()
        self._ensure_message_poll()

    def _handle_operation_message(self, message: _OperationMessage) -> None:
        if self._operation_thread is not None:
            self._operation_thread.join()
            self._operation_thread = None
        self._busy = False
        self.progress.stop()
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
        self._set_monitoring_state(GuiMonitoringState.RUNNING)
        self._set_status("Polling monitor running", _ACCENT)
        self.progress.start(10)
        self._refresh_controls()

        def publish_cycle(cycle: MonitoringCycle) -> None:
            self._messages.put(_MonitoringCycleMessage(session_id, cycle))

        def worker() -> None:
            try:
                session = self.service.monitor_root(
                    selected_folder,
                    interval=interval,
                    stop_event=stop_event,
                    on_cycle=publish_cycle,
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
            self.progress.stop()
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
        if self._busy or self._monitoring.active or not self._messages.empty():
            self._ensure_message_poll()

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
        self.progress.stop()
        self._set_monitoring_state(GuiMonitoringState.STOPPED)
        self._set_status("Monitoring stopped", _MUTED)
        self._refresh_controls()
        if self._closing:
            self.root.destroy()

    def _handle_monitoring_error(self, message: _MonitoringErrorMessage) -> None:
        if not self._monitoring.finish(message.session_id, failed=True):
            return
        self._join_monitor_thread()
        self.progress.stop()
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
        self.status_text.set(f"●  {text}")
        self.status_label.configure(foreground=color)

    def _set_monitoring_state(self, state: GuiMonitoringState) -> None:
        color = {
            GuiMonitoringState.RUNNING: _SUCCESS,
            GuiMonitoringState.STOPPING: _WARNING,
            GuiMonitoringState.STOPPED: _MUTED,
            GuiMonitoringState.ERROR: _DANGER,
        }[state]
        self.monitor_status_text.set(f"●  {state.value.title()}")
        self.monitor_status_label.configure(foreground=color)

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
        self.root.destroy()


def main() -> None:
    """Launch the IntegrityGuard desktop application."""
    root = tk.Tk()
    IntegrityGuardApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
