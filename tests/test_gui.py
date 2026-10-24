"""Display-dependent smoke tests for the Tkinter desktop presentation."""

from __future__ import annotations

import tkinter as tk
import threading
import time
from pathlib import Path
from tkinter import ttk

import pytest

from integrityguard.gui import (
    IntegrityGuardApp,
    _MonitoringErrorMessage,
    _ScanActivityMessage,
)
from integrityguard.gui_service import GuiMonitoringState
from integrityguard.monitoring import MonitoringScanEvent


@pytest.fixture(scope="module")
def display_root():
    """Provide one stable Tk interpreter for the display-dependent test module."""
    try:
        root = tk.Tk()
    except tk.TclError as error:
        pytest.skip(f"Tk display is unavailable: {error}")
    try:
        yield root
    finally:
        if root.winfo_exists():
            root.destroy()


@pytest.fixture
def tk_root(display_root: tk.Tk):
    """Reset widgets while retaining the module's stable Tk interpreter."""
    for child in display_root.winfo_children():
        child.destroy()
    display_root.geometry("1380x900")
    display_root.update()
    yield display_root


def test_dark_dashboard_fits_minimum_supported_window(tk_root: tk.Tk) -> None:
    app = IntegrityGuardApp(tk_root)
    tk_root.geometry("1080x720")
    tk_root.update()

    style = ttk.Style(tk_root)
    assert tk_root.title() == "IntegrityGuard"
    assert tk_root.cget("background") == "#07111f"
    assert style.theme_use() == "clam"
    assert style.lookup("Treeview", "background") == "#0d1b2d"
    assert app.path_entry.instate(("readonly",))
    assert app.table.winfo_height() >= 60
    assert not app._progress_visible
    assert not app.progress.winfo_ismapped()
    assert [button.cget("text") for button in app.coming_soon_buttons] == [
        "Settings  —  Coming Soon",
        "Reports  —  Coming Soon",
        "History  —  Coming Soon",
    ]
    assert all(
        button.instate(("disabled",)) for button in app.coming_soon_buttons
    )
    assert not app.monitor_activity_label.winfo_ismapped()

    window_right = tk_root.winfo_rootx() + tk_root.winfo_width()
    window_bottom = tk_root.winfo_rooty() + tk_root.winfo_height()
    for widget in (
        app.browse_button,
        app.baseline_button,
        app.scan_button,
        app.start_monitor_button,
        app.stop_monitor_button,
        app.interval_box,
        app.table,
    ):
        assert widget.winfo_rootx() + widget.winfo_width() <= window_right
        assert widget.winfo_rooty() + widget.winfo_height() <= window_bottom


def test_dashboard_controls_reflect_workflow_state(
    tk_root: tk.Tk,
    tmp_path: Path,
) -> None:
    app = IntegrityGuardApp(tk_root)
    tk_root.update_idletasks()

    assert app.baseline_button.instate(("disabled",))
    assert app.scan_button.instate(("disabled",))
    assert app.start_monitor_button.instate(("disabled",))
    assert app.stop_monitor_button.instate(("disabled",))

    app.selected_folder = tmp_path
    app._selected_has_baseline = True
    app._refresh_controls()
    assert not app.baseline_button.instate(("disabled",))
    assert not app.scan_button.instate(("disabled",))
    assert not app.start_monitor_button.instate(("disabled",))

    session_id, _ = app._monitoring.start()
    app._refresh_controls()
    assert app.baseline_button.instate(("disabled",))
    assert app.scan_button.instate(("disabled",))
    assert app.start_monitor_button.instate(("disabled",))
    assert not app.stop_monitor_button.instate(("disabled",))
    assert app.interval_box.instate(("disabled",))

    assert app._monitoring.request_stop()
    app._set_monitoring_state(GuiMonitoringState.STOPPING)
    app._refresh_controls()
    assert app.stop_monitor_button.instate(("disabled",))
    assert app._monitoring.finish(session_id)


def _pump_until(root: tk.Tk, condition, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition() and time.monotonic() < deadline:
        root.update()
        time.sleep(0.01)
    assert condition()


def test_monitoring_animation_runs_between_scans_and_stops(
    tk_root: tk.Tk,
) -> None:
    app = IntegrityGuardApp(tk_root)
    session_id, _ = app._monitoring.start()
    app._set_monitoring_state(GuiMonitoringState.RUNNING)
    tk_root.update()

    assert app.monitor_activity_label.winfo_ismapped()
    assert app.monitor_activity_label.animation_running
    assert not app._progress_visible
    assert not app.progress.winfo_ismapped()

    first_items = app.monitor_activity_label.find_all()
    _pump_until(
        tk_root,
        lambda: app.monitor_activity_label.find_all() != first_items,
        timeout=1.0,
    )

    assert app._monitoring.request_stop()
    app._set_monitoring_state(GuiMonitoringState.STOPPING)
    tk_root.update()
    assert not app.monitor_activity_label.animation_running
    assert app.monitor_activity_label.find_all() == ()
    assert not app.monitor_activity_label.winfo_ismapped()
    assert not app._progress_visible
    assert app._monitoring.finish(session_id)


def test_manual_scan_progress_is_visible_only_during_active_scan(
    tk_root: tk.Tk,
) -> None:
    app = IntegrityGuardApp(tk_root)
    scan_started = threading.Event()
    release_scan = threading.Event()

    def operation(on_scan_event):
        on_scan_event(MonitoringScanEvent.STARTED)
        scan_started.set()
        assert release_scan.wait(timeout=3)
        on_scan_event(MonitoringScanEvent.FINISHED)
        return object()

    app._start_operation("Scanning files…", operation)
    assert scan_started.wait(timeout=3)
    _pump_until(tk_root, lambda: app._progress_visible)
    assert app.progress.winfo_ismapped()
    assert app.progress.animation_running
    assert app.progress.find_all()

    release_scan.set()
    _pump_until(tk_root, lambda: not app._busy)
    assert not app._progress_visible
    assert not app.progress.winfo_ismapped()
    assert not app.progress.animation_running


def test_manual_scan_error_hides_progress(
    tk_root: tk.Tk,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = IntegrityGuardApp(tk_root)
    tk_root.update()
    monkeypatch.setattr("integrityguard.gui.messagebox.showerror", lambda *a, **k: None)
    scan_started = threading.Event()
    release_scan = threading.Event()

    def failing_operation(on_scan_event):
        on_scan_event(MonitoringScanEvent.STARTED)
        scan_started.set()
        try:
            assert release_scan.wait(timeout=3)
            raise RuntimeError("test scan error")
        finally:
            on_scan_event(MonitoringScanEvent.FINISHED)

    app._start_operation("Scanning files…", failing_operation)
    assert scan_started.wait(timeout=3)
    _pump_until(tk_root, lambda: app._progress_visible)
    assert app.progress.winfo_ismapped()

    release_scan.set()
    _pump_until(tk_root, lambda: not app._busy)
    assert not app._progress_visible
    assert not app.progress.winfo_ismapped()


def test_progress_hides_for_monitoring_gaps_stopping_and_errors(
    tk_root: tk.Tk,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = IntegrityGuardApp(tk_root)
    tk_root.update()
    monkeypatch.setattr("integrityguard.gui.messagebox.showerror", lambda *a, **k: None)
    session_id, _ = app._monitoring.start()

    app._handle_scan_activity(
        _ScanActivityMessage(
            "monitoring", session_id, MonitoringScanEvent.STARTED
        )
    )
    tk_root.update()
    assert app._progress_visible
    assert app.progress.winfo_ismapped()

    app._handle_scan_activity(
        _ScanActivityMessage(
            "monitoring", session_id, MonitoringScanEvent.FINISHED
        )
    )
    tk_root.update()
    assert app._monitoring.state is GuiMonitoringState.RUNNING
    assert not app._progress_visible
    assert not app.progress.winfo_ismapped()

    app._handle_scan_activity(
        _ScanActivityMessage(
            "monitoring", session_id, MonitoringScanEvent.STARTED
        )
    )
    app._stop_monitoring()
    tk_root.update()
    assert app._monitoring.state is GuiMonitoringState.STOPPING
    assert not app._progress_visible
    assert not app.progress.winfo_ismapped()
    assert app._monitoring.finish(session_id)

    error_session_id, _ = app._monitoring.start()
    app._handle_scan_activity(
        _ScanActivityMessage(
            "monitoring", error_session_id, MonitoringScanEvent.STARTED
        )
    )
    app._handle_monitoring_error(
        _MonitoringErrorMessage(error_session_id, RuntimeError("test error"))
    )
    tk_root.update()
    assert app._monitoring.state is GuiMonitoringState.ERROR
    assert not app._progress_visible
    assert not app.progress.winfo_ismapped()
