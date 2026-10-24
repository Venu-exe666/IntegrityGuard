"""Tests for the presentation-neutral IntegrityGuard GUI integration layer."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from threading import Event
from typing import NoReturn

import pytest

from integrityguard.baseline import (
    BaselineError,
    IncompleteScanError,
    create_baseline,
)
from integrityguard.detector import ChangeStatus, UnknownReason, compare_baseline
from integrityguard.gui_service import (
    GuiBaselineExistsError,
    GuiBaselineNotFoundError,
    GuiIntegrationError,
    GuiMonitoringControl,
    GuiMonitoringState,
    GuiService,
    default_app_data_dir,
    result_rows,
)
from integrityguard.monitoring import MonitoringFindingKind, MonitoringScanEvent
from integrityguard.scanner import (
    ScanError,
    ScanErrorKind,
    ScanStatus,
    scan_directory,
)


def _service(app_data: Path) -> GuiService:
    return GuiService(
        app_data,
        token_function=lambda: "fixedtoken",
    )


def test_default_app_data_prefers_local_app_data(tmp_path: Path) -> None:
    assert default_app_data_dir({"LOCALAPPDATA": str(tmp_path)}) == (
        tmp_path / "IntegrityGuard"
    )


def test_gui_creates_and_uses_baseline_outside_monitored_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "monitored"
    root.mkdir()
    target = root / "evidence.txt"
    target.write_bytes(b"trusted")
    service = _service(tmp_path / "app-data")

    created = service.create_for_root(root)
    outcome = service.scan_root(root)

    assert created.baseline_path.parent == tmp_path / "app-data" / "baselines"
    assert root not in created.baseline_path.parents
    assert created.file_count == 1
    assert created.skipped_path_count == 0
    assert outcome.baseline_path == created.baseline_path
    assert outcome.report.is_clean
    assert outcome.summary.unchanged == 1
    assert outcome.rows == ()
    assert target.read_bytes() == b"trusted"


def test_gui_scan_rows_and_summary_use_real_change_report(tmp_path: Path) -> None:
    root = tmp_path / "monitored"
    root.mkdir()
    (root / "modified.txt").write_bytes(b"before")
    (root / "deleted.txt").write_bytes(b"delete me")
    service = _service(tmp_path / "app-data")
    service.create_for_root(root)

    (root / "modified.txt").write_bytes(b"after")
    (root / "deleted.txt").unlink()
    (root / "added.txt").write_bytes(b"new")
    outcome = service.scan_root(root)

    assert outcome.summary.added == 1
    assert outcome.summary.modified == 1
    assert outcome.summary.deleted == 1
    assert outcome.summary.unknown == 0
    assert outcome.summary.unchanged == 0
    assert outcome.summary.assessment_conclusive
    assert [(row.relative_path, row.status) for row in outcome.rows] == [
        ("added.txt", ChangeStatus.ADDED),
        ("deleted.txt", ChangeStatus.DELETED),
        ("modified.txt", ChangeStatus.MODIFIED),
    ]


def test_existing_baseline_requires_confirmation_and_versions_are_immutable(
    tmp_path: Path,
) -> None:
    root = tmp_path / "monitored"
    root.mkdir()
    (root / "file.txt").write_bytes(b"first")
    tokens = iter(("first", "second"))
    service = GuiService(
        tmp_path / "app-data",
        token_function=lambda: next(tokens),
    )

    first = service.create_for_root(root)
    first_payload = first.baseline_path.read_bytes()
    with pytest.raises(GuiBaselineExistsError, match="already exists"):
        service.create_for_root(root)

    (root / "file.txt").write_bytes(b"second")
    second = service.create_for_root(root, allow_new_version=True)

    assert first.baseline_path.exists()
    assert first.baseline_path.read_bytes() == first_payload
    assert second.baseline_path.exists()
    assert first.baseline_path != second.baseline_path
    assert service.latest_baseline_path(root) == second.baseline_path
    assert len(tuple(service.baseline_directory.glob("*.json"))) == 2
    assert service.scan_root(root).report.is_clean


def test_different_roots_do_not_share_baseline_names(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    (first_root / "file.txt").write_bytes(b"one")
    (second_root / "file.txt").write_bytes(b"two")
    tokens = iter(("one", "two"))
    service = GuiService(
        tmp_path / "app-data",
        token_function=lambda: next(tokens),
    )

    first = service.create_for_root(first_root)
    second = service.create_for_root(second_root)

    assert first.baseline_path.name != second.baseline_path.name
    assert service.latest_baseline_path(first_root) == first.baseline_path
    assert service.latest_baseline_path(second_root) == second.baseline_path


def test_gui_rejects_storage_inside_monitored_root_before_writing(
    tmp_path: Path,
) -> None:
    root = tmp_path / "monitored"
    root.mkdir()
    target = root / "file.txt"
    target.write_bytes(b"unchanged")
    unsafe_app_data = root / "application-data"
    service = GuiService(unsafe_app_data)

    with pytest.raises(GuiIntegrationError, match="baseline storage cannot be inside"):
        service.create_for_root(root)

    assert not unsafe_app_data.exists()
    assert target.read_bytes() == b"unchanged"


def test_missing_gui_baseline_is_reported_without_scanning(tmp_path: Path) -> None:
    root = tmp_path / "monitored"
    root.mkdir()
    scan_called = False

    def unexpected_scan(path: object) -> NoReturn:
        nonlocal scan_called
        scan_called = True
        raise AssertionError("scan should not run without a baseline")

    service = GuiService(tmp_path / "app-data", scan_function=unexpected_scan)

    with pytest.raises(GuiBaselineNotFoundError, match="No GUI baseline"):
        service.scan_root(root)
    assert not scan_called


def test_incomplete_scan_never_creates_gui_baseline(tmp_path: Path) -> None:
    root = tmp_path / "monitored"
    root.mkdir()
    (root / "file.txt").write_bytes(b"content")
    complete = scan_directory(root)
    incomplete = replace(
        complete,
        errors=(
            ScanError(
                relative_path=".",
                kind=ScanErrorKind.DIRECTORY_ACCESS,
                message="sanitized test failure",
                exception_type="PermissionError",
            ),
        ),
    )
    service = GuiService(
        tmp_path / "app-data",
        scan_function=lambda path: incomplete,
    )

    with pytest.raises(IncompleteScanError):
        service.create_for_root(root)
    assert tuple(service.baseline_directory.glob("*.json")) == ()


def test_unknown_change_becomes_an_unknown_gui_row(tmp_path: Path) -> None:
    root = tmp_path / "monitored"
    root.mkdir()
    (root / "file.txt").write_bytes(b"content")
    trusted_scan = scan_directory(root)
    baseline = create_baseline(trusted_scan)
    failed_file = replace(
        trusted_scan.files[0],
        sha256=None,
        status=ScanStatus.ERROR,
    )
    failed_scan = replace(
        trusted_scan,
        files=(failed_file,),
        errors=(
            ScanError(
                relative_path="file.txt",
                kind=ScanErrorKind.FILE_ACCESS,
                message="sanitized test failure",
                exception_type="PermissionError",
            ),
        ),
    )
    report = compare_baseline(baseline, failed_scan)

    rows = result_rows(report)

    assert len(rows) == 1
    assert rows[0].relative_path == "file.txt"
    assert rows[0].status is ChangeStatus.UNKNOWN
    assert rows[0].detail == UnknownReason.UNTRUSTED_RESULT.value


def test_gui_monitoring_uses_latest_baseline_and_typed_alerts(
    tmp_path: Path,
) -> None:
    root = tmp_path / "monitored"
    root.mkdir()
    target = root / "file.txt"
    target.write_bytes(b"trusted")
    service = _service(tmp_path / "app-data")
    service.create_for_root(root)
    target.write_bytes(b"changed")
    stop_event = Event()
    cycles = []

    def receive_cycle(cycle) -> None:
        cycles.append(cycle)
        stop_event.set()

    session = service.monitor_root(
        root,
        interval=60,
        stop_event=stop_event,
        on_cycle=receive_cycle,
    )

    assert session.interrupted is True
    assert session.status.completed_scans == 1
    assert len(cycles) == 1
    assert cycles[0].new_alerts[0].kind is MonitoringFindingKind.MODIFIED


def test_invalid_gui_baseline_stops_before_monitoring(tmp_path: Path) -> None:
    root = tmp_path / "monitored"
    root.mkdir()
    (root / "file.txt").write_bytes(b"trusted")
    monitor_called = False

    def unexpected_monitor(*args, **kwargs) -> NoReturn:
        nonlocal monitor_called
        monitor_called = True
        raise AssertionError("monitor should not start with an invalid baseline")

    service = GuiService(
        tmp_path / "app-data",
        monitor_function=unexpected_monitor,
        token_function=lambda: "fixedtoken",
    )
    created = service.create_for_root(root)
    created.baseline_path.write_text("{}", encoding="utf-8")

    with pytest.raises(BaselineError):
        service.monitor_root(
            root,
            interval=10,
            stop_event=Event(),
            on_cycle=lambda cycle: None,
        )
    assert not monitor_called


def test_gui_monitoring_state_transitions_and_stale_session_rejection() -> None:
    control = GuiMonitoringControl()

    first_id, first_stop = control.start()
    assert control.state is GuiMonitoringState.RUNNING
    assert control.active
    with pytest.raises(RuntimeError, match="already active"):
        control.start()

    assert control.request_stop()
    assert first_stop.is_set()
    assert control.state is GuiMonitoringState.STOPPING
    assert control.finish(first_id)
    assert control.state is GuiMonitoringState.STOPPED
    assert not control.active

    second_id, _ = control.start()
    assert second_id != first_id
    assert not control.finish(first_id, failed=True)
    assert control.state is GuiMonitoringState.RUNNING
    assert control.finish(second_id, failed=True)
    assert control.state is GuiMonitoringState.ERROR


def test_gui_manual_scan_lifecycle_is_balanced_on_failure(tmp_path: Path) -> None:
    root = tmp_path / "monitored"
    root.mkdir()
    events: list[MonitoringScanEvent] = []

    def fail(path: object) -> NoReturn:
        raise RuntimeError("test scan failure")

    service = GuiService(tmp_path / "app-data", scan_function=fail)

    with pytest.raises(RuntimeError, match="test scan failure"):
        service.create_for_root(root, on_scan_event=events.append)

    assert events == [
        MonitoringScanEvent.STARTED,
        MonitoringScanEvent.FINISHED,
    ]


def test_gui_monitoring_forwards_scan_lifecycle_events(tmp_path: Path) -> None:
    root = tmp_path / "monitored"
    root.mkdir()
    (root / "file.txt").write_bytes(b"trusted")
    service = _service(tmp_path / "app-data")
    service.create_for_root(root)
    stop_event = Event()
    events: list[MonitoringScanEvent] = []

    def receive_cycle(cycle) -> None:
        stop_event.set()

    service.monitor_root(
        root,
        interval=60,
        stop_event=stop_event,
        on_cycle=receive_cycle,
        on_scan_event=events.append,
    )

    assert events == [
        MonitoringScanEvent.STARTED,
        MonitoringScanEvent.FINISHED,
    ]
