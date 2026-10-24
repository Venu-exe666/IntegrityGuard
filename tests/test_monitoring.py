"""Tests for foreground periodic file-integrity monitoring."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from integrityguard.baseline import (
    Baseline,
    baseline_to_json,
    create_baseline,
    save_baseline,
)
from integrityguard.detector import RootMismatchError
from integrityguard.monitoring import (
    DEFAULT_INTERVAL_SECONDS,
    AlertEvent,
    InvalidMonitoringIntervalError,
    MonitoringAssessment,
    MonitoringFindingKind,
    MonitoringStartupError,
    format_monitoring_cycle,
    format_monitoring_header,
    format_monitoring_summary,
    monitor_directory,
    validate_interval,
)
from integrityguard.scanner import (
    ScanError,
    ScanErrorKind,
    ScanLimits,
    ScanReport,
    ScanStatus,
    scan_directory,
)


def _baseline_directory(
    tmp_path: Path,
    files: dict[str, bytes] | None = None,
) -> tuple[Path, Baseline]:
    root = tmp_path / "monitored files"
    root.mkdir(parents=True)
    for relative_path, content in (files or {"file.txt": b"original"}).items():
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return root, create_baseline(scan_directory(root))


def _utc_clock() -> Callable[[], datetime]:
    current = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)

    def now() -> datetime:
        nonlocal current
        result = current
        current += timedelta(seconds=1)
        return result

    return now


def _run(
    root: Path,
    baseline: Baseline,
    *,
    scan_limit: int,
    scan_function=scan_directory,
    wait_function=lambda seconds: None,
):
    cycles = []
    session = monitor_directory(
        root,
        baseline,
        scan_function=scan_function,
        wait_function=wait_function,
        utc_now=_utc_clock(),
        monotonic=lambda: 100.0,
        on_cycle=cycles.append,
        scan_limit=scan_limit,
    )
    return cycles, session


def _failed_scan(root: Path) -> ScanReport:
    scan = scan_directory(root)
    failed = replace(scan.files[0], sha256=None, status=ScanStatus.ERROR)
    error = ScanError(
        relative_path=failed.relative_path,
        kind=ScanErrorKind.FILE_ACCESS,
        message="sensitive details",
        exception_type="PermissionError",
    )
    return replace(scan, files=(failed,), errors=(error,))


def test_default_polling_interval_and_immediate_initial_scan(
    tmp_path: Path,
) -> None:
    root, baseline = _baseline_directory(tmp_path)
    events: list[object] = []

    def scan(path: Path) -> ScanReport:
        events.append("scan")
        return scan_directory(path)

    def wait(seconds: float) -> None:
        events.append(("wait", seconds))

    cycles, _ = _run(
        root,
        baseline,
        scan_limit=2,
        scan_function=scan,
        wait_function=wait,
    )

    assert DEFAULT_INTERVAL_SECONDS == 10.0
    assert events == ["scan", ("wait", 10.0), "scan"]
    assert [cycle.scan_number for cycle in cycles] == [1, 2]


def test_custom_polling_interval(tmp_path: Path) -> None:
    root, baseline = _baseline_directory(tmp_path)
    waits: list[float] = []

    monitor_directory(
        root,
        baseline,
        interval=2.5,
        wait_function=waits.append,
        utc_now=_utc_clock(),
        monotonic=lambda: 10.0,
        scan_limit=2,
    )

    assert waits == [2.5]


@pytest.mark.parametrize(
    "value",
    ["invalid", 0, -1, 0.5, float("nan"), float("inf"), float("-inf"), True],
)
def test_invalid_intervals_are_rejected(value: object) -> None:
    with pytest.raises(InvalidMonitoringIntervalError):
        validate_interval(value)


def test_scans_never_overlap_and_use_no_worker_threads(tmp_path: Path) -> None:
    root, baseline = _baseline_directory(tmp_path)
    scanning = False
    thread_ids: list[int] = []

    def scan(path: Path) -> ScanReport:
        nonlocal scanning
        assert not scanning
        scanning = True
        thread_ids.append(threading.get_ident())
        report = scan_directory(path)
        scanning = False
        return report

    _run(root, baseline, scan_limit=3, scan_function=scan)

    assert thread_ids == [threading.main_thread().ident] * 3


def test_repeated_resource_limit_is_inconclusive_and_deduplicated(
    tmp_path: Path,
) -> None:
    root, baseline = _baseline_directory(
        tmp_path,
        {"a.txt": b"a", "b.txt": b"b"},
    )

    cycles, _ = _run(
        root,
        baseline,
        scan_limit=2,
        scan_function=lambda path: scan_directory(
            path,
            limits=ScanLimits(max_entries=1),
        ),
    )

    assert not cycles[0].report.assessment_conclusive
    assert cycles[0].report.deleted == ()
    assert len(cycles[0].new_alerts) == 3  # two UNKNOWN paths and one limit error
    assert cycles[1].new_alerts == ()
    assert cycles[1].repeated_finding_count == 3
    output = format_monitoring_cycle(cycles[1])
    assert "No new alerts" in output
    assert "INCOMPLETE assessment" in output


@pytest.mark.parametrize(
    ("operation", "expected_kind"),
    [
        ("modified", MonitoringFindingKind.MODIFIED),
        ("added", MonitoringFindingKind.ADDED),
        ("deleted", MonitoringFindingKind.DELETED),
    ],
)
def test_file_changes_create_alerts(
    tmp_path: Path,
    operation: str,
    expected_kind: MonitoringFindingKind,
) -> None:
    root, baseline = _baseline_directory(tmp_path)

    def change(_: float) -> None:
        if operation == "modified":
            (root / "file.txt").write_bytes(b"changed")
        elif operation == "added":
            (root / "new.txt").write_bytes(b"new")
        else:
            (root / "file.txt").unlink()

    cycles, _ = _run(root, baseline, scan_limit=2, wait_function=change)

    assert cycles[0].new_alerts == ()
    assert cycles[1].new_alerts[0].kind is expected_kind


def test_unchanged_cycles_are_quiet_by_default(tmp_path: Path) -> None:
    root, baseline = _baseline_directory(tmp_path)
    cycles, _ = _run(root, baseline, scan_limit=2)

    assert cycles[1].new_alerts == ()
    assert "No new alerts" in format_monitoring_cycle(cycles[1])


def test_unknown_and_scan_errors_remain_incomplete(tmp_path: Path) -> None:
    root, baseline = _baseline_directory(tmp_path)
    scans = iter([scan_directory(root), _failed_scan(root), _failed_scan(root)])
    cycles, session = _run(
        root,
        baseline,
        scan_limit=3,
        scan_function=lambda path: next(scans),
    )

    second = cycles[1]
    assert second.report.counts.unknown == 1
    assert second.report.scan_errors[0].kind is ScanErrorKind.FILE_ACCESS
    assert second.status.current_assessment is MonitoringAssessment.INCONCLUSIVE
    assert {alert.kind for alert in second.new_alerts} == {
        MonitoringFindingKind.UNKNOWN,
        MonitoringFindingKind.SCAN_ERROR,
    }
    assert cycles[2].new_alerts == ()
    assert cycles[2].repeated_finding_count == 2
    output = format_monitoring_cycle(cycles[2])
    assert "scan errors: 1" in output
    assert "INCOMPLETE" in output
    assert session.status.unknown_finding_count == 1


def test_scan_error_code_transition_creates_new_sanitized_alert(
    tmp_path: Path,
) -> None:
    root, baseline = _baseline_directory(tmp_path)
    clean = scan_directory(root)
    failed = _failed_scan(root)
    denied = replace(
        failed,
        errors=(
            replace(
                failed.errors[0],
                message="secret first path",
                errno=13,
            ),
        ),
    )
    missing = replace(
        failed,
        errors=(
            replace(
                failed.errors[0],
                message="secret second path",
                errno=2,
            ),
        ),
    )
    scans = iter([clean, denied, missing, missing])

    cycles, _ = _run(
        root,
        baseline,
        scan_limit=4,
        scan_function=lambda path: next(scans),
    )

    assert any(
        alert.kind is MonitoringFindingKind.SCAN_ERROR
        and alert.detail is not None
        and "errno=13" in alert.detail
        for alert in cycles[1].new_alerts
    )
    assert any(
        alert.kind is MonitoringFindingKind.SCAN_ERROR
        and alert.detail is not None
        and "errno=2" in alert.detail
        for alert in cycles[2].new_alerts
    )
    assert cycles[3].new_alerts == ()
    rendered = format_monitoring_cycle(cycles[2])
    assert "secret first path" not in rendered
    assert "secret second path" not in rendered


def test_unsafe_exception_labels_are_not_rendered(tmp_path: Path) -> None:
    root, baseline = _baseline_directory(tmp_path)
    failed = _failed_scan(root)
    unsafe_error = replace(
        failed.errors[0],
        exception_type="PermissionError\nFORGED TERMINAL LINE",
    )
    unsafe_scan = replace(failed, errors=(unsafe_error,))
    scans = iter([scan_directory(root), unsafe_scan])

    cycles, _ = _run(
        root,
        baseline,
        scan_limit=2,
        scan_function=lambda path: next(scans),
    )
    output = format_monitoring_cycle(cycles[1])

    assert "FORGED TERMINAL LINE" not in output
    assert "file_access" in output


def test_baseline_is_fixed_and_identical_alert_is_suppressed(
    tmp_path: Path,
) -> None:
    root, baseline = _baseline_directory(tmp_path)
    original_baseline = baseline_to_json(baseline)
    (root / "file.txt").write_bytes(b"changed")

    cycles, _ = _run(root, baseline, scan_limit=2)

    assert len(cycles[0].report.modified) == 1
    assert len(cycles[1].report.modified) == 1
    assert len(cycles[0].new_alerts) == 1
    assert cycles[1].new_alerts == ()
    assert baseline_to_json(baseline) == original_baseline


def test_modified_hash_change_creates_another_alert(tmp_path: Path) -> None:
    root, baseline = _baseline_directory(tmp_path)
    actions = iter([b"version-b", b"version-c"])

    def change(_: float) -> None:
        (root / "file.txt").write_bytes(next(actions))

    cycles, _ = _run(root, baseline, scan_limit=3, wait_function=change)

    assert cycles[1].new_alerts[0].kind is MonitoringFindingKind.MODIFIED
    assert cycles[2].new_alerts[0].kind is MonitoringFindingKind.MODIFIED


def test_previously_modified_file_becoming_deleted_is_redisplayed(
    tmp_path: Path,
) -> None:
    root, baseline = _baseline_directory(tmp_path)
    actions = iter(["modify", "delete"])

    def change(_: float) -> None:
        action = next(actions)
        if action == "modify":
            (root / "file.txt").write_bytes(b"changed")
        else:
            (root / "file.txt").unlink()

    cycles, _ = _run(root, baseline, scan_limit=3, wait_function=change)

    assert cycles[1].new_alerts[0].kind is MonitoringFindingKind.MODIFIED
    assert cycles[2].new_alerts[0].kind is MonitoringFindingKind.DELETED


def test_changed_file_returning_to_baseline_is_resolved(tmp_path: Path) -> None:
    root, baseline = _baseline_directory(tmp_path)
    actions = iter([b"changed", b"original"])

    def change(_: float) -> None:
        (root / "file.txt").write_bytes(next(actions))

    cycles, _ = _run(root, baseline, scan_limit=3, wait_function=change)

    resolved = cycles[2].resolved_alerts
    assert len(resolved) == 1
    assert resolved[0].event is AlertEvent.RESOLVED
    assert resolved[0].kind is MonitoringFindingKind.MODIFIED
    assert "not proof of system safety" in format_monitoring_cycle(cycles[2])


def test_resolved_issue_reappears(tmp_path: Path) -> None:
    root, baseline = _baseline_directory(tmp_path)
    clean = scan_directory(root)
    failed = _failed_scan(root)
    scans = iter([clean, failed, clean, failed])

    cycles, _ = _run(
        root,
        baseline,
        scan_limit=4,
        scan_function=lambda path: next(scans),
    )

    assert cycles[1].new_alerts
    assert cycles[2].resolved_alerts
    assert cycles[3].new_alerts


def test_unknown_becoming_trusted_is_redisplayed(tmp_path: Path) -> None:
    root, baseline = _baseline_directory(tmp_path)
    clean = scan_directory(root)
    unknown = _failed_scan(root)
    (root / "file.txt").write_bytes(b"modified")
    modified = scan_directory(root)
    scans = iter([clean, unknown, modified])

    cycles, _ = _run(
        root,
        baseline,
        scan_limit=3,
        scan_function=lambda path: next(scans),
    )

    assert any(
        alert.kind is MonitoringFindingKind.UNKNOWN
        for alert in cycles[1].new_alerts
    )
    assert any(
        alert.kind is MonitoringFindingKind.MODIFIED
        for alert in cycles[2].new_alerts
    )


def test_recoverable_oserror_becomes_incomplete_cycle(tmp_path: Path) -> None:
    root, baseline = _baseline_directory(tmp_path)
    calls = 0

    def scan(path: Path) -> ScanReport:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise PermissionError("transient denial")
        return scan_directory(path)

    cycles, _ = _run(root, baseline, scan_limit=2, scan_function=scan)

    assert cycles[1].report.assessment_conclusive is False
    assert cycles[1].report.scan_errors[0].exception_type == "PermissionError"


def test_unexpected_programming_error_is_not_swallowed(tmp_path: Path) -> None:
    root, baseline = _baseline_directory(tmp_path)

    def fail(path: Path) -> ScanReport:
        raise RuntimeError("programming defect")

    with pytest.raises(RuntimeError, match="programming defect"):
        _run(root, baseline, scan_limit=1, scan_function=fail)


def test_missing_root_at_startup_is_rejected(tmp_path: Path) -> None:
    root, baseline = _baseline_directory(tmp_path)
    root.rename(tmp_path / "moved")

    with pytest.raises(MonitoringStartupError):
        _run(root, baseline, scan_limit=1)


def test_root_mismatch_is_rejected(tmp_path: Path) -> None:
    _, baseline = _baseline_directory(tmp_path / "baseline")
    other = tmp_path / "other"
    other.mkdir()

    with pytest.raises(RootMismatchError):
        _run(other, baseline, scan_limit=1)


def test_root_disappearing_during_watch_is_inconclusive(tmp_path: Path) -> None:
    root, baseline = _baseline_directory(tmp_path)

    def remove_root(_: float) -> None:
        (root / "file.txt").unlink()
        root.rmdir()

    cycles, _ = _run(root, baseline, scan_limit=2, wait_function=remove_root)

    assert cycles[1].report.assessment_conclusive is False
    assert cycles[1].report.scan_errors[0].kind is ScanErrorKind.ROOT_NOT_FOUND
    assert cycles[1].report.counts.deleted == 0
    assert cycles[1].report.counts.unknown == 1


@pytest.mark.parametrize("interrupt_stage", ["wait", "scan"])
def test_keyboard_interrupt_stops_cleanly(
    tmp_path: Path,
    interrupt_stage: str,
) -> None:
    root, baseline = _baseline_directory(tmp_path)
    calls = 0

    def scan(path: Path) -> ScanReport:
        nonlocal calls
        calls += 1
        if interrupt_stage == "scan" and calls == 2:
            raise KeyboardInterrupt
        return scan_directory(path)

    def wait(seconds: float) -> None:
        if interrupt_stage == "wait":
            raise KeyboardInterrupt

    cycles, session = _run(
        root,
        baseline,
        scan_limit=3,
        scan_function=scan,
        wait_function=wait,
    )

    assert session.interrupted is True
    assert session.status.completed_scans == 1
    assert len(cycles) == 1
    assert "Completed scans: 1" in format_monitoring_summary(session)


def test_monitoring_does_not_write_monitored_files_or_use_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, baseline = _baseline_directory(tmp_path)
    target = root / "file.txt"
    before = target.read_bytes(), target.stat().st_mtime_ns

    def network_forbidden(*args, **kwargs):
        raise AssertionError("network access attempted")

    import socket

    monkeypatch.setattr(socket, "socket", network_forbidden)
    _run(root, baseline, scan_limit=2)

    assert (target.read_bytes(), target.stat().st_mtime_ns) == before


def test_unicode_spaces_and_multiple_changes_are_deterministic(
    tmp_path: Path,
) -> None:
    root, baseline = _baseline_directory(
        tmp_path,
        {
            "z last.txt": b"z",
            "a first.txt": b"a",
            "整合性 report.txt": b"unicode",
        },
    )
    for target in root.iterdir():
        target.write_bytes(b"changed")

    cycles, _ = _run(root, baseline, scan_limit=1)
    paths = [alert.relative_path for alert in cycles[0].new_alerts]

    assert paths == sorted(paths)
    assert "整合性 report.txt" in paths


def test_header_cycle_and_summary_presentation(tmp_path: Path) -> None:
    root, baseline = _baseline_directory(tmp_path)
    cycles, session = _run(root, baseline, scan_limit=1)

    header = format_monitoring_header(root, 10)
    cycle = format_monitoring_cycle(cycles[0], verbose=True)
    summary = format_monitoring_summary(session)

    assert header.startswith("IntegrityGuard | Monitoring")
    assert "Baseline: Validated fixed reference" in header
    assert "Initial assessment complete" in cycle
    assert "Cycle 1:" in cycle
    assert "Monitoring stopped." in summary
    assert "Final assessment: clean" in summary


def test_real_watch_cli_subprocess_stops_cleanly_on_interrupt(
    tmp_path: Path,
) -> None:
    root, baseline = _baseline_directory(
        tmp_path,
        {"résumé 整合性.txt": b"original"},
    )
    baseline_path = tmp_path / "trusted baseline.json"
    save_baseline(baseline, baseline_path)
    baseline_bytes = baseline_path.read_bytes()
    interrupting_cli = """
import integrityguard.cli as cli
from integrityguard.monitoring import monitor_directory as real_monitor

def interrupted_monitor(root, baseline, **kwargs):
    def interrupt_wait(seconds):
        raise KeyboardInterrupt
    return real_monitor(
        root,
        baseline,
        wait_function=interrupt_wait,
        **kwargs,
    )

cli.monitor_directory = interrupted_monitor
raise SystemExit(cli.main())
"""
    command = [
        sys.executable,
        "-c",
        interrupting_cli,
        "watch",
        "--root",
        str(root),
        "--baseline",
        str(baseline_path),
        "--interval",
        "1",
    ]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        encoding="utf-8",
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0
    assert "IntegrityGuard | Monitoring" in completed.stdout
    assert "Initial assessment complete" in completed.stdout
    assert "Monitoring stopped." in completed.stdout
    assert "Completed scans: 1" in completed.stdout
    assert completed.stderr == ""
    assert baseline_path.read_bytes() == baseline_bytes
