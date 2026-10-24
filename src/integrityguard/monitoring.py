"""Foreground periodic monitoring against one fixed trusted baseline."""

from __future__ import annotations

import math
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from os import PathLike
from pathlib import Path
from threading import Event

from integrityguard.baseline import Baseline
from integrityguard.detector import (
    ChangeReport,
    FileChange,
    compare_baseline,
)
from integrityguard.scanner import (
    ScanError,
    ScanErrorKind,
    ScanReport,
    scan_directory,
)

DEFAULT_INTERVAL_SECONDS = 10.0
MIN_INTERVAL_SECONDS = 1.0
MAX_DISPLAY_ALERTS = 100

_EXCEPTION_TYPE_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,127}\Z")

ScanFunction = Callable[[str | PathLike[str]], ScanReport]
WaitFunction = Callable[[float], object]
UtcNowFunction = Callable[[], datetime]
MonotonicFunction = Callable[[], float]


class MonitoringError(Exception):
    """Base class for expected monitoring failures."""


class InvalidMonitoringIntervalError(MonitoringError):
    """Raised when a polling interval is unsafe or invalid."""


class MonitoringStartupError(MonitoringError):
    """Raised when the selected root cannot start a monitoring session."""


class MonitoringAssessment(StrEnum):
    """Current high-level integrity assessment for a monitoring session."""

    CLEAN = "clean"
    CHANGES_DETECTED = "changes_detected"
    INCONCLUSIVE = "inconclusive"
    NOT_AVAILABLE = "not_available"


class MonitoringFindingKind(StrEnum):
    """Kinds of active findings that participate in alert deduplication."""

    ADDED = "added"
    DELETED = "deleted"
    MODIFIED = "modified"
    UNKNOWN = "unknown"
    SCAN_ERROR = "scan_error"
    SKIPPED_PATH = "skipped_path"


class AlertEvent(StrEnum):
    """Whether a terminal alert is newly observed or resolved."""

    NEW = "new"
    RESOLVED = "resolved"


@dataclass(frozen=True, slots=True)
class MonitoringAlert:
    """One deterministic, sanitized monitoring alert."""

    event: AlertEvent
    kind: MonitoringFindingKind
    relative_path: str
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class MonitoringStatus:
    """Useful bounded state describing a foreground monitoring session."""

    started_at_utc: datetime
    completed_scans: int
    last_scan_at_utc: datetime | None
    current_assessment: MonitoringAssessment
    active_change_count: int
    unknown_finding_count: int
    scan_error_count: int


@dataclass(frozen=True, slots=True)
class MonitoringCycle:
    """One completed scan, assessment, and alert-state transition."""

    scan_number: int
    scanned_at_utc: datetime
    report: ChangeReport
    new_alerts: tuple[MonitoringAlert, ...]
    resolved_alerts: tuple[MonitoringAlert, ...]
    repeated_finding_count: int
    status: MonitoringStatus


@dataclass(frozen=True, slots=True)
class MonitoringSession:
    """Final session state returned after interruption or a scan limit."""

    status: MonitoringStatus
    interrupted: bool


@dataclass(frozen=True, slots=True)
class _Finding:
    key: tuple[str, ...]
    fingerprint: tuple[object, ...]
    kind: MonitoringFindingKind
    relative_path: str
    detail: str | None


CycleHandler = Callable[[MonitoringCycle], object]


def validate_interval(value: object) -> float:
    """Return a finite polling interval of at least one second."""
    if isinstance(value, bool):
        raise InvalidMonitoringIntervalError(
            "The polling interval must be a finite number of seconds."
        )
    try:
        interval = float(value)
    except (TypeError, ValueError) as error:
        raise InvalidMonitoringIntervalError(
            "The polling interval must be a finite number of seconds."
        ) from error
    if not math.isfinite(interval) or interval < MIN_INTERVAL_SECONDS:
        raise InvalidMonitoringIntervalError(
            f"The polling interval must be at least {MIN_INTERVAL_SECONDS:g} second."
        )
    return interval


def monitor_directory(
    root: str | PathLike[str],
    baseline: Baseline,
    *,
    interval: float = DEFAULT_INTERVAL_SECONDS,
    scan_function: ScanFunction = scan_directory,
    wait_function: WaitFunction = time.sleep,
    utc_now: UtcNowFunction | None = None,
    monotonic: MonotonicFunction = time.monotonic,
    on_cycle: CycleHandler | None = None,
    scan_limit: int | None = None,
    stop_event: Event | None = None,
) -> MonitoringSession:
    """Repeatedly compare foreground scans with one unchanged baseline.

    The first scan is immediate. Each later scan starts after the configured
    delay following completion of the previous scan, so scan duration adds to
    the effective observation interval. ``scan_limit`` supports deterministic
    embedding and tests; the CLI deliberately leaves it unset. When supplied,
    ``stop_event`` makes interval waits interruptible. A stop requested during
    a scan is honored after that scan and its cycle callback finish safely.
    Existing callers that omit it continue to use ``wait_function`` unchanged.
    """
    polling_interval = validate_interval(interval)
    if scan_limit is not None and (
        type(scan_limit) is not int or scan_limit <= 0
    ):
        raise ValueError("scan_limit must be a positive integer or None")
    now = utc_now or _utc_now
    started_at = _validate_utc_time(now(), "monitoring start time")
    status = MonitoringStatus(
        started_at_utc=started_at,
        completed_scans=0,
        last_scan_at_utc=None,
        current_assessment=MonitoringAssessment.NOT_AVAILABLE,
        active_change_count=0,
        unknown_finding_count=0,
        scan_error_count=0,
    )
    root_path = Path(os.path.abspath(os.fspath(root)))
    active_findings: dict[tuple[str, ...], _Finding] = {}
    interrupted = False

    while True:
        if stop_event is not None and stop_event.is_set():
            interrupted = True
            break
        try:
            scan = _perform_scan(root_path, scan_function)
            if status.completed_scans == 0:
                _reject_invalid_startup_root(scan)
            report = compare_baseline(baseline, scan)
            scanned_at = _validate_utc_time(now(), "scan time")
            current_findings = _collect_findings(report)
            new_alerts, resolved_alerts = _compare_findings(
                active_findings,
                current_findings,
            )
            active_findings = current_findings
            status = _updated_status(status, report, scanned_at)
            cycle = MonitoringCycle(
                scan_number=status.completed_scans,
                scanned_at_utc=scanned_at,
                report=report,
                new_alerts=new_alerts,
                resolved_alerts=resolved_alerts,
                repeated_finding_count=(
                    len(current_findings) - len(new_alerts)
                ),
                status=status,
            )
            if on_cycle is not None:
                on_cycle(cycle)
            if scan_limit is not None and status.completed_scans >= scan_limit:
                break

            if stop_event is not None and stop_event.is_set():
                interrupted = True
                break

            deadline = monotonic() + polling_interval
            delay = max(0.0, deadline - monotonic())
            if stop_event is None:
                wait_function(delay)
            elif stop_event.wait(delay):
                interrupted = True
                break
        except KeyboardInterrupt:
            interrupted = True
            break

    return MonitoringSession(status=status, interrupted=interrupted)


def format_monitoring_header(
    root: str | PathLike[str],
    interval: float,
) -> str:
    """Return the minimal terminal header for a foreground watch session."""
    root_path = Path(os.path.abspath(os.fspath(root)))
    seconds = validate_interval(interval)
    return "\n".join(
        [
            "IntegrityGuard | Monitoring",
            "",
            f"Root: {root_path}",
            f"Interval: {seconds:g} seconds",
            "Baseline: Validated fixed reference",
            "Press Ctrl+C to stop monitoring.",
            "",
        ]
    )


def format_monitoring_cycle(
    cycle: MonitoringCycle,
    *,
    verbose: bool = False,
    max_alerts: int = MAX_DISPLAY_ALERTS,
) -> str:
    """Render one cycle without repeating unchanged alerts indefinitely."""
    if type(max_alerts) is not int or max_alerts <= 0:
        raise ValueError("max_alerts must be a positive integer")
    timestamp = cycle.scanned_at_utc.strftime("%H:%M:%SZ")
    prefix = f"[{timestamp}]"
    lines: list[str] = []
    alerts = tuple(
        sorted(
            cycle.new_alerts + cycle.resolved_alerts,
            key=_alert_sort_key,
        )
    )

    if cycle.scan_number == 1:
        lines.append(f"{prefix} Initial assessment complete")
    if alerts:
        visible = alerts[:max_alerts]
        lines.extend(f"{prefix} {_format_alert(alert)}" for alert in visible)
        omitted = len(alerts) - len(visible)
        if omitted:
            lines.append(f"{prefix} {omitted} additional alerts omitted")
        if cycle.resolved_alerts:
            lines.append(
                f"{prefix} Resolution means a finding is no longer observed; "
                "it is not proof of system safety."
            )
    elif cycle.scan_number > 1:
        lines.append(
            f"{prefix} No new alerts "
            f"(active changes: {cycle.status.active_change_count}, "
            f"unknown: {cycle.status.unknown_finding_count}, "
            f"scan errors: {cycle.status.scan_error_count})"
        )
    elif cycle.report.is_clean:
        lines.append(f"{prefix} No integrity changes detected")

    if not cycle.report.assessment_conclusive:
        lines.append(
            f"{prefix} INCOMPLETE assessment: do not treat this cycle as clean"
        )
    if verbose:
        counts = cycle.report.counts
        lines.append(
            f"{prefix} Cycle {cycle.scan_number}: added={counts.added}, "
            f"modified={counts.modified}, deleted={counts.deleted}, "
            f"unchanged={counts.unchanged}, unknown={counts.unknown}, "
            f"errors={len(cycle.report.scan_errors)}"
        )
    return "\n".join(lines) + "\n"


def format_monitoring_summary(session: MonitoringSession) -> str:
    """Render a short final summary after normal user-requested shutdown."""
    status = session.status
    last_scan = (
        "none"
        if status.last_scan_at_utc is None
        else _format_utc_time(status.last_scan_at_utc)
    )
    return "\n".join(
        [
            "",
            "Monitoring stopped.",
            f"Started UTC: {_format_utc_time(status.started_at_utc)}",
            f"Completed scans: {status.completed_scans}",
            f"Last scan UTC: {last_scan}",
            f"Final assessment: {status.current_assessment.value}",
            f"Active changes: {status.active_change_count}",
            f"Unknown findings: {status.unknown_finding_count}",
            f"Scan errors: {status.scan_error_count}",
            "",
        ]
    )


def _perform_scan(root: Path, scan_function: ScanFunction) -> ScanReport:
    try:
        return scan_function(root)
    except OSError as error:
        scan_error = ScanError(
            relative_path=".",
            kind=ScanErrorKind.DIRECTORY_ACCESS,
            message="The scan operation could not access the selected root.",
            exception_type=type(error).__name__,
            errno=_safe_error_code(getattr(error, "errno", None)),
            winerror=_safe_error_code(getattr(error, "winerror", None)),
        )
        return ScanReport(root=root, files=(), errors=(scan_error,), skipped_paths=())


def _reject_invalid_startup_root(scan: ScanReport) -> None:
    fatal_kinds = {
        ScanErrorKind.ROOT_NOT_FOUND,
        ScanErrorKind.ROOT_NOT_DIRECTORY,
        ScanErrorKind.ROOT_LINK_NOT_FOLLOWED,
        ScanErrorKind.DIRECTORY_ACCESS,
    }
    if any(
        error.relative_path == "."
        and error.kind in fatal_kinds
        and error.exception_type != "ScanLimitExceededError"
        for error in scan.errors
    ):
        raise MonitoringStartupError(
            "The monitoring root is unavailable, unsafe, or not a directory."
        )


def _collect_findings(
    report: ChangeReport,
) -> dict[tuple[str, ...], _Finding]:
    findings: dict[tuple[str, ...], _Finding] = {}
    for change in report.added + report.deleted + report.modified + report.unknown:
        finding = _file_finding(change)
        findings[finding.key] = finding
    for error in report.scan_errors:
        path_key = _path_key(error.relative_path)
        key = ("scan_error", path_key, error.kind.value)
        exception_type = _safe_exception_type(error.exception_type)
        error_codes = (error.errno, error.winerror)
        findings[key] = _Finding(
            key=key,
            fingerprint=(exception_type, *error_codes),
            kind=MonitoringFindingKind.SCAN_ERROR,
            relative_path=error.relative_path,
            detail=_scan_error_detail(error.kind, exception_type, *error_codes),
        )
    for source, paths in (
        ("baseline", report.baseline_skipped_paths),
        ("current", report.current_skipped_paths),
    ):
        for path in paths:
            key = ("skipped", source, _path_key(path))
            findings[key] = _Finding(
                key=key,
                fingerprint=(source,),
                kind=MonitoringFindingKind.SKIPPED_PATH,
                relative_path=path,
                detail=f"{source} exclusion",
            )
    return findings


def _file_finding(change: FileChange) -> _Finding:
    kind = MonitoringFindingKind(change.status.value)
    key = ("file", _path_key(change.relative_path))
    reason = change.unknown_reason.value if change.unknown_reason else None
    return _Finding(
        key=key,
        fingerprint=(change.status.value, change.current_sha256, reason),
        kind=kind,
        relative_path=change.relative_path,
        detail=reason,
    )


def _compare_findings(
    previous: dict[tuple[str, ...], _Finding],
    current: dict[tuple[str, ...], _Finding],
) -> tuple[tuple[MonitoringAlert, ...], tuple[MonitoringAlert, ...]]:
    new_alerts = [
        _to_alert(AlertEvent.NEW, finding)
        for key, finding in current.items()
        if key not in previous
        or previous[key].fingerprint != finding.fingerprint
    ]
    resolved_alerts = [
        _to_alert(AlertEvent.RESOLVED, finding)
        for key, finding in previous.items()
        if key not in current
    ]
    return (
        tuple(sorted(new_alerts, key=_alert_sort_key)),
        tuple(sorted(resolved_alerts, key=_alert_sort_key)),
    )


def _to_alert(event: AlertEvent, finding: _Finding) -> MonitoringAlert:
    return MonitoringAlert(
        event=event,
        kind=finding.kind,
        relative_path=finding.relative_path,
        detail=finding.detail,
    )


def _updated_status(
    previous: MonitoringStatus,
    report: ChangeReport,
    scanned_at: datetime,
) -> MonitoringStatus:
    return MonitoringStatus(
        started_at_utc=previous.started_at_utc,
        completed_scans=previous.completed_scans + 1,
        last_scan_at_utc=scanned_at,
        current_assessment=_assessment(report),
        active_change_count=(
            report.counts.added
            + report.counts.deleted
            + report.counts.modified
        ),
        unknown_finding_count=report.counts.unknown,
        scan_error_count=len(report.scan_errors),
    )


def _assessment(report: ChangeReport) -> MonitoringAssessment:
    if not report.assessment_conclusive:
        return MonitoringAssessment.INCONCLUSIVE
    if report.has_confirmed_changes:
        return MonitoringAssessment.CHANGES_DETECTED
    return MonitoringAssessment.CLEAN


def _format_alert(alert: MonitoringAlert) -> str:
    if alert.event is AlertEvent.RESOLVED:
        return (
            f"RESOLVED  {alert.relative_path} "
            f"(previously {alert.kind.value})"
        )
    label = {
        MonitoringFindingKind.ADDED: "ADDED",
        MonitoringFindingKind.DELETED: "DELETED",
        MonitoringFindingKind.MODIFIED: "MODIFIED",
        MonitoringFindingKind.UNKNOWN: "UNKNOWN",
        MonitoringFindingKind.SCAN_ERROR: "ERROR",
        MonitoringFindingKind.SKIPPED_PATH: "SKIPPED",
    }[alert.kind]
    detail = f" ({alert.detail})" if alert.detail else ""
    return f"{label:<9} {alert.relative_path}{detail}"


def _alert_sort_key(alert: MonitoringAlert) -> tuple[str, int, str]:
    event_order = 0 if alert.event is AlertEvent.NEW else 1
    return (_path_key(alert.relative_path), event_order, alert.kind.value)


def _path_key(path: str) -> str:
    return path.casefold() if os.name == "nt" else path


def _safe_exception_type(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    if _EXCEPTION_TYPE_PATTERN.fullmatch(value) is None:
        return None
    return value


def _safe_error_code(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _scan_error_detail(
    kind: ScanErrorKind,
    exception_type: str | None,
    errno: int | None,
    winerror: int | None,
) -> str:
    labels: list[str] = []
    if exception_type:
        labels.append(exception_type)
    if errno is not None:
        labels.append(f"errno={errno}")
    if winerror is not None:
        labels.append(f"winerror={winerror}")
    suffix = f" ({', '.join(labels)})" if labels else ""
    return f"{kind.value}{suffix}"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_utc_time(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise MonitoringError(f"The {field_name} must be a datetime.")
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise MonitoringError(f"The {field_name} must use UTC.")
    return value.astimezone(timezone.utc)


def _format_utc_time(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")
