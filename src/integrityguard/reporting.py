"""Versioned JSON reports and terminal presentation for IntegrityGuard."""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from os import PathLike
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import integrityguard.baseline as _baseline_storage
from integrityguard.baseline import BaselineError
from integrityguard.detector import ChangeCounts, ChangeReport, ChangeStatus, FileChange
from integrityguard.scanner import ScanErrorKind

REPORT_SCHEMA_VERSION = 1
MAX_REPORT_BYTES = 16 * 1024 * 1024

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_EXCEPTION_TYPE_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,127}\Z")
_TOP_LEVEL_FIELDS = {
    "report_schema_version",
    "generated_at_utc",
    "assessment_status",
    "counts",
    "file_changes",
    "scan_issues",
    "baseline_skipped_paths",
    "current_skipped_paths",
    "scan_complete",
    "assessment_conclusive",
}
_COUNT_FIELDS = {"added", "deleted", "modified", "unchanged", "unknown"}
_CHANGE_FIELDS = {
    "relative_path",
    "status",
    "previous_sha256",
    "current_sha256",
    "previous_size_bytes",
    "current_size_bytes",
    "previous_modified_at_utc",
    "current_modified_at_utc",
    "metadata_changed",
    "unknown_reason",
}
_ISSUE_FIELDS = {"relative_path", "kind", "exception_type"}


class ReportError(Exception):
    """Base class for expected security-report failures."""


class InvalidReportError(ReportError):
    """Raised when report content violates the strict schema."""


class UnsupportedReportVersionError(InvalidReportError):
    """Raised when a report uses an unsupported schema version."""


class UnsafeReportPathError(ReportError):
    """Raised when a report path violates storage safety rules."""


class ReportExistsError(ReportError):
    """Raised when exclusive report creation finds an existing target."""


class ReportIOError(ReportError):
    """Raised when a report cannot be read or written."""


class AssessmentStatus(StrEnum):
    """High-level meaning of a security report."""

    CLEAN = "clean"
    CHANGES_DETECTED = "changes_detected"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class ReportFile:
    """Serializable file classification without file contents."""

    relative_path: str
    status: ChangeStatus
    previous_sha256: str | None
    current_sha256: str | None
    previous_size_bytes: int | None
    current_size_bytes: int | None
    previous_modified_at_utc: datetime | None
    current_modified_at_utc: datetime | None
    metadata_changed: bool
    unknown_reason: str | None


@dataclass(frozen=True, slots=True)
class ReportIssue:
    """A sanitized structured scanner issue."""

    relative_path: str
    kind: ScanErrorKind
    exception_type: str | None


@dataclass(frozen=True, slots=True)
class SecurityReport:
    """Immutable historical representation of a change assessment."""

    report_schema_version: int
    generated_at_utc: datetime
    assessment_status: AssessmentStatus
    counts: ChangeCounts
    added: tuple[ReportFile, ...]
    deleted: tuple[ReportFile, ...]
    modified: tuple[ReportFile, ...]
    unchanged: tuple[ReportFile, ...]
    unknown: tuple[ReportFile, ...]
    scan_issues: tuple[ReportIssue, ...]
    baseline_skipped_paths: tuple[str, ...]
    current_skipped_paths: tuple[str, ...]
    scan_complete: bool
    assessment_conclusive: bool


def create_security_report(
    change_report: ChangeReport,
    *,
    generated_at_utc: datetime | None = None,
) -> SecurityReport:
    """Create a serializable report from an immutable change report."""
    if not isinstance(change_report, ChangeReport):
        raise TypeError("change_report must be a ChangeReport instance")
    generated_at = _validate_datetime(
        generated_at_utc or datetime.now(timezone.utc),
        "generated_at_utc",
    )
    status = _assessment_status(
        change_report.assessment_conclusive,
        change_report.has_confirmed_changes,
    )
    return SecurityReport(
        report_schema_version=REPORT_SCHEMA_VERSION,
        generated_at_utc=generated_at,
        assessment_status=status,
        counts=change_report.counts,
        added=_report_files(change_report.added),
        deleted=_report_files(change_report.deleted),
        modified=_report_files(change_report.modified),
        unchanged=_report_files(change_report.unchanged),
        unknown=_report_files(change_report.unknown),
        scan_issues=_report_issues(change_report),
        baseline_skipped_paths=change_report.baseline_skipped_paths,
        current_skipped_paths=change_report.current_skipped_paths,
        scan_complete=change_report.scan_complete,
        assessment_conclusive=change_report.assessment_conclusive,
    )


def report_to_json(report: SecurityReport) -> str:
    """Return a strictly validated report as deterministic JSON text."""
    if not isinstance(report, SecurityReport):
        raise TypeError("report must be a SecurityReport instance")
    data = _report_to_data(report)
    validated = validate_report_data(data)
    return json.dumps(
        _report_to_data(validated),
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def validate_report_data(data: object) -> SecurityReport:
    """Strictly validate decoded report JSON and return typed data."""
    if not isinstance(data, dict) or set(data) != _TOP_LEVEL_FIELDS:
        raise InvalidReportError("The report has missing or unexpected fields.")
    version = data["report_schema_version"]
    if type(version) is not int:
        raise InvalidReportError("report_schema_version must be an integer.")
    if version != REPORT_SCHEMA_VERSION:
        raise UnsupportedReportVersionError(
            f"Unsupported report schema version: {version}."
        )

    generated_at = _parse_timestamp(data["generated_at_utc"], "generated_at_utc")
    try:
        assessment_status = AssessmentStatus(data["assessment_status"])
    except (TypeError, ValueError) as error:
        raise InvalidReportError("Invalid assessment_status.") from error
    counts = _validate_counts(data["counts"])

    changes_value = data["file_changes"]
    if not isinstance(changes_value, dict) or set(changes_value) != _COUNT_FIELDS:
        raise InvalidReportError("file_changes has invalid categories.")
    categorized: dict[ChangeStatus, tuple[ReportFile, ...]] = {}
    seen_paths: set[str] = set()
    for status in ChangeStatus:
        values = changes_value[status.value]
        if not isinstance(values, list):
            raise InvalidReportError("Each file change category must be an array.")
        records = tuple(_validate_report_file(value, status) for value in values)
        paths = [record.relative_path for record in records]
        if paths != sorted(paths):
            raise InvalidReportError("Report file records must be sorted.")
        for path in paths:
            key = _path_key(path)
            if key in seen_paths:
                raise InvalidReportError("Duplicate report file paths are not allowed.")
            seen_paths.add(key)
        categorized[status] = records

    actual_counts = ChangeCounts(
        added=len(categorized[ChangeStatus.ADDED]),
        deleted=len(categorized[ChangeStatus.DELETED]),
        modified=len(categorized[ChangeStatus.MODIFIED]),
        unchanged=len(categorized[ChangeStatus.UNCHANGED]),
        unknown=len(categorized[ChangeStatus.UNKNOWN]),
    )
    if counts != actual_counts:
        raise InvalidReportError("Report counts do not match file records.")

    issues = _validate_issues(data["scan_issues"])
    baseline_skipped = _validate_paths(
        data["baseline_skipped_paths"], "baseline_skipped_paths"
    )
    current_skipped = _validate_paths(
        data["current_skipped_paths"], "current_skipped_paths"
    )
    scan_complete = _validate_bool(data["scan_complete"], "scan_complete")
    conclusive = _validate_bool(
        data["assessment_conclusive"], "assessment_conclusive"
    )
    if scan_complete and (issues or current_skipped or counts.unknown):
        raise InvalidReportError("A complete scan cannot contain uncertain states.")
    if conclusive and (not scan_complete or baseline_skipped or counts.unknown):
        raise InvalidReportError("A conclusive assessment contains exclusions.")
    expected_status = _assessment_status(
        conclusive,
        bool(counts.added or counts.deleted or counts.modified),
    )
    if assessment_status is not expected_status:
        raise InvalidReportError("assessment_status conflicts with report contents.")

    return SecurityReport(
        report_schema_version=REPORT_SCHEMA_VERSION,
        generated_at_utc=generated_at,
        assessment_status=assessment_status,
        counts=counts,
        added=categorized[ChangeStatus.ADDED],
        deleted=categorized[ChangeStatus.DELETED],
        modified=categorized[ChangeStatus.MODIFIED],
        unchanged=categorized[ChangeStatus.UNCHANGED],
        unknown=categorized[ChangeStatus.UNKNOWN],
        scan_issues=issues,
        baseline_skipped_paths=baseline_skipped,
        current_skipped_paths=current_skipped,
        scan_complete=scan_complete,
        assessment_conclusive=conclusive,
    )


def save_report(
    report: SecurityReport,
    destination: str | PathLike[str],
    *,
    monitored_root: str | PathLike[str],
) -> Path:
    """Atomically create a report outside the monitored root without overwrite."""
    payload = report_to_json(report).encode("utf-8")
    if len(payload) > MAX_REPORT_BYTES:
        raise InvalidReportError("The serialized report exceeds the size limit.")
    target = _validate_report_destination(destination, monitored_root)
    _atomic_create(target, payload)
    return target


def load_report(
    source: str | PathLike[str],
    *,
    max_bytes: int = MAX_REPORT_BYTES,
) -> SecurityReport:
    """Load and strictly validate a bounded UTF-8 JSON security report."""
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    path = Path(os.path.abspath(os.fspath(source)))
    try:
        _baseline_storage._reject_link_components(path.parent)
        before = path.stat(follow_symlinks=False)
        if _baseline_storage._is_link_like(before):
            raise UnsafeReportPathError("Report links are not followed.")
        if not stat.S_ISREG(before.st_mode):
            raise UnsafeReportPathError("The report source is not a regular file.")
        if before.st_size > max_bytes:
            raise InvalidReportError("The report exceeds the size limit.")
        payload = _read_limited_file(path, before, max_bytes)
    except (InvalidReportError, UnsafeReportPathError):
        raise
    except BaselineError as error:
        raise UnsafeReportPathError("The report source path is unsafe.") from error
    except OSError as error:
        raise ReportIOError("Unable to read the report file.") from error

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InvalidReportError("The report must contain valid UTF-8.") from error
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
    except InvalidReportError:
        raise
    except (json.JSONDecodeError, RecursionError) as error:
        raise InvalidReportError("The report contains malformed JSON.") from error
    return validate_report_data(data)


def format_report(
    report: SecurityReport,
    *,
    verbose: bool = False,
    historical: bool = False,
) -> str:
    """Render a minimal monochrome report suitable for Windows PowerShell."""
    if not isinstance(report, SecurityReport):
        raise TypeError("report must be a SecurityReport instance")
    report = validate_report_data(_report_to_data(report))
    lines = ["IntegrityGuard | File Integrity Report", ""]
    if historical:
        lines.extend(
            [
                "Report type: Historical saved report (not a fresh scan)",
                f"Generated UTC: {_format_timestamp(report.generated_at_utc)}",
                "",
            ]
        )
    lines.extend(
        [
            "Scan summary",
            f"  Added:                 {report.counts.added}",
            f"  Modified:              {report.counts.modified}",
            f"  Deleted:               {report.counts.deleted}",
            f"  Unchanged:             {report.counts.unchanged}",
            f"  Unknown:               {report.counts.unknown}",
            f"  Scan complete:         {_yes_no(report.scan_complete)}",
            f"  Assessment conclusive: {_yes_no(report.assessment_conclusive)}",
            "",
            "File changes",
        ]
    )
    for title, records in (
        ("Added", report.added),
        ("Modified", report.modified),
        ("Deleted", report.deleted),
        ("Unknown", report.unknown),
    ):
        lines.append(f"  {title}:")
        if records:
            lines.extend(f"    - {record.relative_path}" for record in records)
        else:
            lines.append("    (none)")
    if verbose:
        lines.append("  Unchanged:")
        if report.unchanged:
            lines.extend(f"    - {record.relative_path}" for record in report.unchanged)
        else:
            lines.append("    (none)")
    elif report.unchanged:
        lines.append(
            "  Unchanged details hidden "
            f"({len(report.unchanged)} files; use --verbose)."
        )

    lines.extend(["", "Scan errors"])
    if report.scan_issues:
        for issue in report.scan_issues:
            detail = f" ({issue.exception_type})" if issue.exception_type else ""
            lines.append(f"  - [{issue.kind.value}] {issue.relative_path}{detail}")
    else:
        lines.append("  (none)")
    if report.current_skipped_paths:
        lines.append("  Skipped current paths:")
        lines.extend(f"    - {path}" for path in report.current_skipped_paths)

    lines.extend(["", "Integrity assessment"])
    if report.assessment_status is AssessmentStatus.CLEAN:
        lines.append(
            "  No integrity changes detected in the conclusively assessed scope."
        )
    elif report.assessment_status is AssessmentStatus.CHANGES_DETECTED:
        lines.append("  Integrity changes detected.")
    else:
        lines.append(
            "  Assessment incomplete or inconclusive; do not treat this as clean."
        )
    lines.append(
        "  This report assesses file integrity; it does not prove the absence "
        "of malware."
    )
    return "\n".join(lines) + "\n"


def _report_files(changes: tuple[FileChange, ...]) -> tuple[ReportFile, ...]:
    return tuple(
        ReportFile(
            relative_path=item.relative_path,
            status=item.status,
            previous_sha256=item.previous_sha256,
            current_sha256=item.current_sha256,
            previous_size_bytes=item.previous_size_bytes,
            current_size_bytes=item.current_size_bytes,
            previous_modified_at_utc=item.previous_modified_at_utc,
            current_modified_at_utc=item.current_modified_at_utc,
            metadata_changed=item.metadata_changed,
            unknown_reason=item.unknown_reason.value if item.unknown_reason else None,
        )
        for item in changes
    )


def _report_to_data(report: SecurityReport) -> dict[str, Any]:
    return {
        "report_schema_version": report.report_schema_version,
        "generated_at_utc": _format_timestamp(report.generated_at_utc),
        "assessment_status": report.assessment_status.value,
        "counts": {
            "added": report.counts.added,
            "deleted": report.counts.deleted,
            "modified": report.counts.modified,
            "unchanged": report.counts.unchanged,
            "unknown": report.counts.unknown,
        },
        "file_changes": {
            status.value: [
                _report_file_to_data(item)
                for item in getattr(report, status.value)
            ]
            for status in ChangeStatus
        },
        "scan_issues": [
            {
                "relative_path": issue.relative_path,
                "kind": issue.kind.value,
                "exception_type": issue.exception_type,
            }
            for issue in report.scan_issues
        ],
        "baseline_skipped_paths": list(report.baseline_skipped_paths),
        "current_skipped_paths": list(report.current_skipped_paths),
        "scan_complete": report.scan_complete,
        "assessment_conclusive": report.assessment_conclusive,
    }


def _report_file_to_data(item: ReportFile) -> dict[str, Any]:
    return {
        "relative_path": item.relative_path,
        "status": item.status.value,
        "previous_sha256": item.previous_sha256,
        "current_sha256": item.current_sha256,
        "previous_size_bytes": item.previous_size_bytes,
        "current_size_bytes": item.current_size_bytes,
        "previous_modified_at_utc": _optional_timestamp(
            item.previous_modified_at_utc
        ),
        "current_modified_at_utc": _optional_timestamp(item.current_modified_at_utc),
        "metadata_changed": item.metadata_changed,
        "unknown_reason": item.unknown_reason,
    }


def _validate_counts(value: object) -> ChangeCounts:
    if not isinstance(value, dict) or set(value) != _COUNT_FIELDS:
        raise InvalidReportError("counts has invalid fields.")
    for count in value.values():
        if type(count) is not int or count < 0:
            raise InvalidReportError("Report counts must be nonnegative integers.")
    return ChangeCounts(**value)


def _validate_report_file(value: object, expected: ChangeStatus) -> ReportFile:
    if not isinstance(value, dict) or set(value) != _CHANGE_FIELDS:
        raise InvalidReportError("A file record has invalid fields.")
    path = _validate_relative_path(value["relative_path"])
    try:
        status = ChangeStatus(value["status"])
    except (TypeError, ValueError) as error:
        raise InvalidReportError("A file record has an invalid status.") from error
    if status is not expected:
        raise InvalidReportError("A file record is in the wrong category.")
    previous_hash = _validate_optional_hash(value["previous_sha256"])
    current_hash = _validate_optional_hash(value["current_sha256"])
    _validate_hash_semantics(status, previous_hash, current_hash)
    previous_size = _validate_optional_size(value["previous_size_bytes"])
    current_size = _validate_optional_size(value["current_size_bytes"])
    previous_modified = _parse_optional_timestamp(
        value["previous_modified_at_utc"], "previous_modified_at_utc"
    )
    current_modified = _parse_optional_timestamp(
        value["current_modified_at_utc"], "current_modified_at_utc"
    )
    metadata_changed = _validate_bool(
        value["metadata_changed"], "metadata_changed"
    )
    unknown_reason = value["unknown_reason"]
    if status is ChangeStatus.UNKNOWN:
        if unknown_reason not in {"scan_error", "skipped_path", "untrusted_result"}:
            raise InvalidReportError("An unknown record needs a valid reason.")
    elif unknown_reason is not None:
        raise InvalidReportError("Only unknown records may have unknown_reason.")
    _validate_metadata_semantics(
        status,
        previous_hash=previous_hash,
        current_hash=current_hash,
        previous_size=previous_size,
        current_size=current_size,
        previous_modified=previous_modified,
        current_modified=current_modified,
        metadata_changed=metadata_changed,
        unknown_reason=unknown_reason,
    )
    return ReportFile(
        relative_path=path,
        status=status,
        previous_sha256=previous_hash,
        current_sha256=current_hash,
        previous_size_bytes=previous_size,
        current_size_bytes=current_size,
        previous_modified_at_utc=previous_modified,
        current_modified_at_utc=current_modified,
        metadata_changed=metadata_changed,
        unknown_reason=unknown_reason,
    )


def _report_issues(change_report: ChangeReport) -> tuple[ReportIssue, ...]:
    unique: dict[tuple[str, str, str | None], ReportIssue] = {}
    for error in change_report.scan_errors:
        issue = ReportIssue(error.relative_path, error.kind, error.exception_type)
        key = (_path_key(issue.relative_path), issue.kind.value, issue.exception_type)
        unique[key] = issue
    return tuple(
        sorted(
            unique.values(),
            key=lambda issue: (
                issue.relative_path,
                issue.kind.value,
                issue.exception_type or "",
            ),
        )
    )


def _validate_hash_semantics(
    status: ChangeStatus,
    previous: str | None,
    current: str | None,
) -> None:
    if status is ChangeStatus.ADDED and (previous is not None or current is None):
        raise InvalidReportError("An added record has inconsistent hashes.")
    if status is ChangeStatus.DELETED and (previous is None or current is not None):
        raise InvalidReportError("A deleted record has inconsistent hashes.")
    if status is ChangeStatus.MODIFIED and (
        previous is None or current is None or previous == current
    ):
        raise InvalidReportError("A modified record has inconsistent hashes.")
    if status is ChangeStatus.UNCHANGED and (
        previous is None or current is None or previous != current
    ):
        raise InvalidReportError("An unchanged record has inconsistent hashes.")
    if status is ChangeStatus.UNKNOWN and current is not None:
        raise InvalidReportError("An unknown record cannot contain a trusted hash.")


def _validate_metadata_semantics(
    status: ChangeStatus,
    *,
    previous_hash: str | None,
    current_hash: str | None,
    previous_size: int | None,
    current_size: int | None,
    previous_modified: datetime | None,
    current_modified: datetime | None,
    metadata_changed: bool,
    unknown_reason: object,
) -> None:
    previous_exists = previous_hash is not None
    current_trusted = current_hash is not None

    if previous_exists != (previous_size is not None):
        raise InvalidReportError("Previous file metadata is inconsistent.")
    if not previous_exists and previous_modified is not None:
        raise InvalidReportError("Previous file metadata is inconsistent.")
    if current_trusted and current_size is None:
        raise InvalidReportError("Trusted current file metadata is incomplete.")

    if status is ChangeStatus.ADDED:
        if previous_size is not None or previous_modified is not None:
            raise InvalidReportError("An added record has previous metadata.")
        if not current_trusted or current_size is None or metadata_changed:
            raise InvalidReportError("An added record has inconsistent metadata.")
        return

    if status is ChangeStatus.DELETED:
        if current_size is not None or current_modified is not None:
            raise InvalidReportError("A deleted record has current metadata.")
        if not previous_exists or metadata_changed:
            raise InvalidReportError("A deleted record has inconsistent metadata.")
        return

    if status in {ChangeStatus.MODIFIED, ChangeStatus.UNCHANGED}:
        if not previous_exists or not current_trusted or current_size is None:
            raise InvalidReportError("A compared record has incomplete metadata.")
        expected_changed = (
            previous_size != current_size
            or previous_modified != current_modified
        )
        if metadata_changed is not expected_changed:
            raise InvalidReportError("metadata_changed conflicts with file metadata.")
        return

    if unknown_reason in {"scan_error", "skipped_path"}:
        if (
            not previous_exists
            or current_size is not None
            or current_modified is not None
            or metadata_changed
        ):
            raise InvalidReportError("A missing-current unknown record is inconsistent.")
        return

    if unknown_reason == "untrusted_result":
        if current_size is None:
            raise InvalidReportError("An untrusted current record needs observed metadata.")
        expected_changed = previous_exists and (
            previous_size != current_size
            or previous_modified != current_modified
        )
        if metadata_changed is not expected_changed:
            raise InvalidReportError("metadata_changed conflicts with unknown metadata.")
        return

    raise InvalidReportError("An unknown record has inconsistent metadata.")


def _validate_issues(value: object) -> tuple[ReportIssue, ...]:
    if not isinstance(value, list):
        raise InvalidReportError("scan_issues must be an array.")
    issues: list[ReportIssue] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != _ISSUE_FIELDS:
            raise InvalidReportError("A scan issue has invalid fields.")
        path = item["relative_path"]
        if path != ".":
            path = _validate_relative_path(path)
        try:
            kind = ScanErrorKind(item["kind"])
        except (TypeError, ValueError) as error:
            raise InvalidReportError("A scan issue has an invalid kind.") from error
        exception_type = item["exception_type"]
        if exception_type is not None and (
            not isinstance(exception_type, str)
            or _EXCEPTION_TYPE_PATTERN.fullmatch(exception_type) is None
        ):
            raise InvalidReportError("exception_type is invalid.")
        issues.append(ReportIssue(path, kind, exception_type))
    expected = sorted(
        issues,
        key=lambda issue: (
            issue.relative_path,
            issue.kind.value,
            issue.exception_type or "",
        ),
    )
    if issues != expected:
        raise InvalidReportError("scan_issues must be sorted.")
    issue_keys = {
        (_path_key(issue.relative_path), issue.kind.value, issue.exception_type)
        for issue in issues
    }
    if len(issue_keys) != len(issues):
        raise InvalidReportError("Duplicate scan_issues are not allowed.")
    return tuple(issues)


def _validate_paths(value: object, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise InvalidReportError(f"{field_name} must be an array.")
    paths = tuple(_validate_relative_path(path) for path in value)
    unique_paths = {_path_key(path) for path in paths}
    if list(paths) != sorted(paths) or len(unique_paths) != len(paths):
        raise InvalidReportError(f"{field_name} must be sorted and unique.")
    return paths


def _validate_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise InvalidReportError("Relative paths must be nonempty strings.")
    if "\\" in value or PurePosixPath(value).is_absolute():
        raise InvalidReportError("Relative paths must use forward slashes.")
    windows_path = PureWindowsPath(value)
    if windows_path.is_absolute() or windows_path.drive:
        raise InvalidReportError("Absolute file entries are not allowed.")
    components = value.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise InvalidReportError("A relative path contains an unsafe component.")
    if any(any(ord(character) < 32 for character in item) for item in components):
        raise InvalidReportError("A relative path contains control data.")
    if any(item.endswith((" ", ".")) or ":" in item for item in components):
        raise InvalidReportError("A relative path is not Windows-safe.")
    return value


def _validate_optional_hash(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise InvalidReportError("A report hash is not a valid SHA-256 digest.")
    return value


def _validate_optional_size(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0:
        raise InvalidReportError("A file size must be nonnegative or null.")
    return value


def _validate_bool(value: object, field_name: str) -> bool:
    if type(value) is not bool:
        raise InvalidReportError(f"{field_name} must be a boolean.")
    return value


def _validate_datetime(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise InvalidReportError(f"{field_name} must be a datetime.")
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise InvalidReportError(f"{field_name} must be timezone-aware UTC.")
    return value.astimezone(timezone.utc)


def _parse_timestamp(value: object, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise InvalidReportError(f"{field_name} must be an ISO 8601 UTC timestamp.")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise InvalidReportError(f"{field_name} is invalid.") from error
    return _validate_datetime(parsed, field_name)


def _parse_optional_timestamp(value: object, field_name: str) -> datetime | None:
    return None if value is None else _parse_timestamp(value, field_name)


def _format_timestamp(value: datetime) -> str:
    validated = _validate_datetime(value, "timestamp")
    return validated.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _optional_timestamp(value: datetime | None) -> str | None:
    return None if value is None else _format_timestamp(value)


def _assessment_status(conclusive: bool, has_changes: bool) -> AssessmentStatus:
    if not conclusive:
        return AssessmentStatus.INCONCLUSIVE
    return (
        AssessmentStatus.CHANGES_DETECTED
        if has_changes
        else AssessmentStatus.CLEAN
    )


def _validate_report_destination(
    destination: str | PathLike[str],
    monitored_root: str | PathLike[str],
) -> Path:
    target = Path(os.path.abspath(os.fspath(destination)))
    try:
        _baseline_storage._reject_link_components(target.parent)
        parent = target.parent.resolve(strict=True)
        root = Path(monitored_root).resolve(strict=True)
    except BaselineError as error:
        raise UnsafeReportPathError("The report destination path is unsafe.") from error
    except OSError as error:
        raise ReportIOError("Unable to inspect the report destination.") from error
    if not parent.is_dir() or not root.is_dir():
        raise UnsafeReportPathError("Report paths must reference valid directories.")
    target = parent / target.name
    if _baseline_storage._is_within(target, root):
        raise UnsafeReportPathError(
            "A report cannot be stored inside the monitored directory."
        )
    try:
        file_info = target.stat(follow_symlinks=False)
    except FileNotFoundError:
        return target
    except OSError as error:
        raise ReportIOError("Unable to inspect the report destination.") from error
    if _baseline_storage._is_link_like(file_info):
        raise UnsafeReportPathError("A link cannot be used as a report destination.")
    raise ReportExistsError("A report already exists at the destination.")


def _atomic_create(target: Path, payload: bytes) -> None:
    file_descriptor = -1
    temp_path: Path | None = None
    operation_error: BaseException | None = None
    cleanup_error: OSError | None = None
    try:
        file_descriptor, temp_name = tempfile.mkstemp(
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
        )
        temp_path = Path(temp_name)
        with os.fdopen(file_descriptor, "wb") as output:
            file_descriptor = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
            os.link(temp_path, target)
    except BaseException as error:
        operation_error = error
    finally:
        if file_descriptor >= 0:
            try:
                os.close(file_descriptor)
            except OSError as error:
                cleanup_error = error
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError as error:
                cleanup_error = error
    if operation_error is not None:
        if isinstance(operation_error, FileExistsError):
            raise ReportExistsError(
                "A report already exists at the destination."
            ) from operation_error
        if isinstance(operation_error, OSError):
            raise ReportIOError("Unable to write the report file.") from operation_error
        raise operation_error
    if cleanup_error is not None:
        raise ReportIOError("Temporary report cleanup failed.") from cleanup_error
    try:
        _baseline_storage._fsync_directory(target.parent)
    except BaselineError as error:
        raise ReportIOError("Unable to flush the report directory.") from error


def _read_limited_file(
    path: Path,
    before: os.stat_result,
    max_bytes: int,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _identity_changed(before, opened):
            raise UnsafeReportPathError("The report changed while opening.")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            payload = source.read(max_bytes + 1)
        if len(payload) > max_bytes:
            raise InvalidReportError("The report exceeds the size limit.")
        after = path.stat(follow_symlinks=False)
        if _baseline_storage._is_link_like(after) or _identity_changed(opened, after):
            raise UnsafeReportPathError("The report changed while reading.")
        return payload
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _identity_changed(before: os.stat_result, after: os.stat_result) -> bool:
    if before.st_ino == 0 or after.st_ino == 0:
        return False
    return (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidReportError("Duplicate JSON fields are not allowed.")
        result[key] = value
    return result


def _path_key(path: str) -> str:
    return path.casefold() if os.name == "nt" else path


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"
