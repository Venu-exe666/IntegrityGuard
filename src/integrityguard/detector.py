"""Pure, conservative file-integrity change detection."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path, PurePosixPath, PureWindowsPath

from integrityguard.baseline import (
    Baseline,
    BaselineFile,
    InvalidBaselineError,
    baseline_to_json,
)
from integrityguard.scanner import (
    FileScanResult,
    ScanError,
    ScanErrorKind,
    ScanReport,
    ScanStatus,
)

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class DetectorError(Exception):
    """Base class for expected comparison failures."""


class IncompatibleBaselineError(DetectorError):
    """Raised when an in-memory baseline fails schema validation."""


class RootMismatchError(DetectorError):
    """Raised when a baseline and scan describe different roots."""


class InvalidComparisonInputError(DetectorError):
    """Raised when comparison input violates its public data contract."""


class UnexpectedScannerStateError(InvalidComparisonInputError):
    """Raised for scanner states outside the supported scanner contract."""


class ChangeStatus(StrEnum):
    """Classification assigned to one relative file path."""

    ADDED = "added"
    DELETED = "deleted"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"
    UNKNOWN = "unknown"


class UnknownReason(StrEnum):
    """Reason a trustworthy current file state could not be established."""

    SCAN_ERROR = "scan_error"
    SKIPPED_PATH = "skipped_path"
    UNTRUSTED_RESULT = "untrusted_result"


@dataclass(frozen=True, slots=True)
class FileChange:
    """Comparison details for one normalized relative path."""

    relative_path: str
    status: ChangeStatus
    previous_sha256: str | None
    current_sha256: str | None
    previous_size_bytes: int | None
    current_size_bytes: int | None
    previous_modified_at_utc: datetime | None
    current_modified_at_utc: datetime | None
    metadata_changed: bool
    unknown_reason: UnknownReason | None = None


@dataclass(frozen=True, slots=True)
class ChangeCounts:
    """Aggregate counts for every change classification."""

    added: int
    deleted: int
    modified: int
    unchanged: int
    unknown: int

    @property
    def total(self) -> int:
        """Return the total number of classified paths."""
        return self.added + self.deleted + self.modified + self.unchanged + self.unknown


@dataclass(frozen=True, slots=True)
class ChangeReport:
    """Immutable, deterministically ordered integrity comparison output."""

    baseline_root: str
    current_scan_root: str
    added: tuple[FileChange, ...]
    deleted: tuple[FileChange, ...]
    modified: tuple[FileChange, ...]
    unchanged: tuple[FileChange, ...]
    unknown: tuple[FileChange, ...]
    scan_errors: tuple[ScanError, ...]
    baseline_skipped_paths: tuple[str, ...]
    current_skipped_paths: tuple[str, ...]
    counts: ChangeCounts
    scan_complete: bool
    assessment_conclusive: bool

    @property
    def has_confirmed_changes(self) -> bool:
        """Return whether any added, deleted, or modified file was confirmed."""
        return bool(self.added or self.deleted or self.modified)

    @property
    def is_clean(self) -> bool:
        """Return true only for a conclusive report with no confirmed changes."""
        return self.assessment_conclusive and not self.has_confirmed_changes

    @property
    def all_changes(self) -> tuple[FileChange, ...]:
        """Return all records in deterministic relative-path order."""
        return tuple(
            sorted(
                self.added
                + self.deleted
                + self.modified
                + self.unchanged
                + self.unknown,
                key=lambda item: item.relative_path,
            )
        )


def compare_baseline(baseline: Baseline, scan_report: ScanReport) -> ChangeReport:
    """Compare a validated baseline with a fresh scan without side effects.

    A missing baseline path is classified as deleted only when no current scan
    error or skipped path could have hidden it. Untrusted current file records
    are classified as unknown and their digests are never used.
    """
    _validate_baseline(baseline)
    validated_files = _validate_scan_report(scan_report)
    baseline_root, current_root = _validate_matching_roots(baseline, scan_report)

    baseline_by_key = {
        _path_key(item.relative_path): item for item in baseline.files
    }
    current_by_key = {
        _path_key(item.relative_path): item for item in validated_files
    }
    all_keys = sorted(
        baseline_by_key.keys() | current_by_key.keys(),
        key=lambda key: (
            baseline_by_key.get(key) or current_by_key[key]
        ).relative_path,
    )

    classified: dict[ChangeStatus, list[FileChange]] = {
        status: [] for status in ChangeStatus
    }
    for key in all_keys:
        previous = baseline_by_key.get(key)
        current = current_by_key.get(key)
        change = _classify_path(
            previous,
            current,
            scan_report.errors,
            scan_report.skipped_paths,
        )
        classified[change.status].append(change)

    added = tuple(classified[ChangeStatus.ADDED])
    deleted = tuple(classified[ChangeStatus.DELETED])
    modified = tuple(classified[ChangeStatus.MODIFIED])
    unchanged = tuple(classified[ChangeStatus.UNCHANGED])
    unknown = tuple(classified[ChangeStatus.UNKNOWN])
    counts = ChangeCounts(
        added=len(added),
        deleted=len(deleted),
        modified=len(modified),
        unchanged=len(unchanged),
        unknown=len(unknown),
    )

    all_current_files_trusted = all(
        _is_trusted_current_file(item) for item in validated_files
    )
    scan_complete = (
        not scan_report.errors
        and not scan_report.skipped_paths
        and all_current_files_trusted
    )
    assessment_conclusive = (
        scan_complete and not baseline.skipped_paths and not unknown
    )

    return ChangeReport(
        baseline_root=baseline_root,
        current_scan_root=current_root,
        added=added,
        deleted=deleted,
        modified=modified,
        unchanged=unchanged,
        unknown=unknown,
        scan_errors=tuple(
            sorted(
                scan_report.errors,
                key=lambda item: (item.relative_path, item.kind.value),
            )
        ),
        baseline_skipped_paths=baseline.skipped_paths,
        current_skipped_paths=tuple(sorted(scan_report.skipped_paths)),
        counts=counts,
        scan_complete=scan_complete,
        assessment_conclusive=assessment_conclusive,
    )


def _classify_path(
    previous: BaselineFile | None,
    current: FileScanResult | None,
    errors: tuple[ScanError, ...],
    skipped_paths: tuple[str, ...],
) -> FileChange:
    if current is not None and not _is_trusted_current_file(current):
        return _file_change(
            previous,
            current,
            ChangeStatus.UNKNOWN,
            UnknownReason.UNTRUSTED_RESULT,
        )

    if previous is None:
        if current is None:  # pragma: no cover - impossible union state
            raise AssertionError("A comparison key has no file records.")
        return _file_change(None, current, ChangeStatus.ADDED)

    if current is None:
        if _path_is_skipped(previous.relative_path, skipped_paths):
            return _file_change(
                previous,
                None,
                ChangeStatus.UNKNOWN,
                UnknownReason.SKIPPED_PATH,
            )
        if _path_has_scan_error(previous.relative_path, errors):
            return _file_change(
                previous,
                None,
                ChangeStatus.UNKNOWN,
                UnknownReason.SCAN_ERROR,
            )
        return _file_change(previous, None, ChangeStatus.DELETED)

    status = (
        ChangeStatus.UNCHANGED
        if previous.sha256 == current.sha256
        else ChangeStatus.MODIFIED
    )
    return _file_change(previous, current, status)


def _file_change(
    previous: BaselineFile | None,
    current: FileScanResult | None,
    status: ChangeStatus,
    reason: UnknownReason | None = None,
) -> FileChange:
    relative_path = (
        previous.relative_path if previous is not None else current.relative_path
    )
    metadata_changed = (
        previous is not None
        and current is not None
        and (
            previous.size_bytes != current.size_bytes
            or previous.modified_at_utc != current.modified_at_utc
        )
    )
    return FileChange(
        relative_path=relative_path,
        status=status,
        previous_sha256=previous.sha256 if previous is not None else None,
        current_sha256=(
            current.sha256
            if current is not None and _is_trusted_current_file(current)
            else None
        ),
        previous_size_bytes=previous.size_bytes if previous is not None else None,
        current_size_bytes=current.size_bytes if current is not None else None,
        previous_modified_at_utc=(
            previous.modified_at_utc if previous is not None else None
        ),
        current_modified_at_utc=(
            current.modified_at_utc if current is not None else None
        ),
        metadata_changed=metadata_changed,
        unknown_reason=reason,
    )


def _validate_baseline(baseline: Baseline) -> None:
    if not isinstance(baseline, Baseline):
        raise InvalidComparisonInputError("baseline must be a Baseline instance.")
    try:
        baseline_to_json(baseline)
    except (InvalidBaselineError, AttributeError, TypeError, ValueError) as error:
        raise IncompatibleBaselineError(
            "The baseline is invalid or incompatible."
        ) from error


def _validate_scan_report(scan_report: ScanReport) -> tuple[FileScanResult, ...]:
    if not isinstance(scan_report, ScanReport):
        raise InvalidComparisonInputError(
            "scan_report must be a ScanReport instance."
        )
    if not isinstance(scan_report.root, Path) or not scan_report.root.is_absolute():
        raise InvalidComparisonInputError("The current scan root must be absolute.")

    seen_paths: set[str] = set()
    validated_files: list[FileScanResult] = []
    for item in scan_report.files:
        if not isinstance(item, FileScanResult):
            raise InvalidComparisonInputError("Invalid current file record type.")
        relative_path = _validate_relative_path(item.relative_path)
        key = _path_key(relative_path)
        if key in seen_paths:
            raise InvalidComparisonInputError("Duplicate current file paths.")
        seen_paths.add(key)

        if not isinstance(item.status, ScanStatus):
            raise UnexpectedScannerStateError("Unsupported current scan status.")
        if item.size_bytes is not None and (
            type(item.size_bytes) is not int or item.size_bytes < 0
        ):
            raise InvalidComparisonInputError("Invalid current file size.")
        _validate_optional_timestamp(item.modified_at_utc)

        if item.sha256 is not None and _SHA256_PATTERN.fullmatch(item.sha256) is None:
            raise InvalidComparisonInputError("Invalid current SHA-256 digest.")
        if item.status is not ScanStatus.SCANNED and item.sha256 is not None:
            raise UnexpectedScannerStateError(
                "An untrusted scanner status cannot carry a trusted digest."
            )
        validated_files.append(item)

    skipped_keys: set[str] = set()
    for path in scan_report.skipped_paths:
        normalized = _validate_relative_path(path)
        key = _path_key(normalized)
        if key in skipped_keys:
            raise InvalidComparisonInputError("Duplicate skipped paths.")
        skipped_keys.add(key)
        if any(
            _path_in_scope(item.relative_path, normalized)
            for item in validated_files
        ):
            raise UnexpectedScannerStateError(
                "A current file cannot also be inside a skipped path."
            )

    for error in scan_report.errors:
        if not isinstance(error, ScanError) or not isinstance(
            error.kind, ScanErrorKind
        ):
            raise UnexpectedScannerStateError("Invalid structured scan error.")
        if error.relative_path != ".":
            _validate_relative_path(error.relative_path)

    return tuple(validated_files)


def _validate_matching_roots(
    baseline: Baseline,
    scan_report: ScanReport,
) -> tuple[str, str]:
    baseline_root = _resolved_root(Path(baseline.scan_root))
    current_root = _resolved_root(scan_report.root)
    if _root_key(baseline_root) != _root_key(current_root):
        raise RootMismatchError(
            "The baseline and current scan refer to different root directories."
        )
    return str(baseline_root), str(current_root)


def _resolved_root(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise InvalidComparisonInputError(
            "A scan root could not be resolved safely."
        ) from error


def _root_key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(path)))


def _path_key(path: str) -> str:
    return path.casefold() if os.name == "nt" else path


def _validate_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise InvalidComparisonInputError("Relative paths must be nonempty strings.")
    if "\\" in value or PurePosixPath(value).is_absolute():
        raise InvalidComparisonInputError(
            "Relative paths must be normalized with forward slashes."
        )
    windows_path = PureWindowsPath(value)
    if windows_path.is_absolute() or windows_path.drive:
        raise InvalidComparisonInputError("Absolute relative paths are not allowed.")
    components = value.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise InvalidComparisonInputError("A relative path is unsafe.")
    if any(any(ord(character) < 32 for character in item) for item in components):
        raise InvalidComparisonInputError("A relative path contains control data.")
    if any(item.endswith((" ", ".")) or ":" in item for item in components):
        raise InvalidComparisonInputError("A relative path is not Windows-safe.")
    if PurePosixPath(value).as_posix() != value:
        raise InvalidComparisonInputError("A relative path is not normalized.")
    return value


def _validate_optional_timestamp(value: datetime | None) -> None:
    if value is None:
        return
    if not isinstance(value, datetime):
        raise InvalidComparisonInputError("A file timestamp must be a datetime.")
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise InvalidComparisonInputError("A file timestamp must use UTC.")


def _is_trusted_current_file(item: FileScanResult) -> bool:
    return (
        item.status is ScanStatus.SCANNED
        and item.sha256 is not None
        and item.size_bytes is not None
    )


def _path_is_skipped(path: str, skipped_paths: tuple[str, ...]) -> bool:
    return any(_path_in_scope(path, skipped) for skipped in skipped_paths)


def _path_has_scan_error(path: str, errors: tuple[ScanError, ...]) -> bool:
    return any(_error_affects_path(error, path) for error in errors)


def _error_affects_path(error: ScanError, path: str) -> bool:
    if error.relative_path == "." or error.kind in {
        ScanErrorKind.ROOT_NOT_FOUND,
        ScanErrorKind.ROOT_NOT_DIRECTORY,
        ScanErrorKind.ROOT_LINK_NOT_FOLLOWED,
    }:
        return True
    if error.kind in {
        ScanErrorKind.DIRECTORY_ACCESS,
        ScanErrorKind.DIRECTORY_LOOP,
        ScanErrorKind.ENTRY_INSPECTION,
    }:
        return _path_in_scope(path, error.relative_path)
    return _path_key(path) == _path_key(error.relative_path)


def _path_in_scope(path: str, scope: str) -> bool:
    path_key = _path_key(path)
    scope_key = _path_key(scope)
    return path_key == scope_key or path_key.startswith(scope_key + "/")
