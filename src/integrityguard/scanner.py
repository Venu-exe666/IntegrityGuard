"""Read-only recursive directory scanning for IntegrityGuard."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from os import PathLike
from pathlib import Path, PurePosixPath

from integrityguard.hashing import sha256_file

_WINDOWS_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class ScanStatus(StrEnum):
    """Outcome of attempting to hash a discovered regular file."""

    SCANNED = "scanned"
    ERROR = "error"
    CHANGED_DURING_SCAN = "changed_during_scan"


class ScanErrorKind(StrEnum):
    """Machine-readable categories for scan failures."""

    ROOT_NOT_FOUND = "root_not_found"
    ROOT_NOT_DIRECTORY = "root_not_directory"
    ROOT_LINK_NOT_FOLLOWED = "root_link_not_followed"
    DIRECTORY_ACCESS = "directory_access"
    DIRECTORY_LOOP = "directory_loop"
    ENTRY_INSPECTION = "entry_inspection"
    FILE_ACCESS = "file_access"
    FILE_CHANGED = "file_changed"


@dataclass(frozen=True, slots=True)
class FileScanResult:
    """Result of scanning one discovered regular file."""

    relative_path: str
    sha256: str | None
    size_bytes: int | None
    modified_at_utc: datetime | None
    status: ScanStatus


@dataclass(frozen=True, slots=True)
class ScanError:
    """A scan problem kept separate from successful file data."""

    relative_path: str
    kind: ScanErrorKind
    message: str
    exception_type: str | None = None


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Complete, deterministically ordered output from a directory scan."""

    root: Path
    files: tuple[FileScanResult, ...]
    errors: tuple[ScanError, ...]
    skipped_paths: tuple[str, ...]


def scan_directory(directory: str | PathLike[str]) -> ScanReport:
    """Recursively hash regular files below ``directory`` without writing.

    Relative paths use forward slashes on every operating system. Symbolic
    links, Windows junctions, and other reparse points are skipped. Files that
    cannot be read or that appear to change while being hashed receive a
    non-success status and a corresponding entry in ``errors``.

    The function reports invalid or inaccessible roots in the returned report
    instead of raising their filesystem exceptions.
    """
    root = Path(os.path.abspath(os.fspath(directory)))
    files: list[FileScanResult] = []
    errors: list[ScanError] = []
    skipped_paths: list[str] = []

    try:
        root_info = root.stat(follow_symlinks=False)
    except FileNotFoundError as error:
        errors.append(_scan_error(".", ScanErrorKind.ROOT_NOT_FOUND, error))
        return _build_report(root, files, errors, skipped_paths)
    except OSError as error:
        errors.append(_scan_error(".", ScanErrorKind.DIRECTORY_ACCESS, error))
        return _build_report(root, files, errors, skipped_paths)

    if _is_link_like(root_info):
        errors.append(
            ScanError(
                relative_path=".",
                kind=ScanErrorKind.ROOT_LINK_NOT_FOLLOWED,
                message=(
                    "The scan root is a link or reparse point and was not followed."
                ),
            )
        )
        return _build_report(root, files, errors, skipped_paths)

    if not stat.S_ISDIR(root_info.st_mode):
        errors.append(
            ScanError(
                relative_path=".",
                kind=ScanErrorKind.ROOT_NOT_DIRECTORY,
                message="The scan root is not a directory.",
                exception_type="NotADirectoryError",
            )
        )
        return _build_report(root, files, errors, skipped_paths)

    visited_directories: set[tuple[int, int]] = set()
    root_identity = _file_identity(root_info)
    if root_identity is not None:
        visited_directories.add(root_identity)

    _scan_tree(
        root,
        root,
        visited_directories,
        files,
        errors,
        skipped_paths,
    )
    return _build_report(root, files, errors, skipped_paths)


def _scan_tree(
    root: Path,
    directory: Path,
    visited_directories: set[tuple[int, int]],
    files: list[FileScanResult],
    errors: list[ScanError],
    skipped_paths: list[str],
) -> None:
    try:
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
    except OSError as error:
        errors.append(
            _scan_error(
                _relative_path(root, directory),
                ScanErrorKind.DIRECTORY_ACCESS,
                error,
            )
        )
        return

    for entry in entries:
        entry_path = Path(entry.path)
        relative_path = _relative_path(root, entry_path)

        try:
            entry_info = entry.stat(follow_symlinks=False)
        except OSError as error:
            errors.append(
                _scan_error(relative_path, ScanErrorKind.ENTRY_INSPECTION, error)
            )
            continue

        if _is_link_like(entry_info):
            skipped_paths.append(relative_path)
            continue

        if stat.S_ISDIR(entry_info.st_mode):
            identity = _file_identity(entry_info)
            if identity is not None and identity in visited_directories:
                errors.append(
                    ScanError(
                        relative_path=relative_path,
                        kind=ScanErrorKind.DIRECTORY_LOOP,
                        message="A previously visited directory was not scanned again.",
                    )
                )
                continue
            if identity is not None:
                visited_directories.add(identity)
            _scan_tree(
                root,
                entry_path,
                visited_directories,
                files,
                errors,
                skipped_paths,
            )
        elif stat.S_ISREG(entry_info.st_mode):
            result, error = _scan_file(entry_path, relative_path, entry_info)
            files.append(result)
            if error is not None:
                errors.append(error)


def _scan_file(
    path: Path,
    relative_path: str,
    before: os.stat_result,
) -> tuple[FileScanResult, ScanError | None]:
    size_bytes = before.st_size
    modified_at = _modified_at_utc(before)

    try:
        digest = sha256_file(path)
        after = path.stat(follow_symlinks=False)
    except OSError as error:
        return (
            FileScanResult(
                relative_path=relative_path,
                sha256=None,
                size_bytes=size_bytes,
                modified_at_utc=modified_at,
                status=ScanStatus.ERROR,
            ),
            _scan_error(relative_path, ScanErrorKind.FILE_ACCESS, error),
        )

    changed = _changed(before, after)
    if _is_link_like(after) or not stat.S_ISREG(after.st_mode) or changed:
        error = ScanError(
            relative_path=relative_path,
            kind=ScanErrorKind.FILE_CHANGED,
            message=(
                "The file changed while it was being hashed; its digest was "
                "discarded."
            ),
        )
        return (
            FileScanResult(
                relative_path=relative_path,
                sha256=None,
                size_bytes=after.st_size,
                modified_at_utc=_modified_at_utc(after),
                status=ScanStatus.CHANGED_DURING_SCAN,
            ),
            error,
        )

    return (
        FileScanResult(
            relative_path=relative_path,
            sha256=digest,
            size_bytes=after.st_size,
            modified_at_utc=_modified_at_utc(after),
            status=ScanStatus.SCANNED,
        ),
        None,
    )


def _changed(before: os.stat_result, after: os.stat_result) -> bool:
    before_identity = _file_identity(before)
    after_identity = _file_identity(after)
    identity_changed = (
        before_identity is not None
        and after_identity is not None
        and before_identity != after_identity
    )
    return (
        identity_changed
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    )


def _file_identity(file_info: os.stat_result) -> tuple[int, int] | None:
    if file_info.st_ino == 0:
        return None
    return file_info.st_dev, file_info.st_ino


def _is_link_like(file_info: os.stat_result) -> bool:
    attributes = getattr(file_info, "st_file_attributes", 0)
    return stat.S_ISLNK(file_info.st_mode) or bool(
        attributes & _WINDOWS_REPARSE_POINT
    )


def _modified_at_utc(file_info: os.stat_result) -> datetime | None:
    try:
        return datetime.fromtimestamp(file_info.st_mtime, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def _relative_path(root: Path, path: Path) -> str:
    relative = path.relative_to(root)
    if not relative.parts:
        return "."
    return PurePosixPath(*relative.parts).as_posix()


def _scan_error(
    relative_path: str,
    kind: ScanErrorKind,
    error: OSError,
) -> ScanError:
    return ScanError(
        relative_path=relative_path,
        kind=kind,
        message=str(error),
        exception_type=type(error).__name__,
    )


def _build_report(
    root: Path,
    files: list[FileScanResult],
    errors: list[ScanError],
    skipped_paths: list[str],
) -> ScanReport:
    return ScanReport(
        root=root,
        files=tuple(sorted(files, key=lambda result: result.relative_path)),
        errors=tuple(
            sorted(errors, key=lambda error: (error.relative_path, error.kind.value))
        ),
        skipped_paths=tuple(sorted(skipped_paths)),
    )
