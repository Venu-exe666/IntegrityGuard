"""Read-only recursive directory scanning for IntegrityGuard."""

from __future__ import annotations

import math
import os
import stat
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from os import PathLike
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from integrityguard.hashing import sha256_stream

_WINDOWS_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class _ObjectChangedError(OSError):
    """Raised when an opened object does not match its inspected entry."""


class _UnsupportedIdentityError(OSError):
    """Raised when stable object identity is unavailable for safe binding."""


class ScanLimitExceededError(Exception):
    """Raised internally when a configured scan resource limit is exceeded."""


@dataclass(frozen=True, slots=True)
class ScanLimits:
    """Optional resource ceilings for one recursive scan."""

    max_entries: int | None = None
    max_bytes: int | None = None
    max_duration_seconds: float | None = None

    def __post_init__(self) -> None:
        _validate_optional_positive_int(self.max_entries, "max_entries")
        _validate_optional_positive_int(self.max_bytes, "max_bytes")
        value = self.max_duration_seconds
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or value <= 0
        ):
            raise ValueError("max_duration_seconds must be a finite positive number")


@dataclass(slots=True)
class _ScanState:
    limits: ScanLimits
    monotonic: Callable[[], float]
    deadline: float | None
    entries_seen: int = 0
    bytes_hashed: int = 0

    def check_duration(self) -> None:
        if self.deadline is not None and self.monotonic() >= self.deadline:
            raise ScanLimitExceededError("The maximum scan duration was exceeded.")

    def record_entry(self) -> None:
        self.check_duration()
        self.entries_seen += 1
        maximum = self.limits.max_entries
        if maximum is not None and self.entries_seen > maximum:
            raise ScanLimitExceededError("The maximum scan entry count was exceeded.")

    def ensure_file_fits(self, size_bytes: int) -> None:
        maximum = self.limits.max_bytes
        if maximum is not None and self.bytes_hashed + size_bytes > maximum:
            raise ScanLimitExceededError("The maximum cumulative byte count was exceeded.")


class _BoundedScanReader:
    """Count bytes and check time without taking ownership of the file handle."""

    def __init__(self, source: BinaryIO, state: _ScanState) -> None:
        self._source = source
        self._state = state

    def read(self, size: int = -1) -> bytes:
        self._state.check_duration()
        maximum = self._state.limits.max_bytes
        requested = size
        if maximum is not None:
            remaining = maximum - self._state.bytes_hashed
            requested = remaining + 1 if size < 0 else min(size, remaining + 1)
        data = self._source.read(requested)
        if maximum is not None and self._state.bytes_hashed + len(data) > maximum:
            raise ScanLimitExceededError("The maximum cumulative byte count was exceeded.")
        self._state.bytes_hashed += len(data)
        self._state.check_duration()
        return data


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
    errno: int | None = None
    winerror: int | None = None


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Complete, deterministically ordered output from a directory scan."""

    root: Path
    files: tuple[FileScanResult, ...]
    errors: tuple[ScanError, ...]
    skipped_paths: tuple[str, ...]


def scan_directory(
    directory: str | PathLike[str],
    *,
    limits: ScanLimits | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> ScanReport:
    """Recursively hash regular files below ``directory`` without writing.

    Relative paths use forward slashes on every operating system. Discovered
    symbolic links, Windows junctions, and other reparse points are skipped,
    while no-follow opens and handle identity checks reject substitutions.
    Files that cannot be read or that appear to change while being hashed
    receive a non-success status and a corresponding entry in ``errors``.

    The function reports invalid or inaccessible roots in the returned report
    instead of raising their filesystem exceptions.
    """
    root = Path(os.path.abspath(os.fspath(directory)))
    if limits is not None and not isinstance(limits, ScanLimits):
        raise TypeError("limits must be a ScanLimits instance or None")
    if not callable(monotonic):
        raise TypeError("monotonic must be callable")
    active_limits = limits or ScanLimits()
    started = float(monotonic())
    if not math.isfinite(started):
        raise ValueError("monotonic must return a finite number")
    duration = active_limits.max_duration_seconds
    state = _ScanState(
        limits=active_limits,
        monotonic=monotonic,
        deadline=None if duration is None else started + float(duration),
    )
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

    try:
        root_descriptor, opened_root = _open_directory(root, root_info)
    except _ObjectChangedError as error:
        errors.append(_scan_error(".", ScanErrorKind.DIRECTORY_ACCESS, error))
        return _build_report(root, files, errors, skipped_paths)
    except OSError as error:
        errors.append(_scan_error(".", ScanErrorKind.DIRECTORY_ACCESS, error))
        return _build_report(root, files, errors, skipped_paths)

    root_identity = _required_identity(opened_root)
    visited_directories = {root_identity}
    try:
        _scan_tree(
            root,
            root,
            root_descriptor,
            None,
            None,
            opened_root,
            state,
            visited_directories,
            files,
            errors,
            skipped_paths,
        )
    except ScanLimitExceededError as error:
        errors.append(
            ScanError(
                relative_path=".",
                kind=ScanErrorKind.DIRECTORY_ACCESS,
                message=str(error),
                exception_type=type(error).__name__,
            )
        )
    finally:
        os.close(root_descriptor)
    return _build_report(root, files, errors, skipped_paths)


def _scan_tree(
    root: Path,
    directory: Path,
    directory_descriptor: int,
    parent_descriptor: int | None,
    directory_name: str | None,
    opened_directory: os.stat_result,
    state: _ScanState,
    visited_directories: set[tuple[int, int]],
    files: list[FileScanResult],
    errors: list[ScanError],
    skipped_paths: list[str],
) -> None:
    state.check_duration()
    try:
        scan_target: int | Path = (
            directory_descriptor if os.name != "nt" else directory
        )
        entry_names = _read_entry_names(scan_target, state)
    except OSError as error:
        errors.append(
            _scan_error(
                _relative_path(root, directory),
                ScanErrorKind.DIRECTORY_ACCESS,
                error,
            )
        )
        return

    for entry_name in entry_names:
        state.check_duration()
        entry_path = directory / entry_name
        relative_path = _relative_path(root, entry_path)

        try:
            entry_info = _entry_stat(directory_descriptor, entry_path, entry_name)
        except OSError as error:
            errors.append(
                _scan_error(relative_path, ScanErrorKind.ENTRY_INSPECTION, error)
            )
            continue

        if _is_link_like(entry_info):
            skipped_paths.append(relative_path)
            continue

        if stat.S_ISDIR(entry_info.st_mode):
            try:
                child_descriptor, opened_child = _open_directory(
                    entry_path,
                    entry_info,
                    parent_descriptor=directory_descriptor,
                    entry_name=entry_name,
                )
            except OSError as error:
                errors.append(
                    _scan_error(relative_path, ScanErrorKind.DIRECTORY_ACCESS, error)
                )
                continue
            identity = _required_identity(opened_child)
            if identity in visited_directories:
                os.close(child_descriptor)
                errors.append(
                    ScanError(
                        relative_path=relative_path,
                        kind=ScanErrorKind.DIRECTORY_LOOP,
                        message="A previously visited directory was not scanned again.",
                    )
                )
                continue
            visited_directories.add(identity)
            try:
                _scan_tree(
                    root,
                    entry_path,
                    child_descriptor,
                    directory_descriptor,
                    entry_name,
                    opened_child,
                    state,
                    visited_directories,
                    files,
                    errors,
                    skipped_paths,
                )
            finally:
                os.close(child_descriptor)
        elif stat.S_ISREG(entry_info.st_mode):
            result, error = _scan_file(
                entry_path,
                relative_path,
                entry_info,
                state,
                parent_descriptor=directory_descriptor,
                entry_name=entry_name,
            )
            files.append(result)
            if error is not None:
                errors.append(error)

    try:
        current_directory = _directory_entry_stat(
            directory,
            parent_descriptor,
            directory_name,
        )
        if _is_link_like(current_directory) or _changed(
            opened_directory,
            current_directory,
        ):
            raise _ObjectChangedError(
                "The directory changed while its contents were being scanned."
            )
    except OSError as error:
        errors.append(
            _scan_error(
                _relative_path(root, directory),
                ScanErrorKind.DIRECTORY_ACCESS,
                error,
            )
        )


def _scan_file(
    path: Path,
    relative_path: str,
    before: os.stat_result,
    state: _ScanState,
    *,
    parent_descriptor: int,
    entry_name: str,
) -> tuple[FileScanResult, ScanError | None]:
    size_bytes = before.st_size
    modified_at = _modified_at_utc(before)
    state.check_duration()
    state.ensure_file_fits(size_bytes)

    descriptor = -1
    try:
        descriptor = _open_file(
            path,
            before,
            parent_descriptor=parent_descriptor,
            entry_name=entry_name,
        )
        opened_before = os.fstat(descriptor)
        with os.fdopen(descriptor, "rb") as file_handle:
            descriptor = -1
            bounded_reader = _BoundedScanReader(file_handle, state)
            digest = sha256_stream(bounded_reader)  # type: ignore[arg-type]
            opened_after = os.fstat(file_handle.fileno())
            try:
                named_after = _entry_stat(parent_descriptor, path, entry_name)
            except OSError as error:
                raise _ObjectChangedError(
                    "The file entry changed while it was being hashed."
                ) from error
    except _ObjectChangedError as error:
        return _changed_file_result(relative_path, size_bytes, modified_at, error)
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
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    if (
        _is_link_like(named_after)
        or not stat.S_ISREG(named_after.st_mode)
        or _changed(opened_before, opened_after)
        or _changed(opened_after, named_after)
    ):
        return _changed_file_result(
            relative_path,
            opened_after.st_size,
            _modified_at_utc(opened_after),
            _ObjectChangedError(
                "The file changed while it was being hashed; its digest was discarded."
            ),
        )

    return (
        FileScanResult(
            relative_path=relative_path,
            sha256=digest,
            size_bytes=opened_after.st_size,
            modified_at_utc=_modified_at_utc(opened_after),
            status=ScanStatus.SCANNED,
        ),
        None,
    )


def _read_entry_names(
    scan_target: int | Path,
    state: _ScanState,
) -> list[str]:
    names: list[str] = []
    with os.scandir(scan_target) as iterator:
        for entry in iterator:
            state.record_entry()
            names.append(entry.name)
    names.sort()
    return names


def _validate_optional_positive_int(value: object, field_name: str) -> None:
    if value is not None and (type(value) is not int or value <= 0):
        raise ValueError(f"{field_name} must be a positive integer or None")


def _changed_file_result(
    relative_path: str,
    size_bytes: int | None,
    modified_at: datetime | None,
    error: OSError,
) -> tuple[FileScanResult, ScanError]:
    return (
        FileScanResult(
            relative_path=relative_path,
            sha256=None,
            size_bytes=size_bytes,
            modified_at_utc=modified_at,
            status=ScanStatus.CHANGED_DURING_SCAN,
        ),
        ScanError(
            relative_path=relative_path,
            kind=ScanErrorKind.FILE_CHANGED,
            message=str(error),
            exception_type=type(error).__name__,
        ),
    )


def _open_file(
    path: Path,
    expected: os.stat_result,
    *,
    parent_descriptor: int,
    entry_name: str,
) -> int:
    if os.name == "nt":
        descriptor = _windows_open(path, is_directory=False)
    else:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | _required_no_follow_flag()
        )
        descriptor = os.open(entry_name, flags, dir_fd=parent_descriptor)
    try:
        opened = os.fstat(descriptor)
        _verify_opened_object(expected, opened, require_directory=False)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_directory(
    path: Path,
    expected: os.stat_result,
    *,
    parent_descriptor: int | None = None,
    entry_name: str | None = None,
) -> tuple[int, os.stat_result]:
    if os.name == "nt":
        descriptor = _windows_open(path, is_directory=True)
    else:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | _required_no_follow_flag()
        )
        if parent_descriptor is None:
            descriptor = os.open(path, flags)
        else:
            descriptor = os.open(entry_name, flags, dir_fd=parent_descriptor)
    try:
        opened = os.fstat(descriptor)
        _verify_opened_object(expected, opened, require_directory=True)
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _verify_opened_object(
    expected: os.stat_result,
    opened: os.stat_result,
    *,
    require_directory: bool,
) -> None:
    expected_identity = _required_identity(expected)
    opened_identity = _required_identity(opened)
    expected_type = (
        stat.S_ISDIR(expected.st_mode)
        if require_directory
        else stat.S_ISREG(expected.st_mode)
    )
    opened_type = (
        stat.S_ISDIR(opened.st_mode)
        if require_directory
        else stat.S_ISREG(opened.st_mode)
    )
    if (
        _is_link_like(opened)
        or not expected_type
        or not opened_type
        or expected_identity != opened_identity
    ):
        raise _ObjectChangedError(
            "The filesystem object changed between inspection and opening."
        )


def _required_identity(file_info: os.stat_result) -> tuple[int, int]:
    identity = _file_identity(file_info)
    if identity is None:
        raise _UnsupportedIdentityError(
            "Stable filesystem object identity is unavailable; the path was not scanned."
        )
    return identity


def _required_no_follow_flag() -> int:
    value = getattr(os, "O_NOFOLLOW", 0)
    if value == 0:
        raise _UnsupportedIdentityError(
            "This platform does not provide descriptor-relative no-follow opens."
        )
    return value


def _entry_stat(
    parent_descriptor: int,
    path: Path,
    entry_name: str,
) -> os.stat_result:
    if os.name == "nt":
        return path.stat(follow_symlinks=False)
    return os.stat(entry_name, dir_fd=parent_descriptor, follow_symlinks=False)


def _directory_entry_stat(
    path: Path,
    parent_descriptor: int | None,
    entry_name: str | None,
) -> os.stat_result:
    if os.name == "nt" or parent_descriptor is None:
        return path.stat(follow_symlinks=False)
    return os.stat(entry_name, dir_fd=parent_descriptor, follow_symlinks=False)


def _windows_open(path: Path, *, is_directory: bool) -> int:
    if sys.platform != "win32":  # pragma: no cover - guarded by os.name
        raise _UnsupportedIdentityError("Windows handle support is unavailable.")

    import ctypes
    import msvcrt
    from ctypes import wintypes

    create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE

    generic_read = 0x80000000
    share_read = 0x00000001
    share_write = 0x00000002
    open_existing = 3
    open_reparse_point = 0x00200000
    backup_semantics = 0x02000000
    flags = open_reparse_point
    if is_directory:
        flags |= backup_semantics

    handle = create_file(
        str(path),
        generic_read,
        share_read | share_write,
        None,
        open_existing,
        flags,
        None,
    )
    invalid_handle = wintypes.HANDLE(-1).value
    if handle == invalid_handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return msvcrt.open_osfhandle(
            int(handle),
            os.O_RDONLY | getattr(os, "O_BINARY", 0),
        )
    except BaseException:
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)
        raise


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
        errno=_safe_error_code(getattr(error, "errno", None)),
        winerror=_safe_error_code(getattr(error, "winerror", None)),
    )


def _safe_error_code(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


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
