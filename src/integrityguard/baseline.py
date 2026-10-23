"""Versioned, validated baseline storage for IntegrityGuard."""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from os import PathLike
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from integrityguard.scanner import ScanReport, ScanStatus

SCHEMA_VERSION = 1
HASH_ALGORITHM = "sha256"
MAX_BASELINE_BYTES = 16 * 1024 * 1024

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "hash_algorithm",
    "scan_root",
    "created_at_utc",
    "skipped_paths",
    "files",
}
_FILE_FIELDS = {
    "relative_path",
    "sha256",
    "size_bytes",
    "modified_at_utc",
}
_WINDOWS_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class BaselineError(Exception):
    """Base class for expected baseline failures."""


class InvalidBaselineError(BaselineError):
    """Raised when baseline content does not satisfy the strict schema."""


class UnsupportedBaselineVersionError(InvalidBaselineError):
    """Raised when a baseline uses an unsupported schema or algorithm."""


class UnsafeBaselinePathError(BaselineError):
    """Raised when a storage path violates baseline safety rules."""


class IncompleteScanError(BaselineError):
    """Raised when a scan is not trustworthy enough to become a baseline."""


class BaselineExistsError(BaselineError):
    """Raised when exclusive baseline creation finds an existing target."""


class BaselineIOError(BaselineError):
    """Raised when baseline storage cannot be read or written."""


@dataclass(frozen=True, slots=True)
class BaselineFile:
    """One trusted file record stored in a baseline."""

    relative_path: str
    sha256: str
    size_bytes: int
    modified_at_utc: datetime | None


@dataclass(frozen=True, slots=True)
class Baseline:
    """An immutable, versioned snapshot of a successful directory scan."""

    schema_version: int
    hash_algorithm: str
    scan_root: str
    created_at_utc: datetime
    files: tuple[BaselineFile, ...]
    skipped_paths: tuple[str, ...]


def create_baseline(
    scan_report: ScanReport,
    *,
    created_at_utc: datetime | None = None,
) -> Baseline:
    """Create a baseline from a complete and trustworthy scan report.

    Skipped links and reparse points do not make a scan erroneous because the
    scanner excludes them by policy. Their normalized paths are retained in
    the baseline so that the exclusion remains visible.
    """
    if scan_report.errors:
        raise IncompleteScanError("A scan containing errors cannot become a baseline.")

    try:
        root_info = scan_report.root.stat(follow_symlinks=False)
        if _is_link_like(root_info):
            raise IncompleteScanError("The scanned root cannot be a link.")
        canonical_root = scan_report.root.resolve(strict=True)
    except IncompleteScanError:
        raise
    except OSError as error:
        raise IncompleteScanError(
            "The scanned root is no longer accessible."
        ) from error
    if not canonical_root.is_dir():
        raise IncompleteScanError("The scanned root is not a directory.")

    baseline_files: list[BaselineFile] = []
    seen_paths: set[str] = set()
    for result in scan_report.files:
        if (
            result.status is not ScanStatus.SCANNED
            or result.sha256 is None
            or result.size_bytes is None
        ):
            raise IncompleteScanError(
                "Every scanned file must have trusted hash and metadata values."
            )
        try:
            relative_path = _validate_relative_path(result.relative_path)
            digest = _validate_sha256(result.sha256)
            size_bytes = _validate_size(result.size_bytes)
            modified_at = _validate_optional_timestamp(result.modified_at_utc)
        except InvalidBaselineError as error:
            raise IncompleteScanError(
                "A scan file record contains invalid or inconsistent data."
            ) from error

        path_key = relative_path.casefold()
        if path_key in seen_paths:
            raise IncompleteScanError("The scan contains duplicate file paths.")
        seen_paths.add(path_key)
        baseline_files.append(
            BaselineFile(
                relative_path=relative_path,
                sha256=digest,
                size_bytes=size_bytes,
                modified_at_utc=modified_at,
            )
        )

    try:
        skipped_paths = _validate_path_collection(
            list(scan_report.skipped_paths),
            field_name="skipped_paths",
        )
    except InvalidBaselineError as error:
        raise IncompleteScanError("The scan contains invalid skipped paths.") from error

    if _path_collections_overlap(
        (item.relative_path for item in baseline_files),
        skipped_paths,
    ):
        raise IncompleteScanError("Scanned and skipped paths cannot overlap.")

    created_at = created_at_utc or datetime.now(timezone.utc)
    try:
        created_at = _validate_timestamp(created_at, "created_at_utc")
    except InvalidBaselineError as error:
        raise IncompleteScanError("The baseline creation time must be UTC.") from error

    return Baseline(
        schema_version=SCHEMA_VERSION,
        hash_algorithm=HASH_ALGORITHM,
        scan_root=str(canonical_root),
        created_at_utc=created_at,
        files=tuple(sorted(baseline_files, key=lambda item: item.relative_path)),
        skipped_paths=skipped_paths,
    )


def check_baseline_compatibility(
    schema_version: object,
    hash_algorithm: object,
) -> None:
    """Raise when a schema version or hash algorithm is unsupported."""
    if type(schema_version) is not int:
        raise InvalidBaselineError("schema_version must be an integer.")
    if schema_version != SCHEMA_VERSION:
        raise UnsupportedBaselineVersionError(
            f"Unsupported baseline schema version: {schema_version}."
        )
    if not isinstance(hash_algorithm, str):
        raise InvalidBaselineError("hash_algorithm must be a string.")
    if hash_algorithm != HASH_ALGORITHM:
        raise UnsupportedBaselineVersionError(
            f"Unsupported baseline hash algorithm: {hash_algorithm}."
        )


def is_baseline_compatible(
    schema_version: object,
    hash_algorithm: object,
) -> bool:
    """Return whether the supplied baseline format is supported."""
    try:
        check_baseline_compatibility(schema_version, hash_algorithm)
    except InvalidBaselineError:
        return False
    return True


def validate_baseline_data(data: object) -> Baseline:
    """Strictly validate decoded JSON data and return typed baseline data."""
    if not isinstance(data, dict):
        raise InvalidBaselineError("The baseline document must be a JSON object.")
    if set(data) != _TOP_LEVEL_FIELDS:
        raise InvalidBaselineError("The baseline has missing or unexpected fields.")

    check_baseline_compatibility(data["schema_version"], data["hash_algorithm"])
    scan_root = _validate_scan_root(data["scan_root"])
    created_at = _parse_timestamp(data["created_at_utc"], "created_at_utc")

    skipped_value = data["skipped_paths"]
    if not isinstance(skipped_value, list):
        raise InvalidBaselineError("skipped_paths must be a JSON array.")
    skipped_paths = _validate_path_collection(
        skipped_value,
        field_name="skipped_paths",
    )

    files_value = data["files"]
    if not isinstance(files_value, list):
        raise InvalidBaselineError("files must be a JSON array.")

    files: list[BaselineFile] = []
    seen_paths: set[str] = set()
    previous_path: str | None = None
    for value in files_value:
        if not isinstance(value, dict) or set(value) != _FILE_FIELDS:
            raise InvalidBaselineError(
                "Each file must contain exactly the schema fields."
            )

        relative_path = _validate_relative_path(value["relative_path"])
        if previous_path is not None and relative_path <= previous_path:
            raise InvalidBaselineError(
                "File records must be uniquely and deterministically sorted."
            )
        previous_path = relative_path

        path_key = relative_path.casefold()
        if path_key in seen_paths:
            raise InvalidBaselineError("Duplicate file paths are not allowed.")
        seen_paths.add(path_key)

        modified_value = value["modified_at_utc"]
        modified_at = (
            None
            if modified_value is None
            else _parse_timestamp(modified_value, "modified_at_utc")
        )
        files.append(
            BaselineFile(
                relative_path=relative_path,
                sha256=_validate_sha256(value["sha256"]),
                size_bytes=_validate_size(value["size_bytes"]),
                modified_at_utc=modified_at,
            )
        )

    if _path_collections_overlap(
        (item.relative_path for item in files),
        skipped_paths,
    ):
        raise InvalidBaselineError("Scanned and skipped paths cannot overlap.")

    return Baseline(
        schema_version=SCHEMA_VERSION,
        hash_algorithm=HASH_ALGORITHM,
        scan_root=scan_root,
        created_at_utc=created_at,
        files=tuple(files),
        skipped_paths=skipped_paths,
    )


def baseline_to_json(baseline: Baseline) -> str:
    """Return a validated baseline as deterministic UTF-8 JSON text."""
    if not isinstance(baseline, Baseline):
        raise TypeError("baseline must be a Baseline instance")

    data = _baseline_to_data(baseline)
    validated = validate_baseline_data(data)
    canonical_data = _baseline_to_data(validated)
    return json.dumps(
        canonical_data,
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def save_baseline(
    baseline: Baseline,
    destination: str | PathLike[str],
) -> Path:
    """Atomically create a baseline file without replacing existing data.

    A fully flushed temporary file is created beside the destination and then
    published with an atomic hard-link operation. Hard-link creation fails if
    the destination already exists, providing race-safe no-overwrite behavior.
    """
    payload = baseline_to_json(baseline).encode("utf-8")
    if len(payload) > MAX_BASELINE_BYTES:
        raise InvalidBaselineError("The serialized baseline exceeds the size limit.")

    target = _validate_storage_destination(baseline, destination)
    temp_path: Path | None = None
    file_descriptor = -1
    operation_error: BaseException | None = None
    cleanup_error: OSError | None = None

    try:
        file_descriptor, temp_name = tempfile.mkstemp(
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
        )
        temp_path = Path(temp_name)
        with os.fdopen(file_descriptor, "wb") as temp_file:
            file_descriptor = -1
            temp_file.write(payload)
            temp_file.flush()
            os.fsync(temp_file.fileno())
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
            raise BaselineExistsError(
                "A baseline already exists at the destination."
            ) from operation_error
        if isinstance(operation_error, OSError):
            raise BaselineIOError(
                "Unable to write the baseline file."
            ) from operation_error
        raise operation_error
    if cleanup_error is not None:
        raise BaselineIOError(
            "The baseline was published, but temporary-file cleanup failed."
        ) from cleanup_error

    _fsync_directory(target.parent)
    return target


def load_baseline(
    source: str | PathLike[str],
    *,
    max_bytes: int = MAX_BASELINE_BYTES,
) -> Baseline:
    """Load and strictly validate a size-limited UTF-8 JSON baseline."""
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")

    path = Path(os.path.abspath(os.fspath(source)))
    try:
        _reject_link_components(path.parent)
        before = path.stat(follow_symlinks=False)
        if _is_link_like(before):
            raise UnsafeBaselinePathError("Baseline links are not followed.")
        if not stat.S_ISREG(before.st_mode):
            raise UnsafeBaselinePathError("The baseline source is not a regular file.")
        if before.st_size > max_bytes:
            raise InvalidBaselineError("The baseline exceeds the size limit.")
        payload = _read_limited_file(path, before, max_bytes)
    except (InvalidBaselineError, UnsafeBaselinePathError):
        raise
    except OSError as error:
        raise BaselineIOError("Unable to read the baseline file.") from error

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InvalidBaselineError("The baseline must contain valid UTF-8.") from error

    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
    except InvalidBaselineError:
        raise
    except (json.JSONDecodeError, RecursionError) as error:
        raise InvalidBaselineError("The baseline contains malformed JSON.") from error
    return validate_baseline_data(data)


def _baseline_to_data(baseline: Baseline) -> dict[str, Any]:
    return {
        "schema_version": baseline.schema_version,
        "hash_algorithm": baseline.hash_algorithm,
        "scan_root": baseline.scan_root,
        "created_at_utc": _format_timestamp(
            _validate_timestamp(baseline.created_at_utc, "created_at_utc")
        ),
        "skipped_paths": list(baseline.skipped_paths),
        "files": [
            {
                "relative_path": file.relative_path,
                "sha256": file.sha256,
                "size_bytes": file.size_bytes,
                "modified_at_utc": (
                    None
                    if file.modified_at_utc is None
                    else _format_timestamp(
                        _validate_timestamp(
                            file.modified_at_utc,
                            "modified_at_utc",
                        )
                    )
                ),
            }
            for file in baseline.files
        ],
    }


def _validate_storage_destination(
    baseline: Baseline,
    destination: str | PathLike[str],
) -> Path:
    target = Path(os.path.abspath(os.fspath(destination)))
    try:
        _reject_link_components(target.parent)
        parent = target.parent.resolve(strict=True)
        if not parent.is_dir():
            raise UnsafeBaselinePathError(
                "The baseline destination parent is not a directory."
            )

        monitored_root = Path(baseline.scan_root).resolve(strict=True)
        if not monitored_root.is_dir():
            raise UnsafeBaselinePathError("The monitored root is unavailable.")
    except UnsafeBaselinePathError:
        raise
    except OSError as error:
        raise BaselineIOError("Unable to inspect the baseline destination.") from error

    target = parent / target.name
    if _is_within(target, monitored_root):
        raise UnsafeBaselinePathError(
            "A baseline cannot be stored inside the monitored directory."
        )

    try:
        destination_info = target.stat(follow_symlinks=False)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise BaselineIOError("Unable to inspect the baseline destination.") from error
    else:
        if _is_link_like(destination_info):
            raise UnsafeBaselinePathError("A link cannot be used as a destination.")
        raise BaselineExistsError("A baseline already exists at the destination.")

    return target


def _read_limited_file(
    path: Path,
    before: os.stat_result,
    max_bytes: int,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_descriptor = os.open(path, flags)
    try:
        opened = os.fstat(file_descriptor)
        if not stat.S_ISREG(opened.st_mode) or _identity_changed(before, opened):
            raise UnsafeBaselinePathError("The baseline source changed while opening.")
        with os.fdopen(file_descriptor, "rb") as baseline_file:
            file_descriptor = -1
            payload = baseline_file.read(max_bytes + 1)
        if len(payload) > max_bytes:
            raise InvalidBaselineError("The baseline exceeds the size limit.")
        after = path.stat(follow_symlinks=False)
        if _is_link_like(after) or _identity_changed(opened, after):
            raise UnsafeBaselinePathError("The baseline source changed while reading.")
        return payload
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)


def _validate_scan_root(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise InvalidBaselineError("scan_root must be a nonempty path string.")
    path = Path(value)
    if not path.is_absolute() or os.path.normpath(value) != value:
        raise InvalidBaselineError("scan_root must be a canonical absolute path.")
    return value


def _validate_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise InvalidBaselineError("Relative paths must be nonempty strings.")
    if "\\" in value or PurePosixPath(value).is_absolute():
        raise InvalidBaselineError("Relative paths must use forward slashes.")
    windows_path = PureWindowsPath(value)
    if windows_path.is_absolute() or windows_path.drive:
        raise InvalidBaselineError("Absolute file paths are not allowed.")

    components = value.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise InvalidBaselineError("Relative paths contain an unsafe component.")
    if any(any(ord(character) < 32 for character in item) for item in components):
        raise InvalidBaselineError("Relative paths contain control characters.")
    if any(item.endswith((" ", ".")) or ":" in item for item in components):
        raise InvalidBaselineError("Relative paths are not safe Windows names.")
    if PurePosixPath(value).as_posix() != value:
        raise InvalidBaselineError("Relative paths must already be normalized.")
    return value


def _validate_path_collection(
    values: list[object],
    *,
    field_name: str,
) -> tuple[str, ...]:
    validated = tuple(_validate_relative_path(value) for value in values)
    if list(validated) != sorted(validated):
        raise InvalidBaselineError(f"{field_name} must be deterministically sorted.")
    if len({value.casefold() for value in validated}) != len(validated):
        raise InvalidBaselineError(f"{field_name} must not contain duplicates.")
    return validated


def _validate_sha256(value: object) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise InvalidBaselineError("File hashes must be lowercase SHA-256 digests.")
    return value


def _validate_size(value: object) -> int:
    if type(value) is not int or value < 0:
        raise InvalidBaselineError("File sizes must be nonnegative integers.")
    return value


def _validate_optional_timestamp(value: object) -> datetime | None:
    if value is None:
        return None
    return _validate_timestamp(value, "modified_at_utc")


def _validate_timestamp(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise InvalidBaselineError(f"{field_name} must be a datetime.")
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise InvalidBaselineError(f"{field_name} must be timezone-aware UTC.")
    return value.astimezone(timezone.utc)


def _parse_timestamp(value: object, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise InvalidBaselineError(f"{field_name} must be an ISO 8601 UTC timestamp.")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise InvalidBaselineError(
            f"{field_name} must be an ISO 8601 UTC timestamp."
        ) from error
    return _validate_timestamp(parsed, field_name)


def _format_timestamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidBaselineError("Duplicate JSON object fields are not allowed.")
        result[key] = value
    return result


def _reject_link_components(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            file_info = current.stat(follow_symlinks=False)
        except OSError as error:
            raise BaselineIOError(
                "Unable to inspect a storage path component."
            ) from error
        if _is_link_like(file_info):
            raise UnsafeBaselinePathError(
                "Storage paths containing links or reparse points are not allowed."
            )


def _is_link_like(file_info: os.stat_result) -> bool:
    attributes = getattr(file_info, "st_file_attributes", 0)
    return stat.S_ISLNK(file_info.st_mode) or bool(
        attributes & _WINDOWS_REPARSE_POINT
    )


def _identity_changed(before: os.stat_result, after: os.stat_result) -> bool:
    if before.st_ino == 0 or after.st_ino == 0:
        return False
    return (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)


def _path_collections_overlap(
    file_paths: Iterable[str],
    skipped_paths: tuple[str, ...],
) -> bool:
    files = tuple(path.casefold() for path in file_paths)
    skipped = tuple(path.casefold() for path in skipped_paths)
    return any(
        file_path == skipped_path
        or file_path.startswith(skipped_path + "/")
        or skipped_path.startswith(file_path + "/")
        for file_path in files
        for skipped_path in skipped
    )


def _is_within(candidate: Path, directory: Path) -> bool:
    candidate_value = os.path.normcase(os.path.abspath(candidate))
    directory_value = os.path.normcase(os.path.abspath(directory))
    try:
        return os.path.commonpath([candidate_value, directory_value]) == directory_value
    except ValueError:
        return False


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    try:
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise BaselineIOError("Unable to flush the baseline directory.") from error
