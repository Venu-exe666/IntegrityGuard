"""Tests for secure, versioned IntegrityGuard baseline management."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

import integrityguard.baseline as baseline_module
from integrityguard.baseline import (
    Baseline,
    BaselineExistsError,
    BaselineIOError,
    IncompleteScanError,
    InvalidBaselineError,
    UnsupportedBaselineVersionError,
    UnsafeBaselinePathError,
    baseline_to_json,
    check_baseline_compatibility,
    create_baseline,
    is_baseline_compatible,
    load_baseline,
    save_baseline,
)
from integrityguard.scanner import (
    FileScanResult,
    ScanError,
    ScanErrorKind,
    ScanReport,
    ScanStatus,
    scan_directory,
)

_CREATED_AT = datetime(2026, 10, 24, 12, 30, 45, 123456, tzinfo=timezone.utc)


def _scan_and_create(monitored: Path) -> Baseline:
    return create_baseline(scan_directory(monitored), created_at_utc=_CREATED_AT)


def _valid_data(monitored: Path) -> dict[str, object]:
    monitored.mkdir(exist_ok=True)
    (monitored / "file.txt").write_bytes(b"content")
    return json.loads(baseline_to_json(_scan_and_create(monitored)))


def _write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def test_valid_baseline_creation(tmp_path: Path) -> None:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    (monitored / "evidence.txt").write_bytes(b"evidence")

    baseline = _scan_and_create(monitored)

    assert baseline.schema_version == 1
    assert baseline.hash_algorithm == "sha256"
    assert baseline.scan_root == str(monitored.resolve())
    assert baseline.created_at_utc == _CREATED_AT
    assert baseline.files[0].relative_path == "evidence.txt"


def test_json_save_and_load_round_trip(tmp_path: Path) -> None:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    (monitored / "evidence.txt").write_bytes(b"evidence")
    baseline = _scan_and_create(monitored)
    destination = tmp_path / "baseline.json"

    saved_path = save_baseline(baseline, destination)

    assert saved_path == destination.resolve()
    assert load_baseline(destination) == baseline


def test_json_serialization_is_deterministic(tmp_path: Path) -> None:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    (monitored / "z.txt").write_bytes(b"z")
    (monitored / "a.txt").write_bytes(b"a")
    first = _scan_and_create(monitored)
    second = _scan_and_create(monitored)

    first_json = baseline_to_json(first)
    second_json = baseline_to_json(second)

    assert first_json == second_json
    assert first_json.endswith("\n")
    assert [item.relative_path for item in first.files] == ["a.txt", "z.txt"]


def test_empty_directory_baseline(tmp_path: Path) -> None:
    monitored = tmp_path / "empty"
    monitored.mkdir()

    baseline = _scan_and_create(monitored)

    assert baseline.files == ()
    assert load_baseline(save_baseline(baseline, tmp_path / "empty.json")) == baseline


def test_nested_file_records(tmp_path: Path) -> None:
    monitored = tmp_path / "monitored"
    nested = monitored / "one" / "two"
    nested.mkdir(parents=True)
    (nested / "deep.txt").write_bytes(b"deep")

    baseline = _scan_and_create(monitored)

    assert [item.relative_path for item in baseline.files] == ["one/two/deep.txt"]


def test_unicode_paths_round_trip(tmp_path: Path) -> None:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    filename = "integrity-整合性-U0001f512.txt"
    (monitored / filename).write_bytes(b"unicode")
    baseline = _scan_and_create(monitored)

    loaded = load_baseline(save_baseline(baseline, tmp_path / "unicode.json"))

    assert loaded.files[0].relative_path == filename


def test_sha256_and_utc_timestamp_are_preserved(tmp_path: Path) -> None:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    (monitored / "file.txt").write_bytes(b"content")
    baseline = _scan_and_create(monitored)

    loaded = load_baseline(save_baseline(baseline, tmp_path / "baseline.json"))

    assert loaded.files[0].sha256 == baseline.files[0].sha256
    assert loaded.files[0].modified_at_utc == baseline.files[0].modified_at_utc
    assert loaded.created_at_utc == _CREATED_AT
    assert loaded.created_at_utc.tzinfo is timezone.utc


def test_duplicate_file_entries_are_rejected(tmp_path: Path) -> None:
    data = _valid_data(tmp_path / "monitored")
    files = data["files"]
    assert isinstance(files, list)
    files.append(dict(files[0]))

    with pytest.raises(InvalidBaselineError, match="sorted"):
        baseline_module.validate_baseline_data(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sha256", "not-a-sha256-hash"),
        ("size_bytes", -1),
        ("modified_at_utc", "2026-10-24T12:30:45+05:30"),
    ],
)
def test_invalid_file_values_are_rejected(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    data = _valid_data(tmp_path / "monitored")
    files = data["files"]
    assert isinstance(files, list)
    files[0][field] = value

    with pytest.raises(InvalidBaselineError):
        baseline_module.validate_baseline_data(data)


def test_unsupported_schema_version_is_rejected(tmp_path: Path) -> None:
    data = _valid_data(tmp_path / "monitored")
    data["schema_version"] = 99

    with pytest.raises(UnsupportedBaselineVersionError):
        baseline_module.validate_baseline_data(data)
    assert not is_baseline_compatible(99, "sha256")
    with pytest.raises(UnsupportedBaselineVersionError):
        check_baseline_compatibility(99, "sha256")


def test_unsupported_hash_algorithm_is_rejected(tmp_path: Path) -> None:
    data = _valid_data(tmp_path / "monitored")
    data["hash_algorithm"] = "md5"

    with pytest.raises(UnsupportedBaselineVersionError):
        baseline_module.validate_baseline_data(data)
    assert not is_baseline_compatible(1, "md5")


def test_malformed_json_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "malformed.json"
    source.write_text('{"schema_version": ', encoding="utf-8")

    with pytest.raises(InvalidBaselineError, match="malformed JSON"):
        load_baseline(source)


@pytest.mark.parametrize(
    "unsafe_path",
    ["../secret.txt", "folder/../../secret.txt", "folder\\secret.txt"],
)
def test_path_traversal_and_backslashes_are_rejected(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    data = _valid_data(tmp_path / "monitored")
    files = data["files"]
    assert isinstance(files, list)
    files[0]["relative_path"] = unsafe_path

    with pytest.raises(InvalidBaselineError):
        baseline_module.validate_baseline_data(data)


def test_absolute_file_entry_is_rejected(tmp_path: Path) -> None:
    data = _valid_data(tmp_path / "monitored")
    files = data["files"]
    assert isinstance(files, list)
    files[0]["relative_path"] = "C:/Windows/System32/file.dll"

    with pytest.raises(InvalidBaselineError, match="Absolute"):
        baseline_module.validate_baseline_data(data)


def test_existing_baseline_is_never_overwritten(tmp_path: Path) -> None:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    (monitored / "file.txt").write_bytes(b"first")
    baseline = _scan_and_create(monitored)
    destination = tmp_path / "baseline.json"
    save_baseline(baseline, destination)
    original_bytes = destination.read_bytes()

    with pytest.raises(BaselineExistsError):
        save_baseline(baseline, destination)

    assert destination.read_bytes() == original_bytes


def test_incomplete_file_result_is_rejected(tmp_path: Path) -> None:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    report = ScanReport(
        root=monitored,
        files=(
            FileScanResult(
                relative_path="failed.txt",
                sha256=None,
                size_bytes=10,
                modified_at_utc=None,
                status=ScanStatus.ERROR,
            ),
        ),
        errors=(),
        skipped_paths=(),
    )

    with pytest.raises(IncompleteScanError):
        create_baseline(report)


def test_scan_with_errors_is_rejected(tmp_path: Path) -> None:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    report = ScanReport(
        root=monitored,
        files=(),
        errors=(
            ScanError(
                relative_path="file.txt",
                kind=ScanErrorKind.FILE_ACCESS,
                message="read failed",
            ),
        ),
        skipped_paths=(),
    )

    with pytest.raises(IncompleteScanError, match="errors"):
        create_baseline(report)


def test_baseline_inside_monitored_directory_is_rejected(tmp_path: Path) -> None:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    baseline = _scan_and_create(monitored)

    with pytest.raises(UnsafeBaselinePathError, match="inside"):
        save_baseline(baseline, monitored / "baseline.json")


def test_symlink_destination_is_rejected_where_supported(tmp_path: Path) -> None:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    baseline = _scan_and_create(monitored)
    target = tmp_path / "real.json"
    target.write_text("unchanged", encoding="utf-8")
    link = tmp_path / "baseline-link.json"
    try:
        link.symlink_to(target)
    except OSError as error:
        pytest.skip(f"Symbolic links are unavailable in this environment: {error}")

    with pytest.raises(UnsafeBaselinePathError):
        save_baseline(baseline, link)
    assert target.read_text(encoding="utf-8") == "unchanged"


def test_temporary_file_is_cleaned_after_publication_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    baseline = _scan_and_create(monitored)
    destination = tmp_path / "baseline.json"

    def fail_publication(source: Path, target: Path) -> None:
        raise OSError("simulated publication failure")

    monkeypatch.setattr(baseline_module.os, "link", fail_publication)

    with pytest.raises(BaselineIOError):
        save_baseline(baseline, destination)

    assert not destination.exists()
    assert list(tmp_path.glob(".baseline.json.*.tmp")) == []


def test_permission_failure_has_typed_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    baseline = _scan_and_create(monitored)

    def deny_temp_creation(**kwargs: object) -> tuple[int, str]:
        raise PermissionError("simulated access denial")

    monkeypatch.setattr(baseline_module.tempfile, "mkstemp", deny_temp_creation)

    with pytest.raises(BaselineIOError) as captured:
        save_baseline(baseline, tmp_path / "baseline.json")

    assert isinstance(captured.value.__cause__, PermissionError)


def test_baseline_save_does_not_modify_monitored_files(tmp_path: Path) -> None:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    target = monitored / "preserve.bin"
    target.write_bytes(b"do not modify")
    baseline = _scan_and_create(monitored)
    before_content = target.read_bytes()
    before_metadata = target.stat()

    save_baseline(baseline, tmp_path / "baseline.json")
    after_metadata = target.stat()

    assert target.read_bytes() == before_content
    assert after_metadata.st_size == before_metadata.st_size
    assert after_metadata.st_mtime_ns == before_metadata.st_mtime_ns


def test_skipped_paths_are_preserved_for_auditability(tmp_path: Path) -> None:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    report = replace(scan_directory(monitored), skipped_paths=("linked-folder",))

    baseline = create_baseline(report, created_at_utc=_CREATED_AT)
    loaded = load_baseline(save_baseline(baseline, tmp_path / "baseline.json"))

    assert loaded.skipped_paths == ("linked-folder",)


def test_skipped_paths_cannot_overlap_file_records(tmp_path: Path) -> None:
    data = _valid_data(tmp_path / "monitored")
    data["skipped_paths"] = ["file.txt/linked-child"]

    with pytest.raises(InvalidBaselineError, match="overlap"):
        baseline_module.validate_baseline_data(data)


def test_duplicate_json_object_keys_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "duplicate-key.json"
    source.write_text(
        '{"schema_version":1,"schema_version":1}',
        encoding="utf-8",
    )

    with pytest.raises(InvalidBaselineError, match="Duplicate JSON"):
        load_baseline(source)


def test_size_limit_is_enforced_before_json_parsing(tmp_path: Path) -> None:
    source = tmp_path / "oversized.json"
    source.write_bytes(b"{}" + b" " * 20)

    with pytest.raises(InvalidBaselineError, match="size limit"):
        load_baseline(source, max_bytes=10)


def test_unexpected_schema_fields_are_rejected(tmp_path: Path) -> None:
    data = _valid_data(tmp_path / "monitored")
    data["unexpected"] = True

    with pytest.raises(InvalidBaselineError, match="unexpected"):
        baseline_module.validate_baseline_data(data)
