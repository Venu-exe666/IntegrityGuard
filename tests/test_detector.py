"""Tests for conservative, read-only file integrity change detection."""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from integrityguard.baseline import Baseline, create_baseline
from integrityguard.detector import (
    ChangeStatus,
    IncompatibleBaselineError,
    RootMismatchError,
    UnexpectedScannerStateError,
    UnknownReason,
    compare_baseline,
)
from integrityguard.scanner import (
    FileScanResult,
    ScanError,
    ScanErrorKind,
    ScanReport,
    ScanStatus,
    scan_directory,
)


def _baseline_for_files(
    tmp_path: Path,
    files: dict[str, bytes],
) -> tuple[Path, Baseline]:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    for relative_path, content in files.items():
        target = monitored / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return monitored, create_baseline(scan_directory(monitored))


def _replace_file_result(
    report: ScanReport,
    relative_path: str,
    **changes: object,
) -> ScanReport:
    files = tuple(
        replace(item, **changes) if item.relative_path == relative_path else item
        for item in report.files
    )
    return replace(report, files=files)


def test_identical_baseline_and_scan_are_unchanged(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {"file.txt": b"same"})

    report = compare_baseline(baseline, scan_directory(monitored))

    assert [item.relative_path for item in report.unchanged] == ["file.txt"]
    assert report.counts.unchanged == 1
    assert report.is_clean
    assert report.assessment_conclusive


def test_single_added_file(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {"old.txt": b"old"})
    (monitored / "new.txt").write_bytes(b"new")

    report = compare_baseline(baseline, scan_directory(monitored))

    assert [item.relative_path for item in report.added] == ["new.txt"]
    assert report.added[0].previous_sha256 is None
    assert report.added[0].current_sha256 is not None


def test_single_deleted_file(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {"deleted.txt": b"old"})
    (monitored / "deleted.txt").unlink()

    report = compare_baseline(baseline, scan_directory(monitored))

    assert [item.relative_path for item in report.deleted] == ["deleted.txt"]
    assert report.deleted[0].current_sha256 is None


def test_single_modified_file(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {"changed.txt": b"before"})
    (monitored / "changed.txt").write_bytes(b"after")

    report = compare_baseline(baseline, scan_directory(monitored))

    assert [item.relative_path for item in report.modified] == ["changed.txt"]
    assert report.modified[0].previous_sha256 != report.modified[0].current_sha256


def test_multiple_simultaneous_changes(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(
        tmp_path,
        {
            "delete.txt": b"delete",
            "modify.txt": b"before",
            "same.txt": b"same",
        },
    )
    (monitored / "delete.txt").unlink()
    (monitored / "modify.txt").write_bytes(b"after")
    (monitored / "add.txt").write_bytes(b"added")

    report = compare_baseline(baseline, scan_directory(monitored))

    assert report.counts.added == 1
    assert report.counts.deleted == 1
    assert report.counts.modified == 1
    assert report.counts.unchanged == 1
    assert report.has_confirmed_changes


def test_empty_baseline_and_empty_scan(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {})

    report = compare_baseline(baseline, scan_directory(monitored))

    assert report.counts.total == 0
    assert report.scan_complete
    assert report.is_clean


def test_empty_baseline_with_added_files(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {})
    (monitored / "one.txt").write_bytes(b"one")
    (monitored / "two.txt").write_bytes(b"two")

    report = compare_baseline(baseline, scan_directory(monitored))

    assert [item.relative_path for item in report.added] == ["one.txt", "two.txt"]


def test_all_previously_monitored_files_deleted(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(
        tmp_path,
        {"one.txt": b"one", "two.txt": b"two"},
    )
    (monitored / "one.txt").unlink()
    (monitored / "two.txt").unlink()

    report = compare_baseline(baseline, scan_directory(monitored))

    assert [item.relative_path for item in report.deleted] == ["one.txt", "two.txt"]
    assert report.counts.deleted == 2


def test_nested_folder_file(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(
        tmp_path,
        {"first/second/deep.txt": b"before"},
    )
    (monitored / "first" / "second" / "deep.txt").write_bytes(b"after")

    report = compare_baseline(baseline, scan_directory(monitored))

    assert report.modified[0].relative_path == "first/second/deep.txt"


@pytest.mark.parametrize(
    "filename",
    ["evidence-整合性-U0001f512.txt", "incident evidence 01.txt"],
)
def test_unicode_and_space_filenames(tmp_path: Path, filename: str) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {filename: b"before"})
    (monitored / filename).write_bytes(b"after")

    report = compare_baseline(baseline, scan_directory(monitored))

    assert report.modified[0].relative_path == filename


def test_report_order_is_deterministic_for_unsorted_input(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {})
    report = scan_directory(monitored)
    files = tuple(
        FileScanResult(
            relative_path=path,
            sha256=character * 64,
            size_bytes=1,
            modified_at_utc=None,
            status=ScanStatus.SCANNED,
        )
        for path, character in [("z.txt", "a"), ("a.txt", "b"), ("m.txt", "c")]
    )

    first = compare_baseline(baseline, replace(report, files=files))
    second = compare_baseline(baseline, replace(report, files=tuple(reversed(files))))

    expected = ["a.txt", "m.txt", "z.txt"]
    assert [item.relative_path for item in first.added] == expected
    assert first == second


def test_same_hash_with_different_timestamp_is_unchanged(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {"file.txt": b"same"})
    scan = scan_directory(monitored)
    new_time = scan.files[0].modified_at_utc + timedelta(seconds=10)
    scan = _replace_file_result(scan, "file.txt", modified_at_utc=new_time)

    report = compare_baseline(baseline, scan)

    assert report.unchanged[0].status is ChangeStatus.UNCHANGED
    assert report.unchanged[0].metadata_changed


def test_same_size_with_different_hash_is_modified(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {"file.txt": b"aaaa"})
    (monitored / "file.txt").write_bytes(b"bbbb")

    report = compare_baseline(baseline, scan_directory(monitored))

    assert (
        report.modified[0].previous_size_bytes
        == report.modified[0].current_size_bytes
    )


def test_different_size_with_identical_hash_is_unchanged(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {"file.txt": b"same"})
    scan = scan_directory(monitored)
    scan = _replace_file_result(scan, "file.txt", size_bytes=999)

    report = compare_baseline(baseline, scan)

    assert report.unchanged[0].status is ChangeStatus.UNCHANGED
    assert report.unchanged[0].metadata_changed


def test_missing_digest_is_unknown(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {"file.txt": b"content"})
    scan = _replace_file_result(scan_directory(monitored), "file.txt", sha256=None)

    report = compare_baseline(baseline, scan)

    assert report.unknown[0].unknown_reason is UnknownReason.UNTRUSTED_RESULT
    assert not report.scan_complete


def test_file_changed_during_scan_is_unknown(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {"file.txt": b"content"})
    scan = scan_directory(monitored)
    scan = _replace_file_result(
        scan,
        "file.txt",
        sha256=None,
        status=ScanStatus.CHANGED_DURING_SCAN,
    )
    error = ScanError(
        relative_path="file.txt",
        kind=ScanErrorKind.FILE_CHANGED,
        message="changed during scan",
    )

    report = compare_baseline(baseline, replace(scan, errors=(error,)))

    assert report.unknown[0].unknown_reason is UnknownReason.UNTRUSTED_RESULT
    assert report.scan_errors == (error,)


@pytest.mark.parametrize(
    ("kind", "exception_type"),
    [
        (ScanErrorKind.FILE_ACCESS, "PermissionError"),
        (ScanErrorKind.FILE_ACCESS, "FileNotFoundError"),
    ],
)
def test_file_read_failures_are_unknown(
    tmp_path: Path,
    kind: ScanErrorKind,
    exception_type: str,
) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {"file.txt": b"content"})
    scan = _replace_file_result(
        scan_directory(monitored),
        "file.txt",
        sha256=None,
        status=ScanStatus.ERROR,
    )
    error = ScanError(
        relative_path="file.txt",
        kind=kind,
        message="read failed",
        exception_type=exception_type,
    )

    report = compare_baseline(baseline, replace(scan, errors=(error,)))

    assert report.unknown[0].status is ChangeStatus.UNKNOWN
    assert report.deleted == ()
    assert report.scan_errors[0].exception_type == exception_type


def test_directory_traversal_error_makes_subtree_unknown(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(
        tmp_path,
        {"blocked/deep.txt": b"content"},
    )
    error = ScanError(
        relative_path="blocked",
        kind=ScanErrorKind.DIRECTORY_ACCESS,
        message="access denied",
        exception_type="PermissionError",
    )
    partial_scan = ScanReport(
        root=monitored.resolve(),
        files=(),
        errors=(error,),
        skipped_paths=(),
    )

    report = compare_baseline(baseline, partial_scan)

    assert report.unknown[0].relative_path == "blocked/deep.txt"
    assert report.unknown[0].unknown_reason is UnknownReason.SCAN_ERROR
    assert report.deleted == ()


def test_skipped_subtree_does_not_create_false_deletion(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(
        tmp_path,
        {"linked/file.txt": b"content"},
    )
    partial_scan = ScanReport(
        root=monitored.resolve(),
        files=(),
        errors=(),
        skipped_paths=("linked",),
    )

    report = compare_baseline(baseline, partial_scan)

    assert report.unknown[0].unknown_reason is UnknownReason.SKIPPED_PATH
    assert not report.scan_complete
    assert not report.assessment_conclusive


def test_regular_file_replaced_by_link_is_unknown(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {"file.txt": b"content"})
    simulated_link_scan = ScanReport(
        root=monitored.resolve(),
        files=(),
        errors=(),
        skipped_paths=("file.txt",),
    )

    report = compare_baseline(baseline, simulated_link_scan)

    assert report.unknown[0].relative_path == "file.txt"
    assert report.unknown[0].unknown_reason is UnknownReason.SKIPPED_PATH
    assert report.deleted == ()


def test_invalid_or_unsupported_baseline_is_rejected(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {})
    invalid = replace(baseline, schema_version=99)

    with pytest.raises(IncompatibleBaselineError):
        compare_baseline(invalid, scan_directory(monitored))


def test_baseline_and_scan_root_mismatch_is_rejected(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {})
    other = tmp_path / "other"
    other.mkdir()

    with pytest.raises(RootMismatchError):
        compare_baseline(baseline, scan_directory(other))


@pytest.mark.skipif(os.name != "nt", reason="Windows path semantics test")
def test_windows_root_comparison_is_case_insensitive(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {"file.txt": b"content"})
    scan = scan_directory(monitored)
    case_alias = Path(str(scan.root).swapcase())

    report = compare_baseline(baseline, replace(scan, root=case_alias))

    assert report.counts.unchanged == 1


def test_baseline_and_scan_report_remain_immutable(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {"file.txt": b"content"})
    scan = scan_directory(monitored)
    original_baseline = baseline
    original_scan = scan

    compare_baseline(baseline, scan)

    assert baseline == original_baseline
    assert scan == original_scan
    with pytest.raises(AttributeError):
        baseline.scan_root = "changed"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        scan.root = Path("changed")  # type: ignore[misc]


def test_comparison_performs_no_filesystem_writes(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {"file.txt": b"content"})
    scan = scan_directory(monitored)
    before_names = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))
    target = monitored / "file.txt"
    before_content = target.read_bytes()
    before_metadata = target.stat()

    compare_baseline(baseline, scan)

    after_names = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))
    after_metadata = target.stat()
    assert after_names == before_names
    assert target.read_bytes() == before_content
    assert after_metadata.st_mtime_ns == before_metadata.st_mtime_ns


def test_scan_errors_do_not_become_false_deletions(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(
        tmp_path,
        {"blocked/one.txt": b"one", "blocked/two.txt": b"two"},
    )
    error = ScanError(
        relative_path="blocked",
        kind=ScanErrorKind.ENTRY_INSPECTION,
        message="inspection failed",
    )
    partial_scan = ScanReport(monitored.resolve(), (), (error,), ())

    report = compare_baseline(baseline, partial_scan)

    assert report.deleted == ()
    assert [item.relative_path for item in report.unknown] == [
        "blocked/one.txt",
        "blocked/two.txt",
    ]


def test_aggregate_completeness_and_counts(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(
        tmp_path,
        {"same.txt": b"same", "unknown.txt": b"unknown"},
    )
    scan = _replace_file_result(
        scan_directory(monitored),
        "unknown.txt",
        sha256=None,
        status=ScanStatus.ERROR,
    )
    error = ScanError(
        relative_path="unknown.txt",
        kind=ScanErrorKind.FILE_ACCESS,
        message="failed",
    )

    report = compare_baseline(baseline, replace(scan, errors=(error,)))

    assert report.counts.unchanged == 1
    assert report.counts.unknown == 1
    assert report.counts.total == 2
    assert not report.scan_complete
    assert not report.assessment_conclusive
    assert not report.is_clean


def test_unexpected_scanner_status_is_rejected(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {"file.txt": b"content"})
    scan = scan_directory(monitored)
    invalid_file = replace(scan.files[0], status="mystery")  # type: ignore[arg-type]

    with pytest.raises(UnexpectedScannerStateError):
        compare_baseline(baseline, replace(scan, files=(invalid_file,)))


def test_baseline_skipped_scope_prevents_conclusive_claim(tmp_path: Path) -> None:
    monitored, baseline = _baseline_for_files(tmp_path, {})
    baseline = replace(baseline, skipped_paths=("external-link",))

    report = compare_baseline(baseline, scan_directory(monitored))

    assert report.scan_complete
    assert not report.assessment_conclusive
    assert not report.is_clean
