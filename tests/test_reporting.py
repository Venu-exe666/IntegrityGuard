"""Tests for versioned security report serialization and presentation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import integrityguard.reporting as reporting_module
from integrityguard.baseline import create_baseline
from integrityguard.detector import compare_baseline
from integrityguard.reporting import (
    AssessmentStatus,
    InvalidReportError,
    ReportExistsError,
    ReportIOError,
    UnsupportedReportVersionError,
    UnsafeReportPathError,
    create_security_report,
    format_report,
    load_report,
    report_to_json,
    save_report,
    validate_report_data,
)
from integrityguard.scanner import (
    ScanError,
    ScanErrorKind,
    ScanReport,
    scan_directory,
)

_GENERATED_AT = datetime(2026, 10, 24, 15, 0, 0, tzinfo=timezone.utc)


def _change_report(tmp_path: Path, files: dict[str, bytes] | None = None):
    monitored = tmp_path / "monitored"
    monitored.mkdir(parents=True)
    for relative_path, content in (files or {"file.txt": b"content"}).items():
        target = monitored / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    baseline = create_baseline(scan_directory(monitored))
    return monitored, baseline, compare_baseline(baseline, scan_directory(monitored))


def test_report_json_is_valid_deterministic_and_omits_absolute_roots(
    tmp_path: Path,
) -> None:
    monitored, _, changes = _change_report(tmp_path)
    report = create_security_report(changes, generated_at_utc=_GENERATED_AT)

    first = report_to_json(report)
    second = report_to_json(report)
    decoded = json.loads(first)

    assert first == second
    assert decoded["report_schema_version"] == 1
    assert decoded["assessment_status"] == "clean"
    assert str(monitored.resolve()) not in first
    assert "file contents" not in first


def test_json_round_trip_preserves_report(tmp_path: Path) -> None:
    monitored, _, changes = _change_report(
        tmp_path,
        {"nested/integrity-整合性-U0001f512.txt": b"content"},
    )
    report = create_security_report(changes, generated_at_utc=_GENERATED_AT)
    destination = tmp_path / "report.json"

    saved = save_report(report, destination, monitored_root=monitored)
    loaded = load_report(saved)

    assert loaded == report
    assert loaded.unchanged[0].relative_path.endswith("-U0001f512.txt")


def test_report_contains_confirmed_change_metadata(tmp_path: Path) -> None:
    monitored, baseline, _ = _change_report(tmp_path)
    (monitored / "file.txt").write_bytes(b"different")
    changes = compare_baseline(baseline, scan_directory(monitored))

    data = json.loads(
        report_to_json(create_security_report(changes, generated_at_utc=_GENERATED_AT))
    )
    modified = data["file_changes"]["modified"][0]

    assert modified["relative_path"] == "file.txt"
    assert modified["previous_sha256"] != modified["current_sha256"]
    assert "previous_size_bytes" in modified
    assert "current_modified_at_utc" in modified


def test_structured_scan_issue_is_sanitized(tmp_path: Path) -> None:
    monitored, baseline, _ = _change_report(tmp_path)
    error = ScanError(
        relative_path="file.txt",
        kind=ScanErrorKind.FILE_ACCESS,
        message="sensitive absolute path details",
        exception_type="PermissionError",
    )
    partial = ScanReport(monitored.resolve(), (), (error,), ())
    changes = compare_baseline(baseline, partial)

    text = report_to_json(
        create_security_report(changes, generated_at_utc=_GENERATED_AT)
    )
    data = json.loads(text)

    assert data["scan_issues"][0] == {
        "exception_type": "PermissionError",
        "kind": "file_access",
        "relative_path": "file.txt",
    }
    assert "sensitive absolute path details" not in text


def test_report_rejects_terminal_control_data_in_exception_type(
    tmp_path: Path,
) -> None:
    monitored, baseline, _ = _change_report(tmp_path)
    error = ScanError(
        relative_path="file.txt",
        kind=ScanErrorKind.FILE_ACCESS,
        message="not exported",
        exception_type="PermissionError",
    )
    partial = ScanReport(monitored.resolve(), (), (error,), ())
    changes = compare_baseline(baseline, partial)
    report = create_security_report(changes, generated_at_utc=_GENERATED_AT)
    data = json.loads(report_to_json(report))
    data["scan_issues"][0]["exception_type"] = "Error\nforged output"

    with pytest.raises(InvalidReportError, match="exception_type"):
        validate_report_data(data)


def test_unknown_record_rejects_claimed_current_hash(tmp_path: Path) -> None:
    monitored, baseline, _ = _change_report(tmp_path)
    error = ScanError(
        relative_path="file.txt",
        kind=ScanErrorKind.FILE_ACCESS,
        message="not exported",
        exception_type="PermissionError",
    )
    partial = ScanReport(monitored.resolve(), (), (error,), ())
    changes = compare_baseline(baseline, partial)
    report = create_security_report(changes, generated_at_utc=_GENERATED_AT)
    data = json.loads(report_to_json(report))
    data["file_changes"]["unknown"][0]["current_sha256"] = "a" * 64

    with pytest.raises(InvalidReportError, match="trusted hash"):
        validate_report_data(data)


def test_malformed_and_unsupported_reports_are_rejected(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"report_schema_version":', encoding="utf-8")

    with pytest.raises(InvalidReportError, match="malformed"):
        load_report(malformed)

    monitored, _, changes = _change_report(tmp_path / "valid")
    report = create_security_report(changes, generated_at_utc=_GENERATED_AT)
    data = json.loads(report_to_json(report))
    data["report_schema_version"] = 99

    with pytest.raises(UnsupportedReportVersionError):
        validate_report_data(data)


def test_report_count_mismatch_is_rejected(tmp_path: Path) -> None:
    _, _, changes = _change_report(tmp_path)
    report = create_security_report(changes, generated_at_utc=_GENERATED_AT)
    data = json.loads(report_to_json(report))
    data["counts"]["unchanged"] = 999

    with pytest.raises(InvalidReportError, match="counts"):
        validate_report_data(data)


def test_existing_report_is_not_overwritten(tmp_path: Path) -> None:
    monitored, _, changes = _change_report(tmp_path)
    report = create_security_report(changes, generated_at_utc=_GENERATED_AT)
    destination = tmp_path / "report.json"
    save_report(report, destination, monitored_root=monitored)
    original = destination.read_bytes()

    with pytest.raises(ReportExistsError):
        save_report(report, destination, monitored_root=monitored)

    assert destination.read_bytes() == original


def test_report_inside_monitored_root_is_rejected(tmp_path: Path) -> None:
    monitored, _, changes = _change_report(tmp_path)
    report = create_security_report(changes, generated_at_utc=_GENERATED_AT)

    with pytest.raises(UnsafeReportPathError, match="inside"):
        save_report(report, monitored / "report.json", monitored_root=monitored)


def test_report_temporary_file_cleanup_after_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monitored, _, changes = _change_report(tmp_path)
    report = create_security_report(changes, generated_at_utc=_GENERATED_AT)
    destination = tmp_path / "report.json"

    def fail_link(source: Path, target: Path) -> None:
        raise OSError("simulated publication failure")

    monkeypatch.setattr(reporting_module.os, "link", fail_link)

    with pytest.raises(ReportIOError):
        save_report(report, destination, monitored_root=monitored)

    assert not destination.exists()
    assert list(tmp_path.glob(".report.json.*.tmp")) == []


def test_report_save_does_not_modify_monitored_files(tmp_path: Path) -> None:
    monitored, _, changes = _change_report(tmp_path)
    target = monitored / "file.txt"
    before = target.read_bytes(), target.stat().st_mtime_ns
    report = create_security_report(changes, generated_at_utc=_GENERATED_AT)

    save_report(report, tmp_path / "report.json", monitored_root=monitored)

    assert (target.read_bytes(), target.stat().st_mtime_ns) == before


def test_human_report_has_required_sections(tmp_path: Path) -> None:
    _, _, changes = _change_report(tmp_path)
    report = create_security_report(changes, generated_at_utc=_GENERATED_AT)

    output = format_report(report)

    assert output.startswith("IntegrityGuard | File Integrity Report")
    assert "Scan summary" in output
    assert "File changes" in output
    assert "Scan errors" in output
    assert "Integrity assessment" in output
    assert "No integrity changes detected" in output


def test_historical_report_is_clearly_identified(tmp_path: Path) -> None:
    _, _, changes = _change_report(tmp_path)
    report = create_security_report(changes, generated_at_utc=_GENERATED_AT)

    output = format_report(report, historical=True)

    assert "Historical saved report (not a fresh scan)" in output
    assert "2026-10-24T15:00:00.000000Z" in output


def test_large_unchanged_report_is_quiet_unless_verbose(tmp_path: Path) -> None:
    files = {f"file-{index:04}.txt": str(index).encode() for index in range(300)}
    _, _, changes = _change_report(tmp_path, files)
    report = create_security_report(changes, generated_at_utc=_GENERATED_AT)

    normal = format_report(report)
    verbose = format_report(report, verbose=True)

    assert "Unchanged details hidden (300 files" in normal
    assert "file-0000.txt" not in normal
    assert "file-0000.txt" in verbose
    assert "file-0299.txt" in verbose


def test_inconclusive_report_cannot_validate_as_clean(tmp_path: Path) -> None:
    _, _, changes = _change_report(tmp_path)
    report = create_security_report(changes, generated_at_utc=_GENERATED_AT)
    data = json.loads(report_to_json(report))
    data["assessment_status"] = AssessmentStatus.INCONCLUSIVE.value

    with pytest.raises(InvalidReportError, match="conflicts"):
        validate_report_data(data)


def test_duplicate_json_keys_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "duplicate.json"
    source.write_text(
        '{"report_schema_version":1,"report_schema_version":1}',
        encoding="utf-8",
    )

    with pytest.raises(InvalidReportError, match="Duplicate JSON"):
        load_report(source)


def test_report_size_limit_is_enforced(tmp_path: Path) -> None:
    source = tmp_path / "large.json"
    source.write_bytes(b"{}" + b" " * 30)

    with pytest.raises(InvalidReportError, match="size limit"):
        load_report(source, max_bytes=10)


def test_symlink_report_source_is_rejected_where_supported(tmp_path: Path) -> None:
    target = tmp_path / "real.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except OSError as error:
        pytest.skip(f"Symbolic links are unavailable in this environment: {error}")

    with pytest.raises(UnsafeReportPathError):
        load_report(link)
