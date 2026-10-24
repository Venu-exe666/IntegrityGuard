"""Tests for the IntegrityGuard command-line interface."""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

import integrityguard.cli as cli_module
from integrityguard.baseline import load_baseline
from integrityguard.cli import (
    EXIT_CHANGES,
    EXIT_INCONCLUSIVE,
    EXIT_OPERATIONAL_ERROR,
    EXIT_SUCCESS,
    main,
)
from integrityguard.reporting import load_report
from integrityguard.scanner import ScanError, ScanErrorKind, ScanStatus, scan_directory


def _initialize(tmp_path: Path, filename: str = "file.txt") -> tuple[Path, Path]:
    monitored = tmp_path / "monitored files"
    monitored.mkdir(parents=True)
    (monitored / filename).write_bytes(b"original")
    baseline = tmp_path / "integrity baseline.json"
    code = main(
        [
            "init",
            "--root",
            str(monitored),
            "--baseline",
            str(baseline),
        ]
    )
    assert code == EXIT_SUCCESS
    return monitored, baseline


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["init", "--help"],
        ["scan", "--help"],
        ["report", "--help"],
        ["watch", "--help"],
    ],
)
def test_cli_help(arguments: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    args = ["--help"] if not arguments else arguments

    with pytest.raises(SystemExit) as captured:
        main(args)

    assert captured.value.code == 0
    assert "usage:" in capsys.readouterr().out


def test_init_creates_valid_baseline(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monitored, baseline_path = _initialize(tmp_path)
    output = capsys.readouterr().out
    baseline = load_baseline(baseline_path)

    assert "baseline created" in output
    assert len(baseline.files) == 1
    assert baseline.scan_root == str(monitored.resolve())


def test_init_refuses_existing_baseline(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monitored, baseline = _initialize(tmp_path)
    capsys.readouterr()

    code = main(["init", "--root", str(monitored), "--baseline", str(baseline)])
    captured = capsys.readouterr()

    assert code == EXIT_OPERATIONAL_ERROR
    assert "already exists" in captured.err


def test_init_rejects_incomplete_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    scan = scan_directory(root)
    error = ScanError(".", ScanErrorKind.DIRECTORY_ACCESS, "denied")
    monkeypatch.setattr(
        cli_module,
        "scan_directory",
        lambda path: replace(scan, errors=(error,)),
    )

    code = main(
        ["init", "--root", str(root), "--baseline", str(tmp_path / "base.json")]
    )

    assert code == EXIT_OPERATIONAL_ERROR
    assert "containing errors" in capsys.readouterr().err
    assert not (tmp_path / "base.json").exists()


def test_clean_scan_text_output_and_exit_code(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monitored, baseline = _initialize(tmp_path)
    capsys.readouterr()

    code = main(["scan", "--root", str(monitored), "--baseline", str(baseline)])
    captured = capsys.readouterr()

    assert code == EXIT_SUCCESS
    assert "IntegrityGuard | File Integrity Report" in captured.out
    assert "No integrity changes detected" in captured.out
    assert captured.err == ""


@pytest.mark.parametrize(
    ("change", "expected_section"),
    [("added", "Added:"), ("modified", "Modified:"), ("deleted", "Deleted:")],
)
def test_scan_detects_integrity_changes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    change: str,
    expected_section: str,
) -> None:
    monitored, baseline = _initialize(tmp_path)
    capsys.readouterr()
    if change == "added":
        (monitored / "new.txt").write_bytes(b"new")
    elif change == "modified":
        (monitored / "file.txt").write_bytes(b"modified")
    else:
        (monitored / "file.txt").unlink()

    code = main(["scan", "--root", str(monitored), "--baseline", str(baseline)])
    output = capsys.readouterr().out

    assert code == EXIT_CHANGES
    assert expected_section in output
    assert "Integrity changes detected" in output


def test_unknown_scan_state_and_error_use_inconclusive_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monitored, baseline = _initialize(tmp_path)
    capsys.readouterr()
    scan = scan_directory(monitored)
    failed_file = replace(scan.files[0], sha256=None, status=ScanStatus.ERROR)
    error = ScanError(
        "file.txt",
        ScanErrorKind.FILE_ACCESS,
        "access denied",
        "PermissionError",
    )
    monkeypatch.setattr(
        cli_module,
        "scan_directory",
        lambda path: replace(scan, files=(failed_file,), errors=(error,)),
    )

    code = main(["scan", "--root", str(monitored), "--baseline", str(baseline)])
    output = capsys.readouterr().out

    assert code == EXIT_INCONCLUSIVE
    assert "Unknown:               1" in output
    assert "[file_access] file.txt (PermissionError)" in output
    assert "do not treat this as clean" in output


def test_root_mismatch_and_invalid_baseline_are_operational_errors(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monitored, baseline = _initialize(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    capsys.readouterr()

    mismatch_code = main(
        ["scan", "--root", str(other), "--baseline", str(baseline)]
    )
    mismatch = capsys.readouterr()
    invalid = tmp_path / "invalid.json"
    invalid.write_text("not json", encoding="utf-8")
    invalid_code = main(
        ["scan", "--root", str(monitored), "--baseline", str(invalid)]
    )
    invalid_output = capsys.readouterr()

    assert mismatch_code == EXIT_OPERATIONAL_ERROR
    assert "different root" in mismatch.err
    assert invalid_code == EXIT_OPERATIONAL_ERROR
    assert "malformed JSON" in invalid_output.err


def test_json_stdout_is_valid_and_diagnostics_are_separate(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monitored, baseline = _initialize(tmp_path)
    capsys.readouterr()

    code = main(
        [
            "scan",
            "--root",
            str(monitored),
            "--baseline",
            str(baseline),
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert code == EXIT_SUCCESS
    assert data["assessment_status"] == "clean"
    assert captured.err == ""


def test_json_error_does_not_contaminate_stdout(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monitored = tmp_path / "root"
    monitored.mkdir()
    invalid = tmp_path / "invalid.json"
    invalid.write_text("bad", encoding="utf-8")

    code = main(
        [
            "scan",
            "--root",
            str(monitored),
            "--baseline",
            str(invalid),
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()

    assert code == EXIT_OPERATIONAL_ERROR
    assert captured.out == ""
    assert captured.err.startswith("Error:")


def test_report_file_export_and_historical_loading(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monitored, baseline = _initialize(tmp_path)
    report_path = tmp_path / "security report.json"
    capsys.readouterr()

    scan_code = main(
        [
            "scan",
            "--root",
            str(monitored),
            "--baseline",
            str(baseline),
            "--format",
            "json",
            "--output",
            str(report_path),
        ]
    )
    scan_output = capsys.readouterr()
    view_code = main(["report", "--input", str(report_path)])
    view_output = capsys.readouterr()

    assert scan_code == EXIT_SUCCESS
    assert report_path.exists()
    assert load_report(report_path).assessment_status.value == "clean"
    assert "JSON report created" in scan_output.out
    assert view_code == EXIT_SUCCESS
    assert "Historical saved report (not a fresh scan)" in view_output.out


def test_existing_and_unsafe_report_destinations_are_rejected(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monitored, baseline = _initialize(tmp_path)
    report_path = tmp_path / "report.json"
    arguments = [
        "scan",
        "--root",
        str(monitored),
        "--baseline",
        str(baseline),
        "--format",
        "json",
        "--output",
        str(report_path),
    ]
    capsys.readouterr()
    assert main(arguments) == EXIT_SUCCESS
    capsys.readouterr()

    existing_code = main(arguments)
    existing_error = capsys.readouterr().err
    unsafe_arguments = arguments[:-1] + [str(monitored / "report.json")]
    unsafe_code = main(unsafe_arguments)
    unsafe_error = capsys.readouterr().err

    assert existing_code == EXIT_OPERATIONAL_ERROR
    assert "already exists" in existing_error
    assert unsafe_code == EXIT_OPERATIONAL_ERROR
    assert "inside the monitored directory" in unsafe_error


def test_malformed_and_unsupported_saved_reports_return_operational_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")

    malformed_code = main(["report", "--input", str(malformed)])
    malformed_error = capsys.readouterr().err

    assert malformed_code == EXIT_OPERATIONAL_ERROR
    assert "malformed JSON" in malformed_error

    monitored, baseline = _initialize(tmp_path / "valid")
    report_path = tmp_path / "report.json"
    capsys.readouterr()
    assert main(
        [
            "scan",
            "--root",
            str(monitored),
            "--baseline",
            str(baseline),
            "--format",
            "json",
            "--output",
            str(report_path),
        ]
    ) == EXIT_SUCCESS
    capsys.readouterr()
    data = json.loads(report_path.read_text(encoding="utf-8"))
    data["report_schema_version"] = 999
    report_path.write_text(json.dumps(data), encoding="utf-8")

    unsupported_code = main(["report", "--input", str(report_path)])
    unsupported_error = capsys.readouterr().err

    assert unsupported_code == EXIT_OPERATIONAL_ERROR
    assert "Unsupported report schema version" in unsupported_error


def test_output_requires_json_format(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monitored, baseline = _initialize(tmp_path)
    capsys.readouterr()

    code = main(
        [
            "scan",
            "--root",
            str(monitored),
            "--baseline",
            str(baseline),
            "--output",
            str(tmp_path / "report.json"),
        ]
    )

    assert code == EXIT_OPERATIONAL_ERROR
    assert "requires --format json" in capsys.readouterr().err


def test_missing_arguments_use_operational_error_exit_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as captured:
        main(["scan"])

    assert captured.value.code == EXIT_OPERATIONAL_ERROR
    assert "required" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--max-entries", "0"),
        ("--max-bytes", "-1"),
        ("--max-seconds", "nan"),
    ],
)
def test_invalid_scan_limits_use_operational_error_exit_code(
    option: str,
    value: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as captured:
        main(
            [
                "scan",
                "--root",
                ".",
                "--baseline",
                "baseline.json",
                option,
                value,
            ]
        )

    assert captured.value.code == EXIT_OPERATIONAL_ERROR
    assert "positive" in capsys.readouterr().err


def test_scan_limit_exceeded_returns_inconclusive_exit_code(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monitored, baseline = _initialize(tmp_path)
    (monitored / "second.txt").write_bytes(b"second")
    capsys.readouterr()

    code = main(
        [
            "scan",
            "--root",
            str(monitored),
            "--baseline",
            str(baseline),
            "--max-entries",
            "1",
        ]
    )

    assert code == EXIT_INCONCLUSIVE
    output = capsys.readouterr().out
    assert "Assessment conclusive: no" in output
    assert "ScanLimitExceededError" in output


def test_init_limit_exceeded_does_not_create_baseline(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    (monitored / "large.bin").write_bytes(b"too large")
    baseline = tmp_path / "baseline.json"

    code = main(
        [
            "init",
            "--root",
            str(monitored),
            "--baseline",
            str(baseline),
            "--max-bytes",
            "1",
        ]
    )

    assert code == EXIT_OPERATIONAL_ERROR
    assert not baseline.exists()
    assert "containing errors" in capsys.readouterr().err


@pytest.mark.parametrize("interval", ["invalid", "0", "-1", "nan", "inf"])
def test_watch_rejects_invalid_intervals(
    interval: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as captured:
        main(
            [
                "watch",
                "--root",
                ".",
                "--baseline",
                "baseline.json",
                "--interval",
                interval,
            ]
        )

    assert captured.value.code == EXIT_OPERATIONAL_ERROR
    assert "polling interval" in capsys.readouterr().err


def test_watch_missing_baseline_is_operational_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "root"
    root.mkdir()

    code = main(
        [
            "watch",
            "--root",
            str(root),
            "--baseline",
            str(tmp_path / "missing.json"),
        ]
    )

    assert code == EXIT_OPERATIONAL_ERROR
    assert "Unable to read the baseline" in capsys.readouterr().err


def test_unicode_and_space_paths_work_end_to_end(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    filename = "integrity 整合性 U0001f512.txt"
    monitored, baseline = _initialize(tmp_path, filename)
    capsys.readouterr()
    (monitored / filename).write_bytes(b"changed")

    code = main(["scan", "--root", str(monitored), "--baseline", str(baseline)])
    output = capsys.readouterr().out

    assert code == EXIT_CHANGES
    assert filename in output


def test_cli_scan_does_not_modify_monitored_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monitored, baseline = _initialize(tmp_path)
    target = monitored / "file.txt"
    before = target.read_bytes(), target.stat().st_mtime_ns
    capsys.readouterr()

    main(["scan", "--root", str(monitored), "--baseline", str(baseline)])

    assert (target.read_bytes(), target.stat().st_mtime_ns) == before


def test_module_entry_point_help_in_subprocess() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "integrityguard.cli", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == EXIT_SUCCESS
    assert "usage: integrityguard" in completed.stdout
    assert completed.stderr == ""


def test_module_entry_point_handles_unicode_with_redirected_output(
    tmp_path: Path,
) -> None:
    monitored = tmp_path / "monitored files"
    monitored.mkdir()
    target = monitored / "résumé 整合性.txt"
    target.write_bytes(b"original")
    baseline_path = tmp_path / "baseline.json"
    baseline = cli_module.create_baseline(scan_directory(monitored))
    cli_module.save_baseline(baseline, baseline_path)
    target.write_bytes(b"changed")

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "integrityguard.cli",
            "scan",
            "--root",
            str(monitored),
            "--baseline",
            str(baseline_path),
        ],
        check=False,
        capture_output=True,
        encoding="utf-8",
        text=True,
    )

    assert completed.returncode == EXIT_CHANGES
    assert "Modified:" in completed.stdout
    assert target.name in completed.stdout
    assert completed.stderr == ""
