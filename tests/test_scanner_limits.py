from __future__ import annotations

from pathlib import Path

import pytest

import integrityguard.scanner as scanner_module
from integrityguard.baseline import create_baseline
from integrityguard.detector import compare_baseline
from integrityguard.scanner import ScanErrorKind, ScanLimits, scan_directory


def _assert_limit_error(report) -> None:
    assert any(
        error.relative_path == "."
        and error.kind is ScanErrorKind.DIRECTORY_ACCESS
        and error.exception_type == "ScanLimitExceededError"
        for error in report.errors
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_entries", 0),
        ("max_entries", True),
        ("max_bytes", -1),
        ("max_bytes", False),
        ("max_duration_seconds", 0),
        ("max_duration_seconds", float("inf")),
        ("max_duration_seconds", True),
    ],
)
def test_invalid_scan_limits_are_rejected(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        ScanLimits(**{field: value})  # type: ignore[arg-type]


def test_entry_limit_stops_during_enumeration_and_is_inconclusive(
    tmp_path: Path,
) -> None:
    for name in ("a.txt", "b.txt", "c.txt"):
        (tmp_path / name).write_bytes(name.encode())
    baseline = create_baseline(scan_directory(tmp_path))

    limited = scan_directory(tmp_path, limits=ScanLimits(max_entries=2))
    changes = compare_baseline(baseline, limited)

    assert limited.files == ()
    _assert_limit_error(limited)
    assert changes.deleted == ()
    assert len(changes.unknown) == 3
    assert not changes.scan_complete
    assert not changes.assessment_conclusive
    assert not changes.is_clean


def test_cumulative_byte_limit_preserves_completed_files_and_unknown_scope(
    tmp_path: Path,
) -> None:
    (tmp_path / "a.bin").write_bytes(b"aaa")
    (tmp_path / "b.bin").write_bytes(b"bbb")
    baseline = create_baseline(scan_directory(tmp_path))

    limited = scan_directory(tmp_path, limits=ScanLimits(max_bytes=5))
    changes = compare_baseline(baseline, limited)

    assert [item.relative_path for item in limited.files] == ["a.bin"]
    _assert_limit_error(limited)
    assert [item.relative_path for item in changes.unchanged] == ["a.bin"]
    assert [item.relative_path for item in changes.unknown] == ["b.bin"]
    assert changes.deleted == ()
    assert not changes.assessment_conclusive


def test_byte_limit_is_enforced_against_growth_after_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "growing.bin"
    target.write_bytes(b"ab")

    def grow_then_read(reader) -> str:
        with target.open("ab") as output:
            output.write(b"cd")
        while reader.read(64 * 1024):
            pass
        raise AssertionError("the bounded reader accepted too many bytes")

    monkeypatch.setattr(scanner_module, "sha256_stream", grow_then_read)

    report = scan_directory(tmp_path, limits=ScanLimits(max_bytes=3))

    _assert_limit_error(report)
    assert report.files == ()


def test_duration_limit_uses_monotonic_time(tmp_path: Path) -> None:
    (tmp_path / "file.txt").write_bytes(b"content")
    current = -0.6

    def clock() -> float:
        nonlocal current
        current += 0.6
        return current

    report = scan_directory(
        tmp_path,
        limits=ScanLimits(max_duration_seconds=1.0),
        monotonic=clock,
    )

    _assert_limit_error(report)
    assert report.files == ()


def test_entry_limit_bounds_oversized_directory_name_collection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    yielded = 0

    class FakeEntry:
        def __init__(self, name: str) -> None:
            self.name = name

    class FakeScandir:
        def __enter__(self):
            def entries():
                nonlocal yielded
                for index in range(1_000_000):
                    yielded += 1
                    yield FakeEntry(f"{index}.txt")

            return entries()

        def __exit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr(scanner_module.os, "scandir", lambda target: FakeScandir())

    report = scan_directory(tmp_path, limits=ScanLimits(max_entries=3))

    _assert_limit_error(report)
    assert yielded == 4
    assert report.files == ()


def test_unconfigured_limits_preserve_normal_scan(tmp_path: Path) -> None:
    (tmp_path / "file.txt").write_bytes(b"content")

    report = scan_directory(tmp_path)

    assert len(report.files) == 1
    assert report.errors == ()
