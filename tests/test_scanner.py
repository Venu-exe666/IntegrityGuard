"""Tests for IntegrityGuard's read-only recursive directory scanner."""

from __future__ import annotations

import hashlib
from datetime import timezone
from pathlib import Path

import pytest

import integrityguard.scanner as scanner_module
from integrityguard.hashing import sha256_file
from integrityguard.scanner import ScanErrorKind, ScanStatus, scan_directory


def test_scans_directory_containing_one_file(tmp_path: Path) -> None:
    target = tmp_path / "only.txt"
    target.write_text("one", encoding="utf-8")

    report = scan_directory(tmp_path)

    assert [result.relative_path for result in report.files] == ["only.txt"]
    assert report.files[0].status is ScanStatus.SCANNED
    assert report.files[0].size_bytes == 3
    assert report.files[0].modified_at_utc is not None
    assert report.files[0].modified_at_utc.tzinfo is timezone.utc
    assert report.errors == ()


def test_scans_multiple_files(tmp_path: Path) -> None:
    (tmp_path / "one.txt").write_bytes(b"one")
    (tmp_path / "two.txt").write_bytes(b"two")
    (tmp_path / "three.txt").write_bytes(b"three")

    report = scan_directory(tmp_path)

    assert len(report.files) == 3
    assert all(result.status is ScanStatus.SCANNED for result in report.files)


def test_scans_nested_directories_with_normalized_paths(tmp_path: Path) -> None:
    nested = tmp_path / "first" / "second"
    nested.mkdir(parents=True)
    (nested / "deep.txt").write_bytes(b"nested")

    report = scan_directory(tmp_path)

    assert [result.relative_path for result in report.files] == [
        "first/second/deep.txt"
    ]


def test_empty_directory_returns_empty_report(tmp_path: Path) -> None:
    report = scan_directory(tmp_path)

    assert report.files == ()
    assert report.errors == ()
    assert report.skipped_paths == ()


def test_scans_binary_file(tmp_path: Path) -> None:
    content = bytes(range(256)) + b"\x00\xff"
    (tmp_path / "data.bin").write_bytes(content)

    report = scan_directory(tmp_path)

    assert report.files[0].sha256 == hashlib.sha256(content).hexdigest()
    assert report.files[0].size_bytes == len(content)


def test_scans_unicode_filename(tmp_path: Path) -> None:
    filename = "evidence-整合性-U0001f512.txt"
    (tmp_path / filename).write_bytes(b"unicode name")

    report = scan_directory(tmp_path)

    assert [result.relative_path for result in report.files] == [filename]


def test_scans_filename_containing_spaces(tmp_path: Path) -> None:
    filename = "incident evidence 01.txt"
    (tmp_path / filename).write_bytes(b"spaces")

    report = scan_directory(tmp_path)

    assert [result.relative_path for result in report.files] == [filename]


def test_missing_directory_is_reported(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"

    report = scan_directory(missing)

    assert report.files == ()
    assert len(report.errors) == 1
    assert report.errors[0].kind is ScanErrorKind.ROOT_NOT_FOUND
    assert report.errors[0].exception_type == "FileNotFoundError"


def test_symbolic_links_are_skipped(tmp_path: Path) -> None:
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    (real_directory / "target.txt").write_bytes(b"target")
    link = tmp_path / "loop"
    try:
        link.symlink_to(tmp_path, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Symbolic links are unavailable in this environment: {error}")

    report = scan_directory(tmp_path)

    assert [result.relative_path for result in report.files] == ["real/target.txt"]
    assert report.skipped_paths == ("loop",)
    assert report.errors == ()


def test_reparse_points_are_skipped_without_accessing_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeEntry:
        name = "junction"
        path = str(tmp_path / name)

        @staticmethod
        def stat(*, follow_symlinks: bool) -> object:
            assert follow_symlinks is False
            return type(
                "FakeStat",
                (),
                {
                    "st_mode": 0,
                    "st_file_attributes": scanner_module._WINDOWS_REPARSE_POINT,
                },
            )()

    class FakeScandir:
        def __enter__(self) -> object:
            return iter([FakeEntry()])

        def __exit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr(scanner_module.os, "scandir", lambda path: FakeScandir())

    report = scan_directory(tmp_path)

    assert report.files == ()
    assert report.errors == ()
    assert report.skipped_paths == ("junction",)


def test_file_path_as_scan_root_is_reported(tmp_path: Path) -> None:
    target = tmp_path / "not-a-directory.txt"
    target.write_bytes(b"content")

    report = scan_directory(target)

    assert report.files == ()
    assert report.errors[0].kind is ScanErrorKind.ROOT_NOT_DIRECTORY


def test_results_have_deterministic_relative_path_order(tmp_path: Path) -> None:
    for relative_path in ["z.txt", "b/two.txt", "a.txt", "b/one.txt"]:
        target = tmp_path / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(relative_path, encoding="utf-8")

    first_report = scan_directory(tmp_path)
    second_report = scan_directory(tmp_path)

    expected = ["a.txt", "b/one.txt", "b/two.txt", "z.txt"]
    assert [result.relative_path for result in first_report.files] == expected
    assert first_report.files == second_report.files


def test_scanner_reuses_correct_sha256_hashing(tmp_path: Path) -> None:
    target = tmp_path / "evidence.txt"
    content = b"known evidence content"
    target.write_bytes(content)

    report = scan_directory(tmp_path)

    assert report.files[0].sha256 == sha256_file(target)
    assert report.files[0].sha256 == hashlib.sha256(content).hexdigest()


def test_permission_error_is_reported_separately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "restricted.txt"
    target.write_bytes(b"restricted")

    def deny_read(path: Path) -> str:
        raise PermissionError(13, "Access is denied", path)

    monkeypatch.setattr(scanner_module, "sha256_file", deny_read)

    report = scan_directory(tmp_path)

    assert report.files[0].status is ScanStatus.ERROR
    assert report.files[0].sha256 is None
    assert report.errors[0].relative_path == "restricted.txt"
    assert report.errors[0].kind is ScanErrorKind.FILE_ACCESS
    assert report.errors[0].exception_type == "PermissionError"


def test_file_deleted_during_scan_is_reported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "temporary.txt"
    target.write_bytes(b"temporary")

    def delete_before_read(path: Path) -> str:
        path.unlink()
        return sha256_file(path)

    monkeypatch.setattr(scanner_module, "sha256_file", delete_before_read)

    report = scan_directory(tmp_path)

    assert report.files[0].status is ScanStatus.ERROR
    assert report.errors[0].kind is ScanErrorKind.FILE_ACCESS
    assert report.errors[0].exception_type == "FileNotFoundError"


def test_file_modified_while_hashing_is_not_reported_as_successful(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "changing.txt"
    target.write_bytes(b"before")

    def hash_then_change(path: Path) -> str:
        digest = sha256_file(path)
        path.write_bytes(b"different length after hashing")
        return digest

    monkeypatch.setattr(scanner_module, "sha256_file", hash_then_change)

    report = scan_directory(tmp_path)

    assert report.files[0].status is ScanStatus.CHANGED_DURING_SCAN
    assert report.files[0].sha256 is None
    assert report.errors[0].kind is ScanErrorKind.FILE_CHANGED


def test_scanning_does_not_modify_monitored_files(tmp_path: Path) -> None:
    target = tmp_path / "preserve.bin"
    original_content = b"must remain unchanged\x00\xff"
    target.write_bytes(original_content)
    before = target.stat()

    report = scan_directory(tmp_path)
    after = target.stat()

    assert report.files[0].status is ScanStatus.SCANNED
    assert target.read_bytes() == original_content
    assert after.st_size == before.st_size
    assert after.st_mtime_ns == before.st_mtime_ns
