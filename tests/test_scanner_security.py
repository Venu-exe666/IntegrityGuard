from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path

import pytest

import integrityguard.scanner as scanner_module
from integrityguard.baseline import create_baseline
from integrityguard.detector import ChangeStatus, UnknownReason, compare_baseline
from integrityguard.reporting import create_security_report
from integrityguard.scanner import ScanErrorKind, ScanStatus, scan_directory


def test_same_sized_substitute_restoring_original_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "watched.bin"
    substitute = tmp_path / "substitute.bin"
    backup = tmp_path / "original.bin"
    target.write_bytes(b"AAAA")
    substitute.write_bytes(b"BBBB")
    root_info = root.stat()
    original_info = target.stat()
    os.utime(
        substitute,
        ns=(original_info.st_atime_ns, original_info.st_mtime_ns),
    )
    real_open = scanner_module._open_file
    hash_was_called = False

    def swap_before_open(
        path: Path,
        expected: os.stat_result,
        *,
        parent_descriptor: int,
        entry_name: str,
    ) -> int:
        os.replace(target, backup)
        os.link(substitute, target)
        try:
            return real_open(
                path,
                expected,
                parent_descriptor=parent_descriptor,
                entry_name=entry_name,
            )
        finally:
            target.unlink(missing_ok=True)
            os.replace(backup, target)
            os.utime(root, ns=(root_info.st_atime_ns, root_info.st_mtime_ns))

    def record_hash(file_handle: object) -> str:
        nonlocal hash_was_called
        hash_was_called = True
        return "0" * 64

    monkeypatch.setattr(scanner_module, "_open_file", swap_before_open)
    monkeypatch.setattr(scanner_module, "sha256_stream", record_hash)

    report = scan_directory(root)

    assert report.files[0].status is ScanStatus.CHANGED_DURING_SCAN
    assert report.files[0].sha256 is None
    assert any(error.kind is ScanErrorKind.FILE_CHANGED for error in report.errors)
    assert not hash_was_called
    assert target.read_bytes() == b"AAAA"


def test_path_replacement_during_hash_cannot_change_hashed_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "watched.bin"
    substitute = tmp_path / "substitute.bin"
    backup = tmp_path / "original.bin"
    original = b"original bytes"
    alternate = b"alternate data"
    assert len(original) == len(alternate)
    target.write_bytes(original)
    substitute.write_bytes(alternate)
    baseline = create_baseline(scan_directory(root))
    real_hash = scanner_module.sha256_stream
    replacement_blocked = False

    def attempt_swap(file_handle: object) -> str:
        nonlocal replacement_blocked
        try:
            os.replace(target, backup)
        except PermissionError:
            replacement_blocked = True
        else:
            os.link(substitute, target)
        try:
            return real_hash(file_handle)  # type: ignore[arg-type]
        finally:
            if backup.exists():
                target.unlink(missing_ok=True)
                os.replace(backup, target)

    monkeypatch.setattr(scanner_module, "sha256_stream", attempt_swap)

    report = scan_directory(root)
    changes = compare_baseline(baseline, report)
    security_report = create_security_report(changes)

    assert len(report.files) == 1
    assert report.files[0].status is ScanStatus.SCANNED
    assert report.files[0].sha256 == hashlib.sha256(original).hexdigest()
    assert report.files[0].sha256 != hashlib.sha256(alternate).hexdigest()
    assert target.read_bytes() == original
    if os.name == "nt":
        assert replacement_blocked
        assert report.errors == ()
        assert changes.scan_complete
        assert changes.assessment_conclusive
        assert changes.is_clean
    else:
        assert not replacement_blocked
        assert len(report.errors) == 1
        error = report.errors[0]
        assert error.relative_path == "."
        assert error.kind is ScanErrorKind.DIRECTORY_ACCESS
        assert error.exception_type == "_ObjectChangedError"
        assert error.message == (
            "The directory changed while its contents were being scanned."
        )
        assert len(security_report.scan_issues) == 1
        issue = security_report.scan_issues[0]
        assert issue.relative_path == error.relative_path
        assert issue.kind is error.kind
        assert issue.exception_type == error.exception_type
        assert not changes.scan_complete
        assert not changes.assessment_conclusive
        assert not changes.is_clean

    assert changes.deleted == ()


def test_symlink_substitution_is_rejected_without_hashing_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "watched.bin"
    outside = tmp_path / "outside.bin"
    backup = tmp_path / "original.bin"
    target.write_bytes(b"inside")
    outside.write_bytes(b"outside")
    baseline = create_baseline(scan_directory(root))
    root_info = root.stat()
    probe = tmp_path / "symlink-probe"
    try:
        probe.symlink_to(outside)
        probe.unlink()
    except OSError as error:
        pytest.skip(f"Symbolic links are unavailable in this environment: {error}")

    real_open = scanner_module._open_file
    hash_was_called = False

    def replace_with_link(
        path: Path,
        expected: os.stat_result,
        *,
        parent_descriptor: int,
        entry_name: str,
    ) -> int:
        os.replace(target, backup)
        target.symlink_to(outside)
        try:
            return real_open(
                path,
                expected,
                parent_descriptor=parent_descriptor,
                entry_name=entry_name,
            )
        finally:
            target.unlink(missing_ok=True)
            os.replace(backup, target)
            os.utime(root, ns=(root_info.st_atime_ns, root_info.st_mtime_ns))

    def record_hash(file_handle: object) -> str:
        nonlocal hash_was_called
        hash_was_called = True
        return "0" * 64

    monkeypatch.setattr(scanner_module, "_open_file", replace_with_link)
    monkeypatch.setattr(scanner_module, "sha256_stream", record_hash)

    report = scan_directory(root)
    changes = compare_baseline(baseline, report)
    security_report = create_security_report(changes)

    assert len(report.files) == 1
    assert report.files[0].sha256 is None
    assert not hash_was_called
    assert target.read_bytes() == b"inside"
    assert outside.read_bytes() == b"outside"
    file_errors = [
        error for error in report.errors if error.relative_path == "watched.bin"
    ]
    assert len(file_errors) == 1
    error = file_errors[0]
    assert error.relative_path == "watched.bin"
    if os.name == "nt":
        assert report.files[0].status is ScanStatus.CHANGED_DURING_SCAN
        assert error.kind is ScanErrorKind.FILE_CHANGED
        assert error.exception_type == "_ObjectChangedError"
        assert error.errno is None
    else:
        assert report.files[0].status is ScanStatus.ERROR
        assert error.kind is ScanErrorKind.FILE_ACCESS
        assert error.exception_type == "OSError"
        assert error.errno == errno.ELOOP

    issues = [
        issue
        for issue in security_report.scan_issues
        if issue.relative_path == "watched.bin"
    ]
    assert len(issues) == 1
    issue = issues[0]
    assert issue.relative_path == error.relative_path
    assert issue.kind is error.kind
    assert issue.exception_type == error.exception_type
    assert not changes.scan_complete
    assert not changes.assessment_conclusive
    assert not changes.is_clean
    assert changes.deleted == ()
    assert len(changes.unknown) == 1
    assert changes.unknown[0].relative_path == "watched.bin"
    assert changes.unknown[0].status is ChangeStatus.UNKNOWN
    assert changes.unknown[0].unknown_reason is UnknownReason.UNTRUSTED_RESULT


def test_parent_directory_substitution_makes_comparison_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (nested / "tracked.txt").write_bytes(b"expected")
    baseline = create_baseline(scan_directory(root))
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "other.txt").write_bytes(b"outside")
    backup = tmp_path / "original-nested"
    root_info = root.stat()
    real_open_directory = scanner_module._open_directory

    def substitute_directory(
        path: Path,
        expected: os.stat_result,
        *,
        parent_descriptor: int | None = None,
        entry_name: str | None = None,
    ) -> tuple[int, os.stat_result]:
        if path == nested:
            os.replace(nested, backup)
            os.replace(replacement, nested)
            try:
                return real_open_directory(
                    path,
                    expected,
                    parent_descriptor=parent_descriptor,
                    entry_name=entry_name,
                )
            finally:
                os.replace(nested, replacement)
                os.replace(backup, nested)
                os.utime(root, ns=(root_info.st_atime_ns, root_info.st_mtime_ns))
        return real_open_directory(
            path,
            expected,
            parent_descriptor=parent_descriptor,
            entry_name=entry_name,
        )

    monkeypatch.setattr(scanner_module, "_open_directory", substitute_directory)

    scan = scan_directory(root)
    changes = compare_baseline(baseline, scan)

    assert scan.files == ()
    assert any(
        error.kind is ScanErrorKind.DIRECTORY_ACCESS
        and error.relative_path == "nested"
        for error in scan.errors
    )
    assert not changes.scan_complete
    assert not changes.assessment_conclusive
    assert changes.deleted == ()
    assert changes.unknown[0].status is ChangeStatus.UNKNOWN
    assert changes.unknown[0].relative_path == "nested/tracked.txt"


def test_unsupported_file_identity_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "evidence.bin"
    target.write_bytes(b"evidence")

    def unsupported(*args: object, **kwargs: object) -> int:
        raise scanner_module._UnsupportedIdentityError(
            "Stable filesystem identity is unavailable."
        )

    monkeypatch.setattr(scanner_module, "_open_file", unsupported)

    report = scan_directory(tmp_path)

    assert report.files[0].status is ScanStatus.ERROR
    assert report.files[0].sha256 is None
    assert report.errors[0].kind is ScanErrorKind.FILE_ACCESS
    assert report.errors[0].exception_type == "_UnsupportedIdentityError"


@pytest.mark.skipif(os.name != "nt", reason="Windows handle-sharing behavior")
def test_windows_open_file_handle_blocks_rename_during_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "locked.bin"
    backup = tmp_path / "backup.bin"
    target.write_bytes(b"locked")
    real_hash = scanner_module.sha256_stream
    observed_error: PermissionError | None = None

    def try_rename(file_handle: object) -> str:
        nonlocal observed_error
        try:
            os.replace(target, backup)
        except PermissionError as error:
            observed_error = error
        return real_hash(file_handle)  # type: ignore[arg-type]

    monkeypatch.setattr(scanner_module, "sha256_stream", try_rename)

    report = scan_directory(tmp_path)

    assert report.errors == ()
    assert report.files[0].status is ScanStatus.SCANNED
    assert observed_error is not None
    assert target.read_bytes() == b"locked"
