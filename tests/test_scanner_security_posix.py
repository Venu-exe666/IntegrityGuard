"""POSIX-specific regression tests for descriptor-bound scanner traversal."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import integrityguard.scanner as scanner_module
from integrityguard.scanner import ScanErrorKind, ScanStatus, scan_directory

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="POSIX descriptor-relative filesystem behavior",
)


def test_posix_file_and_directory_opens_are_descriptor_relative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "evidence.bin").write_bytes(b"evidence")
    real_open = scanner_module.os.open
    calls: list[tuple[object, int, int | None]] = []

    def record_open(
        path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        calls.append((path, flags, dir_fd))
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(scanner_module.os, "open", record_open)

    report = scan_directory(tmp_path)

    assert report.errors == ()
    assert report.files[0].status is ScanStatus.SCANNED
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory_only = getattr(os, "O_DIRECTORY", 0)
    assert no_follow != 0
    assert directory_only != 0
    assert any(
        path == "nested"
        and dir_fd is not None
        and flags & no_follow
        and flags & directory_only
        for path, flags, dir_fd in calls
    )
    assert any(
        path == "evidence.bin"
        and dir_fd is not None
        and flags & no_follow
        and not flags & directory_only
        for path, flags, dir_fd in calls
    )


def test_posix_entry_stat_is_descriptor_relative_and_does_not_follow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "evidence.bin").write_bytes(b"evidence")
    real_stat = scanner_module.os.stat
    calls: list[tuple[object, int | None, bool]] = []

    def record_stat(
        path: object,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        calls.append((path, dir_fd, follow_symlinks))
        return real_stat(
            path,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(scanner_module.os, "stat", record_stat)

    report = scan_directory(tmp_path)

    assert report.errors == ()
    assert any(
        path == "evidence.bin"
        and dir_fd is not None
        and follow_symlinks is False
        for path, dir_fd, follow_symlinks in calls
    )


def test_posix_symlinks_cannot_escape_the_scan_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "inside.txt").write_bytes(b"inside")
    (outside / "secret.txt").write_bytes(b"outside")
    (root / "file-link").symlink_to(outside / "secret.txt")
    (root / "directory-link").symlink_to(outside, target_is_directory=True)

    report = scan_directory(root)

    assert [item.relative_path for item in report.files] == ["inside.txt"]
    assert report.skipped_paths == ("directory-link", "file-link")
    assert report.errors == ()
    assert all(item.sha256 is not None for item in report.files)


def test_posix_symlink_scan_root_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "real-root"
    root.mkdir()
    (root / "inside.txt").write_bytes(b"inside")
    link = tmp_path / "root-link"
    link.symlink_to(root, target_is_directory=True)

    report = scan_directory(link)

    assert report.files == ()
    assert report.skipped_paths == ()
    assert len(report.errors) == 1
    assert report.errors[0].relative_path == "."
    assert report.errors[0].kind is ScanErrorKind.ROOT_LINK_NOT_FOLLOWED
