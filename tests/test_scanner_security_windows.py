"""Windows-specific regression tests for handles and real reparse points."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import integrityguard.scanner as scanner_module
from integrityguard.scanner import ScanStatus, scan_directory

pytestmark = pytest.mark.skipif(
    os.name != "nt",
    reason="Windows CreateFileW and reparse-point behavior",
)


def _create_junction(link: Path, target: Path) -> None:
    completed = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        reason = (completed.stderr or completed.stdout).strip()
        pytest.skip(f"Windows junction creation is unavailable: {reason}")


def test_windows_real_junction_is_opened_as_reparse_point_and_skipped(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "inside.txt").write_bytes(b"inside")
    (outside / "secret.txt").write_bytes(b"outside")
    junction = root / "outside-junction"
    _create_junction(junction, outside)

    try:
        descriptor = scanner_module._windows_open(junction, is_directory=True)
        try:
            opened = os.fstat(descriptor)
        finally:
            os.close(descriptor)

        report = scan_directory(root)

        assert scanner_module._is_link_like(opened)
        assert [item.relative_path for item in report.files] == ["inside.txt"]
        assert report.files[0].status is ScanStatus.SCANNED
        assert report.skipped_paths == ("outside-junction",)
        assert report.errors == ()
    finally:
        if junction.exists():
            os.rmdir(junction)


def test_windows_directory_handle_has_stable_identity(tmp_path: Path) -> None:
    directory = tmp_path / "directory"
    directory.mkdir()
    expected = directory.stat(follow_symlinks=False)

    descriptor = scanner_module._windows_open(directory, is_directory=True)
    try:
        opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    assert scanner_module._file_identity(opened) == scanner_module._file_identity(
        expected
    )
    scanner_module._verify_opened_object(
        expected,
        opened,
        require_directory=True,
    )
