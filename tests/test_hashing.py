"""Tests for IntegrityGuard's streaming SHA-256 helper."""

import hashlib
from pathlib import Path

import pytest

from integrityguard.hashing import sha256_file


def test_empty_file(tmp_path: Path) -> None:
    target = tmp_path / "empty.txt"
    target.write_bytes(b"")

    assert sha256_file(target) == hashlib.sha256(b"").hexdigest()


def test_normal_text_file(tmp_path: Path) -> None:
    target = tmp_path / "message.txt"
    content = "IntegrityGuard checks file contents.\n".encode("utf-8")
    target.write_bytes(content)

    assert sha256_file(target) == hashlib.sha256(content).hexdigest()


def test_binary_file(tmp_path: Path) -> None:
    target = tmp_path / "sample.bin"
    content = bytes(range(256)) + b"\x00\xff\x00\xff"
    target.write_bytes(content)

    assert sha256_file(target) == hashlib.sha256(content).hexdigest()


def test_large_file_is_hashed_across_multiple_chunks(tmp_path: Path) -> None:
    target = tmp_path / "large.bin"
    block = bytes(range(256))
    content = block * 20_481
    target.write_bytes(content)

    assert sha256_file(target, chunk_size=8_191) == hashlib.sha256(content).hexdigest()


def test_file_not_found(tmp_path: Path) -> None:
    missing_file = tmp_path / "missing.txt"

    with pytest.raises(FileNotFoundError):
        sha256_file(missing_file)


def test_hash_is_consistent(tmp_path: Path) -> None:
    target = tmp_path / "stable.txt"
    target.write_bytes(b"unchanged content")

    first_digest = sha256_file(target)
    second_digest = sha256_file(target)

    assert first_digest == second_digest


def test_different_contents_produce_different_hashes(tmp_path: Path) -> None:
    first_file = tmp_path / "first.txt"
    second_file = tmp_path / "second.txt"
    first_file.write_bytes(b"first content")
    second_file.write_bytes(b"second content")

    assert sha256_file(first_file) != sha256_file(second_file)


@pytest.mark.parametrize("invalid_chunk_size", [0, -1])
def test_non_positive_chunk_size_is_rejected(
    tmp_path: Path,
    invalid_chunk_size: int,
) -> None:
    target = tmp_path / "sample.txt"
    target.write_bytes(b"content")

    with pytest.raises(ValueError, match="greater than zero"):
        sha256_file(target, chunk_size=invalid_chunk_size)


def test_non_integer_chunk_size_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "sample.txt"
    target.write_bytes(b"content")

    with pytest.raises(TypeError, match="must be an integer"):
        sha256_file(target, chunk_size=1.5)  # type: ignore[arg-type]
