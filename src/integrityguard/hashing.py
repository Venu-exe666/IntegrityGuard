"""File hashing utilities for IntegrityGuard."""

from __future__ import annotations

import hashlib
from os import PathLike
from pathlib import Path

DEFAULT_CHUNK_SIZE = 64 * 1024


def sha256_file(
    file_path: str | PathLike[str],
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    """Return the lowercase SHA-256 hexadecimal digest of a file.

    The file is opened in binary mode and read incrementally, so memory use is
    bounded by ``chunk_size`` rather than by the file's total size. The
    function only reads the target and never changes it.

    Args:
        file_path: Path to the file to hash.
        chunk_size: Maximum number of bytes requested per read operation.

    Returns:
        A 64-character lowercase SHA-256 hexadecimal digest.

    Raises:
        TypeError: If ``chunk_size`` is not an integer.
        ValueError: If ``chunk_size`` is not positive.
        OSError: If the file cannot be opened or completely read. Specific
            subclasses such as ``FileNotFoundError`` and ``PermissionError``
            are preserved. No partial digest is returned when this occurs.
    """
    if not isinstance(chunk_size, int):
        raise TypeError("chunk_size must be an integer")
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    digest = hashlib.sha256()
    path = Path(file_path)

    with path.open("rb") as file_handle:
        while chunk := file_handle.read(chunk_size):
            digest.update(chunk)

    return digest.hexdigest()
