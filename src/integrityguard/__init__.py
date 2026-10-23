"""IntegrityGuard file integrity monitoring tools."""

from integrityguard.hashing import DEFAULT_CHUNK_SIZE, sha256_file
from integrityguard.scanner import (
    FileScanResult,
    ScanError,
    ScanErrorKind,
    ScanReport,
    ScanStatus,
    scan_directory,
)

__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "FileScanResult",
    "ScanError",
    "ScanErrorKind",
    "ScanReport",
    "ScanStatus",
    "scan_directory",
    "sha256_file",
]
__version__ = "0.1.0"
