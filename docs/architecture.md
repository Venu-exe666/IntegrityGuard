# IntegrityGuard Architecture

## Milestone 2 components

IntegrityGuard currently has two independent application layers:

```text
scanner.scan_directory()
        |
        +-- discovers regular files and collects metadata
        |
        +-- hashing.sha256_file()
                |
                +-- streams file bytes into SHA-256
```

`hashing.py` performs one task: calculate the SHA-256 digest of a specified
file. It knows nothing about directory traversal or scan reports.

`scanner.py` owns traversal, relative-path normalization, file metadata,
deterministic ordering, link avoidance, race checks, and error aggregation. It
calls the existing hashing function rather than duplicating hashing logic.

## Result model

`scan_directory()` returns an immutable `ScanReport` containing:

- the absolute scan root;
- ordered `FileScanResult` records for discovered regular files;
- ordered `ScanError` records kept separate from file data; and
- normalized paths of links and reparse points that were intentionally skipped.

A successful file record contains its normalized relative path, SHA-256 hash,
byte size, UTC modification time, and `scanned` status. Failed reads and files
that change during hashing stay visible in the file records, but their digest
is `None` and their status explains that the result is not trustworthy.

## Trust boundaries and race checks

The monitored filesystem is untrusted and can change at any time. The scanner
collects metadata before hashing and checks identity, size, and nanosecond
modification time afterward. A detected difference causes the digest to be
discarded and an error to be recorded.

These checks reduce risk but cannot create an atomic snapshot. An attacker or
another process may change a file and restore its observable metadata between
checks. Strong snapshot guarantees require operating-system or filesystem
support outside this milestone.

The scanner never follows symbolic links, junctions, or other Windows reparse
points. It also tracks visited directory identities as defense in depth against
recursive traversal loops.

## Deferred components

Baseline persistence, change comparison, reporting formats, CLI commands,
background monitoring, and notifications are deliberately not implemented in
Milestone 2.
