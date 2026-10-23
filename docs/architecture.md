# IntegrityGuard Architecture

## Milestone 3 components

IntegrityGuard currently has three application layers:

```text
baseline.create_baseline() / save_baseline() / load_baseline()
        |
        +-- consumes and validates ScanReport records
        |
scanner.scan_directory()
        |
        +-- discovers regular files and collects metadata
        |
hashing.sha256_file()
        |
        +-- streams file bytes into SHA-256
```

`hashing.py` performs one task: calculate the SHA-256 digest of a specified
file. It knows nothing about directory traversal or scan reports.

`scanner.py` owns traversal, relative-path normalization, file metadata,
deterministic ordering, link avoidance, race checks, and error aggregation. It
calls the existing hashing function rather than duplicating hashing logic.

`baseline.py` owns the versioned persistence schema, compatibility checks,
strict JSON validation, size-limited loading, storage-path policy, and atomic
exclusive creation. It consumes scanner results but never reads monitored file
contents itself.

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

## Baseline data flow

`create_baseline()` rejects any report containing scan errors, missing hashes,
failed statuses, invalid metadata, or duplicate paths. Intentionally skipped
links remain allowed because they are outside the scanner's policy boundary;
their paths are persisted for auditability.

The JSON schema contains:

- `schema_version` and `hash_algorithm` compatibility identifiers;
- the canonical absolute `scan_root`;
- a UTC `created_at_utc` timestamp;
- a sorted `skipped_paths` array; and
- sorted file records with relative path, SHA-256, byte size, and optional UTC
  modification timestamp.

Loading is a trust-boundary operation. The loader limits input size, requires
UTF-8, rejects duplicate JSON keys, accepts exactly the documented fields, and
validates every value without silently normalizing path input.

## Atomic exclusive publication

The baseline is encoded completely before filesystem publication. A temporary
file is created with a random name in the destination directory, written,
flushed, and synchronized. `os.link()` then creates the final name as a hard
link while the temporary file is still open. Creating a hard link is atomic and
fails if the final name already exists, so concurrent creators cannot silently
replace one another. The temporary name is removed afterward.

The temporary and final names share one already-flushed file object, which
avoids exposing a partially copied destination. If the filesystem does not
support hard links, saving fails safely with a typed I/O error. `os.replace()`
is intentionally not used because it permits replacement.

Before writing, the parent path is inspected without following links or
Windows reparse points. The resolved destination is compared with the resolved
monitored root using Windows-aware case normalization. The destination must be
outside that root and must not already exist.

## Deferred components

Change comparison, baseline authentication, rotation, reporting formats, CLI
commands, background monitoring, and notifications are deliberately not
implemented in Milestone 3.
