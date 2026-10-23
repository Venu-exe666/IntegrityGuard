# IntegrityGuard Architecture

## Milestone 7.1 components

IntegrityGuard currently has seven application layers:

```text
cli.main()
  +-- monitoring.monitor_directory() -- schedules scans and alert transitions
  +-- reporting.* -------------------- presents and persists assessments
  +-- baseline.* --------------------- validates and stores trusted state
  +-- scanner.scan_directory() ------- discovers files and metadata
             |
             +-- hashing.sha256_stream() hashes the scanner's open handle

monitoring and reporting consume detector.compare_baseline(), which compares
trusted hashes and preserves uncertain states. Monitoring also calls the
scanner directly for every polling cycle.
```

`hashing.py` calculates SHA-256 digests from either a pathname for general API
use or an already-open binary stream. It knows nothing about traversal or scan
reports. The scanner uses the stream form so hashing cannot reopen a validated
pathname as a different object.

`scanner.py` owns traversal, relative-path normalization, file metadata,
deterministic ordering, link avoidance, race checks, and error aggregation. It
calls the existing hashing function rather than duplicating hashing logic.

`baseline.py` owns the versioned persistence schema, compatibility checks,
strict JSON validation, size-limited loading, storage-path policy, and atomic
exclusive creation. It consumes scanner results but never reads monitored file
contents itself.

`detector.py` is a read-only comparison layer. It validates an in-memory
baseline through the existing baseline validation path, validates the scanner
contract, confirms that both roots refer to the same directory, and returns an
immutable `ChangeReport`. It performs no baseline update or report-file write.

`reporting.py` converts a `ChangeReport` into an immutable `SecurityReport`,
renders compact monochrome text, and strictly serializes report schema version
1. Loading a historical report is a bounded trust-boundary operation. Report
JSON omits the absolute scan root and raw scanner messages.

`cli.py` is a thin orchestration layer. It parses arguments, calls the existing
scanner, baseline, detector, and reporting APIs, routes normal output to stdout
and diagnostics to stderr, and maps assessment state to stable process codes.
It does not duplicate hashing, traversal, or comparison logic.

`monitoring.py` is a synchronous foreground polling layer. It accepts one
immutable `Baseline`, calls `scan_directory()`, compares every result with that
same baseline, and exposes immutable cycle and session status objects. Clock,
wait, scan, and cycle-handler callables are injectable for deterministic tests.
No worker thread, event watcher, persistent state, or network component exists.

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

The monitored filesystem is untrusted and can change at any time. For each
file, the scanner inspects the directory entry, opens it with platform-specific
no-follow controls, compares the entry identity with `fstat()` on the opened
object, hashes that same object, and checks both the handle and directory entry
again. A detected difference causes the digest to be discarded and an error to
be recorded.

On POSIX, child opens and metadata reads are relative to held directory
descriptors and require `O_NOFOLLOW`. On Windows, `CreateFileW` uses
`FILE_FLAG_OPEN_REPARSE_POINT`; directory and file handles exclude delete
sharing while in use. Stable device/inode identity is required, and a platform
that cannot supply it fails the affected scan closed.

These checks close the confirmed race caused by reopening a pathname for
hashing, but they do not create an atomic filesystem snapshot. Concurrent
in-place writes may still produce a mixed read if an attacker restores size and
timestamps before the handle's final metadata check. Kernel-level deception,
network-filesystem semantics, filesystems that reuse or misreport object
identity, and transient directory-entry changes restored with their metadata
remain outside the guarantee. Discovered links and reparse points are excluded,
and visited directory identities provide additional loop defense.

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

## Change detection model

The detector joins `BaselineFile` and `FileScanResult` records by normalized
relative path. Windows comparisons are case-insensitive while stored display
paths remain unchanged. Results are sorted deterministically.

```text
baseline only + fully enumerated scope       -> deleted
baseline only + failed/skipped scope         -> unknown
current only + trusted digest                -> added
both + different trusted digest              -> modified
both + equal trusted digest                  -> unchanged
current record without a trusted digest      -> unknown
```

Size and timestamp differences are exposed as `metadata_changed`, but content
is marked modified only when trusted SHA-256 values differ.

Scanner error kinds define conservative scopes. Root errors cover every path;
directory-access, directory-loop, and entry-inspection errors cover a path and
its descendants; file read/change errors cover the exact file. Current skipped
links and reparse points similarly cover their complete relative subtree.

`scan_complete` requires no scanner errors, no skipped current paths, and a
trusted result for every current file. `assessment_conclusive` additionally
requires no unknown records and no excluded paths recorded by the baseline.
Confirmed changes may still be reported during a partial scan, but the overall
assessment remains inconclusive.

## CLI and report data flow

```text
init:   root -> scan -> validated baseline -> exclusive baseline file
scan:   root + baseline -> scan -> comparison -> text or SecurityReport JSON
report: saved JSON -> bounded strict validation -> historical text view
watch:  fixed baseline -> scan -> compare -> alert transition -> wait -> repeat
```

The JSON report has one versioned envelope with exact fields. File records are
grouped by status and sorted by normalized relative path. Counts and overall
assessment must agree with those records. Unknown records cannot claim a
trusted current digest. Exception class names are constrained before display,
and raw exception messages are never serialized.

Report publication applies the same security properties as baseline
publication: the destination must be outside the monitored root, existing
targets and link-like paths are rejected, data is flushed before publication,
and atomic hard-link creation prevents replacement. A saved report is evidence
from an earlier scan, not a baseline and not a fresh assessment.

## Polling and alert-state flow

The first watch scan runs immediately. After a scan and its output complete, a
monotonic deadline determines the remaining polling wait. The next scan runs
in the same foreground thread, so scans cannot overlap. Scan duration plus the
configured wait determines the effective time between observations.

Assessment and presentation are separate. `ChangeReport` always classifies the
fresh scan relative to the fixed baseline. A bounded dictionary then retains
only fingerprints for findings active in the most recent cycle. A new key or a
changed fingerprint generates an alert; a missing prior key generates a
resolution. Identical active findings are not reprinted, although each cycle
summarizes active change, unknown, and scan-error counts. This state is never
written to disk and disappears when the process exits.

An ordinary `OSError` escaping the scanner becomes a root-scoped structured
error and therefore an inconclusive cycle. Existing structured scanner errors
remain unchanged. `KeyboardInterrupt` during scanning or waiting stops the
loop before another scan begins and returns the last completed session status.
Other unexpected exceptions propagate rather than being hidden.

## Deferred components

Baseline authentication and rotation, event-driven filesystem watching,
background services, notifications, database storage, cloud integrations, and
automatic remediation are deliberately not implemented in Milestone 6.
