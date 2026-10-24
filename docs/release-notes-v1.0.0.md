# IntegrityGuard v1.0.0 Release Notes (Draft)

IntegrityGuard 1.0.0 is the first stable portfolio release of the local,
standard-library-only file integrity monitoring CLI.

## Highlights

- Streams SHA-256 hashing without loading whole files into memory.
- Recursively scans regular files with deterministic normalized paths.
- Creates versioned, strictly validated, create-only baselines.
- Reports added, deleted, modified, unchanged, and unknown states.
- Produces human-readable output and versioned JSON security reports.
- Repeats comparisons against a fixed baseline with foreground `watch` mode.
- Supports optional entry, byte, and scan-duration limits.
- Uses handle-bound hashing, link/reparse-point controls, and conservative
  incomplete-scan classification.

## Compatibility

- Python 3.12 or newer.
- Tested by CI on Ubuntu and Windows with Python 3.12 and 3.13.
- Baseline schema remains version 1.
- Report schema remains version 1.
- CLI commands and exit codes remain compatible with the pre-1.0 implementation.
- No third-party runtime dependencies are required.

## Security notes

The release closes the confirmed pathname-reopen hashing race by hashing an
already-open object and validating metadata against that handle. It also adds
strict persisted-report validation, resource ceilings, safer watch-error
fingerprints, and cross-platform adversarial tests.

IntegrityGuard is not an atomic snapshot system. Concurrent in-place writes,
privileged filesystem attackers, deceptive filesystems, and changes occurring
entirely between polling cycles may evade observation. Baselines and reports
are not signed or authenticated. The tool detects byte-level differences under
its scan policy; it does not identify or remove malware.

## Upgrade notes

No baseline or report migration is required. Existing valid schema-version-1
documents remain supported. Operators should continue storing baselines and
reports outside monitored roots with restrictive operating-system permissions.

This document is a draft until the release commit passes the complete GitHub
Actions matrix and an approved `v1.0.0` tag is created.
