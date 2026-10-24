# Changelog

All notable changes to IntegrityGuard are documented in this file. The project
uses semantic versioning from the 1.0.0 release onward.

## [1.0.0] - 2026-10-24

### Added

- Streaming SHA-256 hashing for paths and already-open binary streams.
- Recursive, deterministic scanning with normalized relative paths and
  structured error reporting.
- Versioned baseline schema 1 with bounded parsing and create-only atomic
  publication.
- Conservative added, deleted, modified, unchanged, and unknown detection.
- `init`, `scan`, `report`, and foreground `watch` CLI commands.
- Versioned report schema 1, sanitized scan issues, and historical reports.
- Optional entry, byte, and elapsed-time scan limits.
- Cross-platform GitHub Actions testing on Windows and Ubuntu with Python 3.12
  and 3.13.

### Security

- Bound scanner hashing and metadata checks to the same opened file object.
- Added POSIX descriptor-relative no-follow traversal and Windows reparse-point
  handle checks.
- Preserved incomplete scans as inconclusive and prevented uncertain paths
  from becoming false deletions or clean assessments.
- Enforced strict report-state validation, input-size limits, safe relative
  paths, exclusive output creation, and sanitized monitoring fingerprints.
- Added adversarial path-replacement, symlink, junction, partial-scan, and
  resource-limit regression tests.

### Known limitations

- Scans are sequential observations, not atomic filesystem snapshots.
- Baselines and reports are not cryptographically authenticated.
- Monitoring is polling-based and does not remove or identify malware.

[1.0.0]: https://github.com/Venu-exe666/IntegrityGuard/releases/tag/v1.0.0
