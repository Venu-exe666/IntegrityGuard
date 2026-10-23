# IntegrityGuard Security Model

## Scope and protected assets

Milestone 3 records SHA-256 fingerprints and metadata for regular files found
by a completed scan. The protected assets are the monitored file contents, the
accuracy of the scan result, and the stored baseline used by future comparison.

IntegrityGuard reads monitored files but does not modify, execute, upload, or
delete them. It makes no network requests and does not elevate privileges.

## Trust boundaries

The monitored filesystem is untrusted while scanning. Files and directories
may disappear, change, or become inaccessible. A baseline JSON file is also
untrusted when loaded and must pass size, syntax, schema, type, timestamp, hash,
ordering, uniqueness, and relative-path validation.

A baseline can be created only from a `ScanReport` with no errors and with a
trusted hash and complete metadata for every discovered regular file. Skipped
symbolic links, junctions, and reparse points are allowed because the scanner
deliberately excludes their targets. Their paths are recorded in the baseline.

## Storage policy

Baselines must be stored outside the monitored directory. Otherwise a later
scan could include its own baseline, creating self-reference and noisy changes.
The destination parent must already exist and must not contain symbolic links,
junctions, or other reparse points. Windows case-insensitive aliases are
considered during containment checks.

Saving is create-only. A same-directory temporary file is written and flushed,
then atomically published with a hard link. The operation fails if the final
name exists, including when two processes race to create it. Failed operations
attempt to remove the temporary file. The storage directory should grant write
access only to trusted administrators or the IntegrityGuard service account.

## Threats addressed

- Incomplete scans cannot silently become trusted baselines.
- Malformed, oversized, duplicate, or incompatible JSON is rejected.
- Absolute paths, traversal components, backslashes, and unsafe Windows path
  aliases are rejected rather than normalized.
- Existing baseline files and destination links are not overwritten.
- Temporary-file publication avoids a partially written final baseline.
- Link and reparse-point checks reduce destination redirection risk.

## Residual risks and assumptions

Filesystem checks are not transactions. A local attacker with write access to
the baseline directory may race path checks or tamper with a baseline after it
is saved. The portable standard-library design reduces these windows but cannot
provide a Windows kernel handle-based directory sandbox.

Hard-link publication requires a filesystem that supports hard links. On an
unsupported filesystem IntegrityGuard fails instead of falling back to a
non-atomic or overwrite-capable method. Temporary cleanup is best effort when
the operating system itself denies cleanup.

Reading monitored files may allow the operating system to update access-time
metadata. Scanner pre/post checks cannot detect every adversarial change that
restores identity, size, and timestamps before verification.

## Integrity is not authentication

SHA-256 can show that bytes differ from a stored digest. It cannot establish
who created the baseline or whether an attacker replaced both the file hash and
the baseline record. A JSON baseline is not authentic merely because it
contains cryptographic hashes.

Use operating-system ACLs, restricted directories, backups, and independent
audit logs to protect current baselines. A future milestone may add an HMAC or
digital signature. Secret keys or signing keys must be stored separately from
the baseline; keeping a key beside the file would not provide meaningful
protection against the same attacker.

## Explicit non-goals for Milestone 3

Milestone 3 does not detect malware, prevent file changes, compare scans,
authenticate baselines, rotate existing baselines, provide a CLI, or perform
background monitoring and notifications.
