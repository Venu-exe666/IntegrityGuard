# IntegrityGuard Security Model

## Scope and protected assets

Milestones 3 through 7.2 record SHA-256 fingerprints, compare them with fresh
scanner output, present results through a CLI and saved reports, and repeat
those comparisons in a foreground polling session. The protected assets are
the monitored file contents, assessment accuracy, the stored baseline, exported
report records, and the integrity of the active monitoring state.

IntegrityGuard reads monitored files but does not modify, execute, upload, or
delete them. It makes no network requests and does not elevate privileges.

## Trust boundaries

The monitored filesystem is untrusted while scanning. Files and directories
may disappear, change, or become inaccessible. A baseline JSON file is also
untrusted when loaded and must pass size, syntax, schema, type, timestamp, hash,
ordering, uniqueness, and relative-path validation.

Saved reports cross another trust boundary. Their loader uses a fixed size
limit, rejects duplicate keys, duplicate scan issues, and unknown fields,
validates status-specific hash and metadata semantics,
and checks that counts and assessment flags agree. It also rejects terminal
control data in exception type labels. Viewing a saved report never rescans the
filesystem and is clearly labeled historical.

A baseline can be created only from a `ScanReport` with no errors and with a
trusted hash and complete metadata for every discovered regular file. Symbolic
links, junctions, and reparse points found during inspection are deliberately
excluded, and their paths are recorded in the baseline. Substitutions detected
during opening or traversal instead make the scan incomplete.

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
- Failed scans and skipped subtrees cannot silently create confirmed deletions.
- Untrusted current digests are never used for content classification.
- Unrelated scan roots cannot be compared accidentally.
- JSON stdout contains no banners or diagnostics that would corrupt parsing.
- Report files omit monitored absolute roots and raw exception messages.
- Existing report destinations and report paths inside the root are rejected.
- Invalid or inconsistent historical reports are rejected before rendering.
- Optional scan ceilings bound discovered entries, cumulative hashed bytes, and
  cooperative monotonic elapsed time.
- Watch cycles always compare with the original loaded baseline, never merely
  with the previous scan.
- Identical alert suppression changes presentation only, not classification.
- A root that disappears during monitoring produces UNKNOWN states rather than
  false deletions.
- Foreground synchronous scans cannot overlap or leave worker threads behind.

## Conservative change assessment

A deletion requires positive evidence that the relevant directory scope was
enumerated successfully and the baseline path was absent. If a directory or
entry inspection failed, every affected baseline descendant becomes `unknown`.
A previously regular file that is now a skipped link or reparse point is also
`unknown`, not deleted.

A current file becomes added, modified, or unchanged only when its scanner
status and SHA-256 digest are trusted. Scanner errors remain attached to the
`ChangeReport`; they are not converted into file changes or suppressed.

The detector may still confirm unaffected changes in a partial scan. However,
`scan_complete` and `assessment_conclusive` remain false, and `is_clean` cannot
be true. This prevents a partial result from being summarized as an entirely
clean system.

A configured resource ceiling has the same conservative effect. Already
completed records remain usable, but remaining baseline paths within the
root-scoped error are UNKNOWN. The result is incomplete and inconclusive, never
clean, and cannot be used to create a baseline.

## Residual risks and assumptions

Filesystem checks are not transactions. A local attacker with write access to
the baseline directory may race storage-path checks or tamper with a baseline
after it is saved. Scanner file hashing is handle-bound, but baseline and report
publication still rely on pathname checks and do not provide a kernel-enforced
directory sandbox.

Hard-link publication requires a filesystem that supports hard links. On an
unsupported filesystem IntegrityGuard fails instead of falling back to a
non-atomic or overwrite-capable method. Temporary cleanup is best effort when
the operating system itself denies cleanup.

Report files are not authenticated. Anyone able to replace a report can create
a different internally valid history, and reports may still reveal relative
filenames, hashes, sizes, timestamps, and operational security findings. Store
them with suitable ACLs and retention rules. Terminal output is monochrome and
validated, but shell redirection and surrounding automation remain the
operator's responsibility.

Resource ceilings are application-level cooperative safeguards, not hard CPU,
memory, I/O, or operating-system quotas. A blocking filesystem operation can
delay the next duration check. Directory-name collection is bounded only when
an entry ceiling is configured, and memory use grows up to that ceiling. The
default remains unlimited for compatibility, so deployments should select
limits appropriate to their tree and storage performance.

Reading monitored files may allow the operating system to update access-time
metadata. The scanner requires stable object identity and rejects a pathname
that opens as a different object. It cannot detect every concurrent in-place
write that restores size and timestamps before handle verification, nor can it
detect every directory-entry change restored together with directory metadata.
It also cannot defend against a compromised kernel or deceptive filesystem
implementation.

The detector trusts scanner evidence and the loaded baseline after validation.
It cannot recover a file state hidden by a TOCTOU race, detect kernel-level
filesystem deception, or determine whether matching bytes are benign.

Periodic polling has an observation gap. A short-lived change that begins and
ends between two scans may not be detected. A shorter interval narrows that gap
but increases file reads, hashing work, CPU usage, and disk I/O. Large trees or
slow storage increase scan duration, which is added to the configured wait.

Monitoring alert state exists only in process memory and contains current
relative paths and finding fingerprints. It is intentionally not persisted or
sent elsewhere. Error fingerprints use sanitized category, relative path,
exception label, and numeric errno/winerror; raw exception messages and
absolute paths are not printed. Restarting a session forgets suppression history and reports
active findings again. Repeated identical scan errors are summarized on every
cycle so operational failures do not disappear indefinitely.

Ctrl+C is handled in the foreground loop. An interruption during a wait or
scan prevents another scan from launching and preserves the last fully
completed status for the final summary. OS-level force termination, power loss,
or interpreter failure cannot guarantee that summary output appears.

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

## Why a clean report is not proof of safety

A conclusive clean report means that all tracked regular files successfully
scanned under the current policy have the expected SHA-256 values. It does not
prove that the host is uncompromised. An attacker might alter excluded data,
tamper with an unauthenticated baseline, evade a non-atomic scan, operate only
in memory, or compromise components below the scanner's trust boundary.

## Explicit non-goals for Milestone 7.2

Milestone 7.2 does not provide real-time event monitoring, detect malware,
prevent or remediate file changes, authenticate or rotate baselines, update
baselines automatically, install a background service, send notifications, or
use databases, telemetry, external logging, or cloud services.
