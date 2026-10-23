# IntegrityGuard Learning Notes: Milestones 1 through 5

## SHA-256

SHA-256 is a cryptographic hash function in the SHA-2 family. It accepts any
sequence of bytes and produces a fixed-size 256-bit result, commonly displayed
as 64 hexadecimal characters. The same bytes produce the same digest. Even a
small content change should produce a very different digest.

IntegrityGuard hashes bytes rather than interpreting text. This makes the same
function suitable for text, images, executables, archives, and other binary
files. SHA-256 is designed to make finding two different inputs with the same
digest computationally infeasible, although no fixed-size hash can make
collisions mathematically impossible.

## Hashing versus encryption

Hashing is one-way: it creates a compact fingerprint and is not intended to be
reversed. There is no decryption key. IntegrityGuard will compare fingerprints
to identify content changes.

Encryption is reversible for an authorized party with the correct key. Its
goal is confidentiality: preventing unauthorized readers from understanding
data. A hash does not hide a file's contents, and encryption alone does not
provide a stable public fingerprint of those contents.

## File integrity

File integrity means that a file's contents remain complete and unaltered from
an expected state. A future IntegrityGuard baseline will record trusted hashes;
a later scan can calculate new hashes and compare them with those values.

A mismatch shows that the bytes differ. It does not explain why they changed,
identify the person or process responsible, prove that the original baseline
is trustworthy, or classify the file as malicious. Baseline protection and
access controls therefore remain important parts of the security model.

## Streaming reads

Reading a whole file into memory makes memory consumption grow with file size.
IntegrityGuard instead opens a file in binary, read-only mode and feeds SHA-256
one fixed-size chunk at a time. SHA-256 maintains a small internal state, so the
final digest is the same as hashing all bytes at once while application memory
use stays bounded.

The function reports open and read failures through Python's standard
filesystem exceptions. It returns a digest only after reaching the end of the
file, preventing callers from mistaking an incomplete hash for a successful
result.

## Why automated testing matters

Security tools need predictable behavior on ordinary and unusual inputs.
Automated tests make expectations executable and repeatable. Milestone 1 tests
empty, text, binary, and multi-chunk files; missing paths; repeated hashing;
different contents; and invalid chunk sizes.

The tests use pytest temporary directories. They create only synthetic data,
do not depend on a developer's personal files, and are cleaned up by the test
framework. Tests reduce regressions, but passing tests are evidence for the
tested behavior rather than proof that software is free of defects or secure
in every environment.

## Recursive directory traversal

A recursive scan visits a starting directory, processes its regular files, and
repeats the same operation for each child directory. IntegrityGuard uses
`os.scandir()` because each directory entry can provide file type and metadata
efficiently. Traversal and hashing remain separate: the scanner discovers a
file, then delegates its bytes to the Milestone 1 hashing function.

Recursion must have boundaries. IntegrityGuard does not follow links or Windows
reparse points and tracks directory identities it has already visited. These
rules prevent common cycles such as a child link that points back to a parent.

## File metadata

Metadata describes a file without being its content. Milestone 2 records byte
size and modification time. Modification times are converted to timezone-aware
UTC `datetime` values so callers do not accidentally compare local times from
different systems. A timestamp can be missing if the operating system cannot
represent it safely.

Metadata is useful for display and race detection, but it is not proof of file
content. Timestamps can be manipulated, and two files can have the same size.
The SHA-256 digest remains the content fingerprint.

## Relative versus absolute paths

An absolute path includes machine-specific details such as a Windows drive and
the full parent hierarchy. A relative path describes a file starting at the
selected scan root. Relative paths make future baselines portable when the
monitored directory moves.

IntegrityGuard stores result paths relative to the root and uses forward
slashes on every platform. This normalization makes ordering and future JSON
comparison consistent between Windows and other operating systems.

## Symbolic links and junctions

A symbolic link refers to another filesystem path. A Windows directory
junction is another kind of filesystem redirection implemented as a reparse
point. Following either during recursion can leave the intended scan tree,
scan the same data repeatedly, or create a loop.

Milestone 2 skips symbolic links, junctions, and other reparse points. Skipped
paths are listed separately in the report so the decision remains visible.

## Filesystem race conditions

The filesystem can change while a scan is running. A file may be deleted after
discovery, replaced before opening, or modified while bytes are being read.
These time-of-check/time-of-use situations are commonly called TOCTOU races.

IntegrityGuard compares file identity, size, and nanosecond modification time
before and after hashing. If a difference is visible, it discards the digest.
This is detection, not an atomic snapshot: a carefully timed change that
restores the observed metadata can escape detection. Snapshot-capable storage
or operating-system-specific file locking would be needed for stronger
guarantees and is outside this milestone.

## Secure error handling

Treating an unreadable file as deleted would create misleading integrity data.
The scanner therefore keeps errors separate from file records. A failed file
has an `error` status, no digest, and a matching error containing a category
and exception type. A file detected changing during hashing uses a distinct
status and also has no trusted digest.

This design lets a future caller distinguish content state from scanner health
without suppressing evidence. Error messages can contain filesystem paths or
operating-system details, so reports should be protected before sharing them.

## What a baseline is

A baseline is a trusted snapshot of expected file fingerprints and metadata.
Future scans can be compared with it to determine which paths were added,
removed, or modified. A baseline is useful only when its originating scan is
complete, so IntegrityGuard refuses to create one from failed or unstable file
records.

Skipped links are different from failed reads. The scanner deliberately does
not cross links or reparse points, and the baseline records their paths so an
operator can see what was outside the snapshot's scope.

## Versioned JSON schema

JSON is portable, human-readable, and supported by Python's standard library.
The schema version allows later releases to reject or deliberately migrate
formats they do not understand. The hash algorithm identifier prevents a
digest from being interpreted under the wrong algorithm.

Strict validation is important because JSON permits more shapes than the
application expects. IntegrityGuard rejects unknown or missing fields,
duplicate object keys, duplicate file paths, malformed hashes, negative sizes,
invalid timestamps, unsafe paths, and unsupported versions. It also bounds the
number of input bytes before parsing to limit memory consumption.

## Canonical paths

The baseline stores the scan root as a resolved absolute path. File entries use
already-normalized relative paths. The loader never converts a suspicious path
such as `folder/../secret` into an acceptable one; it rejects the input. This
avoids allowing two different strings to alias the same future filesystem path.

Windows paths require special attention because drive-qualified paths,
backslashes, junctions, trailing dots, trailing spaces, and case differences
can create aliases. Baseline file entries therefore use forward slashes and a
strict portable component policy.

## Atomic writes and exclusive creation

An atomic publication changes the visible destination from absent to complete
in one filesystem operation. IntegrityGuard first writes and synchronizes a
temporary file in the destination directory. It then creates the final name as
a hard link to that same file and removes the temporary name.

Hard-link creation is also exclusive: it fails if the destination exists.
This matters because checking `exists()` and then calling a replacement
operation has a race between those actions. `os.replace()` is atomic for
replacement, but replacement is exactly what baseline creation must avoid.

The approach intentionally fails on filesystems without hard-link support.
Falling back to copying or direct creation would expose partial output or lose
race-safe no-overwrite behavior.

## Integrity versus authentication

SHA-256 supports integrity comparison: a changed file normally has a different
digest. It does not authenticate the baseline. If an attacker can edit the
baseline, they can calculate a new digest for their modified file and store
both together.

Authentication needs a secret or private signing key that the baseline attacker
cannot access. An HMAC uses a shared secret, while a digital signature uses a
private signing key and a public verification key. Both are future work. For
now, baseline directories need strong operating-system permissions, backups,
and independent audit controls.

## Baseline filesystem races

Path inspection, temporary creation, publication, and later loading occur at
different times. Link rejection and file-identity checks reduce redirection
risk, but portable Python cannot turn all Windows path operations into one
transaction. An attacker who can write to the baseline directory may still
race those checks. Restricting directory write access is therefore part of the
security model, not an optional deployment detail.

## Comparing a baseline with a current scan

The detector matches baseline and current records by normalized relative path.
A trusted current-only path is added. A baseline-only path is deleted only when
its directory scope was enumerated successfully. Paths found in both states are
modified when their trusted SHA-256 digests differ and unchanged when the
digests match.

Timestamps and sizes are supporting metadata. They can reveal useful context,
but a timestamp-only or size-only difference does not prove a content change.
Conversely, two different byte sequences can have the same size. IntegrityGuard
therefore bases content classification on the digest.

## Unknown is a security result

`unknown` does not mean unchanged, changed, or deleted. It means the available
evidence cannot safely establish the current state. Examples include a failed
file read, a file changing during hashing, an inaccessible directory, or a
regular baseline path becoming a skipped link.

Reporting unknown explicitly prevents a dangerous shortcut: treating every
path missing from a partial scan as deleted. Directory-scoped errors cover all
baseline descendants because the scanner cannot prove that it enumerated those
names. Errors elsewhere do not erase trustworthy evidence for unaffected
paths, but they do make the overall scan incomplete.

## Completeness and conclusiveness

Scan completeness describes whether current traversal and hashing finished
without errors, skipped paths, or untrusted results. Assessment conclusiveness
also considers baseline exclusions and unknown records. A report can contain a
confirmed modification and still be inconclusive about other paths.

A clean result requires both a conclusive assessment and no confirmed added,
deleted, or modified records. This is deliberately stricter than merely having
an empty `modified` list.

## False positives and false negatives

Using SHA-256 rather than timestamps avoids many false modification reports
caused by metadata-only updates. Scoped unknown states prevent false deletion
reports during partial traversal.

False negatives remain possible. Scanning is not an atomic snapshot; an
attacker may restore observable state between checks. A compromised or replaced
baseline can make malicious content appear expected. Excluded links are not
examined, and file-integrity monitoring does not detect memory-only activity or
decide whether unchanged content is safe.

## Command-line interface design

`argparse` subcommands give each workflow its own required inputs and help. The
top-level parser selects `init`, `scan`, or `report`, then dispatches to a small
handler. This keeps interface concerns separate from hashing, traversal,
storage, and comparison. The command layer composes existing APIs instead of
reimplementing them.

Paths with spaces and Unicode characters should be passed as individual
arguments by the shell. `pathlib.Path` carries those values without manual
separator manipulation. The library still performs its own canonicalization
and trust-boundary checks; argument parsing alone does not make a path safe.

## Standard output and standard error

Standard output is the command's result. Standard error is for diagnostics.
That distinction matters when another program parses `--format json`: a warning
or banner mixed into stdout would make otherwise valid JSON unusable. Expected
input, storage, or filesystem failures therefore produce concise stderr text
without a traceback, while successful JSON stdout contains exactly one JSON
document.

Human text favors quick triage: summary counts, changed paths, scan errors, and
an integrity assessment. Large unchanged lists are suppressed unless
`--verbose` is requested. Machine JSON favors deterministic field names,
ordering, types, and schema validation.

## Process exit codes

Exit status is another machine interface. IntegrityGuard uses 0 for a
successful clean assessment, 1 for conclusive detected changes, 2 when a fresh
assessment is incomplete or inconclusive, and 3 for argument or operational
failure. Automation must distinguish 1 from 3: detected changes are a valid
security result, not a crashed command.

A successful `report` view returns 0 even if the historical data records
changes. The viewer validated and displayed a file; it did not make a fresh
claim about the monitored directory.

## Versioned security reports

Report schema version 1 groups sorted records into added, deleted, modified,
unchanged, and unknown categories. Counts are redundant on purpose: strict
loading recalculates them and rejects disagreement. The loader also verifies
hash/status semantics, UTC timestamps, normalized paths, uniqueness,
completeness, conclusiveness, and the overall assessment.

Schemas should fail closed. Silently accepting unknown fields, duplicate JSON
keys, malformed digests, or future schema versions can cause different tools
to interpret the same bytes differently. Bounded reads and exact validation
limit resource consumption and ambiguity at this trust boundary.

## Historical reports versus baselines

A baseline is trusted comparison input describing an expected file state. A
report is output describing one assessment. They are deliberately separate
schemas and are not interchangeable. Loading a report never updates a baseline,
and viewing one never scans the filesystem.

Reports omit the absolute monitored root and raw exception messages because
those can disclose host layout or sensitive details. Relative filenames,
hashes, sizes, timestamps, and security findings may still be sensitive.
Reports therefore need access controls and retention policy, and—like current
baselines—are not authenticated in Milestone 5.

## Safe report publication

Exported reports use create-only atomic publication outside the monitored root.
Rejecting an existing target avoids accidental evidence destruction. Keeping
reports outside the root prevents a scan from detecting its own output.
Rejecting link-like destination components reduces redirection risk, while a
same-directory temporary file plus exclusive hard-link publication avoids a
partially written final name.

These protections have limits. Hard-link support is filesystem-dependent, and
portable path checks cannot eliminate every Windows time-of-check/time-of-use
race against an attacker who can modify the report directory. Restrictive ACLs
remain essential.
