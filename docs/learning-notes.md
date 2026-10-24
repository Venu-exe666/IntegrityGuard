# IntegrityGuard Learning Notes: Milestones 1 through 7.2

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

Python's `bool` is a subclass of `int`, so `isinstance(True, int)` is true.
Security-sensitive numeric validation uses `type(value) is int` here: chunk
sizes accept genuine positive integers while rejecting booleans, floats,
strings, zero, and negative values.

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
`os.scandir()` to enumerate names, then performs security-sensitive metadata
checks through held directory descriptors where the platform supports them.
Traversal and hashing remain separate: the scanner securely opens the object,
then delegates that open binary stream to the hashing function.

Recursion must have boundaries. IntegrityGuard excludes links and Windows
reparse points detected during inspection and tracks directory identities it
has already visited. Platform-specific no-follow opens and post-open checks
reject detected substitutions. These rules prevent common cycles such as a
child link that points back to a parent without claiming an atomic snapshot.

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

IntegrityGuard does not validate one pathname and ask the hasher to open it
again. It opens the object once, compares the inspected entry with `fstat()`,
hashes that same handle, and performs handle and entry checks afterward. POSIX
uses descriptor-relative operations with `O_NOFOLLOW`. Windows opens reparse
points themselves for inspection and denies delete sharing while handles are
active. A stable identity is mandatory; without one, scanning fails closed.

This is still not an atomic snapshot. On systems that allow concurrent writes,
a process can alter bytes in place while they are read. If it restores size and
timestamps quickly enough, metadata checks may not reveal that the digest was
calculated across multiple content states. Filesystem snapshots or stronger
platform-specific locking are required to rule out that class of attack. A
directory entry can likewise disappear and be restored between enumeration and
the final directory check; restoring its directory metadata can conceal the
temporary omission.

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

## Cooperative resource limits

Traversal can be adversarial even when every file is ordinary: a directory can
contain huge numbers of names, files can be enormous, and repeated watch scans
can multiply the work. `ScanLimits` optionally caps enumerated entries,
cumulative bytes passed to hashing, and monotonic elapsed time. Enforcement
happens while names and bytes are consumed, not after a complete unbounded list
or hash operation.

The time limit is cooperative. It is checked around operations but cannot
preempt a filesystem call blocked in the kernel. Deterministic sorting also
requires holding the permitted names for one directory in memory. These limits
reduce exposure; they are not an atomic snapshot or an OS-enforced sandbox.
When one is reached, the root-scoped error deliberately turns unobserved paths
into UNKNOWN and prevents a false clean or false deletion result.

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
hash/status semantics, status-specific metadata combinations,
`metadata_changed`, UNKNOWN reasons, UTC timestamps, normalized paths,
uniqueness, completeness, conclusiveness, and the overall assessment.

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

## Periodic polling versus event-driven monitoring

Periodic polling scans the complete selected tree, waits, and scans again. It
uses only portable Python and reuses the same trustworthy scanner behavior on
Windows. Event-driven monitoring instead asks an operating-system facility to
report filesystem events. Event APIs can react faster and avoid repeatedly
hashing unchanged trees, but they are platform-specific, may overflow event
queues, and still need verification scans. Milestone 6 implements polling only.

Polling is not real-time detection. A file can be created, changed, and restored
entirely between observations. Reducing the interval narrows that opportunity
but consumes more CPU time, disk bandwidth, cache capacity, and energy. A scan
of a large or slow tree can itself take longer than the configured interval.

## Foreground scheduling and monotonic time

The first watch scan starts immediately. After each scan finishes, the engine
uses a monotonic clock to calculate the polling wait. Monotonic time is suitable
for elapsed-duration scheduling because wall-clock corrections cannot make it
jump backward or forward. UTC wall-clock time remains appropriate for labels
and session records.

Scanning and waiting happen sequentially in the main thread. This prevents
overlapping scans, eliminates worker-thread shutdown problems, and means scan
duration is added to the configured wait. `time.sleep()` avoids busy waiting,
so the idle monitor does not continuously consume a CPU core.

## A fixed baseline is not the previous scan

Every watch cycle compares its fresh `ScanReport` to the same loaded trusted
`Baseline`. If baseline hash A changes to B, later scans containing B remain
modified relative to A. Treating B as the new reference would silently
acknowledge an unapproved change and defeat integrity monitoring.

The watch process never writes, replaces, or updates the baseline. Operators
must use a separate explicit trust decision and baseline-management workflow
for any future approved update.

## Alert deduplication is presentation state

Repeatedly printing the same modified path every few seconds creates noise, but
changing its integrity classification would be incorrect. The monitor therefore
keeps a bounded in-memory map of findings active in the most recent cycle. Its
fingerprints include classification and the current trusted hash where one is
available.

For scan failures the fingerprint also includes the sanitized error category,
relative path, exception type, errno, and winerror. This distinguishes, for
example, permission loss from a later missing-file error even when Python uses
the same exception class. Raw operating-system messages are excluded because
they can contain absolute paths or other sensitive text.

A new key or changed fingerprint is displayed. A key that disappears produces
a resolution. This makes a new hash, classification change, resolved issue, or
reappearing issue visible while suppressing identical repetitions. The map is
replaced every cycle, is never persisted, and is forgotten on restart.

Resolution means only that the particular finding is no longer observed. A
file matching its baseline-observed bytes again does not prove that no malicious
activity occurred or that the wider system is safe.

## UNKNOWN during monitoring

An inaccessible file, interrupted hash, skipped path, or failed subtree remains
UNKNOWN. If the root disappears after monitoring begins, baseline files in the
affected scope become UNKNOWN rather than deleted because successful enumeration
did not prove their absence. The entire assessment is inconclusive.

New structured scan errors are displayed immediately. Identical recurring
errors may be deduplicated as alert lines, but every cycle continues to show the
number of active errors and an incomplete-assessment warning. When an UNKNOWN
file later has a trusted digest, its new trusted classification is displayed.

## Ctrl+C and deterministic cleanup

Python delivers an interactive Ctrl+C as `KeyboardInterrupt` in the main
thread. The polling loop catches it around both scanning and sleeping, launches
no further scan, and returns the last completely recorded status. The CLI then
prints start time, completed scan count, last scan time, final assessment,
active changes, unknown findings, and scan-error count before exiting with 0.

No worker threads, child services, network clients, or persistent alert stores
need cleanup. A force-kill, power failure, or OS crash is different from Ctrl+C
and may prevent final output.

## Monitoring races and Windows considerations

Repeating scans does not eliminate all TOCTOU limits. Handle-bound hashing
prevents a pathname replacement from changing which object supplies the bytes,
and Windows sharing rules prevent renaming an opened scan object. Each scan is
still a sequence rather than an atomic snapshot, so in-place writes and
permissions can change between operations. Junctions and reparse points found
during inspection remain outside the monitored scope.

PowerShell paths containing spaces should be quoted when entered manually.
IntegrityGuard writes UTF-8 terminal streams so Unicode relative paths survive
redirection. Very aggressive intervals can contend with applications and
security software for Windows filesystem and antivirus scanning resources;
start with the ten-second default and tune using measured scan duration.
