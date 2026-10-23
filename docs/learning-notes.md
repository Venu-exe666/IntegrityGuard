# IntegrityGuard Learning Notes: Milestones 1 and 2

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
