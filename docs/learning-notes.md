# IntegrityGuard Learning Notes: Milestone 1

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
