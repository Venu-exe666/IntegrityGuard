# IntegrityGuard

IntegrityGuard is a Python file integrity monitoring (FIM) project for learning
secure software development and practical cybersecurity engineering. It is
being developed incrementally as a command-line application.

## Current status

Milestones 1 through 4 provide streaming SHA-256 hashing, a reusable recursive
directory scanner, secure versioned JSON baseline storage, and conservative
file-integrity change detection. Report exporting, the CLI, and background
monitoring are planned but are **not yet implemented**.

The hashing function:

- opens files read-only in binary mode;
- reads fixed-size chunks instead of loading an entire file into memory;
- returns a lowercase SHA-256 hexadecimal digest; and
- preserves standard filesystem exceptions when a file cannot be fully read.

Hashing detects content differences; it does not identify malware, prove who
changed a file, or prevent changes.

The directory scanner:

- recursively discovers regular files;
- returns hashes, byte sizes, UTC modification times, and scan statuses;
- normalizes relative paths with forward slashes and sorts them predictably;
- reports read and traversal errors separately;
- skips symbolic links, directory junctions, and Windows reparse points; and
- detects common signs that a file changed while it was being hashed.

Baseline management:

- accepts only complete scans with trusted file hashes;
- stores a versioned, strictly validated JSON document;
- records the canonical scan root and intentionally skipped link paths;
- rejects malformed hashes, timestamps, paths, duplicates, and unknown fields;
- enforces a 16 MiB default input limit;
- requires storage outside the monitored directory; and
- creates new files atomically without replacing an existing baseline.

Change detection:

- matches files using normalized relative paths;
- compares trusted SHA-256 values rather than timestamps alone;
- classifies files as added, deleted, modified, unchanged, or unknown;
- keeps metadata-only differences visible without calling them modifications;
- preserves structured scanner errors in the result;
- prevents failed or skipped subtrees from producing false deletions; and
- rejects comparisons between unrelated scan roots.

## Requirements

- Python 3.12 or newer
- pytest 8 or newer for development and testing

The application has no third-party runtime dependencies.

## Development setup (PowerShell)

Create and activate a virtual environment if one does not already exist:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the package in editable mode with its development dependency:

```powershell
python -m pip install -e ".[dev]"
```

Run the tests:

```powershell
python -m pytest
```

## Minimal usage

```python
from integrityguard.hashing import sha256_file

digest = sha256_file("path/to/file.bin")
print(digest)
```

Callers should handle filesystem exceptions such as `FileNotFoundError` and
`PermissionError`. IntegrityGuard does not suppress these failures or return a
digest for an incomplete read.

Scan a directory and inspect successful files and errors separately:

```python
from integrityguard.scanner import scan_directory

report = scan_directory("path/to/directory")
for file in report.files:
    print(file.relative_path, file.sha256, file.status)
for error in report.errors:
    print(error.relative_path, error.kind, error.message)
```

The scanner returns filesystem problems in `report.errors`; it does not raise
ordinary missing-path, permission, or mid-scan deletion errors. Files that fail
or change during scanning have no trusted digest.

Create, save, and load a baseline outside the monitored directory:

```python
from integrityguard.baseline import create_baseline, load_baseline, save_baseline
from integrityguard.scanner import scan_directory

report = scan_directory("C:/monitored")
baseline = create_baseline(report)
save_baseline(baseline, "C:/integrity-data/baseline.json")
loaded = load_baseline("C:/integrity-data/baseline.json")
```

`save_baseline()` never overwrites its destination. Replace or rotation policy
must be an explicit future operation rather than an accidental side effect.

Compare a validated baseline with a fresh scan:

```python
from integrityguard.detector import compare_baseline
from integrityguard.scanner import scan_directory

current_scan = scan_directory("C:/monitored")
changes = compare_baseline(loaded, current_scan)

for change in changes.modified:
    print(change.relative_path, change.previous_sha256, change.current_sha256)
for unknown in changes.unknown:
    print(unknown.relative_path, unknown.unknown_reason)
```

`changes.is_clean` is true only when the assessment is conclusive and no
added, deleted, or modified files were confirmed. A scan containing errors or
skipped paths is never presented as completely clean.

## Project layout

```text
src/integrityguard/   Python package
tests/                Automated tests using synthetic temporary files
docs/learning-notes.md
                      Security and implementation learning material
docs/architecture.md  Current component and trust-boundary design
docs/security-model.md
                      Assets, threats, assumptions, and limitations
```

## Roadmap

The next milestone can add user-facing CLI commands and report presentation on
top of the existing library APIs. Report file exporting, optional monitoring,
and notifications remain future work.

## Security limitations

Directory scans are not atomic filesystem snapshots. Another process can
change a file between discovery, hashing, and the final metadata check. The
scanner detects common size, timestamp, and identity changes, but cannot detect
every adversarial race.

SHA-256 does not authenticate a baseline. Anyone who can alter a baseline can
replace both a stored digest and its related metadata. Baseline files therefore
need operating-system access controls and backups. Digital signatures or an
HMAC with separately protected keys are future enhancements, not implemented
features.

A clean comparison is evidence about the files successfully scanned under the
configured policy. It is not proof that a system is uncompromised, malware-free,
or free from changes hidden by filesystem races, excluded paths, or a tampered
baseline.

## License

The project metadata declares the MIT License. A full license file will be
added before distribution.
