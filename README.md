# IntegrityGuard

IntegrityGuard is a Python file integrity monitoring (FIM) project for learning
secure software development and practical cybersecurity engineering. It is
being developed incrementally as a command-line application.

## Current status

Milestones 1 and 2 provide streaming SHA-256 hashing and a reusable recursive
directory scanner. Baselines, change detection, report formats, the CLI, and
background monitoring are planned but are **not yet implemented**.

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

## Project layout

```text
src/integrityguard/   Python package
tests/                Automated tests using synthetic temporary files
docs/learning-notes.md
                      Security and implementation learning material
docs/architecture.md  Current component and trust-boundary design
```

## Roadmap

The next milestone will introduce versioned baseline storage using the scanner
results. Later milestones will add change detection, reporting, a CLI, and
optional monitoring.

## Security limitations

Directory scans are not atomic filesystem snapshots. Another process can
change a file between discovery, hashing, and the final metadata check. The
scanner detects common size, timestamp, and identity changes, but cannot detect
every adversarial race. Protecting future baseline files is also outside the
current milestone.

## License

The project metadata declares the MIT License. A full license file will be
added before distribution.
