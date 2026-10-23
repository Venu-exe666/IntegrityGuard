# IntegrityGuard

IntegrityGuard is a Python file integrity monitoring (FIM) project for learning
secure software development and practical cybersecurity engineering. It is
being developed incrementally as a command-line application.

## Current status

Milestone 1 provides one reusable capability: streaming SHA-256 hashing for
text and binary files. Directory scanning, baselines, change detection,
reports, the CLI, and background monitoring are planned but are **not yet
implemented**.

The hashing function:

- opens files read-only in binary mode;
- reads fixed-size chunks instead of loading an entire file into memory;
- returns a lowercase SHA-256 hexadecimal digest; and
- preserves standard filesystem exceptions when a file cannot be fully read.

Hashing detects content differences; it does not identify malware, prove who
changed a file, or prevent changes.

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

## Project layout

```text
src/integrityguard/   Python package
tests/                Automated tests using synthetic temporary files
docs/learning-notes.md
                      Milestone 1 learning material
```

## Roadmap

The next milestone will add secure recursive directory scanning using
normalized relative paths without following symbolic links by default. Later
milestones will introduce baselines, change detection, reporting, a CLI, and
optional monitoring.

## License

The project metadata declares the MIT License. A full license file will be
added before distribution.
