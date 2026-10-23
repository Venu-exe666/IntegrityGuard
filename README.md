# IntegrityGuard

IntegrityGuard is a Python file integrity monitoring (FIM) project for learning
secure software development and practical cybersecurity engineering. It is
being developed incrementally as a command-line application.

## Current status

Milestones 1 through 5 provide streaming SHA-256 hashing, a reusable recursive
directory scanner, secure versioned JSON baseline storage, conservative
file-integrity change detection, and a user-facing CLI with versioned reports.
Background monitoring and notifications are **not implemented**.

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

CLI and reporting:

- provide `init`, `scan`, and `report` commands through `argparse`;
- keep human-readable and machine-readable output separate;
- use documented exit codes for clean, changed, inconclusive, and failed runs;
- serialize deterministic, strictly validated report schema version 1 JSON;
- omit absolute monitored roots and raw filesystem error messages from reports;
- refuse to overwrite report files or store them inside the monitored root; and
- clearly identify saved reports as historical rather than fresh scans.

## Requirements

- Python 3.12 or newer
- pytest 8 or newer for development and testing

The application has no third-party runtime dependencies.

## Development setup (PowerShell)

Create and activate a virtual environment if one does not already exist:

```powershell
Set-Location G:\PROJECTSS\IntegrityGuard
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the package in editable mode with its development dependency:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Run the tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

The editable installation creates an `integrityguard` console command. Without
activating the environment, invoke it explicitly as
`.\.venv\Scripts\integrityguard.exe`.

## Command-line workflow

The baseline and exported report must be outside the monitored directory. This
example uses synthetic files and separate state storage under the project root:

```powershell
Set-Location G:\PROJECTSS\IntegrityGuard
New-Item -ItemType Directory -Force .\demo\monitored, .\demo\state
Set-Content -LiteralPath .\demo\monitored\example.txt -Value "original"

integrityguard init `
  --root .\demo\monitored `
  --baseline .\demo\state\baseline.json

integrityguard scan `
  --root .\demo\monitored `
  --baseline .\demo\state\baseline.json

Set-Content -LiteralPath .\demo\monitored\example.txt -Value "changed"
integrityguard scan `
  --root .\demo\monitored `
  --baseline .\demo\state\baseline.json `
  --format json `
  --output .\demo\state\change-report.json

integrityguard report --input .\demo\state\change-report.json
```

Baseline initialization produces a short confirmation such as:

```text
IntegrityGuard baseline created.
Files recorded: 1
Skipped link paths: 0
Baseline: G:\PROJECTSS\IntegrityGuard\demo\state\baseline.json
```

After `example.txt` changes, the assessment includes:

```text
IntegrityGuard | File Integrity Report

Scan summary
  Added:                 0
  Modified:              1
  Deleted:               0
  Unchanged:             0
  Unknown:               0
  Scan complete:         yes
  Assessment conclusive: yes

File changes
  Modified:
    - example.txt

Integrity assessment
  Integrity changes detected.
```

Use `integrityguard --help` or `integrityguard <command> --help` for the full
argument reference. Text scans hide individual unchanged paths by default;
add `--verbose` to display them. A JSON scan writes JSON alone to standard
output unless `--output` is supplied. Diagnostics go to standard error. Both
streams are configured as UTF-8 so Unicode paths remain stable when redirected.

### Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Successful initialization, conclusive clean scan, or successful report view |
| 1 | Fresh scan conclusively detected one or more changes |
| 2 | Fresh scan was incomplete or its assessment was inconclusive |
| 3 | Invalid arguments, unsafe paths, invalid data, or another operational failure |

The `report` command returns 0 after successfully validating and displaying a
historical report, even if that report records changes. It does not perform a
fresh integrity assessment.

### JSON report schema

Report schema version 1 contains the generation timestamp, overall assessment,
category counts, sorted file-change records, sanitized scan issues, skipped
paths, and completeness/conclusiveness flags. It does not contain file contents,
the absolute monitored root, or raw exception messages. Treat reports as
sensitive security records despite these omissions.

Common failures are sent to standard error without a traceback. If publication
fails on a filesystem without hard-link support, choose an NTFS directory that
supports hard links. Creating symbolic-link test fixtures on Windows may require
Developer Mode or elevated privileges; those tests skip when unavailable.

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

Milestone 5 is complete. Baseline authentication or rotation, optional
monitoring, and notifications remain future work and are not exposed by the
current CLI.

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
