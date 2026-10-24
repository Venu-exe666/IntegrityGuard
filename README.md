# IntegrityGuard

IntegrityGuard is a Python file integrity monitoring (FIM) project for learning
secure software development and practical cybersecurity engineering. It is
being developed incrementally as a command-line application.

## Current status

Milestones 1 through 6 plus Milestones 7.1 through 7.3 provide streaming
SHA-256 hashing, a reusable recursive directory scanner, secure versioned JSON
baseline storage, conservative
file-integrity change detection, a user-facing CLI with versioned reports, and
foreground periodic monitoring. The 7.x hardening adds handle-bound scanning,
strict report-state validation, optional scan resource ceilings, and structured
watch-error deduplication. Milestone 7.3 adds a least-privilege GitHub Actions
matrix and explicit POSIX/Windows security suites. Background services and
notifications are **not implemented**.

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
- excludes symbolic links, directory junctions, and Windows reparse points
  found during inspection;
- hashes an already-open file object and binds metadata checks to that handle;
  and
- rejects detected identity substitutions and changes during hashing; and
- optionally limits discovered entries, cumulative bytes hashed, and elapsed
  scan time; a reached limit is a structured incomplete-scan error.

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

CLI, reporting, and monitoring:

- provide `init`, `scan`, `report`, and `watch` commands through `argparse`;
- keep human-readable and machine-readable output separate;
- use documented exit codes for clean, changed, inconclusive, and failed runs;
- serialize deterministic, strictly validated report schema version 1 JSON;
- reject status/metadata contradictions and duplicate persisted scan issues;
- omit absolute monitored roots and raw filesystem error messages from reports;
- refuse to overwrite report files or store them inside the monitored root; and
- clearly identify saved reports as historical rather than fresh scans.

The `watch` command repeatedly compares fresh scans with the same trusted
baseline, suppresses identical repeated alerts in memory, reports meaningful
error-code transitions and resolutions,
and exits cleanly on Ctrl+C. It remains a foreground polling command: it does
not update the baseline, run as a service, or provide real-time detection.

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

On Linux or macOS, the equivalent test command is:

```bash
python -m pytest -v -ra
```

The editable installation creates an `integrityguard` console command. Without
activating the environment, invoke it explicitly as
`.\.venv\Scripts\integrityguard.exe`.

## Continuous integration

The workflow in `.github/workflows/ci.yml` is configured for these jobs:

| Runner | Python |
| --- | --- |
| `ubuntu-latest` | 3.12 |
| `ubuntu-latest` | 3.13 |
| `windows-latest` | 3.12 |
| `windows-latest` | 3.13 |

It runs on pushes to `main`, pull requests targeting `main`, and manual
dispatch. Each job installs the project with its test extra, verifies package
imports and dependencies, exercises installed CLI help/version behavior, and
runs the complete pytest suite with skip reasons. The workflow grants only
`contents: read`, persists no checkout credential, uses no project secrets or
project-specific external services, and has a 20-minute job timeout.

This matrix is configuration until GitHub-hosted jobs actually pass. Local
Windows results do not establish Ubuntu or Python 3.12 behavior. Recommended
branch protection should require all four matrix jobs before merging to
`main`; repository settings are not managed by this project.

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

### Optional scan limits

The `init`, `scan`, and `watch` commands accept the same optional ceilings:

```powershell
integrityguard scan `
  --root .\demo\monitored `
  --baseline .\demo\state\baseline.json `
  --max-entries 100000 `
  --max-bytes 1073741824 `
  --max-seconds 300
```

All three limits are opt-in to preserve existing workflows. `--max-entries`
counts every enumerated filesystem entry, including entries later skipped;
`--max-bytes` counts bytes actually supplied to SHA-256 across the scan; and
`--max-seconds` uses a monotonic clock. Reaching any ceiling stops that scan,
records a sanitized `ScanLimitExceededError`, and makes comparison exit 2
(inconclusive). `init` refuses to create a baseline from such a scan.

### Periodic monitoring

Start a foreground watch session with the default ten-second interval:

```powershell
Set-Location G:\PROJECTSS\IntegrityGuard
.\.venv\Scripts\integrityguard.exe watch `
  --root .\demo\monitored `
  --baseline .\demo\state\baseline.json
```

Or select another interval of at least one second:

```powershell
.\.venv\Scripts\integrityguard.exe watch `
  --root .\demo\monitored `
  --baseline .\demo\state\baseline.json `
  --interval 5 `
  --verbose
```

The first scan runs immediately. Each later scan starts after the interval has
elapsed following completion of the previous scan. A session may therefore
observe changes less often than the configured interval when hashing takes a
long time. Press Ctrl+C to stop it; normal user-requested shutdown returns 0.

Example output:

```text
IntegrityGuard | Monitoring

Root: G:\PROJECTSS\IntegrityGuard\demo\monitored
Interval: 10 seconds
Baseline: Validated fixed reference
Press Ctrl+C to stop monitoring.
[12:00:00Z] Initial assessment complete
[12:00:00Z] No integrity changes detected
[12:00:10Z] MODIFIED  example.txt
[12:00:20Z] No new alerts (active changes: 1, unknown: 0, scan errors: 0)
[12:00:30Z] RESOLVED  example.txt (previously modified)

Monitoring stopped.
Completed scans: 4
Final assessment: clean
```

Every cycle is still compared with the saved baseline. Suppressing an identical
terminal alert does not reclassify the file as unchanged or acknowledge the
change. Resolutions mean only that a finding is no longer observed; they do not
prove the system is safe. Incomplete scans remain explicitly inconclusive, and
repeated scan errors produce a per-cycle active-error reminder.

### Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Successful operation, clean scan, or user-requested watch shutdown |
| 1 | Fresh scan conclusively detected one or more changes |
| 2 | Fresh scan was incomplete or its assessment was inconclusive |
| 3 | Invalid arguments, unsafe paths, invalid data, or another operational failure |

The `report` command returns 0 after successfully validating and displaying a
historical report, even if that report records changes. It does not perform a
fresh integrity assessment. `watch` returns 3 for startup configuration errors;
individual recoverable scan failures remain visible as incomplete cycles.

### JSON report schema

Report schema version 1 contains the generation timestamp, overall assessment,
category counts, sorted file-change records, sanitized scan issues, skipped
paths, and completeness/conclusiveness flags. Its loader cross-checks hashes,
available metadata, `metadata_changed`, unknown reasons, status categories, and
duplicate issues. It does not contain file contents,
the absolute monitored root, or raw exception messages. Treat reports as
sensitive security records despite these omissions.

Common failures are sent to standard error without a traceback. If publication
fails on a filesystem without hard-link support, choose an NTFS directory that
supports hard links. Creating symbolic-link test fixtures on Windows may require
Developer Mode or elevated privileges; those tests probe support and report an
explicit skip when unavailable. Real Windows junction coverage does not rely on
symlink privilege and uses temporary directories only. A skipped privileged
test is an unverified behavior, not evidence that the protection passed.

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
from integrityguard.scanner import ScanLimits, scan_directory

report = scan_directory(
    "path/to/directory",
    limits=ScanLimits(max_entries=100_000, max_bytes=1_073_741_824),
)
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

Milestones 7.1 through 7.3 add handle-bound scanner hashing, adversarial race
tests, strict report validation, resource ceilings, safer watch deduplication,
and cross-platform CI/security-test configuration.
Baseline authentication or
rotation, background service operation, notifications, and release engineering
remain future work.

## Security limitations

Directory scans are not atomic filesystem snapshots. The scanner opens files
with no-follow or reparse-point controls, verifies the opened object's identity,
hashes that same handle, and checks it again afterward. POSIX traversal uses
directory-relative descriptors. Windows holds directory and file handles
without delete sharing while they are in use. These controls close the
confirmed pathname-reopen vulnerability, but they cannot detect every
concurrent in-place write that restores observable metadata or deception below
the operating-system filesystem interface. A transient directory-entry change
that is restored together with directory metadata can also evade a sequential
enumeration.

SHA-256 does not authenticate a baseline. Anyone who can alter a baseline can
replace both a stored digest and its related metadata. Baseline files therefore
need operating-system access controls and backups. Digital signatures or an
HMAC with separately protected keys are future enhancements, not implemented
features.

A clean comparison is evidence about the files successfully scanned under the
configured policy. It is not proof that a system is uncompromised, malware-free,
or free from changes hidden by filesystem races, excluded paths, or a tampered
baseline.

Polling is not real-time monitoring. A file created, changed, and restored
between scans may never be observed. Shorter intervals reduce that window but
increase CPU use, disk reads, and hashing activity. Scan duration also extends
the effective observation interval, and concurrent filesystem changes retain
the scanner's documented TOCTOU limitations.

Limits reduce exposure to unexpectedly large trees but are not quotas enforced
by the operating system. A single filesystem call or chunk read can block past
the time ceiling, names collected for one directory still consume memory up to
the remaining entry limit, and leaving limits unset preserves unbounded legacy
behavior. A limit-hit cycle is never clean: unscanned baseline paths remain
UNKNOWN, and watch mode suppresses identical alert lines while continuing to
show an incomplete-cycle reminder.

## License

The project metadata declares the MIT License. A full license file will be
added before distribution.
