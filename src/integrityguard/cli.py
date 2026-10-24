"""Command-line interface for IntegrityGuard."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

from integrityguard import __version__
from integrityguard.baseline import (
    BaselineError,
    create_baseline,
    load_baseline,
    save_baseline,
)
from integrityguard.detector import DetectorError, compare_baseline
from integrityguard.monitoring import (
    DEFAULT_INTERVAL_SECONDS,
    InvalidMonitoringIntervalError,
    MonitoringCycle,
    MonitoringError,
    format_monitoring_cycle,
    format_monitoring_header,
    format_monitoring_summary,
    monitor_directory,
    validate_interval,
)
from integrityguard.reporting import (
    AssessmentStatus,
    ReportError,
    create_security_report,
    format_report,
    load_report,
    report_to_json,
    save_report,
)
from integrityguard.scanner import ScanLimits, ScanReport, scan_directory

EXIT_SUCCESS = 0
EXIT_CHANGES = 1
EXIT_INCONCLUSIVE = 2
EXIT_OPERATIONAL_ERROR = 3


class CLIError(Exception):
    """Raised for expected CLI usage errors after argument parsing."""


class IntegrityArgumentParser(argparse.ArgumentParser):
    """Argument parser using IntegrityGuard's operational-error exit code."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(EXIT_OPERATIONAL_ERROR, f"integrityguard: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    """Build and return the reusable command-line argument parser."""
    parser = IntegrityArgumentParser(
        prog="integrityguard",
        description="Local file integrity monitoring with SHA-256 baselines.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser(
        "init",
        help="Create a trusted baseline from a complete directory scan.",
        description="Scan a directory and exclusively create a validated baseline.",
    )
    init_parser.add_argument(
        "--root",
        required=True,
        type=Path,
        help="Directory to monitor.",
    )
    init_parser.add_argument(
        "--baseline",
        required=True,
        type=Path,
        help="New baseline JSON file outside the monitored directory.",
    )
    _add_scan_limit_arguments(init_parser)
    init_parser.set_defaults(handler=_run_init)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Compare a fresh scan with an existing baseline.",
        description="Scan a directory and compare trusted hashes with a baseline.",
    )
    scan_parser.add_argument(
        "--root",
        required=True,
        type=Path,
        help="Directory to scan.",
    )
    scan_parser.add_argument(
        "--baseline",
        required=True,
        type=Path,
        help="Existing validated baseline JSON file.",
    )
    scan_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )
    scan_parser.add_argument(
        "--output",
        type=Path,
        help="Exclusively create a JSON report outside the monitored directory.",
    )
    scan_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Include individual unchanged paths in text output.",
    )
    _add_scan_limit_arguments(scan_parser)
    scan_parser.set_defaults(handler=_run_scan)

    report_parser = subparsers.add_parser(
        "report",
        help="View a validated historical JSON report.",
        description="Validate and display a previously exported security report.",
    )
    report_parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Existing IntegrityGuard JSON report.",
    )
    report_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Include individual unchanged paths.",
    )
    report_parser.set_defaults(handler=_run_report)

    watch_parser = subparsers.add_parser(
        "watch",
        help="Periodically compare foreground scans with a fixed baseline.",
        description=(
            "Monitor a directory in the foreground until Ctrl+C, without "
            "updating its baseline."
        ),
    )
    watch_parser.add_argument(
        "--root",
        required=True,
        type=Path,
        help="Directory to monitor.",
    )
    watch_parser.add_argument(
        "--baseline",
        required=True,
        type=Path,
        help="Existing validated baseline JSON file.",
    )
    watch_parser.add_argument(
        "--interval",
        type=_polling_interval,
        default=DEFAULT_INTERVAL_SECONDS,
        help="Seconds between completed scans (minimum: 1; default: 10).",
    )
    watch_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show classification counts for every completed cycle.",
    )
    _add_scan_limit_arguments(watch_parser)
    watch_parser.set_defaults(handler=_run_watch)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a documented process exit code."""
    _configure_text_streams()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except CLIError as error:
        _diagnostic(str(error))
    except (BaselineError, DetectorError, MonitoringError, ReportError) as error:
        _diagnostic(str(error))
    except OSError:
        _diagnostic("A filesystem operation failed.")
    return EXIT_OPERATIONAL_ERROR


def _run_init(args: argparse.Namespace) -> int:
    scan = _scan_with_limits(args.root, args)
    baseline = create_baseline(scan)
    destination = save_baseline(baseline, args.baseline)
    print("IntegrityGuard baseline created.")
    print(f"Files recorded: {len(baseline.files)}")
    print(f"Skipped link paths: {len(baseline.skipped_paths)}")
    print(f"Baseline: {destination}")
    return EXIT_SUCCESS


def _run_scan(args: argparse.Namespace) -> int:
    if args.output is not None and args.format != "json":
        raise CLIError("--output requires --format json.")

    baseline = load_baseline(args.baseline)
    scan = _scan_with_limits(args.root, args)
    changes = compare_baseline(baseline, scan)
    report = create_security_report(changes)

    if args.format == "json":
        if args.output is None:
            sys.stdout.write(report_to_json(report))
        else:
            destination = save_report(
                report,
                args.output,
                monitored_root=args.root,
            )
            print(f"IntegrityGuard JSON report created: {destination}")
    else:
        sys.stdout.write(format_report(report, verbose=args.verbose))

    if report.assessment_status is AssessmentStatus.INCONCLUSIVE:
        return EXIT_INCONCLUSIVE
    if report.assessment_status is AssessmentStatus.CHANGES_DETECTED:
        return EXIT_CHANGES
    return EXIT_SUCCESS


def _run_report(args: argparse.Namespace) -> int:
    report = load_report(args.input)
    sys.stdout.write(format_report(report, verbose=args.verbose, historical=True))
    return EXIT_SUCCESS


def _run_watch(args: argparse.Namespace) -> int:
    baseline = load_baseline(args.baseline)
    sys.stdout.write(format_monitoring_header(args.root, args.interval))
    sys.stdout.flush()

    def display_cycle(cycle: MonitoringCycle) -> None:
        sys.stdout.write(format_monitoring_cycle(cycle, verbose=args.verbose))
        sys.stdout.flush()

    limits = _scan_limits_from_args(args)
    monitor_arguments: dict[str, object] = {
        "interval": args.interval,
        "on_cycle": display_cycle,
    }
    if limits is not None:
        monitor_arguments["scan_function"] = (
            lambda root: scan_directory(root, limits=limits)
        )
    session = monitor_directory(args.root, baseline, **monitor_arguments)
    sys.stdout.write(format_monitoring_summary(session))
    sys.stdout.flush()
    return EXIT_SUCCESS


def _polling_interval(value: str) -> float:
    try:
        return validate_interval(value)
    except InvalidMonitoringIntervalError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _positive_duration(value: str) -> float:
    try:
        parsed = float(value)
        ScanLimits(max_duration_seconds=parsed)
        return parsed
    except (TypeError, ValueError) as error:
        raise argparse.ArgumentTypeError(
            "must be a finite positive number of seconds"
        ) from error


def _add_scan_limit_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--max-entries",
        type=_positive_integer,
        help="Stop after discovering this many filesystem entries.",
    )
    parser.add_argument(
        "--max-bytes",
        type=_positive_integer,
        help="Stop after hashing this many cumulative bytes.",
    )
    parser.add_argument(
        "--max-seconds",
        type=_positive_duration,
        help="Stop a scan after this many monotonic seconds.",
    )


def _scan_limits_from_args(args: argparse.Namespace) -> ScanLimits | None:
    values = (
        getattr(args, "max_entries", None),
        getattr(args, "max_bytes", None),
        getattr(args, "max_seconds", None),
    )
    if values == (None, None, None):
        return None
    return ScanLimits(
        max_entries=values[0],
        max_bytes=values[1],
        max_duration_seconds=values[2],
    )


def _scan_with_limits(root: Path, args: argparse.Namespace) -> ScanReport:
    limits = _scan_limits_from_args(args)
    if limits is None:
        return scan_directory(root)
    return scan_directory(root, limits=limits)


def _diagnostic(message: str) -> None:
    print(f"Error: {message}", file=sys.stderr)


def _configure_text_streams() -> None:
    """Use deterministic UTF-8 output, including through Windows redirection."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


if __name__ == "__main__":  # pragma: no cover - exercised through subprocess tests
    raise SystemExit(main())
