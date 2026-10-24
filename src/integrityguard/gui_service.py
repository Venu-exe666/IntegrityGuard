"""Testable application services for the IntegrityGuard desktop GUI."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from os import PathLike
from pathlib import Path
from threading import Event

from integrityguard.baseline import (
    Baseline,
    create_baseline,
    load_baseline,
    save_baseline,
)
from integrityguard.detector import ChangeReport, ChangeStatus, compare_baseline
from integrityguard.monitoring import (
    CycleHandler,
    MonitoringSession,
    MonitoringScanEvent,
    ScanEventHandler,
    monitor_directory,
)
from integrityguard.scanner import ScanReport, scan_directory

ScanFunction = Callable[[str | PathLike[str]], ScanReport]
CreateBaselineFunction = Callable[[ScanReport], Baseline]
SaveBaselineFunction = Callable[[Baseline, str | PathLike[str]], Path]
LoadBaselineFunction = Callable[[str | PathLike[str]], Baseline]
CompareFunction = Callable[[Baseline, ScanReport], ChangeReport]
TokenFunction = Callable[[], str]
MonitorFunction = Callable[..., MonitoringSession]


class GuiIntegrationError(Exception):
    """Base class for expected GUI integration failures."""


class GuiBaselineNotFoundError(GuiIntegrationError):
    """Raised when a selected root has no GUI-managed baseline."""


class GuiBaselineExistsError(GuiIntegrationError):
    """Raised when creating another baseline requires explicit confirmation."""


class GuiMonitoringState(StrEnum):
    """User-visible lifecycle states for one GUI monitoring worker."""

    STOPPED = "stopped"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


class GuiMonitoringControl:
    """Track GUI monitoring state and reject stale worker messages.

    Tk's main thread owns all state transitions. Worker threads only observe
    the returned ``Event`` and send the session identifier back through the
    GUI queue.
    """

    def __init__(self) -> None:
        self._state = GuiMonitoringState.STOPPED
        self._session_id = 0
        self._stop_event: Event | None = None

    @property
    def state(self) -> GuiMonitoringState:
        return self._state

    @property
    def active(self) -> bool:
        return self._state in {
            GuiMonitoringState.RUNNING,
            GuiMonitoringState.STOPPING,
        }

    def start(self) -> tuple[int, Event]:
        """Begin a distinct session and return its identifier and stop event."""
        if self.active:
            raise RuntimeError("A monitoring session is already active.")
        self._session_id += 1
        self._stop_event = Event()
        self._state = GuiMonitoringState.RUNNING
        return self._session_id, self._stop_event

    def request_stop(self) -> bool:
        """Request cooperative shutdown of the active session."""
        if not self.active or self._stop_event is None:
            return False
        self._state = GuiMonitoringState.STOPPING
        self._stop_event.set()
        return True

    def is_current(self, session_id: int) -> bool:
        """Return whether a queued message belongs to the newest session."""
        return session_id == self._session_id

    def finish(self, session_id: int, *, failed: bool = False) -> bool:
        """Finish the current session, ignoring delayed messages from older ones."""
        if not self.is_current(session_id) or not self.active:
            return False
        self._state = (
            GuiMonitoringState.ERROR if failed else GuiMonitoringState.STOPPED
        )
        self._stop_event = None
        return True


@dataclass(frozen=True, slots=True)
class BaselineCreationResult:
    """Information displayed after a GUI baseline is safely published."""

    baseline_path: Path
    file_count: int
    skipped_path_count: int


@dataclass(frozen=True, slots=True)
class ScanSummary:
    """Compact real counts from a detector ``ChangeReport``."""

    added: int
    modified: int
    deleted: int
    unknown: int
    unchanged: int
    scan_complete: bool
    assessment_conclusive: bool


@dataclass(frozen=True, slots=True)
class ResultRow:
    """Presentation-neutral table row derived from one file change."""

    relative_path: str
    status: ChangeStatus
    size_bytes: int | None
    detail: str


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    """A GUI scan result backed by the engine's immutable change report."""

    baseline_path: Path
    report: ChangeReport
    summary: ScanSummary
    rows: tuple[ResultRow, ...]


class GuiService:
    """Connect GUI actions to the existing scanner, baseline, and detector APIs.

    Baselines are stored as immutable versions. Creating a replacement never
    deletes or overwrites the previous trusted file; the newest filename for a
    root becomes the version selected by later GUI scans.
    """

    def __init__(
        self,
        app_data_dir: str | PathLike[str] | None = None,
        *,
        scan_function: ScanFunction = scan_directory,
        create_baseline_function: CreateBaselineFunction = create_baseline,
        save_baseline_function: SaveBaselineFunction = save_baseline,
        load_baseline_function: LoadBaselineFunction = load_baseline,
        compare_function: CompareFunction = compare_baseline,
        monitor_function: MonitorFunction = monitor_directory,
        token_function: TokenFunction | None = None,
    ) -> None:
        self.app_data_dir = Path(
            app_data_dir if app_data_dir is not None else default_app_data_dir()
        )
        self._scan = scan_function
        self._create_baseline = create_baseline_function
        self._save_baseline = save_baseline_function
        self._load_baseline = load_baseline_function
        self._compare = compare_function
        self._monitor = monitor_function
        self._token = token_function or (lambda: secrets.token_hex(4))

    @property
    def baseline_directory(self) -> Path:
        """Return the GUI baseline directory without creating it."""
        return self.app_data_dir / "baselines"

    def baseline_exists(self, root: str | PathLike[str]) -> bool:
        """Return whether at least one GUI-managed baseline exists for ``root``."""
        return bool(self._baseline_candidates(root))

    def latest_baseline_path(self, root: str | PathLike[str]) -> Path:
        """Return the newest immutable baseline version for ``root``."""
        candidates = self._baseline_candidates(root)
        if not candidates:
            raise GuiBaselineNotFoundError(
                "No GUI baseline exists for the selected folder."
            )
        return candidates[-1]

    def create_for_root(
        self,
        root: str | PathLike[str],
        *,
        allow_new_version: bool = False,
        on_scan_event: ScanEventHandler | None = None,
    ) -> BaselineCreationResult:
        """Scan ``root`` and exclusively publish a new trusted baseline version."""
        selected_root = _absolute_root(root)
        if self.baseline_exists(selected_root) and not allow_new_version:
            raise GuiBaselineExistsError(
                "A baseline already exists for the selected folder."
            )

        self._reject_storage_inside_root(selected_root)
        self.baseline_directory.mkdir(parents=True, exist_ok=True)
        scan = self._scan_once(selected_root, on_scan_event)
        baseline = self._create_baseline(scan)

        # Do not let a concurrent first-time creator bypass the GUI's explicit
        # confirmation requirement while this potentially long scan was running.
        if self.baseline_exists(selected_root) and not allow_new_version:
            raise GuiBaselineExistsError(
                "Another baseline was created while the folder was being scanned."
            )

        destination = self._new_baseline_path(selected_root)
        saved_path = self._save_baseline(baseline, destination)
        return BaselineCreationResult(
            baseline_path=saved_path,
            file_count=len(baseline.files),
            skipped_path_count=len(baseline.skipped_paths),
        )

    def scan_root(
        self,
        root: str | PathLike[str],
        *,
        on_scan_event: ScanEventHandler | None = None,
    ) -> ScanOutcome:
        """Compare a fresh engine scan with the newest baseline for ``root``."""
        selected_root = _absolute_root(root)
        baseline_path = self.latest_baseline_path(selected_root)
        baseline = self._load_baseline(baseline_path)
        current_scan = self._scan_once(selected_root, on_scan_event)
        report = self._compare(baseline, current_scan)
        return ScanOutcome(
            baseline_path=baseline_path,
            report=report,
            summary=summary_from_report(report),
            rows=result_rows(report),
        )

    def monitor_root(
        self,
        root: str | PathLike[str],
        *,
        interval: float,
        stop_event: Event,
        on_cycle: CycleHandler,
        on_scan_event: ScanEventHandler | None = None,
    ) -> MonitoringSession:
        """Monitor ``root`` against its newest valid GUI baseline.

        Baseline loading and compatibility checks remain in the existing
        baseline, detector, and monitoring layers. No baseline is created or
        updated by this operation.
        """
        selected_root = _absolute_root(root)
        baseline_path = self.latest_baseline_path(selected_root)
        baseline = self._load_baseline(baseline_path)
        return self._monitor(
            selected_root,
            baseline,
            interval=interval,
            stop_event=stop_event,
            on_cycle=on_cycle,
            on_scan_event=on_scan_event,
        )

    def _scan_once(
        self,
        root: Path,
        on_scan_event: ScanEventHandler | None,
    ) -> ScanReport:
        """Run one scan with balanced optional lifecycle notifications."""
        notification_started = False
        try:
            if on_scan_event is not None:
                on_scan_event(MonitoringScanEvent.STARTED)
                notification_started = True
            return self._scan(root)
        finally:
            if on_scan_event is not None and notification_started:
                on_scan_event(MonitoringScanEvent.FINISHED)

    def _baseline_candidates(self, root: str | PathLike[str]) -> tuple[Path, ...]:
        directory = self.baseline_directory
        if not directory.is_dir():
            return ()
        prefix = _root_storage_key(root) + "-"
        return tuple(
            sorted(
                path
                for path in directory.iterdir()
                if path.is_file()
                and path.name.startswith(prefix)
                and path.suffix == ".json"
                and _baseline_generation(path.name, prefix) > 0
            )
        )

    def _new_baseline_path(self, root: str | PathLike[str]) -> Path:
        prefix = _root_storage_key(root) + "-"
        generations = [
            _baseline_generation(path.name, prefix)
            for path in self._baseline_candidates(root)
        ]
        generation = max(generations, default=0) + 1
        token = re.sub(r"[^A-Za-z0-9]", "", self._token())[:32]
        if not token:
            raise ValueError("token_function must provide letters or digits")
        filename = f"{prefix}{generation:08d}-{token}.json"
        return self.baseline_directory / filename

    def _reject_storage_inside_root(self, root: Path) -> None:
        try:
            resolved_root = root.resolve(strict=True)
            resolved_storage = self.baseline_directory.resolve(strict=False)
        except (OSError, RuntimeError) as error:
            raise GuiIntegrationError(
                "The baseline storage location could not be validated safely."
            ) from error
        if _is_within(resolved_storage, resolved_root):
            raise GuiIntegrationError(
                "GUI baseline storage cannot be inside the monitored folder."
            )


def default_app_data_dir(
    environment: Mapping[str, str] | None = None,
) -> Path:
    """Return the platform-appropriate per-user IntegrityGuard data directory."""
    values = os.environ if environment is None else environment
    local_app_data = values.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "IntegrityGuard"
    xdg_data_home = values.get("XDG_DATA_HOME")
    if xdg_data_home:
        return Path(xdg_data_home) / "IntegrityGuard"
    if os.name == "nt":
        return Path.home() / "AppData" / "Local" / "IntegrityGuard"
    return Path.home() / ".local" / "share" / "IntegrityGuard"


def summary_from_report(report: ChangeReport) -> ScanSummary:
    """Build dashboard statistics directly from a ``ChangeReport``."""
    return ScanSummary(
        added=report.counts.added,
        modified=report.counts.modified,
        deleted=report.counts.deleted,
        unknown=report.counts.unknown,
        unchanged=report.counts.unchanged,
        scan_complete=report.scan_complete,
        assessment_conclusive=report.assessment_conclusive,
    )


def result_rows(report: ChangeReport) -> tuple[ResultRow, ...]:
    """Return deterministic non-clean rows for the dashboard results table."""
    rows: list[ResultRow] = []
    for changes in (report.added, report.modified, report.deleted, report.unknown):
        for change in changes:
            size = (
                change.current_size_bytes
                if change.current_size_bytes is not None
                else change.previous_size_bytes
            )
            detail = {
                ChangeStatus.ADDED: "New file",
                ChangeStatus.MODIFIED: "SHA-256 content change",
                ChangeStatus.DELETED: "Absent from successfully scanned scope",
                ChangeStatus.UNKNOWN: (
                    change.unknown_reason.value
                    if change.unknown_reason is not None
                    else "Uncertain scan result"
                ),
            }[change.status]
            rows.append(
                ResultRow(
                    relative_path=change.relative_path,
                    status=change.status,
                    size_bytes=size,
                    detail=detail,
                )
            )
    return tuple(sorted(rows, key=lambda item: item.relative_path))


def _absolute_root(root: str | PathLike[str]) -> Path:
    return Path(os.path.abspath(os.fspath(root)))


def _root_storage_key(root: str | PathLike[str]) -> str:
    absolute = os.path.normcase(os.path.normpath(os.fspath(_absolute_root(root))))
    # This digest names a root-specific storage bucket; monitored file hashes
    # continue to come exclusively from the existing hashing/scanner engine.
    return hashlib.sha256(absolute.encode("utf-8")).hexdigest()[:32]


def _baseline_generation(filename: str, prefix: str) -> int:
    remainder = filename.removeprefix(prefix)
    generation, separator, _rest = remainder.partition("-")
    if not separator or len(generation) != 8 or not generation.isdigit():
        return 0
    return int(generation)


def _is_within(candidate: Path, directory: Path) -> bool:
    candidate_value = os.path.normcase(os.path.abspath(candidate))
    directory_value = os.path.normcase(os.path.abspath(directory))
    try:
        return os.path.commonpath([candidate_value, directory_value]) == directory_value
    except ValueError:
        return False
