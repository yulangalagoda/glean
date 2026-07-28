"""Scan history storage (ADR-0011 D6).

A fixed, cwd-independent location so "my past scans" means the same thing
regardless of which folder `glean` happens to be launched from -- an
explicit operator decision, not a default picked without asking. File-based
(one directory + a manifest per scan), no database: consistent with every
other piece of state this project already keeps as files (raw archives,
eval scans, ground truth), nothing to migrate as the schema evolves.

Stage 3 (ADR-0011): the CLI's own `--raw-dir` default now also points
here (`cli.py`'s `_default_raw_dir`), and `--live` scans write a manifest
too -- a scan run from the terminal and one run from the web UI now land
in the same history, browsable from either surface.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

DEFAULT_HISTORY_ROOT = (
    Path(os.environ.get("XDG_DATA_HOME", "~/.local/share")).expanduser() / "glean" / "scans"
)


def scan_id_for(target: str, started_at: datetime) -> str:
    slug = target.replace(".", "-")
    timestamp = started_at.strftime("%Y%m%dT%H%M%SZ")
    return f"{slug}-{timestamp}"


@dataclass(frozen=True, slots=True)
class ScanManifest:
    scan_id: str
    target: str
    started_at: str
    tools_run: tuple[str, ...]
    authorisation: str | None
    findings_count: int
    warnings: tuple[str, ...] = ()


def write_manifest(scan_dir: Path, manifest: ScanManifest) -> None:
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "manifest.json").write_text(json.dumps(asdict(manifest), indent=2))


def read_manifest(scan_dir: Path) -> ScanManifest | None:
    path = scan_dir / "manifest.json"
    try:
        data = json.loads(path.read_text())
        data["tools_run"] = tuple(data.get("tools_run", ()))
        data["warnings"] = tuple(data.get("warnings", ()))
        return ScanManifest(**data)
    except (OSError, ValueError, TypeError, KeyError):
        # Missing, partially-written, or corrupt manifest -- degrade to
        # "not listed", never crash the history page over one bad entry
        # (ADR-0002 D5's discipline applied to history browsing).
        return None


def write_entities_snapshot(scan_dir: Path, entities: list[dict[str, Any]]) -> None:
    """A flat `Entity.to_dict()` list (every finding, top priorities and
    also-found alike) saved alongside `manifest.json`/`brief.html` --
    the rendered brief is prose/markup, this is the underlying
    structured graph a JSON/CSV export or a future scan-to-scan diff
    needs, and it otherwise only ever existed in memory for the
    lifetime of one request. Takes plain dicts, not `Entity` objects,
    so this module keeps its existing zero-dependency-on-brief.py shape
    (callers build the list via `[f.entity.to_dict() for f in ...]`
    themselves)."""
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "entities.json").write_text(json.dumps(entities, indent=2))


def read_entities_snapshot(scan_dir: Path) -> list[dict[str, Any]] | None:
    """`None` for a missing or corrupt snapshot -- degrades to "export/
    diff unavailable for this scan" rather than crashing (ADR-0002 D5's
    discipline applied here too), notably for any scan run before this
    feature existed, which never wrote entities.json at all."""
    path = scan_dir / "entities.json"
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, list) else None


def list_scans(history_root: Path = DEFAULT_HISTORY_ROOT) -> list[ScanManifest]:
    """Newest first -- `scan_id` embeds a sortable timestamp
    (`scan_id_for`), so a plain reverse name sort is exact, no need to
    parse `started_at` back out of each manifest."""
    if not history_root.is_dir():
        return []
    manifests = (read_manifest(d) for d in sorted(history_root.iterdir(), reverse=True))
    return [m for m in manifests if m is not None]


def group_scans_by_target(scans: list[ScanManifest]) -> list[tuple[str, list[ScanManifest]]]:
    """Collapse repeat scans of the same target into one group each --
    the real gap in a flat history list once a target's been scanned a
    handful of times (four yulan.me runs shouldn't read as four
    unrelated rows). `scans` must already be newest-first (list_scans's
    own contract) -- a target's group is ordered the same way, and
    groups themselves are ordered by each target's most recent scan,
    both falling out for free from a single newest-first pass rather
    than a second sort."""
    groups: dict[str, list[ScanManifest]] = {}
    order: list[str] = []
    for scan in scans:
        if scan.target not in groups:
            groups[scan.target] = []
            order.append(scan.target)
        groups[scan.target].append(scan)
    return [(target, groups[target]) for target in order]


def previous_scan_for(
    scan_id: str, history_root: Path = DEFAULT_HISTORY_ROOT
) -> ScanManifest | None:
    """The scan of the same target immediately *older* than `scan_id`
    -- `None` if `scan_id` is unknown or is already the oldest scan of
    its target. Deliberately relative to whichever scan you're looking
    at, not always "vs. the newest" -- viewing an old scan and asking
    "what changed since the one before this" should work the same way
    as viewing the latest one."""
    manifest = read_manifest(history_root / scan_id)
    if manifest is None:
        return None
    same_target = [m for m in list_scans(history_root) if m.target == manifest.target]
    try:
        index = next(i for i, m in enumerate(same_target) if m.scan_id == scan_id)
    except StopIteration:
        return None
    if index + 1 < len(same_target):
        return same_target[index + 1]
    return None


def delete_scan(scan_dir: Path) -> None:
    """Irreversibly removes a scan's entire directory (manifest,
    brief.html, raw archive, entities snapshot). The caller (the web
    route) is responsible for confirming intent first -- this function
    itself just does it. `ignore_errors=True` so a double-delete or a
    dir that's already gone degrades to a no-op rather than a 500."""
    shutil.rmtree(scan_dir, ignore_errors=True)
