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
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

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


def list_scans(history_root: Path = DEFAULT_HISTORY_ROOT) -> list[ScanManifest]:
    """Newest first -- `scan_id` embeds a sortable timestamp
    (`scan_id_for`), so a plain reverse name sort is exact, no need to
    parse `started_at` back out of each manifest."""
    if not history_root.is_dir():
        return []
    manifests = (read_manifest(d) for d in sorted(history_root.iterdir(), reverse=True))
    return [m for m in manifests if m is not None]
