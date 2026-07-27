"""Scan history storage (ADR-0011 D6).

A fixed, cwd-independent location so "my past scans" means the same thing
regardless of which folder `glean` happens to be launched from -- an
explicit operator decision, not a default picked without asking. File-based
(one directory + a manifest per scan), no database: consistent with every
other piece of state this project already keeps as files (raw archives,
eval scans, ground truth), nothing to migrate as the schema evolves.

Only the web interface writes here in v1 (ADR-0011 stage 1) -- the CLI's
own `--raw-dir` default is deliberately left unchanged for now; unifying
the two is ADR-0011 D6's own follow-up, sequenced into a later stage so it
doesn't risk the CLI's already-validated behaviour for a UI feature that
doesn't exist yet.

Read-side browsing (`list_scans` etc.) is stage 3's job (ADR-0011), not
built here -- this module is deliberately write-only until something
actually reads it back.
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
