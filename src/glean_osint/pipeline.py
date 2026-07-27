"""Shared scan pipeline for the web interface (ADR-0011).

Reuses the exact same building blocks the CLI's `scan` command already
uses and validated -- `runner.py`'s live invocation (incl. crt.sh caching,
ADR-0008 D9), each adapter's `parse`, `dedup.merge_graph`,
`scoring.score_graph`, `brief.build_brief`. This module only adds fresh
orchestration glue for the web UI's simpler, always-live, tool-selected-
by-set use case.

Deliberately does NOT touch `cli.py`'s own `scan()` command: that function
already correctly handles mixed live/file-ingestion modes, per-tool binary
overrides, cache-hit reporting, and spinners -- real, already-tested
behaviour not worth risking in a refactor just to share orchestration glue
that the two surfaces genuinely need in different shapes anyway (a CLI
flag set vs. a selected tool-id set).
"""

from __future__ import annotations

import os
import subprocess
import urllib.error
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from glean_osint import __version__, runner
from glean_osint.adapters.base import ParseResult, ScanContext
from glean_osint.adapters.crtsh import CrtshAdapter
from glean_osint.adapters.dnsx import DnsxAdapter
from glean_osint.adapters.httpx import HttpxAdapter
from glean_osint.adapters.theharvester import TheHarvesterAdapter
from glean_osint.brief import Brief, build_brief
from glean_osint.dedup import merge_graph
from glean_osint.registry import normalise_selection
from glean_osint.schema.entities import ScanMeta, ToolRun
from glean_osint.scoring import score_graph

# A live tool degrading (not installed, timed out, network failure) must
# never abort the rest of the scan (ADR-0002 D5, ADR-0008 D5) -- the exact
# same set cli.py's scan() command already relies on (_LIVE_INVOCATION_ERRORS
# there): subprocess.TimeoutExpired/CalledProcessError are NOT OSError
# subclasses, so they'd otherwise crash the whole scan instead of degrading
# just the one tool that raised.
_LIVE_INVOCATION_ERRORS = (
    runner.ToolUnavailable,
    urllib.error.URLError,
    subprocess.TimeoutExpired,
    subprocess.CalledProcessError,
    OSError,
)


def _tool_binary(env_var: str, default: str) -> str:
    """The web app has no CLI options for the operator to set
    --theharvester-bin/--dnsx-bin/--httpx-bin -- these env vars
    (ADR-0008's CLI --*-bin envvar= support) are the only way to point at
    the correct binary here, so the pipeline needs to read them directly
    rather than relying on Typer's option layer, which doesn't exist on
    this path. Read fresh on every call (not a module-level constant) so
    a long-running server picks up a changed env var without a restart.
    """
    return os.environ.get(env_var, default)


@dataclass(frozen=True, slots=True)
class ScanRequest:
    target: str
    tools: frozenset[str]  # subset of registry.TOOL_REGISTRY's keys
    authorisation: str | None = None
    top_n: int = 5


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    brief: Brief
    warnings: tuple[str, ...]  # degraded-tool messages, reported not raised (ADR-0002 D5)


def run_scan(
    request: ScanRequest,
    *,
    raw_dir: Path,
    on_status: Callable[[str], None] | None = None,
    on_warning: Callable[[str], None] | None = None,
) -> ScanOutcome:
    """Run `request.tools` live against `request.target` and return a
    scored `Brief`. Mirrors the CLI's 3-stage pipeline (ADR-0008 D1)
    exactly, just driven by a tool-id set instead of individual CLI
    flags.

    `on_status` (optional) is called with a short plain-language status
    string before each stage -- the same shape the terminal `Spinner`
    labels already use. `on_warning` (optional, added for ADR-0011
    Stage 2's live progress) is called at the same point each warning
    is recorded, so a caller streaming this to a browser can show it
    the moment it happens rather than only once the whole scan
    finishes. Both are independent of the returned `warnings` tuple,
    which always holds the complete set regardless of whether either
    callback was given -- streaming is additive, never the only record.
    """
    tools = normalise_selection(request.tools)
    status = on_status or (lambda _: None)
    warn = on_warning or (lambda _: None)
    warnings: list[str] = []

    def add_warning(message: str) -> None:
        warnings.append(message)
        warn(message)

    collected_at_dt = datetime.now(timezone.utc)
    collected_at = collected_at_dt.isoformat()
    results: list[ParseResult] = []
    tools_run: list[ToolRun] = []

    # --- Stage 1: crt.sh + theHarvester (independent, ADR-0008 D1) ---

    if "crtsh" in tools:
        status("Searching certificate transparency logs (crt.sh)...")
        info: list[str] = []
        try:
            raw = runner.fetch_crtsh_cached(request.target, info=info)
        except _LIVE_INVOCATION_ERRORS as error:
            add_warning(f"crt.sh: live invocation failed ({error}), skipping.")
        else:
            for message in info:
                add_warning(message)
            ref = runner.archive_raw(raw_dir, f"crtsh-{request.target}.json", raw)
            ctx = ScanContext(target=request.target, collected_at=collected_at, raw_output_ref=ref)
            result = CrtshAdapter().parse(raw, ctx)
            results.append(result)
            tools_run.append(ToolRun(source_tool="crtsh", method="passive", raw_output_ref=ref))
            _warn_skipped(add_warning, "crt.sh", result.skipped)

    if "theharvester" in tools:
        status("Searching public sources for hosts and emails (theHarvester)...")
        try:
            raw = runner.run_theharvester(
                request.target, binary=_tool_binary("GLEAN_THEHARVESTER_BIN", "theHarvester")
            )
        except _LIVE_INVOCATION_ERRORS as error:
            add_warning(f"theHarvester: live invocation failed ({error}), skipping.")
        else:
            ref = runner.archive_raw(raw_dir, f"theharvester-{request.target}.json", raw)
            ctx = ScanContext(target=request.target, collected_at=collected_at, raw_output_ref=ref)
            result = TheHarvesterAdapter().parse(raw, ctx)
            results.append(result)
            tools_run.append(
                ToolRun(source_tool="theharvester", method="passive", raw_output_ref=ref)
            )
            _warn_skipped(add_warning, "theHarvester", result.skipped)

    # --- Stage 2: dnsx, fed Stage 1's parsed hostnames (ADR-0008 D1) ---

    if "dnsx" in tools:
        candidates = runner.extract_candidates(request.target, results)
        status(f"Resolving {len(candidates)} candidate hostname(s) (dnsx)...")
        try:
            raw = runner.run_dnsx(candidates, binary=_tool_binary("GLEAN_DNSX_BIN", "dnsx"))
        except _LIVE_INVOCATION_ERRORS as error:
            add_warning(f"dnsx: live invocation failed ({error}), skipping.")
        else:
            ref = runner.archive_raw(raw_dir, f"dnsx-{request.target}.json", raw)
            ctx = ScanContext(target=request.target, collected_at=collected_at, raw_output_ref=ref)
            result = DnsxAdapter().parse(raw, ctx)
            results.append(result)
            tools_run.append(ToolRun(source_tool="dnsx", method="passive", raw_output_ref=ref))
            _warn_skipped(add_warning, "dnsx", result.skipped)

    # --- Stage 3: httpx, fed Stage 2's resolved hosts, ACTIVE ---
    # normalise_selection already guarantees dnsx is present whenever
    # httpx is (ADR-0011 D4) -- no separate opt-in gate needed here, the
    # web UI's own tool selection *is* the opt-in (unlike the CLI, which
    # has --live without --active as a valid, common ingest-first mode).

    if "httpx" in tools:
        resolved_hosts = runner.extract_resolved_hosts(results)
        status(f"Probing {len(resolved_hosts)} live host(s) for services and tech (httpx)...")
        try:
            raw = runner.run_httpx(resolved_hosts, binary=_tool_binary("GLEAN_HTTPX_BIN", "httpx"))
        except _LIVE_INVOCATION_ERRORS as error:
            add_warning(f"httpx: live invocation failed ({error}), skipping.")
        else:
            ref = runner.archive_raw(raw_dir, f"httpx-{request.target}.jsonl", raw)
            ctx = ScanContext(target=request.target, collected_at=collected_at, raw_output_ref=ref)
            result = HttpxAdapter().parse(raw, ctx)
            results.append(result)
            tools_run.append(ToolRun(source_tool="httpx", method="active", raw_output_ref=ref))
            _warn_skipped(add_warning, "httpx", result.skipped)

    status("Scoring and building the brief...")
    merged = merge_graph(results)
    scored = score_graph(merged.entities, merged.edges, datetime.now(timezone.utc))
    scan_meta = ScanMeta(
        target=request.target,
        started_at=collected_at,
        glean_version=__version__,
        authorisation=request.authorisation,
        tools_run=tuple(tools_run),
    )
    brief = build_brief(scored, merged.edges, scan_meta, top_n=request.top_n)
    return ScanOutcome(brief=brief, warnings=tuple(warnings))


def _warn_skipped(add_warning: Callable[[str], None], tool_name: str, skipped: int) -> None:
    if skipped:
        add_warning(f"{tool_name}: skipped {skipped} malformed record(s).")
