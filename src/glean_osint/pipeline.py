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
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from glean_osint import __version__, runner, synthesis
from glean_osint.adapters.base import ParseResult, ScanContext
from glean_osint.adapters.crtsh import CrtshAdapter
from glean_osint.adapters.dnsx import DnsxAdapter
from glean_osint.adapters.httpx import HttpxAdapter
from glean_osint.adapters.subfinder import SubfinderAdapter
from glean_osint.adapters.theharvester import TheHarvesterAdapter
from glean_osint.brief import Brief, build_brief
from glean_osint.dedup import merge_graph
from glean_osint.registry import normalise_selection
from glean_osint.schema.entities import Edge, Entity, ScanMeta, ToolRun
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
    # Opt-in LLM narration (ADR-0009), matching `glean scan --llm --model`.
    # Defaulted off for the same conservative reason `--live` was: narration
    # needs a local Ollama running, and a scan must not start depending on
    # one silently.
    llm: bool = False
    model: str = synthesis.DEFAULT_MODEL


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    brief: Brief
    warnings: tuple[str, ...]  # degraded-tool messages, reported not raised (ADR-0002 D5)
    # The correlation stage's own output. `Brief` deliberately doesn't carry
    # these -- it's a rendering contract (ADR-0005), and `build_brief` only
    # borrows the edge set to phrase finding bodies. Returning them here is
    # what stops them being discarded the moment `run_scan` returns; the
    # caller decides whether to persist them.
    edges: tuple[Edge, ...] = ()
    # The scored entity graph, so callers writing a snapshot don't have to
    # reconstruct it by concatenating the brief's own two finding lists.
    entities: tuple[Entity, ...] = ()
    # The model that actually produced prose, or None when the brief is
    # template-narrated. `None` after a requested-but-failed narration too:
    # what matters downstream is what the reader is actually looking at, not
    # what was asked for.
    narrated_by: str | None = None


def run_scan(
    request: ScanRequest,
    *,
    raw_dir: Path,
    on_status: Callable[[str], None] | None = None,
    on_warning: Callable[[str], None] | None = None,
    cancel: runner.CancellationToken | None = None,
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

    def check_cancelled() -> None:
        """Cooperative stop points. Cancellation is checked between stages
        and at the head of each concurrent Stage 1 worker, so a scan stops
        at the next boundary rather than only when its current tool
        happens to finish. `ScanCancelled` is deliberately not in
        `_LIVE_INVOCATION_ERRORS`: every entry there means "degrade this
        one tool and continue", which is the opposite of what cancelling
        must do, so it propagates out of run_scan untouched.
        """
        if cancel is not None:
            cancel.raise_if_cancelled()

    collected_at_dt = datetime.now(timezone.utc)
    collected_at = collected_at_dt.isoformat()
    results: list[ParseResult] = []
    tools_run: list[ToolRun] = []

    # --- Stage 1: crt.sh + theHarvester + subfinder, run concurrently ---
    # (independent, ADR-0008 D1). All three are independent I/O-bound
    # calls; theHarvester/subfinder can each individually take minutes
    # querying live external sources, so running them one after another
    # is additive wall-clock time for no reason (same reasoning, same
    # change, as cli.py's own scan() command). status()/add_warning()
    # calls happen live from inside each worker thread here -- unlike
    # the CLI there's no local terminal spinner to race, and an SSE
    # stream showing genuinely-concurrent events as they really happen
    # is the more honest live-progress experience anyway.

    def _run_crtsh_stage1() -> None:
        check_cancelled()
        status("Searching certificate transparency logs (crt.sh)...")
        info: list[str] = []
        try:
            raw = runner.fetch_crtsh_cached(request.target, info=info)
        except _LIVE_INVOCATION_ERRORS as error:
            add_warning(f"crt.sh: live invocation failed ({error}), skipping.")
            return
        # Cache-hit/stale-failsafe notices are informational, not a
        # problem -- routed through status() (shown live, no history
        # warning pill), matching the CLI's own cyan-vs-yellow treatment
        # of the same messages.
        for message in info:
            status(message)
        ref = runner.archive_raw(raw_dir, f"crtsh-{request.target}.json", raw)
        ctx = ScanContext(target=request.target, collected_at=collected_at, raw_output_ref=ref)
        result = CrtshAdapter().parse(raw, ctx)
        results.append(result)
        tools_run.append(ToolRun(source_tool="crtsh", method="passive", raw_output_ref=ref))
        _warn_skipped(add_warning, "crt.sh", result.skipped)

    def _run_theharvester_stage1() -> None:
        check_cancelled()
        status("Searching public sources for hosts and emails (theHarvester)...")
        try:
            raw = runner.run_theharvester(
                request.target,
                binary=_tool_binary("GLEAN_THEHARVESTER_BIN", "theHarvester"),
                cancel=cancel,
            )
        except _LIVE_INVOCATION_ERRORS as error:
            add_warning(f"theHarvester: live invocation failed ({error}), skipping.")
            return
        ref = runner.archive_raw(raw_dir, f"theharvester-{request.target}.json", raw)
        ctx = ScanContext(target=request.target, collected_at=collected_at, raw_output_ref=ref)
        result = TheHarvesterAdapter().parse(raw, ctx)
        results.append(result)
        tools_run.append(ToolRun(source_tool="theharvester", method="passive", raw_output_ref=ref))
        _warn_skipped(add_warning, "theHarvester", result.skipped)

    def _run_subfinder_stage1() -> None:
        check_cancelled()
        status("Searching passive sources for subdomains (subfinder)...")
        try:
            raw = runner.run_subfinder(
                request.target,
                binary=_tool_binary("GLEAN_SUBFINDER_BIN", "subfinder"),
                cancel=cancel,
            )
        except _LIVE_INVOCATION_ERRORS as error:
            add_warning(f"subfinder: live invocation failed ({error}), skipping.")
            return
        ref = runner.archive_raw(raw_dir, f"subfinder-{request.target}.jsonl", raw)
        ctx = ScanContext(target=request.target, collected_at=collected_at, raw_output_ref=ref)
        result = SubfinderAdapter().parse(raw, ctx)
        results.append(result)
        tools_run.append(ToolRun(source_tool="subfinder", method="passive", raw_output_ref=ref))
        _warn_skipped(add_warning, "subfinder", result.skipped)

    stage1_tasks = {
        "crtsh": _run_crtsh_stage1,
        "theharvester": _run_theharvester_stage1,
        "subfinder": _run_subfinder_stage1,
    }
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(fn) for tool_id, fn in stage1_tasks.items() if tool_id in tools]
        for future in futures:
            future.result()  # propagate a genuinely unexpected exception, don't swallow it

    # tools_run's append order is otherwise whichever thread finished
    # first (non-deterministic) -- fixed here into a stable sequence,
    # matching cli.py's own equivalent fix-up. merge_graph itself
    # doesn't care (ADR-0003 D7); only this list's display order does.
    _stage1_tool_order = {"crtsh": 0, "theharvester": 1, "subfinder": 2}
    tools_run.sort(key=lambda t: _stage1_tool_order.get(t.source_tool, 99))

    check_cancelled()

    # --- Stage 2: dnsx, fed Stage 1's parsed hostnames (ADR-0008 D1) ---

    if "dnsx" in tools:
        candidates = runner.extract_candidates(request.target, results)
        status(f"Resolving {len(candidates)} candidate hostname(s) (dnsx)...")
        try:
            raw = runner.run_dnsx(
                candidates, binary=_tool_binary("GLEAN_DNSX_BIN", "dnsx"), cancel=cancel
            )
        except _LIVE_INVOCATION_ERRORS as error:
            add_warning(f"dnsx: live invocation failed ({error}), skipping.")
        else:
            ref = runner.archive_raw(raw_dir, f"dnsx-{request.target}.json", raw)
            ctx = ScanContext(target=request.target, collected_at=collected_at, raw_output_ref=ref)
            result = DnsxAdapter().parse(raw, ctx)
            results.append(result)
            tools_run.append(ToolRun(source_tool="dnsx", method="passive", raw_output_ref=ref))
            _warn_skipped(add_warning, "dnsx", result.skipped)

    check_cancelled()

    # --- Stage 3: httpx, fed Stage 2's resolved hosts, ACTIVE ---
    # normalise_selection already guarantees dnsx is present whenever
    # httpx is (ADR-0011 D4) -- no separate opt-in gate needed here, the
    # web UI's own tool selection *is* the opt-in (unlike the CLI, which
    # has --live without --active as a valid, common ingest-first mode).

    if "httpx" in tools:
        resolved_hosts = runner.extract_resolved_hosts(results)
        status(f"Probing {len(resolved_hosts)} live host(s) for services and tech (httpx)...")
        try:
            raw = runner.run_httpx(
                resolved_hosts, binary=_tool_binary("GLEAN_HTTPX_BIN", "httpx"), cancel=cancel
            )
        except _LIVE_INVOCATION_ERRORS as error:
            add_warning(f"httpx: live invocation failed ({error}), skipping.")
        else:
            ref = runner.archive_raw(raw_dir, f"httpx-{request.target}.jsonl", raw)
            ctx = ScanContext(target=request.target, collected_at=collected_at, raw_output_ref=ref)
            result = HttpxAdapter().parse(raw, ctx)
            results.append(result)
            tools_run.append(ToolRun(source_tool="httpx", method="active", raw_output_ref=ref))
            _warn_skipped(add_warning, "httpx", result.skipped)

    check_cancelled()
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

    narrated_by: str | None = None
    if request.llm:
        status(f"Narrating top priorities with {request.model} (Ollama)...")
        synthesis_result = synthesis.synthesize_brief(brief, scored, model=request.model)
        brief = synthesis_result.brief
        # `synthesize_brief` never raises -- an unreachable Ollama, a
        # malformed response, or a contract violation all degrade to the
        # template brief (ADR-0009). That is the right behaviour, but it is
        # also silent: the reader asked for model narration and would
        # otherwise be handed template prose with nothing to distinguish it.
        # Report which of the three cases actually happened.
        if synthesis_result.narrated_count:
            narrated_by = request.model
        if synthesis_result.narrated_count == 0 and brief.top_priorities:
            add_warning(
                f"LLM narration unavailable ({request.model}) — every finding fell back to "
                "the deterministic template. Is Ollama running locally with that model pulled?"
            )
        elif synthesis_result.fell_back_count:
            attempted = synthesis_result.narrated_count + synthesis_result.fell_back_count
            add_warning(
                f"{request.model} narrated {synthesis_result.narrated_count} of "
                f"{attempted} top findings; the rest fell back to the template."
            )
        if synthesis_result.invented_ids_dropped:
            invented = synthesis_result.invented_ids_dropped
            add_warning(
                f"{request.model} referred to {invented} finding(s) that do not exist in "
                "this scan; those were discarded before the brief was built."
            )

    return ScanOutcome(
        brief=brief,
        warnings=tuple(warnings),
        edges=tuple(merged.edges),
        entities=tuple(scored),
        narrated_by=narrated_by,
    )


def _warn_skipped(add_warning: Callable[[str], None], tool_name: str, skipped: int) -> None:
    if skipped:
        add_warning(f"{tool_name}: skipped {skipped} malformed record(s).")
