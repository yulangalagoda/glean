"""The `glean` CLI entrypoint (roadmap Workstream E1).

`glean scan` runs the full deterministic pipeline (adapters -> dedup ->
scoring -> brief). Ingest-only by default (point it at already-fetched raw
tool output); pass `--live` to actually invoke tools (ADR-0008 — the
runner). `--active` additionally opts into `httpx`, the only active-method
tool — never invoked live without it, per the charter's "active requires
explicit opt-in".
"""

from __future__ import annotations

import json
import subprocess
import urllib.error
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer
import yaml

from glean_osint import __version__, history, runner, synthesis
from glean_osint import judge_audit as judge_audit_mod
from glean_osint.adapters.base import ParseResult, ScanContext
from glean_osint.adapters.crtsh import CrtshAdapter
from glean_osint.adapters.dnsx import DnsxAdapter
from glean_osint.adapters.hibp import HibpAdapter
from glean_osint.adapters.httpx import HttpxAdapter
from glean_osint.adapters.subfinder import SubfinderAdapter
from glean_osint.adapters.theharvester import TheHarvesterAdapter
from glean_osint.brief import (
    DEFAULT_TOP_N,
    build_brief,
    render_html,
    render_markdown,
    surface_counts,
)
from glean_osint.dedup import merge_graph
from glean_osint.evaluation import (
    DEFAULT_JUDGE_MODEL,
    FaithfulnessResult,
    PrioritisationQuality,
    Stage2FaithfulnessResult,
    faithfulness_stage1,
    faithfulness_stage2,
    load_ground_truth,
    prioritisation_quality,
    provenance_retention,
)
from glean_osint.progress import SECTION_BREAK, Spinner
from glean_osint.schema.entities import Entity, ScanMeta, ToolRun
from glean_osint.scoring import score_graph

# A live tool degrading (not installed, timed out, network failure) must
# never abort the rest of the scan (ADR-0002 D5, ADR-0008 D5).
_LIVE_INVOCATION_ERRORS = (
    runner.ToolUnavailable,
    urllib.error.URLError,
    subprocess.TimeoutExpired,
    subprocess.CalledProcessError,
    OSError,
)

# "Also found" is deliberately unbounded in the Brief itself (ADR-0005) --
# a large/historically-rich target can produce hundreds of entries, which
# is unreadable dumped straight to a terminal. This only caps what
# prints to stdout; --out always writes the complete brief.
DEFAULT_ALSO_FOUND_LIMIT = 25

app = typer.Typer(add_completion=False)


@app.callback(invoke_without_command=True)
def _main(
    ctx: typer.Context,
    host: Annotated[
        str, typer.Option(help="Host to bind the web interface to (bare `glean` only).")
    ] = "127.0.0.1",
    port: Annotated[
        int, typer.Option(help="Port to bind the web interface to (bare `glean` only).")
    ] = 8420,
) -> None:
    """Glean — unify open-source recon tools into a provenance-tracked,
    prioritised intelligence brief.

    Bare `glean` (no subcommand) launches the local web interface
    (ADR-0011) — additive, not a replacement: `glean scan ...` /
    `glean eval ...` remain the CLI path, entirely unaffected. Binds to
    localhost only by default (ADR-0011 D8): an unauthenticated control
    plane that can trigger *active* recon must never be reachable from
    the network by default.

    A callback (even a no-op one) is required here, not cosmetic: with
    only one registered command, Typer collapses to `glean <args>`
    directly instead of `glean <command> <args>` — silently reopening the
    `glean <domain>` vs `glean scan <domain>` question already decided
    against once `glean eval` exists as a sibling command (roadmap
    Workstream E4).
    """
    if ctx.invoked_subcommand is None:
        # Imported lazily: FastAPI/uvicorn/jinja2 shouldn't add import
        # weight to the common case (`glean scan ...`), which never
        # touches the web interface at all.
        from glean_osint.web.app import serve

        typer.echo(f"Glean web interface: http://{host}:{port}")
        serve(host=host, port=port)


@app.command()
def scan(
    domain: Annotated[str, typer.Argument(help="Target domain to build a brief for.")],
    crtsh: Annotated[
        Path | None,
        typer.Option(
            exists=True, readable=True, help="Path to crt.sh JSON output for this target."
        ),
    ] = None,
    theharvester: Annotated[
        Path | None,
        typer.Option(
            exists=True, readable=True, help="Path to theHarvester JSON output for this target."
        ),
    ] = None,
    subfinder: Annotated[
        Path | None,
        typer.Option(
            exists=True,
            readable=True,
            help="Path to subfinder -json (JSON-lines) output for this target.",
        ),
    ] = None,
    dnsx: Annotated[
        Path | None,
        typer.Option(
            exists=True,
            readable=True,
            help="Path to a dnsx {candidates, resolved} JSON envelope for this target.",
        ),
    ] = None,
    httpx: Annotated[
        Path | None,
        typer.Option(
            exists=True,
            readable=True,
            help="Path to httpx -json (JSON-lines) output for this target. "
            "This is an ACTIVE-recon tool: only use it against targets you're "
            "authorised to probe directly.",
        ),
    ] = None,
    hibp: Annotated[
        Path | None,
        typer.Option(
            exists=True,
            readable=True,
            help="Path to a Have I Been Pwned envelope for this target "
            "({domain_breaches, account_breaches}), or a bare breach array.",
        ),
    ] = None,
    hibp_api_key: Annotated[
        str | None,
        typer.Option(
            envvar=runner.HIBP_API_KEY_ENV,
            help="HIBP API key. Only needed to check discovered EMAIL ADDRESSES against "
            "breaches (a paid endpoint); domain-level breach lookup is free and needs none.",
        ),
    ] = None,
    live: Annotated[
        bool,
        typer.Option(
            help="Actually invoke tools live (ADR-0008) instead of only ingesting files. "
            "A per-tool file option, if given, still overrides live invocation for that tool. "
            "Implied when no per-tool input file is given at all."
        ),
    ] = False,
    offline: Annotated[
        bool,
        typer.Option(
            "--offline",
            help="Never invoke tools live: ingest the given files and nothing else. "
            "Only needed to refuse the live fallback that otherwise applies when no input "
            "file is given.",
        ),
    ] = False,
    active: Annotated[
        bool,
        typer.Option(
            help="With --live, also invoke httpx (ACTIVE recon — real HTTP requests at the "
            "target). Never invoked live without this; only use it against targets you're "
            "authorised to probe directly."
        ),
    ] = False,
    raw_dir: Annotated[
        Path | None,
        typer.Option(
            help="Where to archive live-fetched raw tool output. "
            "Default: ./glean-output/<slug>-<timestamp>/raw/"
        ),
    ] = None,
    crtsh_cache_ttl: Annotated[
        float,
        typer.Option(
            help="How long (seconds) a cached crt.sh response is served without re-querying "
            "(ADR-0008 D9) — reduces load on crt.sh across repeated scans of the same target, "
            "the observed trigger for real 502/404 responses in practice. 0 forces a live "
            "fetch every time while still allowing the stale-cache failsafe below."
        ),
    ] = runner.DEFAULT_CRTSH_CACHE_TTL_SECONDS,
    no_crtsh_cache: Annotated[
        bool,
        typer.Option(
            "--no-crtsh-cache",
            help="Bypass crt.sh caching entirely (no read, no write, no stale-data failsafe) "
            "for a guaranteed fresh-or-nothing answer — e.g. reproducing a bug or confirming "
            "a fix just went live at crt.sh's end.",
        ),
    ] = False,
    theharvester_bin: Annotated[
        str,
        typer.Option(
            envvar="GLEAN_THEHARVESTER_BIN",
            help="Executable name/path for theHarvester. Override this if it isn't on PATH "
            "(e.g. installed in its own venv) — pass the full path to its binary, or set "
            "$GLEAN_THEHARVESTER_BIN once instead of passing this every time.",
        ),
    ] = "theHarvester",
    subfinder_bin: Annotated[
        str,
        typer.Option(
            envvar="GLEAN_SUBFINDER_BIN",
            help="Executable name/path for subfinder. Override this if it isn't on PATH, or "
            "set $GLEAN_SUBFINDER_BIN once instead of passing this every time. No "
            "impostor-binary check here (unlike --dnsx-bin/--httpx-bin): confirmed live that "
            "subfinder's own -version output doesn't print a projectdiscovery.io banner the "
            "way dnsx/httpx do, and there's no known real name-collision risk for "
            "'subfinder' the way there confirmedly is for 'httpx'.",
        ),
    ] = "subfinder",
    dnsx_bin: Annotated[
        str,
        typer.Option(
            envvar="GLEAN_DNSX_BIN",
            help="Executable name/path for ProjectDiscovery's dnsx. Override this if a "
            "different, unrelated 'dnsx' is on PATH first, or set $GLEAN_DNSX_BIN once "
            "instead of passing this every time.",
        ),
    ] = "dnsx",
    httpx_bin: Annotated[
        str,
        typer.Option(
            envvar="GLEAN_HTTPX_BIN",
            help="Executable name/path for ProjectDiscovery's httpx. Override this if a "
            "different, unrelated 'httpx' (e.g. the Python HTTP client CLI) is on PATH first — "
            "this collision is common enough in practice to be worth a dedicated option. Set "
            "$GLEAN_HTTPX_BIN once instead of passing this every time.",
        ),
    ] = "httpx",
    authorisation: Annotated[
        str | None,
        typer.Option(help="Authorisation basis for this scan (recorded in the brief header)."),
    ] = None,
    top_n: Annotated[
        int, typer.Option(help="Number of findings in 'Top priorities'.")
    ] = DEFAULT_TOP_N,
    llm: Annotated[
        bool,
        typer.Option(
            help="Narrate 'Top priorities' with a real local LLM via Ollama (ADR-0009) "
            "instead of the deterministic template. Falls back to the template per-finding "
            "on any failure; never invented, never touches ordering/skeleton."
        ),
    ] = False,
    model: Annotated[
        str, typer.Option(help="Ollama model tag to use with --llm.")
    ] = synthesis.DEFAULT_MODEL,
    out: Annotated[
        Path | None,
        typer.Option(
            help="Write the brief to this file instead of stdout. A .html extension writes a "
            "self-contained HTML report (ADR-0010); anything else writes markdown."
        ),
    ] = None,
    show_all: Annotated[
        bool,
        typer.Option(
            help="Print every 'Also found' entry to the terminal instead of the default "
            f"{DEFAULT_ALSO_FOUND_LIMIT}. A target with a lot of history can have hundreds; "
            "--out always writes the complete brief regardless of this flag."
        ),
    ] = False,
) -> None:
    """Build a prioritised, provenance-tracked brief for DOMAIN.

    Ingest-only by default: point it at already-fetched raw tool output
    (--crtsh / --theharvester / --subfinder / --dnsx / --httpx). Pass
    --live to actually invoke tools (ADR-0008); a per-tool file option
    still overrides live invocation for that specific tool (mixed mode).
    Given no input file at all, live invocation is implied, so
    `glean scan <domain>` produces a report on its own.
    --active is required in addition to --live to invoke httpx, the
    only active-method tool.
    """
    if live and offline:
        typer.secho("--live and --offline contradict each other.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    no_input_files = (
        crtsh is None
        and theharvester is None
        and subfinder is None
        and dnsx is None
        and httpx is None
        and hibp is None
    )
    if no_input_files and offline:
        typer.secho(
            "--offline needs at least one of --crtsh, --theharvester, --subfinder, --dnsx, "
            "--httpx or --hibp to ingest.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)
    if no_input_files and not live:
        # Closes the charter's MVP criterion 1 -- "glean scan <domain> ->
        # one report, no manual steps" -- which a bare invocation did not
        # meet while it exited asking for input (ADR-0008 open question 2).
        #
        # Narrow on purpose: live is implied only when *no* input file was
        # given at all, which is precisely the case that previously did
        # nothing. Passing any file still means ingest-only, so every
        # existing ingest workflow is untouched rather than silently
        # acquiring network calls it never asked for.
        #
        # Only passive tools are reached this way. httpx stays behind
        # --active (ADR-0008 D4), so nothing here touches the target
        # directly without a second, explicit opt-in -- the charter's
        # active/passive split is unaffected by this default.
        live = True
        typer.secho(
            "No input files given — fetching with passive tools (crt.sh, theHarvester, "
            "subfinder, dnsx, HIBP). Pass --offline with input files to ingest instead.",
            fg=typer.colors.CYAN,
            err=True,
        )

    # Every degraded-tool warning this scan emits, collected as well as
    # printed. Previously the CLI only printed them, so a scan run from the
    # terminal always wrote `warnings: []` into its manifest and its history
    # entry never showed the warning pill -- even when a tool had genuinely
    # failed. Since Stage 3 put CLI and web scans in one shared history
    # (ADR-0011 D6), that made two rows of the same list mean different
    # things depending on which surface produced them.
    scan_warnings: list[str] = []

    def warn(message: str) -> None:
        typer.secho(message, fg=typer.colors.YELLOW, err=True)
        scan_warnings.append(message)

    collected_at_dt = datetime.now(timezone.utc)
    collected_at = collected_at_dt.isoformat()
    output_dir = raw_dir if raw_dir is not None else _default_raw_dir(domain, collected_at_dt)
    results: list[ParseResult] = []
    tools_run: list[ToolRun] = []

    # --- Stage 1: crt.sh + theHarvester + subfinder, run concurrently ---
    # (independent, ADR-0008 D1). All three are independent I/O-bound
    # calls (an HTTP fetch, two subprocesses) -- theHarvester/subfinder
    # can each individually take minutes querying live external sources,
    # so running them one after another is additive wall-clock time for
    # no reason. Flagged as an open question in ADR-0008 when Stage 1
    # only had two tools; a real enough cost now that it has three.
    # merge_graph is proven order-independent (ADR-0003 D7), so which
    # thread finishes first cannot affect the final entity graph -- only
    # tools_run's *display* order is worth fixing up afterward, for a
    # consistent "Tools:" line across runs.
    #
    # A single spinner spans the whole concurrent phase (there's no one
    # "current stage" to label individually anymore); each tool's
    # info/warning messages are collected into `stage1_messages` rather
    # than printed directly, for the same reason `_invoke_live`'s own
    # docstring already explains -- printing from inside an active
    # spinner's `with` block races its `\r`-driven redraw thread.

    _Stage1Message = tuple[str, str]  # (colour, text)

    def _run_crtsh_stage1(messages: list[_Stage1Message]) -> None:
        crtsh_info: list[str] = []
        crtsh_fetch: Callable[[], bytes] = (
            (lambda: runner.fetch_crtsh(domain))
            if no_crtsh_cache
            else (lambda: runner.fetch_crtsh_cached(domain, ttl=crtsh_cache_ttl, info=crtsh_info))
        )
        crtsh_raw, crtsh_ref, crtsh_warning = _resolve_input(crtsh, live, crtsh_fetch, "crt.sh")
        for message in crtsh_info:
            messages.append((typer.colors.CYAN, message))
        if crtsh_warning:
            messages.append((typer.colors.YELLOW, crtsh_warning))
        if crtsh_raw is not None:
            ref = crtsh_ref
            if crtsh is None:
                ref = runner.archive_raw(output_dir, f"crtsh-{domain}.json", crtsh_raw)
            ctx = ScanContext(target=domain, collected_at=collected_at, raw_output_ref=ref)
            result = CrtshAdapter().parse(crtsh_raw, ctx)
            results.append(result)
            tools_run.append(ToolRun(source_tool="crtsh", method="passive", raw_output_ref=ref))
            if result.skipped:
                messages.append(
                    (typer.colors.YELLOW, f"crt.sh: skipped {result.skipped} malformed record(s).")
                )

    def _run_theharvester_stage1(messages: list[_Stage1Message]) -> None:
        theharvester_raw, theharvester_ref, theharvester_warning = _resolve_input(
            theharvester,
            live,
            lambda: runner.run_theharvester(domain, binary=theharvester_bin),
            "theHarvester",
        )
        if theharvester_warning:
            messages.append((typer.colors.YELLOW, theharvester_warning))
        if theharvester_raw is not None:
            ref = theharvester_ref
            if theharvester is None:
                ref = runner.archive_raw(
                    output_dir, f"theharvester-{domain}.json", theharvester_raw
                )
            ctx = ScanContext(target=domain, collected_at=collected_at, raw_output_ref=ref)
            result = TheHarvesterAdapter().parse(theharvester_raw, ctx)
            results.append(result)
            tools_run.append(
                ToolRun(source_tool="theharvester", method="passive", raw_output_ref=ref)
            )
            if result.skipped:
                messages.append(
                    (
                        typer.colors.YELLOW,
                        f"theHarvester: skipped {result.skipped} malformed record(s).",
                    )
                )

    def _run_subfinder_stage1(messages: list[_Stage1Message]) -> None:
        subfinder_raw, subfinder_ref, subfinder_warning = _resolve_input(
            subfinder,
            live,
            lambda: runner.run_subfinder(domain, binary=subfinder_bin),
            "subfinder",
        )
        if subfinder_warning:
            messages.append((typer.colors.YELLOW, subfinder_warning))
        if subfinder_raw is not None:
            ref = subfinder_ref
            if subfinder is None:
                ref = runner.archive_raw(output_dir, f"subfinder-{domain}.jsonl", subfinder_raw)
            ctx = ScanContext(target=domain, collected_at=collected_at, raw_output_ref=ref)
            result = SubfinderAdapter().parse(subfinder_raw, ctx)
            results.append(result)
            tools_run.append(ToolRun(source_tool="subfinder", method="passive", raw_output_ref=ref))
            if result.skipped:
                messages.append(
                    (
                        typer.colors.YELLOW,
                        f"subfinder: skipped {result.skipped} malformed record(s).",
                    )
                )

    stage1_any_live = live and (crtsh is None or theharvester is None or subfinder is None)
    stage1_messages: list[_Stage1Message] = []
    with (
        _maybe_spin(
            stage1_any_live, "Running passive discovery (crt.sh, theHarvester, subfinder)..."
        ),
        ThreadPoolExecutor(max_workers=3) as executor,
    ):
        futures = [
            executor.submit(_run_crtsh_stage1, stage1_messages),
            executor.submit(_run_theharvester_stage1, stage1_messages),
            executor.submit(_run_subfinder_stage1, stage1_messages),
        ]
        for future in futures:
            future.result()  # propagate a genuinely unexpected exception, don't swallow it

    for colour, message in stage1_messages:
        # Only the yellow ones are real degradation. crt.sh cache-hit and
        # stale-failsafe notices come through here in cyan and must not be
        # recorded as warnings -- that exact conflation is what made
        # /history claim "1 warning" on healthy scans once before.
        if colour == typer.colors.YELLOW:
            warn(message)
        else:
            typer.secho(message, fg=colour, err=True)

    # tools_run's append order is otherwise whichever thread finished
    # first (non-deterministic) -- fixed here into a stable sequence for
    # a consistent "Tools:" line across runs. merge_graph itself doesn't
    # care (ADR-0003 D7); only this list's own display order does. Safe
    # to sort the whole list at this point -- Stage 2/3 haven't appended
    # anything to it yet.
    _stage1_tool_order = {"crtsh": 0, "theharvester": 1, "subfinder": 2}
    tools_run.sort(key=lambda t: _stage1_tool_order.get(t.source_tool, 99))

    # --- Stage 2: dnsx, fed Stage 1's parsed hostnames (ADR-0008 D1) ---

    candidates = runner.extract_candidates(domain, results)
    with _maybe_spin(
        dnsx is None and live, f"Resolving {len(candidates)} candidate hostname(s) (dnsx)..."
    ):
        dnsx_raw, dnsx_ref, dnsx_warning = _resolve_input(
            dnsx, live, lambda: runner.run_dnsx(candidates, binary=dnsx_bin), "dnsx"
        )
    if dnsx_warning:
        warn(dnsx_warning)
    if dnsx_raw is not None:
        if dnsx is None:
            dnsx_ref = runner.archive_raw(output_dir, f"dnsx-{domain}.json", dnsx_raw)
        ctx = ScanContext(target=domain, collected_at=collected_at, raw_output_ref=dnsx_ref)
        result = DnsxAdapter().parse(dnsx_raw, ctx)
        results.append(result)
        tools_run.append(ToolRun(source_tool="dnsx", method="passive", raw_output_ref=dnsx_ref))
        _warn_skipped("dnsx", result.skipped, scan_warnings)

    # --- Stage 3: httpx, fed Stage 2's resolved hosts, ACTIVE + opt-in only ---

    if httpx is not None:
        httpx_raw: bytes | None = httpx.read_bytes()
        httpx_ref: str | None = str(httpx)
    elif live and active:
        resolved_hosts = runner.extract_resolved_hosts(results)
        label = f"Probing {len(resolved_hosts)} live host(s) for services and tech (httpx)..."
        with _maybe_spin(True, label):
            httpx_raw, httpx_warning = _invoke_live(
                "httpx", lambda: runner.run_httpx(resolved_hosts, binary=httpx_bin)
            )
        if httpx_warning:
            warn(httpx_warning)
        httpx_ref = None
    else:
        if live:
            warn("httpx: skipped (active recon not enabled; pass --active to include it).")
        httpx_raw, httpx_ref = None, None

    if httpx_raw is not None:
        if httpx is None:
            httpx_ref = runner.archive_raw(output_dir, f"httpx-{domain}.jsonl", httpx_raw)
        ctx = ScanContext(target=domain, collected_at=collected_at, raw_output_ref=httpx_ref)
        result = HttpxAdapter().parse(httpx_raw, ctx)
        results.append(result)
        tools_run.append(ToolRun(source_tool="httpx", method="active", raw_output_ref=httpx_ref))
        _warn_skipped("httpx", result.skipped, scan_warnings)

    # --- Stage 4: HIBP, fed the addresses the other tools actually found ---
    #
    # Last because the account half needs those addresses. Passive: HIBP is
    # asked about the target, never touching it.

    if hibp is not None:
        hibp_raw: bytes | None = hibp.read_bytes()
        hibp_ref: str | None = str(hibp)
    elif live:
        emails = runner.extract_emails(results)
        label = "Checking breach exposure (HIBP)..."
        with _maybe_spin(True, label):
            hibp_raw, hibp_warning = _invoke_live(
                "hibp",
                lambda: runner.fetch_hibp(domain, emails=emails, api_key=hibp_api_key),
            )
        if hibp_warning:
            warn(hibp_warning)
        hibp_ref = None
    else:
        hibp_raw, hibp_ref = None, None

    if hibp_raw is not None:
        if hibp is None:
            hibp_ref = runner.archive_raw(output_dir, f"hibp-{domain}.json", hibp_raw)
        ctx = ScanContext(target=domain, collected_at=collected_at, raw_output_ref=hibp_ref)
        result = HibpAdapter().parse(hibp_raw, ctx)
        results.append(result)
        tools_run.append(ToolRun(source_tool="hibp", method="passive", raw_output_ref=hibp_ref))
        _warn_skipped("hibp", result.skipped, scan_warnings)

    merged = merge_graph(results)
    scored = score_graph(merged.entities, merged.edges, datetime.now(timezone.utc))

    scan_meta = ScanMeta(
        target=domain,
        started_at=collected_at,
        glean_version=__version__,
        authorisation=authorisation,
        tools_run=tuple(tools_run),
    )
    brief = build_brief(scored, merged.edges, scan_meta, top_n=top_n)
    if llm:
        with Spinner(f"Narrating top priorities with {model} (Ollama)..."):
            synthesis_result = synthesis.synthesize_brief(brief, scored, model=model)
        brief = synthesis_result.brief
        typer.secho(
            f"[llm] model={model} narrated={synthesis_result.narrated_count} "
            f"fell_back={synthesis_result.fell_back_count} "
            f"invented_ids_dropped={synthesis_result.invented_ids_dropped}",
            fg=typer.colors.CYAN,
            err=True,
        )
    if live and raw_dir is None:
        # ADR-0011 D6: only the default history location gets a manifest
        # -- an explicit --raw-dir signals "put output somewhere else,
        # on my own terms," which opts out of the shared-history
        # bookkeeping too. Created explicitly rather than relied on as a
        # side effect of archive_raw() -- a --live scan where every tool
        # is *also* overridden by a per-tool file never calls
        # archive_raw at all (the exact bug already found once in the
        # web app's own history writing).
        scan_dir = history.DEFAULT_HISTORY_ROOT / history.scan_id_for(domain, collected_at_dt)
        scan_dir.mkdir(parents=True, exist_ok=True)
        (scan_dir / "brief.html").write_text(render_html(brief), encoding="utf-8")
        history.write_manifest(
            scan_dir,
            history.ScanManifest(
                scan_id=scan_dir.name,
                target=domain,
                started_at=collected_at,
                tools_run=tuple(t.source_tool for t in brief.scan.tools_run),
                authorisation=authorisation,
                findings_count=brief.findings_count,
                warnings=tuple(scan_warnings),
                surface=surface_counts(scored),
            ),
        )
        history.write_entities_snapshot(
            scan_dir, [f.entity.to_dict() for f in brief.top_priorities + brief.also_found]
        )
        # `merged.edges` is still in scope here, unlike in pipeline.run_scan
        # where it needed returning explicitly -- but it was being dropped
        # just the same, so a CLI-run scan and a web-run scan now archive
        # the identical set of files into the shared history (ADR-0011 D6).
        history.write_edges_snapshot(scan_dir, [e.to_dict() for e in merged.edges])

    typer.echo(SECTION_BREAK)
    if out is not None:
        # Format follows --out's extension (ADR-0010 D2): .html gets the
        # self-contained report view, anything else stays markdown. A
        # saved file is always a complete archive copy regardless of
        # --show-all -- that flag only affects what prints to the terminal.
        if out.suffix.lower() == ".html":
            out.write_text(render_html(brief), encoding="utf-8")
        else:
            out.write_text(render_markdown(brief, also_found_limit=None), encoding="utf-8")
        typer.echo(f"Brief written to {out}")
    else:
        limit = None if show_all else DEFAULT_ALSO_FOUND_LIMIT
        typer.echo(render_markdown(brief, also_found_limit=limit))

    typer.secho(
        f"\n[dedup] entities_before={merged.stats.entities_before} "
        f"entities_after={merged.stats.entities_after} "
        f"duplicate_rate={merged.stats.duplicate_rate:.1%}",
        fg=typer.colors.CYAN,
        err=True,
    )


def _warn_skipped(tool: str, skipped: int, sink: list[str] | None = None) -> None:
    if skipped:
        message = f"{tool}: skipped {skipped} malformed record(s)."
        typer.secho(message, fg=typer.colors.YELLOW, err=True)
        if sink is not None:
            sink.append(message)


@dataclass(frozen=True, slots=True)
class _TargetEvalResult:
    target: str
    faithfulness: FaithfulnessResult
    provenance_retention: float
    prioritisation: PrioritisationQuality
    stage2: Stage2FaithfulnessResult | None
    # The scored graph this result was computed from. Defaulted, so the
    # summary table is unaffected; it's here so a caller can check *what*
    # was evaluated (which adapters actually contributed, whether a ground
    # truth references an entity that exists) rather than only the scores,
    # which cannot distinguish "nothing regressed" from "nothing ran".
    entities: tuple[Entity, ...] = ()


# Every passive adapter the evaluation harness reads, by the filename its
# capture is archived under. Each is optional: a target predating an
# adapter simply has no such file and is skipped (`path.exists()` below),
# which is why adding one here cannot change any already-computed number.
# subfinder was added as the fifth adapter (ADR-0002) but never wired in
# here, so `glean eval` silently ignored a `subfinder-*.jsonl` capture --
# the one adapter the evaluation could not see. No target in the existing
# ground-truth set has a subfinder capture, so this is inert for them and
# correct for anything captured from now on.
_RAW_ADAPTERS = (
    (CrtshAdapter, "crtsh-{slug}.json"),
    (TheHarvesterAdapter, "theharvester-{slug}.json"),
    (SubfinderAdapter, "subfinder-{slug}.jsonl"),
    (DnsxAdapter, "dnsx-{slug}.json"),
    (HibpAdapter, "hibp-{slug}.json"),
)


def _evaluate_target(
    target_dir: Path,
    top_n: int,
    *,
    llm: bool = False,
    model: str = synthesis.DEFAULT_MODEL,
    judge_model: str = DEFAULT_JUDGE_MODEL,
) -> _TargetEvalResult:
    """Run the real pipeline (adapters -> dedup -> scoring -> brief) against
    one target's raw captures and compare it against its ground truth
    (ADR-0006/0007). Roadmap E4's single reproducible entrypoint."""
    slug = target_dir.name
    raw_dir = target_dir / "raw"
    ground_truth = load_ground_truth(target_dir / "ground_truth.yaml")
    collected_at = datetime.now(timezone.utc).isoformat()
    ctx = ScanContext(target=ground_truth.target, collected_at=collected_at)

    results: list[ParseResult] = []
    for adapter_cls, filename_template in _RAW_ADAPTERS:
        path = raw_dir / filename_template.format(slug=slug)
        if path.exists():
            results.append(adapter_cls().parse(path.read_bytes(), ctx))
    httpx_path = raw_dir / f"httpx-{slug}.jsonl"
    if httpx_path.exists():
        results.append(HttpxAdapter().parse(httpx_path.read_bytes(), ctx))

    merged = merge_graph(results)
    # A target that parsed nothing must be an error, never a result. Both
    # headline metrics are ratios over the findings in a brief, so an empty
    # graph makes them vacuously perfect: faithfulness 1.000 because no
    # finding is unfaithful, provenance_retention 1.000 because no finding
    # lacks a source. Caught by exactly that happening in CI -- the raw
    # captures were missing, and `glean eval` reported a flawless 1.000/1.000
    # and exited 0 rather than saying it had evaluated nothing at all. That
    # is absence-as-evidence, which this project refuses everywhere else,
    # and it would have silently hidden a renamed or corrupted capture in
    # the real ground-truth set. Raised rather than returned: `run_eval`
    # already degrades one bad target into a warning and keeps going, and
    # exits non-zero if every target fails (ADR-0002 D5's discipline).
    if not merged.entities:
        msg = (
            f"no entities parsed from {raw_dir} — expected at least one capture matching "
            f"<tool>-{slug}.json/.jsonl. An empty graph scores a vacuous 1.000, so it is "
            "reported as a failure rather than counted as a result"
        )
        raise ValueError(msg)
    scored = score_graph(merged.entities, merged.edges, datetime.now(timezone.utc))
    scan_meta = ScanMeta(
        target=ground_truth.target, started_at=collected_at, glean_version=__version__
    )
    brief = build_brief(scored, merged.edges, scan_meta, top_n=top_n)
    stage2: Stage2FaithfulnessResult | None = None
    if llm:
        brief = synthesis.synthesize_brief(brief, scored, model=model).brief
        # Stage 2 only means something once there's real narration to judge
        # (also_found is always template text, trivially faithful, D2) --
        # skip the extra judge call entirely on a template-only brief.
        stage2 = faithfulness_stage2(brief, edges=merged.edges, judge_model=judge_model)

    entity_ids = {e.id for e in scored}
    glean_ranked_ids = [e.id for e in scored]
    return _TargetEvalResult(
        target=ground_truth.target,
        faithfulness=faithfulness_stage1(
            brief,
            entity_ids,
            edges=merged.edges,
            entity_types={e.id: e.type for e in scored},
        ),
        provenance_retention=provenance_retention(brief),
        prioritisation=prioritisation_quality(glean_ranked_ids, ground_truth, n=top_n),
        stage2=stage2,
        entities=tuple(scored),
    )


@app.command(name="eval")
def run_eval(
    scans_dir: Annotated[
        Path,
        typer.Option(help="Directory containing <slug>/raw + <slug>/ground_truth.yaml pairs."),
    ] = Path("eval/scans"),
    top_n: Annotated[
        int, typer.Option(help="N for prioritisation-quality overlap@N/nDCG@N (ADR-0006 D2).")
    ] = DEFAULT_TOP_N,
    llm: Annotated[
        bool,
        typer.Option(
            help="Narrate 'Top priorities' with a real local LLM via Ollama (ADR-0009) before "
            "scoring faithfulness/provenance-retention, instead of the trivially-faithful "
            "template brief."
        ),
    ] = False,
    model: Annotated[
        str, typer.Option(help="Ollama model tag to use with --llm.")
    ] = synthesis.DEFAULT_MODEL,
    judge_model: Annotated[
        str,
        typer.Option(
            help="Ollama model tag for the stage-2 faithfulness judge (ADR-0006 D4). Should be "
            "a different, ideally stronger model than --model. Only used with --llm."
        ),
    ] = DEFAULT_JUDGE_MODEL,
) -> None:
    """Run the evaluation harness (ADR-0006) across every target under
    SCANS_DIR that has both raw tool output and a ground_truth.yaml
    (ADR-0007), and report the three headline numbers.

    Without --llm, faithfulness/provenance-retention are trivially 1.0
    (the template brief can't fabricate by construction). With --llm,
    faithfulness is reported at both stages: stage 1 (structural —
    does the finding's entity exist at all) will *still* read 1.0, since
    an invented entity is already filtered out before it can reach the
    brief; stage 2 (an LLM judge checking the narrated prose's actual
    claims against that entity's real facts) is where a real fabricated
    detail would actually show up.
    """
    if not scans_dir.is_dir():
        typer.secho(f"{scans_dir} is not a directory.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    target_dirs = sorted(
        d for d in scans_dir.iterdir() if d.is_dir() and (d / "ground_truth.yaml").exists()
    )
    if not target_dirs:
        typer.secho(
            f"No targets with ground_truth.yaml found under {scans_dir}.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    results: list[_TargetEvalResult] = []
    for index, target_dir in enumerate(target_dirs, start=1):
        label = f"Evaluating {target_dir.name} ({index}/{len(target_dirs)})..."
        try:
            with Spinner(label):
                results.append(
                    _evaluate_target(
                        target_dir, top_n, llm=llm, model=model, judge_model=judge_model
                    )
                )
        except Exception as error:  # noqa: BLE001 -- one bad target must not abort the report
            typer.secho(
                f"{target_dir.name}: evaluation failed ({error}), skipping.",
                fg=typer.colors.YELLOW,
                err=True,
            )

    typer.echo(SECTION_BREAK)
    if not results:
        typer.secho("No targets evaluated successfully.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    # `stage1_faith`, not a bare `faithfulness`: the two stages measure
    # genuinely different things (ADR-0006 D1), and a column headed
    # "faithfulness" invites reading a structural id-existence check as a
    # statement that the prose is accurate. Real evidence that this matters,
    # not a hypothetical tidy-up: one narrated brief scored stage 1 = 1.000
    # and stage 2 = 0.455 on identical text, with a finding stating the
    # opposite of its own entity's attributes (ADR-0009 Validation,
    # 2026-08-04). Naming the stages symmetrically also makes stage 2's
    # *absence* visible, which a lone "faithfulness" column hid.
    header = f"{'target':<20} {'stage1_faith':>13} {'provenance':>11} "
    header += f"{'overlap@' + str(top_n):>10} {'ndcg@' + str(top_n):>9}"
    if llm:
        header += f" {'stage2_faith':>13}"
    typer.echo(header)
    for r in results:
        line = (
            f"{r.target:<20} {r.faithfulness.score:>13.3f} {r.provenance_retention:>11.3f} "
            f"{r.prioritisation.overlap_at_n:>10.3f} {r.prioritisation.ndcg_at_n:>9.3f}"
        )
        if llm and r.stage2 is not None:
            line += f" {r.stage2.score:>13.3f}"
        typer.echo(line)

    # Listed rather than only counted: a stage-1 score below 1.000 is new
    # (ADR-0006 D1 stage 1b, 2026-08-06) and a reader's first question is
    # which finding caused it. Each line is a deterministic, checkable
    # statement, so showing it costs nothing and makes the number auditable
    # without re-running anything.
    flagged = [(r.target, c) for r in results for c in r.faithfulness.contradictions]
    if flagged:
        typer.echo("")
        typer.secho(
            f"{len(flagged)} structurally unsupported assertion(s) — these fail stage 1:",
            fg=typer.colors.YELLOW,
        )
        for target, contradiction in flagged:
            typer.echo(f"  {target}: {contradiction}")

    n = len(results)
    mean_faithfulness = sum(r.faithfulness.score for r in results) / n
    mean_provenance = sum(r.provenance_retention for r in results) / n
    mean_overlap = sum(r.prioritisation.overlap_at_n for r in results) / n
    mean_ndcg = sum(r.prioritisation.ndcg_at_n for r in results) / n

    summary = (
        f"\n[{n} targets] mean stage1_faithfulness={mean_faithfulness:.3f} "
        f"mean provenance_retention={mean_provenance:.3f} "
        f"mean overlap@{top_n}={mean_overlap:.3f} mean nDCG@{top_n}={mean_ndcg:.3f}"
    )
    stage2_results = [r.stage2 for r in results if r.stage2 is not None]
    if stage2_results:
        mean_stage2 = sum(s.score for s in stage2_results) / len(stage2_results)
        total_unjudged = sum(s.unjudged_findings for s in stage2_results)
        summary += f" mean stage2_faithfulness={mean_stage2:.3f} (unjudged={total_unjudged})"

    typer.secho(summary, fg=typer.colors.CYAN)
    typer.echo(_faithfulness_caveat(measured_content=bool(stage2_results)))


def _faithfulness_caveat(*, measured_content: bool) -> str:
    """What the reported faithfulness number does and does not cover.

    Printed with the numbers rather than left to the README, because the
    numbers are what gets pasted into a report or a paper -- a caveat that
    only exists in documentation does not travel with them.

    Stage 1 checks that each finding's entity exists in the graph. Invented
    ids are filtered out before a brief is ever built (ADR-0009 D5), so it
    is structurally incapable of reading below 1.000, and a reader shown it
    alone would reasonably but wrongly conclude the prose was accurate --
    a real narrated brief has scored stage 1 = 1.000 and stage 2 = 0.455 on
    identical text (ADR-0009 Validation, 2026-08-04).
    """
    lines = [
        "stage1_faith is deterministic and now has two parts (ADR-0006 D1). Entity existence",
        "cannot fail for a generated brief. The structural check CAN: it fails prose that",
        "asserts what the graph decides on its own, e.g. a wildcard narrated as resolving",
        "when nothing records it resolving. It still says nothing about claims that need",
        "judgement rather than lookup — that is stage 2's job.",
    ]
    if measured_content:
        lines += [
            "stage2_faith judges the prose itself, but the judge errs in ways measured three",
            "times against human labels: flag precision has read 0.250, 1.000 and 0.444 as the",
            "evidence it is shown changed. It never overstates faithfulness, so read this as a",
            "lower bound rather than an estimate, and see ADR-0006 Validation for how loose.",
        ]
    else:
        lines += [
            "Content-level fabrication — a real entity described with false prose — is NOT",
            "measured in this run. Pass --llm to also run the stage-2 judge.",
        ]
    return "\n".join(lines)


@app.command(name="judge-audit")
def judge_audit(
    scans_dir: Annotated[
        Path, typer.Option(help="Directory of ground-truth targets to draw claims from.")
    ] = Path("eval/scans"),
    out: Annotated[Path, typer.Option(help="Where to write the annotation packet.")] = Path(
        "judge-audit.yaml"
    ),
    sample: Annotated[
        int, typer.Option(help="How many claims to sample. 0 takes every claim.")
    ] = 50,
    seed: Annotated[
        int, typer.Option(help="Sampling seed, so a packet can be regenerated exactly.")
    ] = 0,
    carry_over: Annotated[
        Path | None,
        typer.Option(
            exists=True,
            readable=True,
            help="An earlier labelled packet. Labels for claims that still exist verbatim "
            "are reused, so only genuinely-new claims need labelling.",
        ),
    ] = None,
    model: Annotated[str, typer.Option(help="Narration model.")] = synthesis.DEFAULT_MODEL,
    judge_model: Annotated[str, typer.Option(help="Judge model.")] = DEFAULT_JUDGE_MODEL,
    top_n: Annotated[int, typer.Option(help="Findings narrated per brief.")] = DEFAULT_TOP_N,
) -> None:
    """Build a packet of judge verdicts for a human to label (ADR-0006 Q5).

    `glean eval --llm` reports `stage2_faith` on the judge's word alone. This
    samples the judge's individual verdicts, together with the exact evidence
    it was shown, so a person can rule on the same claims independently. Score
    the labelled result with `glean judge-score`.

    Run three times so far: flag precision 0.250 as first shipped, 1.000
    once evidence was stated as plain sentences, 0.444 when connected-entity
    facts arrived in a separate field the judge read as second-class
    (ADR-0006 Validation). Every swing traced to evidence presentation
    rather than the judge's reasoning, which is the argument for re-running
    this after any change to the prompt or the facts -- and for using
    --carry-over so it costs a handful of labels rather than all of them.

    Nothing here writes a `human_verdict` -- those labels are research data
    and have to come from a person.
    """
    if not scans_dir.is_dir():
        typer.secho(f"{scans_dir} is not a directory.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    target_dirs = sorted(
        d for d in scans_dir.iterdir() if d.is_dir() and (d / "ground_truth.yaml").exists()
    )
    if not target_dirs:
        typer.secho(f"No targets under {scans_dir}.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    collected: list[tuple[str, object]] = []
    for index, target_dir in enumerate(target_dirs, start=1):
        try:
            with Spinner(f"Judging {target_dir.name} ({index}/{len(target_dirs)})..."):
                result = _evaluate_target(
                    target_dir, top_n, llm=True, model=model, judge_model=judge_model
                )
        except Exception as error:  # noqa: BLE001 -- one bad target must not abort the packet
            typer.secho(f"{target_dir.name}: skipped ({error}).", fg=typer.colors.YELLOW, err=True)
            continue
        if result.stage2 is not None:
            collected.extend((result.target, c) for c in result.stage2.claims)

    if not collected:
        typer.secho(
            "No judged claims collected — is Ollama running with the judge model pulled?",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    entries = judge_audit_mod.build_packet(collected, sample_size=sample, seed=seed)
    carried: judge_audit_mod.CarryOver | None = None
    if carry_over is not None:
        entries, carried = judge_audit_mod.carry_over_labels(
            entries, _load_audit_packet(carry_over)
        )
    out.write_text(_render_audit_packet(entries, judge_model=judge_model, seed=seed), "utf-8")
    typer.echo(SECTION_BREAK)
    typer.echo(f"{len(entries)} claim(s) sampled from {len(collected)} judged, written to {out}")
    if carried is not None:
        typer.echo(f"{carried.summary} (from {carry_over})")
        if carried.dropped:
            typer.secho(
                f"{carried.dropped} previously-labelled claim(s) no longer exist — the judge "
                "re-decomposed the prose, so those rulings do not transfer.",
                fg=typer.colors.YELLOW,
            )
    remaining = carried.still_unlabelled if carried is not None else len(entries)
    typer.secho(
        f"Fill in the {remaining} blank `human_verdict` field(s) (supported | unsupported), "
        f"then run `glean judge-score {out}`.",
        fg=typer.colors.CYAN,
    )


@app.command(name="judge-score")
def judge_score(
    packet: Annotated[Path, typer.Argument(exists=True, readable=True)],
) -> None:
    """Score the judge against a labelled packet (ADR-0006 Q5)."""
    entries = _load_audit_packet(packet)
    if not entries:
        typer.secho("No entries in that packet.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    try:
        result = judge_audit_mod.score_packet(entries)
    except ValueError as error:
        typer.secho(str(error), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from error

    def pct(v: float | None) -> str:
        return "n/a" if v is None else f"{v:.3f}"

    typer.echo(SECTION_BREAK)
    typer.echo(f"claims labelled     {result.labelled}")
    typer.echo(f"raw agreement       {result.agreement:.3f}")
    typer.echo(f"flag precision      {pct(result.flag_precision)}   (judge flagged, human agreed)")
    typer.echo(f"flag recall         {pct(result.flag_recall)}   (real problems it caught)")
    typer.echo(f"Cohen's kappa       {pct(result.kappa)}")
    typer.secho("\n" + judge_audit_mod.interpret(result), fg=typer.colors.CYAN)


def _load_audit_packet(packet: Path) -> list[judge_audit_mod.AuditEntry]:
    """Read a packet back, splitting each `human_verdict` into label and note."""
    data = yaml.safe_load(packet.read_text(encoding="utf-8")) or {}
    return [
        judge_audit_mod.AuditEntry(
            index=e.get("index", i),
            target=e.get("target", ""),
            entity_id=e.get("entity_id", ""),
            claim=e.get("claim", ""),
            judge_verdict=e.get("judge_verdict", ""),
            entity_facts=e.get("entity_facts", ""),
            human_verdict=judge_audit_mod.parse_verdict(e.get("human_verdict"))[0],
            note=judge_audit_mod.parse_verdict(e.get("human_verdict"))[1],
        )
        for i, e in enumerate(data.get("entries") or [], start=1)
    ]


def _render_audit_packet(
    entries: list[judge_audit_mod.AuditEntry], *, judge_model: str, seed: int
) -> str:
    """Hand-rendered rather than `yaml.dump`ed: this is a document a person
    has to read and edit dozens of times, so it carries its instructions
    inline and keeps one blank `human_verdict` per entry sitting exactly
    where the annotator's cursor needs to go."""
    lines = [
        "# Judge reliability annotation packet (ADR-0006 Q5).",
        "#",
        "# For each claim: does the recorded evidence support what the prose says?",
        "# Write `supported` or `unsupported` in `human_verdict`. You may add your",
        "# reasoning after it -- `unsupported - no service anywhere in the facts` --",
        "# and it is kept with the label rather than discarded.",
        "#",
        "# WHAT COUNTS AS EVIDENCE. All three of these are facts about the entity:",
        "#",
        "#   attributes  what the tools recorded directly (dns_resolved, port, ...)",
        "#   signals     facts DERIVED by the scoring rubric. These are evidence,",
        "#               not commentary. `resolves to a live IP with an exposed",
        "#               service` fires only when a service was actually found, so",
        "#               prose mentioning a service IS supported when that signal",
        "#               is present, even though `attributes` shows only",
        "#               dns_resolved.",
        "#   seen_by     which tools asserted it. `httpx (active)` is the only one",
        "#               that probes services at all.",
        "#",
        "# A claim is unsupported when the prose asserts something none of the",
        "# three record -- a service with no service signal and no httpx, or a",
        "# characterisation the model supplied from world knowledge (calling a",
        "# technology a CDN when nothing says so).",
        "#",
        "# `judge_verdict` is what the model decided. The whole value here is an",
        "# independent second opinion, so decide from the evidence first.",
        "#",
        "# Then: glean judge-score <this file>",
        f"judge_model: {judge_model}",
        f"seed: {seed}",
        "entries:",
    ]
    for e in entries:
        try:
            facts = json.dumps(json.loads(e.entity_facts), indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, ValueError):
            facts = e.entity_facts
        existing = e.human_verdict or ""
        if existing and e.note:
            existing = f"{existing} - {e.note}"
        lines += [
            f"  - index: {e.index}",
            f"    target: {json.dumps(e.target)}",
            f"    entity_id: {json.dumps(e.entity_id)}",
            f"    claim: {json.dumps(e.claim)}",
            "    entity_facts: |",
            *("      " + line for line in facts.splitlines()),
            f"    judge_verdict: {e.judge_verdict}",
            # Quoted whenever it carries content: an annotator's note can
            # contain a colon, a dash, or anything else, and an unquoted
            # scalar would let that reshape the document. Losing labelled
            # research data to a YAML quirk is not an acceptable failure.
            (
                f"    human_verdict: {json.dumps(existing)}"
                if existing
                else "    human_verdict:   # supported | unsupported"
            ),
            "",
        ]
    return "\n".join(lines) + "\n"


def _default_raw_dir(domain: str, collected_at: datetime) -> Path:
    """ADR-0008 D7, amended by ADR-0011 D6: raw output from a live run is
    archived under the same fixed history location the web interface
    uses (`~/.local/share/glean/scans/<scan_id>/raw/`), distinct from
    `eval/scans/` (the private ground-truth set, not general end-user
    scan output) -- so a scan run from the terminal and one run from
    the web UI land in one shared, browsable history rather than two
    disconnected ones. Still fully overridable via `--raw-dir`; only
    the default moved."""
    return history.DEFAULT_HISTORY_ROOT / history.scan_id_for(domain, collected_at) / "raw"


def _invoke_live(tool_name: str, fetch: Callable[[], bytes]) -> tuple[bytes | None, str | None]:
    """A degraded tool must never abort the scan (ADR-0002 D5, ADR-0008 D5).

    Returns the warning message rather than printing it directly: this is
    always called from inside an active `Spinner`'s `with` block, and
    printing here would race the spinner thread's own `\\r`-driven
    animation and corrupt the terminal line (confirmed in practice —
    `theHarvester: live invocation failed (...)` landing mid-spin, glued
    onto the spinner's own text). The caller prints the warning after the
    `with Spinner(...):` block has exited and cleanly cleared its line.
    """
    try:
        return fetch(), None
    except _LIVE_INVOCATION_ERRORS as error:
        return None, f"{tool_name}: live invocation failed ({error}), skipping."


def _resolve_input(
    file: Path | None, live: bool, live_fetch: Callable[[], bytes], tool_name: str
) -> tuple[bytes | None, str | None, str | None]:
    """A per-tool file always overrides live invocation for that tool
    (ADR-0008 D6 mixed mode); otherwise fall back to --live if it's set.

    Returns (raw, raw_output_ref, warning) -- the warning (if any) is only
    ever meaningful for the live path and must be printed by the caller
    once any active spinner has exited (see `_invoke_live`)."""
    if file is not None:
        return file.read_bytes(), str(file), None
    if live:
        raw, warning = _invoke_live(tool_name, live_fetch)
        return raw, None, warning
    return None, None, None


def _maybe_spin(active: bool, label: str) -> AbstractContextManager[object]:
    """A spinner only when we're actually about to do the slow thing --
    reading an already-given file is instant and shouldn't flash a
    progress line, so callers pass the exact condition that means 'this
    call is really about to hit the network/a subprocess/an LLM'."""
    return Spinner(label) if active else nullcontext()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
