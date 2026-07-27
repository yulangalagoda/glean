"""The `glean` CLI entrypoint (roadmap Workstream E1).

`glean scan` runs the full deterministic pipeline (adapters -> dedup ->
scoring -> brief). Ingest-only by default (point it at already-fetched raw
tool output); pass `--live` to actually invoke tools (ADR-0008 — the
runner). `--active` additionally opts into `httpx`, the only active-method
tool — never invoked live without it, per the charter's "active requires
explicit opt-in".
"""

from __future__ import annotations

import subprocess
import urllib.error
from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer

from glean_osint import __version__, runner, synthesis
from glean_osint.adapters.base import ParseResult, ScanContext
from glean_osint.adapters.crtsh import CrtshAdapter
from glean_osint.adapters.dnsx import DnsxAdapter
from glean_osint.adapters.httpx import HttpxAdapter
from glean_osint.adapters.theharvester import TheHarvesterAdapter
from glean_osint.brief import DEFAULT_TOP_N, build_brief, render_markdown
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
from glean_osint.schema.entities import ScanMeta, ToolRun
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

app = typer.Typer(add_completion=False, no_args_is_help=True)


@app.callback()
def _main() -> None:
    """Glean — unify open-source recon tools into a provenance-tracked,
    prioritised intelligence brief.

    A callback (even a no-op one) is required here, not cosmetic: with
    only one registered command, Typer collapses to `glean <args>`
    directly instead of `glean <command> <args>` — silently reopening the
    `glean <domain>` vs `glean scan <domain>` question already decided
    against once `glean eval` exists as a sibling command (roadmap
    Workstream E4).
    """


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
    live: Annotated[
        bool,
        typer.Option(
            help="Actually invoke tools live (ADR-0008) instead of only ingesting files. "
            "A per-tool file option, if given, still overrides live invocation for that tool."
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
    theharvester_bin: Annotated[
        str,
        typer.Option(
            envvar="GLEAN_THEHARVESTER_BIN",
            help="Executable name/path for theHarvester. Override this if it isn't on PATH "
            "(e.g. installed in its own venv) — pass the full path to its binary, or set "
            "$GLEAN_THEHARVESTER_BIN once instead of passing this every time.",
        ),
    ] = "theHarvester",
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
        Path | None, typer.Option(help="Write the brief to this file instead of stdout.")
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
    (--crtsh / --theharvester / --dnsx / --httpx). Pass --live to actually
    invoke tools (ADR-0008); a per-tool file option still overrides live
    invocation for that specific tool (mixed mode). --active is required
    in addition to --live to invoke httpx, the only active-method tool.
    """
    if not live and crtsh is None and theharvester is None and dnsx is None and httpx is None:
        typer.secho(
            "Provide at least one of --crtsh, --theharvester, --dnsx, --httpx, or --live.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    collected_at_dt = datetime.now(timezone.utc)
    collected_at = collected_at_dt.isoformat()
    output_dir = raw_dir if raw_dir is not None else _default_raw_dir(domain, collected_at_dt)
    results: list[ParseResult] = []
    tools_run: list[ToolRun] = []

    # --- Stage 1: crt.sh + theHarvester (independent, ADR-0008 D1) ---

    with _maybe_spin(crtsh is None and live, "Searching certificate transparency logs (crt.sh)..."):
        crtsh_raw, crtsh_ref, crtsh_warning = _resolve_input(
            crtsh, live, lambda: runner.fetch_crtsh(domain), "crt.sh"
        )
    if crtsh_warning:
        typer.secho(crtsh_warning, fg=typer.colors.YELLOW, err=True)
    if crtsh_raw is not None:
        if crtsh is None:
            crtsh_ref = runner.archive_raw(output_dir, f"crtsh-{domain}.json", crtsh_raw)
        ctx = ScanContext(target=domain, collected_at=collected_at, raw_output_ref=crtsh_ref)
        result = CrtshAdapter().parse(crtsh_raw, ctx)
        results.append(result)
        tools_run.append(ToolRun(source_tool="crtsh", method="passive", raw_output_ref=crtsh_ref))
        _warn_skipped("crt.sh", result.skipped)

    with _maybe_spin(
        theharvester is None and live,
        "Searching public sources for hosts and emails (theHarvester)...",
    ):
        theharvester_raw, theharvester_ref, theharvester_warning = _resolve_input(
            theharvester,
            live,
            lambda: runner.run_theharvester(domain, binary=theharvester_bin),
            "theHarvester",
        )
    if theharvester_warning:
        typer.secho(theharvester_warning, fg=typer.colors.YELLOW, err=True)
    if theharvester_raw is not None:
        if theharvester is None:
            theharvester_ref = runner.archive_raw(
                output_dir, f"theharvester-{domain}.json", theharvester_raw
            )
        ctx = ScanContext(target=domain, collected_at=collected_at, raw_output_ref=theharvester_ref)
        result = TheHarvesterAdapter().parse(theharvester_raw, ctx)
        results.append(result)
        tools_run.append(
            ToolRun(source_tool="theharvester", method="passive", raw_output_ref=theharvester_ref)
        )
        _warn_skipped("theHarvester", result.skipped)

    # --- Stage 2: dnsx, fed Stage 1's parsed hostnames (ADR-0008 D1) ---

    candidates = runner.extract_candidates(domain, results)
    with _maybe_spin(
        dnsx is None and live, f"Resolving {len(candidates)} candidate hostname(s) (dnsx)..."
    ):
        dnsx_raw, dnsx_ref, dnsx_warning = _resolve_input(
            dnsx, live, lambda: runner.run_dnsx(candidates, binary=dnsx_bin), "dnsx"
        )
    if dnsx_warning:
        typer.secho(dnsx_warning, fg=typer.colors.YELLOW, err=True)
    if dnsx_raw is not None:
        if dnsx is None:
            dnsx_ref = runner.archive_raw(output_dir, f"dnsx-{domain}.json", dnsx_raw)
        ctx = ScanContext(target=domain, collected_at=collected_at, raw_output_ref=dnsx_ref)
        result = DnsxAdapter().parse(dnsx_raw, ctx)
        results.append(result)
        tools_run.append(ToolRun(source_tool="dnsx", method="passive", raw_output_ref=dnsx_ref))
        _warn_skipped("dnsx", result.skipped)

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
            typer.secho(httpx_warning, fg=typer.colors.YELLOW, err=True)
        httpx_ref = None
    else:
        if live:
            typer.secho(
                "httpx: skipped (active recon not enabled; pass --active to include it).",
                fg=typer.colors.YELLOW,
                err=True,
            )
        httpx_raw, httpx_ref = None, None

    if httpx_raw is not None:
        if httpx is None:
            httpx_ref = runner.archive_raw(output_dir, f"httpx-{domain}.jsonl", httpx_raw)
        ctx = ScanContext(target=domain, collected_at=collected_at, raw_output_ref=httpx_ref)
        result = HttpxAdapter().parse(httpx_raw, ctx)
        results.append(result)
        tools_run.append(ToolRun(source_tool="httpx", method="active", raw_output_ref=httpx_ref))
        _warn_skipped("httpx", result.skipped)

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
    typer.echo(SECTION_BREAK)
    if out is not None:
        # A saved file is a complete archive copy regardless of --show-all.
        out.write_text(render_markdown(brief, also_found_limit=None))
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


def _warn_skipped(tool: str, skipped: int) -> None:
    if skipped:
        typer.secho(
            f"{tool}: skipped {skipped} malformed record(s).", fg=typer.colors.YELLOW, err=True
        )


@dataclass(frozen=True, slots=True)
class _TargetEvalResult:
    target: str
    faithfulness: FaithfulnessResult
    provenance_retention: float
    prioritisation: PrioritisationQuality
    stage2: Stage2FaithfulnessResult | None


_RAW_ADAPTERS = (
    (CrtshAdapter, "crtsh-{slug}.json"),
    (TheHarvesterAdapter, "theharvester-{slug}.json"),
    (DnsxAdapter, "dnsx-{slug}.json"),
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
        stage2 = faithfulness_stage2(brief, judge_model=judge_model)

    entity_ids = {e.id for e in scored}
    glean_ranked_ids = [e.id for e in scored]
    return _TargetEvalResult(
        target=ground_truth.target,
        faithfulness=faithfulness_stage1(brief, entity_ids),
        provenance_retention=provenance_retention(brief),
        prioritisation=prioritisation_quality(glean_ranked_ids, ground_truth, n=top_n),
        stage2=stage2,
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

    header = f"{'target':<20} {'faithfulness':>13} {'provenance':>11} "
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

    n = len(results)
    mean_faithfulness = sum(r.faithfulness.score for r in results) / n
    mean_provenance = sum(r.provenance_retention for r in results) / n
    mean_overlap = sum(r.prioritisation.overlap_at_n for r in results) / n
    mean_ndcg = sum(r.prioritisation.ndcg_at_n for r in results) / n

    summary = (
        f"\n[{n} targets] mean faithfulness={mean_faithfulness:.3f} "
        f"mean provenance_retention={mean_provenance:.3f} "
        f"mean overlap@{top_n}={mean_overlap:.3f} mean nDCG@{top_n}={mean_ndcg:.3f}"
    )
    stage2_results = [r.stage2 for r in results if r.stage2 is not None]
    if stage2_results:
        mean_stage2 = sum(s.score for s in stage2_results) / len(stage2_results)
        total_unjudged = sum(s.unjudged_findings for s in stage2_results)
        summary += f" mean stage2_faithfulness={mean_stage2:.3f} (unjudged={total_unjudged})"

    typer.secho(summary, fg=typer.colors.CYAN)


def _default_raw_dir(domain: str, collected_at: datetime) -> Path:
    """ADR-0008 D7: raw output from a live run is archived under a fresh
    location, distinct from `eval/scans/` (which is specifically the
    private ground-truth set, not general end-user scan output)."""
    slug = domain.replace(".", "-")
    timestamp = collected_at.strftime("%Y%m%dT%H%M%SZ")
    return Path("glean-output") / f"{slug}-{timestamp}" / "raw"


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
