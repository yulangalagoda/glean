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
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer

from glean_osint import __version__, runner
from glean_osint.adapters.base import ParseResult, ScanContext
from glean_osint.adapters.crtsh import CrtshAdapter
from glean_osint.adapters.dnsx import DnsxAdapter
from glean_osint.adapters.httpx import HttpxAdapter
from glean_osint.adapters.theharvester import TheHarvesterAdapter
from glean_osint.brief import DEFAULT_TOP_N, build_brief, render_markdown
from glean_osint.dedup import merge_graph
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
    httpx_bin: Annotated[
        str,
        typer.Option(
            help="Executable name/path for ProjectDiscovery's httpx. Override this if a "
            "different, unrelated 'httpx' (e.g. the Python HTTP client CLI) is on PATH first — "
            "this collision is common enough in practice to be worth a dedicated option."
        ),
    ] = "httpx",
    authorisation: Annotated[
        str | None,
        typer.Option(help="Authorisation basis for this scan (recorded in the brief header)."),
    ] = None,
    top_n: Annotated[
        int, typer.Option(help="Number of findings in 'Top priorities'.")
    ] = DEFAULT_TOP_N,
    out: Annotated[
        Path | None, typer.Option(help="Write the brief to this file instead of stdout.")
    ] = None,
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

    crtsh_raw, crtsh_ref = _resolve_input(crtsh, live, lambda: runner.fetch_crtsh(domain), "crt.sh")
    if crtsh_raw is not None:
        if crtsh is None:
            crtsh_ref = runner.archive_raw(output_dir, f"crtsh-{domain}.json", crtsh_raw)
        ctx = ScanContext(target=domain, collected_at=collected_at, raw_output_ref=crtsh_ref)
        result = CrtshAdapter().parse(crtsh_raw, ctx)
        results.append(result)
        tools_run.append(ToolRun(source_tool="crtsh", method="passive", raw_output_ref=crtsh_ref))
        _warn_skipped("crt.sh", result.skipped)

    theharvester_raw, theharvester_ref = _resolve_input(
        theharvester, live, lambda: runner.run_theharvester(domain), "theHarvester"
    )
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
    dnsx_raw, dnsx_ref = _resolve_input(dnsx, live, lambda: runner.run_dnsx(candidates), "dnsx")
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
        httpx_raw = _invoke_live(
            "httpx", lambda: runner.run_httpx(resolved_hosts, binary=httpx_bin)
        )
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
    rendered = render_markdown(brief)

    if out is not None:
        out.write_text(rendered)
        typer.echo(f"Brief written to {out}")
    else:
        typer.echo(rendered)

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


def _default_raw_dir(domain: str, collected_at: datetime) -> Path:
    """ADR-0008 D7: raw output from a live run is archived under a fresh
    location, distinct from `eval/scans/` (which is specifically the
    private ground-truth set, not general end-user scan output)."""
    slug = domain.replace(".", "-")
    timestamp = collected_at.strftime("%Y%m%dT%H%M%SZ")
    return Path("glean-output") / f"{slug}-{timestamp}" / "raw"


def _invoke_live(tool_name: str, fetch: Callable[[], bytes]) -> bytes | None:
    """A degraded tool must never abort the scan (ADR-0002 D5, ADR-0008 D5)."""
    try:
        return fetch()
    except _LIVE_INVOCATION_ERRORS as error:
        typer.secho(
            f"{tool_name}: live invocation failed ({error}), skipping.",
            fg=typer.colors.YELLOW,
            err=True,
        )
        return None


def _resolve_input(
    file: Path | None, live: bool, live_fetch: Callable[[], bytes], tool_name: str
) -> tuple[bytes | None, str | None]:
    """A per-tool file always overrides live invocation for that tool
    (ADR-0008 D6 mixed mode); otherwise fall back to --live if it's set."""
    if file is not None:
        return file.read_bytes(), str(file)
    if live:
        return _invoke_live(tool_name, live_fetch), None
    return None, None


def main() -> None:
    app()


if __name__ == "__main__":
    main()
