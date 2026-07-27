"""The `glean` CLI entrypoint (roadmap Workstream E1).

`glean scan` runs the full deterministic pipeline (adapters -> dedup ->
scoring -> brief) against already-fetched raw tool output. Ingest-only for
now: live invocation (crt.sh over HTTP, theHarvester as a subprocess) is
deliberately deferred — ADR-0002's own open questions flag "the runner"
(invocation, timeouts, retries) as needing its own design pass before
code, not something to improvise here.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer

from glean_osint import __version__
from glean_osint.adapters.base import ParseResult, ScanContext
from glean_osint.adapters.crtsh import CrtshAdapter
from glean_osint.adapters.dnsx import DnsxAdapter
from glean_osint.adapters.httpx import HttpxAdapter
from glean_osint.adapters.theharvester import TheHarvesterAdapter
from glean_osint.brief import DEFAULT_TOP_N, build_brief, render_markdown
from glean_osint.dedup import merge_graph
from glean_osint.schema.entities import ScanMeta, ToolRun
from glean_osint.scoring import score_graph

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
    """Build a prioritised, provenance-tracked brief for DOMAIN from
    already-fetched raw tool output (see --crtsh / --theharvester / --dnsx
    / --httpx).

    This does not run any tool itself — live invocation (fetching crt.sh,
    running theHarvester/dnsx/httpx) isn't built yet. Fetch the raw output
    yourself first (see _private/scripts/ for this project's own
    conventions), then point this command at the saved files.
    """
    if crtsh is None and theharvester is None and dnsx is None and httpx is None:
        typer.secho(
            "Provide at least one of --crtsh, --theharvester, --dnsx, or --httpx.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    collected_at = datetime.now(timezone.utc).isoformat()
    results: list[ParseResult] = []
    tools_run: list[ToolRun] = []

    if crtsh is not None:
        ctx = ScanContext(target=domain, collected_at=collected_at, raw_output_ref=str(crtsh))
        result = CrtshAdapter().parse(crtsh.read_bytes(), ctx)
        results.append(result)
        tools_run.append(ToolRun(source_tool="crtsh", method="passive", raw_output_ref=str(crtsh)))
        _warn_skipped("crt.sh", result.skipped)

    if theharvester is not None:
        ctx = ScanContext(
            target=domain, collected_at=collected_at, raw_output_ref=str(theharvester)
        )
        result = TheHarvesterAdapter().parse(theharvester.read_bytes(), ctx)
        results.append(result)
        tools_run.append(
            ToolRun(source_tool="theharvester", method="passive", raw_output_ref=str(theharvester))
        )
        _warn_skipped("theHarvester", result.skipped)

    if dnsx is not None:
        ctx = ScanContext(target=domain, collected_at=collected_at, raw_output_ref=str(dnsx))
        result = DnsxAdapter().parse(dnsx.read_bytes(), ctx)
        results.append(result)
        tools_run.append(ToolRun(source_tool="dnsx", method="passive", raw_output_ref=str(dnsx)))
        _warn_skipped("dnsx", result.skipped)

    if httpx is not None:
        ctx = ScanContext(target=domain, collected_at=collected_at, raw_output_ref=str(httpx))
        result = HttpxAdapter().parse(httpx.read_bytes(), ctx)
        results.append(result)
        tools_run.append(ToolRun(source_tool="httpx", method="active", raw_output_ref=str(httpx)))
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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
