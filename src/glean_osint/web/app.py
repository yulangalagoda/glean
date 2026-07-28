"""FastAPI app for the interactive web interface (ADR-0011).

Stage 2: live progress via Server-Sent Events (ADR-0011 D5). A scan runs
as a FastAPI background task (started right after the redirect response
is sent, not before) so the request that submits the form returns
immediately; the browser lands on a "watching" page that opens an
EventSource against `/scan/{scan_id}/events` and gets redirected to the
real results page (still `render_html()`, ADR-0010, unchanged) once the
background task signals completion.
"""

from __future__ import annotations

import csv
import io
import json
import queue
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from html import escape as _escape_html
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode

import uvicorn
from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from glean_osint import pipeline, synthesis
from glean_osint.brief import DEFAULT_TOP_N, render_html, surface_counts, surface_label
from glean_osint.diff import diff_entities
from glean_osint.graph import build_graph_view
from glean_osint.history import (
    DEFAULT_HISTORY_ROOT,
    TRIAGE_STATES,
    ScanManifest,
    delete_scan,
    group_scans_by_target,
    list_scans,
    previous_scan_for,
    read_edges_snapshot,
    read_entities_snapshot,
    read_manifest,
    read_triage,
    scan_id_for,
    write_edges_snapshot,
    write_entities_snapshot,
    write_manifest,
    write_triage,
)
from glean_osint.pipeline import ScanRequest
from glean_osint.registry import PRESETS, TOOL_REGISTRY, normalise_selection

_WEB_DIR = Path(__file__).parent


def _build_templates(*, network_exposed: bool) -> Jinja2Templates:
    """A fresh Jinja environment per `create_app()` rather than one shared
    module-level instance. `network_exposed` is a template global, so
    `base.html` can render the exposure banner without every single route
    having to remember to thread the flag through its own context dict --
    but a *shared* environment would mean two apps in one process (exactly
    what the test suite builds) silently overwriting each other's flag."""
    templates = Jinja2Templates(directory=str(_WEB_DIR / "templates"))
    templates.env.globals["network_exposed"] = network_exposed
    # Shared with the brief header so the two renderings of the same
    # breakdown can't word it differently ("4 IP addresses" vs "4 ips").
    templates.env.globals["surface_label"] = surface_label
    return templates


# SSE event payloads are single lines by construction throughout this
# project (spinner labels, warnings) -- collapsed defensively anyway so a
# surprising embedded newline can never corrupt the `data: ...\n\n` framing.
_ScanEvent = tuple[str, str]  # (event type, payload) -- "status"|"warning"|"done"|"error"


def _sse_line(event_type: str, payload: str) -> str:
    return f"event: {event_type}\ndata: {payload.replace(chr(10), ' ')}\n\n"


_WEB_NAV_SNIPPET = """<header class="site-header">
  <nav class="nav">
    <a class="nav-brand" href="/">Glean</a>
    <div class="nav-links">
      <a href="/">New scan</a>
      <a href="/history">History</a>
    </div>
  </nav>
</header>
"""


def _export_bar(scan_id: str, *, has_previous_scan: bool) -> str:
    """Plain `<a href>` links, not JS-driven -- export shouldn't be
    gated behind report.js loading successfully. `scan_id` is already
    constrained by `_is_safe_scan_id` at the call site, but still
    HTML-escaped here on general principle before landing in an
    attribute."""
    safe_id = _escape_html(scan_id)
    compare_link = (
        f'<a href="/scan/{safe_id}/diff">Compare to previous scan</a>\n'
        if has_previous_scan
        else ""
    )
    return f"""<div class="export-bar">
  {compare_link}<a href="/scan/{safe_id}/graph">Relationships</a>
  <a href="/scan/{safe_id}/download/html" download>Download HTML</a>
  <a href="/scan/{safe_id}/download/json" download>Export JSON</a>
  <a href="/scan/{safe_id}/download/csv" download>Export CSV</a>
</div>
"""


def _triage_payload(triage: dict[str, str]) -> str:
    """Current triage state, embedded as a JSON `<script>` block rather than
    fetched separately on load -- it's a handful of bytes that the server
    already has in hand, and a second round trip would mean the page briefly
    renders every finding as untriaged before correcting itself.

    `</` is escaped because the JSON is operator-supplied entity ids inside
    an HTML `<script>`: without it an id containing `</script>` would end the
    block early. `<!--` likewise, which can flip a script into HTML-comment
    parsing.
    """
    return json.dumps(triage).replace("</", "<\\/").replace("<!--", "<\\!--")


def _wrap_scan_result_for_web(
    html: str,
    scan_id: str,
    *,
    has_previous_scan: bool = False,
    triage: dict[str, str] | None = None,
) -> str:
    """The saved `brief.html` (ADR-0010) is deliberately chrome-free --
    it's the exact same file `--out report.html` writes to disk, meant
    to open standalone via `file://` with no dependency on this server
    ever running. That's also exactly why it was hard to get back to
    the app from it (real feedback): there was nothing there on
    purpose. This injects a nav bar *and* the interactive-brief script
    *only* into the HTTP response `view_scan` returns, never into the
    file on disk -- `execute_scan`/the CLI still write `render_html()`'s
    output completely unmodified, zero JS, exactly ADR-0010 D3.

    The site stylesheet is linked *before* the report's own inline
    `<style>` (not after): the report defines its own `body { ... }`
    (860px width), and if the linked sheet landed after the inline one
    it would win on an equal-specificity tie and silently strip the
    report's own width/padding. Ordering it first means the report
    always wins by default, and the site sheet only overrides where it
    deliberately out-specifies -- which it does via `body[data-scan-id]`
    (0,1,1 vs. the bare `body`'s 0,0,1) to widen the web view onto a
    real desktop window. Because that selector keys off an attribute
    this function is the only thing that ever adds, the file written to
    disk cannot match it: the standalone `brief.html` / `--out
    report.html` keeps its own 860px column exactly as ADR-0010 D3
    requires.

    `scan_id` lands in a `data-scan-id` attribute (not inlined into a
    `<script>` string) specifically because it's built from the
    operator-supplied target -- `html.escape` on an HTML attribute is a
    well-trodden safe pattern already used throughout brief.py; hand-
    escaping a value for a JS string literal is exactly the kind of
    thing that's easy to get subtly wrong (e.g. an embedded `</script`
    sequence), so it's avoided entirely rather than risked.
    """
    html = html.replace("<style>", '<link rel="stylesheet" href="/static/style.css">\n<style>', 1)
    html = html.replace(
        "<body>",
        f'<body data-scan-id="{_escape_html(scan_id)}">\n'
        + _WEB_NAV_SNIPPET
        + _export_bar(scan_id, has_previous_scan=has_previous_scan),
        1,
    )
    script_tag = (
        f'<script type="application/json" id="triage-state">{_triage_payload(triage or {})}'
        "</script>\n"
        '<script src="/static/report.js" defer></script>\n'
    )
    return html.replace("</body>", script_tag + "</body>", 1)


def _pretty_print_raw(content: str) -> str:
    """Archived raw tool output (ADR-0002 D7) is either one JSON document
    (crt.sh, dnsx) or JSON-lines (theHarvester, subfinder, httpx) --
    pretty-print whichever it turns out to be, without hardcoding which
    tool uses which shape, so the raw view stays readable. Falls back to
    the untouched original text if neither parses cleanly -- never crash
    a provenance click-through over a formatting nicety."""
    try:
        return json.dumps(json.loads(content), indent=2)
    except (json.JSONDecodeError, ValueError):
        pass
    lines = [line for line in content.splitlines() if line.strip()]
    try:
        pretty_lines = [json.dumps(json.loads(line), indent=2) for line in lines]
    except (json.JSONDecodeError, ValueError):
        return content
    return "\n\n".join(pretty_lines) if pretty_lines else content


def _is_safe_scan_id(scan_id: str) -> bool:
    """`scan_id` is a path segment, not a filesystem path -- reject
    anything that could escape `history_root` before it ever touches
    disk. Extracted as its own pure function rather than inlined: a
    literal ".."/"/" can never actually reach the route handler through
    a normal HTTP client (browsers and httpx both normalise `/scan/..`
    to `/` before the request is even sent), which makes the inline
    version of this check untestable dead code in practice -- this
    stays real defence in depth (a raw client or misconfigured proxy
    could still send one through) *and* something a test can actually
    exercise directly.
    """
    return scan_id not in {"..", "."} and "/" not in scan_id


def create_app(
    history_root: Path = DEFAULT_HISTORY_ROOT, *, network_exposed: bool = False
) -> FastAPI:
    app = FastAPI(title="Glean")
    app.mount("/static", StaticFiles(directory=str(_WEB_DIR / "static")), name="static")
    templates = _build_templates(network_exposed=network_exposed)

    # One queue per in-flight scan, keyed by scan_id -- a fresh dict per
    # create_app() call, same closure pattern as history_root, so tests
    # never share state across FastAPI app instances.
    active_scans: dict[str, queue.Queue[_ScanEvent]] = {}

    def execute_scan(
        scan_id: str,
        scan_dir: Path,
        target: str,
        selected: frozenset[str],
        authorisation: str | None,
        top_n: int,
        llm: bool,
        model: str,
    ) -> None:
        q = active_scans[scan_id]
        try:
            outcome = pipeline.run_scan(
                ScanRequest(
                    target=target,
                    tools=selected,
                    authorisation=authorisation,
                    top_n=top_n,
                    llm=llm,
                    model=model,
                ),
                raw_dir=scan_dir / "raw",
                on_status=lambda message: q.put(("status", message)),
                on_warning=lambda message: q.put(("warning", message)),
            )
            (scan_dir / "brief.html").write_text(render_html(outcome.brief), encoding="utf-8")
            write_manifest(
                scan_dir,
                ScanManifest(
                    scan_id=scan_id,
                    target=target,
                    started_at=datetime.now(timezone.utc).isoformat(),
                    tools_run=tuple(t.source_tool for t in outcome.brief.scan.tools_run),
                    authorisation=authorisation,
                    findings_count=outcome.brief.findings_count,
                    warnings=outcome.warnings,
                    surface=surface_counts(list(outcome.entities)),
                    narrated_by=outcome.narrated_by,
                ),
            )
            write_entities_snapshot(
                scan_dir,
                [
                    f.entity.to_dict()
                    for f in outcome.brief.top_priorities + outcome.brief.also_found
                ],
            )
            write_edges_snapshot(scan_dir, [e.to_dict() for e in outcome.edges])
        except Exception as error:  # noqa: BLE001 -- must reach the browser, never crash silently
            # A background task's own exception is otherwise only logged
            # server-side (Starlette's default) -- the browser would be
            # left waiting on the watch page forever with no signal at
            # all. This is a genuinely unexpected failure (every tool-
            # level error is already handled inside run_scan itself and
            # never raises); reported, not swallowed.
            q.put(("error", str(error)))
        else:
            q.put(("done", f"/scan/{scan_id}"))

    @app.get("/", response_class=HTMLResponse)
    def index(
        request: Request,
        target: str = "",
        tools: str = "",
        authorisation: str = "",
    ) -> HTMLResponse:
        """The query parameters exist for "re-run this scan" on the history
        page: they pre-fill the form rather than launching anything, so a
        repeat run is still an explicit, reviewable submission. That matters
        for a tool that can trigger active reconnaissance -- a link that
        started a scan on GET would be one stray crawler or prefetch away
        from probing a target nobody authorised today.

        Unknown tool ids are dropped by `normalise_selection` rather than
        raising, so a link naming a tool that has since been removed still
        opens a usable form (ADR-0002 D5's degrade-don't-crash rule).
        """
        prefill: dict[str, object] = {}
        if target:
            prefill["target"] = target
        if tools:
            prefill["tools"] = sorted(
                normalise_selection(frozenset(t for t in tools.split(",") if t))
            )
        if authorisation:
            prefill["authorisation"] = authorisation
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "tools": TOOL_REGISTRY,
                "presets": PRESETS,
                "error": None,
                "form": prefill,
                # Read from synthesis rather than hardcoded in the template:
                # the command preview shows a real model tag the CLI would
                # actually use, and it can't drift out of sync with the code.
                "default_llm_model": synthesis.DEFAULT_MODEL,
                # The CLI's passive set, so the preview can tell an exactly-
                # equivalent selection from one the CLI cannot express.
                "cli_passive_tools": sorted(
                    t for t, i in TOOL_REGISTRY.items() if i.default_method == "passive"
                ),
            },
        )

    @app.post("/scan", response_model=None)
    def submit_scan(
        request: Request,
        background_tasks: BackgroundTasks,
        # target defaults to "" rather than being a required Form field so
        # a genuinely missing key (not just an empty string) still reaches
        # this function's own validation below, instead of FastAPI
        # rejecting it upstream with a generic 422 the operator never sees
        # an actionable message for.
        target: Annotated[str, Form()] = "",
        tools: Annotated[list[str], Form()] = [],  # noqa: B006 -- FastAPI's own Form() pattern
        authorisation: Annotated[str, Form()] = "",
        top_n: Annotated[int, Form()] = DEFAULT_TOP_N,
        llm: Annotated[bool, Form()] = False,
        model: Annotated[str, Form()] = "",
    ) -> HTMLResponse | RedirectResponse:
        target = target.strip()
        selected = normalise_selection(frozenset(tools))
        # An empty model box means "the default", not a request to narrate
        # with a model named "".
        model = model.strip() or synthesis.DEFAULT_MODEL
        error = None
        if not target:
            error = "Enter a target domain."
        elif not selected:
            error = "Select at least one tool."
        if error is not None:
            return templates.TemplateResponse(
                request,
                "index.html",
                {
                    "tools": TOOL_REGISTRY,
                    "presets": PRESETS,
                    "error": error,
                    "form": {
                        "target": target,
                        "tools": tools,
                        "authorisation": authorisation,
                        "llm": llm,
                        "model": model,
                    },
                    "default_llm_model": synthesis.DEFAULT_MODEL,
                    "cli_passive_tools": sorted(
                        t for t, i in TOOL_REGISTRY.items() if i.default_method == "passive"
                    ),
                },
                status_code=400,
            )

        started_at = datetime.now(timezone.utc)
        scan_id = scan_id_for(target, started_at)
        scan_dir = history_root / scan_id
        # Created explicitly, not relied on as a side effect of
        # archive_raw() -- a scan where every tool degrades never calls
        # archive_raw at all, and brief.html still needs somewhere to land.
        scan_dir.mkdir(parents=True, exist_ok=True)
        active_scans[scan_id] = queue.Queue()
        background_tasks.add_task(
            execute_scan,
            scan_id,
            scan_dir,
            target,
            selected,
            authorisation or None,
            top_n,
            llm,
            model,
        )
        # `tools` rides along so the watch page's stage checklist can show
        # only the stages this particular scan will actually run (a
        # passive-only scan never reaches a "Probing... (httpx)" status
        # line, so it shouldn't show a permanently-pending httpx stage).
        query = urlencode({"target": target, "tools": ",".join(sorted(selected))})
        return RedirectResponse(url=f"/scan/{scan_id}/watch?{query}", status_code=303)

    @app.get("/scan/{scan_id}/watch", response_class=HTMLResponse, response_model=None)
    def watch_scan(scan_id: str, request: Request) -> HTMLResponse | RedirectResponse:
        if not _is_safe_scan_id(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found.")
        if (history_root / scan_id / "brief.html").is_file():
            # Already finished (e.g. a refreshed/reopened watch tab) --
            # go straight to the real results, no point re-watching.
            return RedirectResponse(url=f"/scan/{scan_id}")
        if scan_id not in active_scans:
            raise HTTPException(status_code=404, detail="Scan not found.")
        target = request.query_params.get("target", scan_id)
        tools_csv = request.query_params.get("tools", "")
        return templates.TemplateResponse(
            request, "watch.html", {"scan_id": scan_id, "target": target, "tools_csv": tools_csv}
        )

    @app.get("/scan/{scan_id}/events")
    async def scan_events(scan_id: str) -> StreamingResponse:
        if not _is_safe_scan_id(scan_id) or scan_id not in active_scans:
            raise HTTPException(status_code=404, detail="Scan not found.")

        async def stream() -> AsyncIterator[str]:
            # Only pop on a genuine terminal event, not on generator
            # teardown in general -- real live testing found that an
            # early client disconnect (tab closed, network blip, or a
            # test harness cutting the connection) also tears this
            # generator down, and popping unconditionally there made a
            # still-running scan's *next* connection attempt (a refresh,
            # or watch_scan's own re-check) 404 as "not found" even
            # though execute_scan was still working -- it holds its own
            # reference to this queue, so it never depended on this
            # dict entry surviving.
            q = active_scans[scan_id]
            while True:
                # queue.Queue.get() blocks the calling thread, not the
                # event loop -- run in the threadpool so other requests
                # (including other scans' own SSE streams) keep being
                # served while this one waits.
                event_type, payload = await run_in_threadpool(q.get)
                yield _sse_line(event_type, payload)
                if event_type in {"done", "error"}:
                    active_scans.pop(scan_id, None)
                    return

        return StreamingResponse(stream(), media_type="text/event-stream")

    @app.get("/scan/{scan_id}", response_class=HTMLResponse)
    def view_scan(scan_id: str) -> HTMLResponse:
        if not _is_safe_scan_id(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found.")
        brief_path = history_root / scan_id / "brief.html"
        if not brief_path.is_file():
            raise HTTPException(status_code=404, detail="Scan not found.")
        has_previous = previous_scan_for(scan_id, history_root) is not None
        return HTMLResponse(
            _wrap_scan_result_for_web(
                brief_path.read_text(encoding="utf-8"),
                scan_id,
                has_previous_scan=has_previous,
                triage=read_triage(history_root / scan_id),
            )
        )

    @app.get("/scan/{scan_id}/diff", response_class=HTMLResponse, response_model=None)
    def view_diff(scan_id: str, request: Request) -> HTMLResponse:
        """Scan-to-scan monitoring (ADR-0011 roadmap): what changed
        since the last time this target was scanned. Relative to
        whichever scan `scan_id` is, not always "vs. latest" --
        `previous_scan_for` already encodes that."""
        if not _is_safe_scan_id(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found.")
        current = read_manifest(history_root / scan_id)
        if current is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        previous = previous_scan_for(scan_id, history_root)
        if previous is None:
            raise HTTPException(
                status_code=404, detail="No earlier scan of this target to compare against."
            )
        newer_entities = read_entities_snapshot(history_root / scan_id)
        older_entities = read_entities_snapshot(history_root / previous.scan_id)
        if newer_entities is None or older_entities is None:
            raise HTTPException(
                status_code=404,
                detail="Structured findings data not available for one of these scans.",
            )
        diff = diff_entities(older_entities, newer_entities)
        return templates.TemplateResponse(
            request,
            "diff.html",
            {
                "scan_id": scan_id,
                "target": current.target,
                "current": current,
                "previous": previous,
                "diff": diff,
            },
        )

    @app.post("/scan/{scan_id}/triage", response_model=None)
    def set_triage(
        scan_id: str,
        entity_id: Annotated[str, Form()],
        # Defaulted, so an *absent* `state` field means the same as an empty
        # one: clear this finding's triage. Not merely defensive -- some HTTP
        # clients drop empty-valued form fields entirely rather than sending
        # `state=`, so requiring the field would make "clear" work from a
        # browser and 422 from anything else.
        state: Annotated[str, Form()] = "",
    ) -> Response:
        """Record (or clear) one finding's triage state.

        Both inputs are validated server-side rather than trusted: `state`
        against `TRIAGE_STATES`, and `entity_id` against the scan's own
        entity snapshot. Without the second check a hand-crafted POST could
        grow this file indefinitely with ids that correspond to nothing,
        and every later read would carry them forward.

        An empty `state` clears the entry rather than storing "none" --
        untriaged is the absence of a record, not a fourth state.
        """
        if not _is_safe_scan_id(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found.")
        scan_dir = history_root / scan_id
        entities = read_entities_snapshot(scan_dir)
        if entities is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        if state and state not in TRIAGE_STATES:
            raise HTTPException(status_code=400, detail=f"Unknown triage state: {state!r}")
        known_ids = {e.get("id") for e in entities}
        if entity_id not in known_ids:
            raise HTTPException(status_code=400, detail="No such finding in this scan.")

        triage = read_triage(scan_dir)
        if state:
            triage[entity_id] = state
        else:
            triage.pop(entity_id, None)
        write_triage(scan_dir, triage)
        return Response(
            content=json.dumps({"entity_id": entity_id, "state": state or None}),
            media_type="application/json",
        )

    @app.get("/scan/{scan_id}/graph", response_class=HTMLResponse, response_model=None)
    def view_graph(scan_id: str, request: Request) -> HTMLResponse:
        """The correlation stage made visible: which findings are actually
        connected to which, by which typed relation.

        A scan archived before edges were persisted has an entity snapshot
        but no `edges.json`. That is reported as "not available for this
        scan", never as "this scan found no relationships" -- the two are
        different facts and conflating them would be exactly the
        absence-as-evidence reasoning the adapters refuse."""
        if not _is_safe_scan_id(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found.")
        manifest = read_manifest(history_root / scan_id)
        if manifest is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        entities = read_entities_snapshot(history_root / scan_id)
        edges = read_edges_snapshot(history_root / scan_id)
        if entities is None or edges is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    "Relationship data isn't available for this scan. Scans run before "
                    "edges were archived kept only their findings, not the links between "
                    "them — re-run the scan to build a graph."
                ),
            )
        return templates.TemplateResponse(
            request,
            "graph.html",
            {
                "scan_id": scan_id,
                "manifest": manifest,
                "view": build_graph_view(entities, edges),
            },
        )

    @app.get("/scan/{scan_id}/raw/{tool_id}", response_class=HTMLResponse, response_model=None)
    def view_raw(scan_id: str, tool_id: str, request: Request) -> HTMLResponse:
        """Provenance made clickable: each "Seen by" source in the brief
        links here. v1 scope is deliberately the tool's *whole* archived
        raw output, not the exact asserting record -- `raw_record_ref`'s
        shape (line number vs. JSONPath) varies per adapter, and an
        adapter-aware single-record extractor is real additional scope
        this round didn't need to reach for real trust-through-
        transparency value."""
        if not _is_safe_scan_id(scan_id) or tool_id not in TOOL_REGISTRY:
            raise HTTPException(status_code=404, detail="Not found.")
        raw_dir = history_root / scan_id / "raw"
        matches = sorted(raw_dir.glob(f"{tool_id}-*")) if raw_dir.is_dir() else []
        if not matches:
            raise HTTPException(status_code=404, detail="No archived raw output for this tool.")
        return templates.TemplateResponse(
            request,
            "raw.html",
            {
                "scan_id": scan_id,
                "tool_name": TOOL_REGISTRY[tool_id].display_name,
                "content": _pretty_print_raw(matches[0].read_text(encoding="utf-8")),
            },
        )

    @app.get("/scan/{scan_id}/download/html", response_model=None)
    def download_html(scan_id: str) -> Response:
        if not _is_safe_scan_id(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found.")
        brief_path = history_root / scan_id / "brief.html"
        if not brief_path.is_file():
            raise HTTPException(status_code=404, detail="Scan not found.")
        return Response(
            content=brief_path.read_text(encoding="utf-8"),
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="{scan_id}.html"'},
        )

    @app.get("/scan/{scan_id}/download/json", response_model=None)
    def download_json(scan_id: str) -> Response:
        if not _is_safe_scan_id(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found.")
        manifest = read_manifest(history_root / scan_id)
        entities = read_entities_snapshot(history_root / scan_id)
        if manifest is None or entities is None:
            raise HTTPException(
                status_code=404, detail="Structured findings data not available for this scan."
            )
        payload = {
            "scan_id": manifest.scan_id,
            "target": manifest.target,
            "started_at": manifest.started_at,
            "tools_run": manifest.tools_run,
            "authorisation": manifest.authorisation,
            "findings_count": manifest.findings_count,
            "findings": entities,
        }
        return Response(
            content=json.dumps(payload, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{scan_id}.json"'},
        )

    @app.get("/scan/{scan_id}/download/csv", response_model=None)
    def download_csv(scan_id: str) -> Response:
        if not _is_safe_scan_id(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found.")
        entities = read_entities_snapshot(history_root / scan_id)
        if entities is None:
            raise HTTPException(
                status_code=404, detail="Structured findings data not available for this scan."
            )
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            ["id", "type", "value", "score", "rank", "signals", "tools", "methods", "first_seen"]
        )
        for entity in entities:
            priority = entity.get("priority") or {}
            provenance = entity.get("provenance") or []
            tools = ";".join(sorted({p["source_tool"] for p in provenance}))
            methods = ";".join(sorted({p["method"] for p in provenance}))
            writer.writerow(
                [
                    entity.get("id", ""),
                    entity.get("type", ""),
                    entity.get("value", ""),
                    priority.get("score", ""),
                    priority.get("rank", ""),
                    ";".join(priority.get("signals", [])),
                    tools,
                    methods,
                    entity.get("first_seen", ""),
                ]
            )
        return Response(
            content=buffer.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{scan_id}.csv"'},
        )

    @app.get("/history", response_class=HTMLResponse)
    def history(request: Request) -> HTMLResponse:
        groups = group_scans_by_target(list_scans(history_root))
        return templates.TemplateResponse(
            request, "history.html", {"groups": groups, "tool_names": TOOL_REGISTRY}
        )

    @app.post("/scan/{scan_id}/delete", response_model=None)
    def delete_scan_route(scan_id: str) -> RedirectResponse:
        if not _is_safe_scan_id(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found.")
        delete_scan(history_root / scan_id)
        return RedirectResponse(url="/history", status_code=303)

    return app


LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def serve(host: str = "127.0.0.1", port: int = 8420) -> None:
    """Bare `glean` entry point (ADR-0011 D2/D8): localhost-only by
    design -- an unauthenticated control plane that can trigger *active*
    recon must never be reachable from the network by default.

    `--host` can still override that, deliberately (an operator may have
    a real reason). When it is overridden the UI stops being silent
    about it: `create_app` is told the bind is non-loopback and every
    page carries a standing banner, because the one thing worse than a
    network-exposed recon trigger is a network-exposed recon trigger
    that looks exactly like a safe local one.
    """
    exposed = host not in LOOPBACK_HOSTS
    if exposed:
        print(
            f"WARNING: binding to {host}, not loopback. This interface has no "
            "authentication and can trigger active reconnaissance. Anyone who can "
            "reach this port can scan on your behalf, using your authorisation.",
            flush=True,
        )
    uvicorn.run(create_app(network_exposed=exposed), host=host, port=port)
