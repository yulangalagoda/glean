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

import queue
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import uvicorn
from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from glean_osint import pipeline
from glean_osint.brief import DEFAULT_TOP_N, render_html
from glean_osint.history import (
    DEFAULT_HISTORY_ROOT,
    ScanManifest,
    list_scans,
    scan_id_for,
    write_manifest,
)
from glean_osint.pipeline import ScanRequest
from glean_osint.registry import PRESETS, TOOL_REGISTRY, normalise_selection

_WEB_DIR = Path(__file__).parent
_templates = Jinja2Templates(directory=str(_WEB_DIR / "templates"))

# SSE event payloads are single lines by construction throughout this
# project (spinner labels, warnings) -- collapsed defensively anyway so a
# surprising embedded newline can never corrupt the `data: ...\n\n` framing.
_ScanEvent = tuple[str, str]  # (event type, payload) -- "status"|"warning"|"done"|"error"


def _sse_line(event_type: str, payload: str) -> str:
    return f"event: {event_type}\ndata: {payload.replace(chr(10), ' ')}\n\n"


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


def create_app(history_root: Path = DEFAULT_HISTORY_ROOT) -> FastAPI:
    app = FastAPI(title="Glean")
    app.mount("/static", StaticFiles(directory=str(_WEB_DIR / "static")), name="static")

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
    ) -> None:
        q = active_scans[scan_id]
        try:
            outcome = pipeline.run_scan(
                ScanRequest(
                    target=target, tools=selected, authorisation=authorisation, top_n=top_n
                ),
                raw_dir=scan_dir / "raw",
                on_status=lambda message: q.put(("status", message)),
                on_warning=lambda message: q.put(("warning", message)),
            )
            (scan_dir / "brief.html").write_text(render_html(outcome.brief))
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
                ),
            )
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
    def index(request: Request) -> HTMLResponse:
        return _templates.TemplateResponse(
            request,
            "index.html",
            {"tools": TOOL_REGISTRY, "presets": PRESETS, "error": None, "form": {}},
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
    ) -> HTMLResponse | RedirectResponse:
        target = target.strip()
        selected = normalise_selection(frozenset(tools))
        error = None
        if not target:
            error = "Enter a target domain."
        elif not selected:
            error = "Select at least one tool."
        if error is not None:
            return _templates.TemplateResponse(
                request,
                "index.html",
                {
                    "tools": TOOL_REGISTRY,
                    "presets": PRESETS,
                    "error": error,
                    "form": {"target": target, "tools": tools, "authorisation": authorisation},
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
            execute_scan, scan_id, scan_dir, target, selected, authorisation or None, top_n
        )
        return RedirectResponse(url=f"/scan/{scan_id}/watch?target={target}", status_code=303)

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
        return _templates.TemplateResponse(
            request, "watch.html", {"scan_id": scan_id, "target": target}
        )

    @app.get("/scan/{scan_id}/events")
    async def scan_events(scan_id: str) -> StreamingResponse:
        if not _is_safe_scan_id(scan_id) or scan_id not in active_scans:
            raise HTTPException(status_code=404, detail="Scan not found.")

        async def stream() -> AsyncIterator[str]:
            q = active_scans[scan_id]
            try:
                while True:
                    # queue.Queue.get() blocks the calling thread, not the
                    # event loop -- run in the threadpool so other
                    # requests (including other scans' own SSE streams)
                    # keep being served while this one waits.
                    event_type, payload = await run_in_threadpool(q.get)
                    yield _sse_line(event_type, payload)
                    if event_type in {"done", "error"}:
                        return
            finally:
                active_scans.pop(scan_id, None)

        return StreamingResponse(stream(), media_type="text/event-stream")

    @app.get("/scan/{scan_id}", response_class=HTMLResponse)
    def view_scan(scan_id: str) -> HTMLResponse:
        if not _is_safe_scan_id(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found.")
        brief_path = history_root / scan_id / "brief.html"
        if not brief_path.is_file():
            raise HTTPException(status_code=404, detail="Scan not found.")
        return HTMLResponse(brief_path.read_text())

    @app.get("/history", response_class=HTMLResponse)
    def history(request: Request) -> HTMLResponse:
        return _templates.TemplateResponse(
            request,
            "history.html",
            {"scans": list_scans(history_root), "tool_names": TOOL_REGISTRY},
        )

    return app


def serve(host: str = "127.0.0.1", port: int = 8420) -> None:
    """Bare `glean` entry point (ADR-0011 D2/D8): localhost-only by
    design -- an unauthenticated control plane that can trigger *active*
    recon must never be reachable from the network by default."""
    uvicorn.run(create_app(), host=host, port=port)
