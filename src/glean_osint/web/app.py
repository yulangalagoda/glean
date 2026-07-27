"""FastAPI app for the interactive web interface (ADR-0011).

Stage 1 only: a scan form, a synchronous run (no live progress streaming
yet -- that's stage 2, Server-Sent Events per ADR-0011 D5), and a results
view that reuses `render_html()` (ADR-0010) directly rather than a second
results-rendering implementation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import uvicorn
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from glean_osint import pipeline
from glean_osint.brief import DEFAULT_TOP_N, render_html
from glean_osint.history import DEFAULT_HISTORY_ROOT, ScanManifest, scan_id_for, write_manifest
from glean_osint.pipeline import ScanRequest
from glean_osint.registry import PRESETS, TOOL_REGISTRY, normalise_selection

_WEB_DIR = Path(__file__).parent
_templates = Jinja2Templates(directory=str(_WEB_DIR / "templates"))


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
        outcome = pipeline.run_scan(
            ScanRequest(
                target=target,
                tools=selected,
                authorisation=authorisation or None,
                top_n=top_n,
            ),
            raw_dir=scan_dir / "raw",
        )
        (scan_dir / "brief.html").write_text(render_html(outcome.brief))
        write_manifest(
            scan_dir,
            ScanManifest(
                scan_id=scan_id,
                target=target,
                started_at=started_at.isoformat(),
                tools_run=tuple(t.source_tool for t in outcome.brief.scan.tools_run),
                authorisation=authorisation or None,
                findings_count=outcome.brief.findings_count,
                warnings=outcome.warnings,
            ),
        )
        return RedirectResponse(url=f"/scan/{scan_id}", status_code=303)

    @app.get("/scan/{scan_id}", response_class=HTMLResponse)
    def view_scan(scan_id: str) -> HTMLResponse:
        if not _is_safe_scan_id(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found.")
        brief_path = history_root / scan_id / "brief.html"
        if not brief_path.is_file():
            raise HTTPException(status_code=404, detail="Scan not found.")
        return HTMLResponse(brief_path.read_text())

    return app


def serve(host: str = "127.0.0.1", port: int = 8420) -> None:
    """Bare `glean` entry point (ADR-0011 D2/D8): localhost-only by
    design -- an unauthenticated control plane that can trigger *active*
    recon must never be reachable from the network by default."""
    uvicorn.run(create_app(), host=host, port=port)
