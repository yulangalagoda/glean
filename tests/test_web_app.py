"""Tests for the web interface (ADR-0011), stages 1 & 2.

`create_app(history_root=tmp_path)` isolates every test from the real
`~/.local/share/glean/scans/` -- the crt.sh cache bug earlier this session
is exactly the class of mistake this guards against (real state written
during `pytest` because a test-time override wasn't actually wired
through). `pipeline.run_scan` is monkeypatched at `glean_osint.pipeline`
(module-qualified access in `app.py`, not a bound `from ... import`, for
the same reason) so no real network/subprocess call happens here either.

Stage 2 note on background tasks: Starlette's TestClient runs a request's
`BackgroundTasks` to completion as part of finishing the response, before
`.post(...)` returns control to the test -- so by the time a POST /scan
call returns here, `execute_scan` (and everything it queued) has already
happened. That's convenient for testing the queued events' *content* and
the manifest/brief.html's final state, but it means these tests can't
naturally observe a scan genuinely "still running" the way a real browser
talking to a real long-lived server would -- that part is only really
exercised by the live validation this ADR's own Validation section
records, not by this suite.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from glean_osint import pipeline
from glean_osint.brief import Brief
from glean_osint.pipeline import ScanOutcome, ScanRequest
from glean_osint.registry import PRESETS, TOOL_REGISTRY
from glean_osint.schema.entities import ScanMeta
from glean_osint.web.app import create_app


def _fake_outcome(request: ScanRequest) -> ScanOutcome:
    scan_meta = ScanMeta(
        target=request.target,
        started_at="2026-07-27T00:00:00Z",
        glean_version="0.0.2",
        authorisation=request.authorisation,
        tools_run=(),
    )
    brief = Brief(
        scan=scan_meta,
        surface_line="0 domains",
        top_priorities=(),
        also_found=(),
        findings_count=0,
        findings_with_valid_provenance=0,
        fabricated_findings=0,
    )
    return ScanOutcome(brief=brief, warnings=())


def _client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(history_root=tmp_path))


def test_index_lists_every_registered_tool_and_preset(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/")
    assert response.status_code == 200
    for info in TOOL_REGISTRY.values():
        assert info.display_name in response.text
    for preset_name in PRESETS:
        assert preset_name in response.text


def test_nav_marks_new_scan_active_on_the_index_page(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/")
    assert 'href="/" class="active"' in response.text
    assert 'href="/history" class="active"' not in response.text


def test_nav_marks_history_active_on_the_history_page(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/history")
    assert 'href="/history" class="active"' in response.text
    assert 'href="/" class="active"' not in response.text


def test_nav_appears_on_both_form_and_history_pages(tmp_path: Path) -> None:
    # The results page (/scan/{id}) deliberately has no nav -- it's the
    # exact same render_html() output ADR-0010's --out writes to disk,
    # and that file should never carry web-only chrome.
    client = _client(tmp_path)
    for url in ["/", "/history"]:
        response = client.get(url)
        assert 'class="nav-brand" href="/">Glean</a>' in response.text
        assert "New scan" in response.text
        assert "History" in response.text


def _scan_id_from_watch_redirect(location: str) -> str:
    # location is "/scan/<scan_id>/watch?target=...".
    return urlparse(location).path.removeprefix("/scan/").removesuffix("/watch")


def test_submit_scan_redirects_to_the_watch_page_immediately(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = []
    monkeypatch.setattr(
        pipeline,
        "run_scan",
        lambda request, **kw: (calls.append(request), _fake_outcome(request))[1],
    )

    client = _client(tmp_path)
    response = client.post(
        "/scan",
        data={"target": "example.com", "tools": ["crtsh"], "authorisation": "Owned"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/scan/example-com-")
    assert location.endswith("/watch?target=example.com")
    assert calls[0].target == "example.com"
    assert calls[0].tools == frozenset({"crtsh"})


def test_submit_scan_eventually_serves_the_saved_html_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(pipeline, "run_scan", lambda request, **kw: _fake_outcome(request))

    client = _client(tmp_path)
    redirect = client.post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    scan_id = _scan_id_from_watch_redirect(redirect.headers["location"])
    result = client.get(f"/scan/{scan_id}")

    assert result.status_code == 200
    assert result.text.startswith("<!doctype html>")
    assert "example.com" in result.text


def test_view_scan_response_has_a_nav_bar_but_the_saved_file_does_not(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Real feedback: once inside a report there was no way back to the
    app. Fixed by injecting a nav bar into the HTTP *response* only --
    the file view_scan reads from must stay byte-identical to what
    render_html() (ADR-0010) produces, since it's the same file --out
    report.html writes to disk for standalone, serverless use."""
    monkeypatch.setattr(pipeline, "run_scan", lambda request, **kw: _fake_outcome(request))

    client = _client(tmp_path)
    redirect = client.post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    scan_id = _scan_id_from_watch_redirect(redirect.headers["location"])

    result = client.get(f"/scan/{scan_id}")
    assert 'class="nav-brand" href="/">Glean</a>' in result.text
    assert '<link rel="stylesheet" href="/static/style.css">' in result.text
    # The stylesheet link must land before the report's own inline
    # <style> block, or its generic `body` rule would win the cascade
    # and silently strip the report's own width/padding.
    assert result.text.index('rel="stylesheet"') < result.text.index("<style>")

    saved = (tmp_path / scan_id / "brief.html").read_text()
    assert "nav-brand" not in saved
    assert "stylesheet" not in saved
    assert saved != result.text  # the response is a wrapped copy, not the same bytes


def test_submit_scan_writes_a_manifest(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(pipeline, "run_scan", lambda request, **kw: _fake_outcome(request))

    redirect = _client(tmp_path).post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    scan_id = _scan_id_from_watch_redirect(redirect.headers["location"])
    manifest = json.loads((tmp_path / scan_id / "manifest.json").read_text())

    assert manifest["target"] == "example.com"
    assert manifest["scan_id"] == scan_id


def test_watch_page_redirects_straight_to_results_once_the_scan_has_finished(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """By the time a TestClient POST returns, the background task has
    already completed (see module docstring) -- a watch-page request
    after that point (e.g. a refreshed tab) must skip straight to the
    real results instead of showing a stale "in progress" page."""
    monkeypatch.setattr(pipeline, "run_scan", lambda request, **kw: _fake_outcome(request))

    client = _client(tmp_path)
    redirect = client.post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    watch_response = client.get(redirect.headers["location"], follow_redirects=False)

    assert watch_response.status_code in (302, 307)
    scan_id = _scan_id_from_watch_redirect(redirect.headers["location"])
    assert watch_response.headers["location"] == f"/scan/{scan_id}"


def test_watch_page_is_404_for_a_scan_that_was_never_submitted(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/scan/never-submitted/watch")
    assert response.status_code == 404


def test_scan_events_streams_status_and_a_final_done_event(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run_scan(request, *, raw_dir, on_status=None, on_warning=None):
        if on_status is not None:
            on_status("Searching certificate transparency logs (crt.sh)...")
            on_status("Scoring and building the brief...")
        return _fake_outcome(request)

    monkeypatch.setattr(pipeline, "run_scan", fake_run_scan)

    client = _client(tmp_path)
    redirect = client.post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    scan_id = _scan_id_from_watch_redirect(redirect.headers["location"])
    events_response = client.get(f"/scan/{scan_id}/events")

    assert events_response.status_code == 200
    body = events_response.text
    assert "event: status\ndata: Searching certificate transparency logs (crt.sh)..." in body
    assert "event: status\ndata: Scoring and building the brief..." in body
    assert f"event: done\ndata: /scan/{scan_id}" in body
    # status events must appear before the terminal done event, not after
    assert body.index("event: status") < body.index("event: done")


def test_scan_events_streams_warnings_too(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run_scan(request, *, raw_dir, on_status=None, on_warning=None):
        if on_warning is not None:
            on_warning("theHarvester: live invocation failed (theHarvester), skipping.")
        return _fake_outcome(request)

    monkeypatch.setattr(pipeline, "run_scan", fake_run_scan)

    client = _client(tmp_path)
    redirect = client.post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    scan_id = _scan_id_from_watch_redirect(redirect.headers["location"])
    events_response = client.get(f"/scan/{scan_id}/events")

    assert "event: warning\ndata: theHarvester: live invocation failed" in events_response.text


def test_scan_events_reports_an_unexpected_exception_instead_of_hanging_forever(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A background task's own exception is otherwise only logged
    server-side (Starlette's default) -- the browser must still learn
    the scan failed rather than being left on the watch page forever."""

    def failing_run_scan(request, **kw):
        raise RuntimeError("something genuinely unexpected")

    monkeypatch.setattr(pipeline, "run_scan", failing_run_scan)

    client = _client(tmp_path)
    redirect = client.post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    scan_id = _scan_id_from_watch_redirect(redirect.headers["location"])
    events_response = client.get(f"/scan/{scan_id}/events")

    assert "event: error\ndata: something genuinely unexpected" in events_response.text


def test_scan_events_is_404_for_a_scan_that_was_never_submitted(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/scan/never-submitted/events")
    assert response.status_code == 404


def test_submit_scan_with_a_missing_target_key_shows_an_error(tmp_path: Path) -> None:
    """The Form field itself defaults to "" rather than being required,
    so a genuinely missing key reaches our own validation message
    instead of FastAPI's generic 422."""
    response = _client(tmp_path).post("/scan", data={"tools": ["crtsh"]})
    assert response.status_code == 400
    assert "Enter a target domain" in response.text


def test_submit_scan_with_an_empty_target_shows_the_same_error(tmp_path: Path) -> None:
    response = _client(tmp_path).post("/scan", data={"target": "  ", "tools": ["crtsh"]})
    assert response.status_code == 400
    assert "Enter a target domain" in response.text


def test_submit_scan_without_any_tools_shows_an_error(tmp_path: Path) -> None:
    response = _client(tmp_path).post("/scan", data={"target": "example.com"})
    assert response.status_code == 400
    assert "Select at least one tool" in response.text


def test_view_an_unknown_scan_id_is_404(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/scan/does-not-exist")
    assert response.status_code == 404


def test_history_page_shows_the_empty_state_when_no_scans_exist(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/history")
    assert response.status_code == 200
    assert "No scans yet" in response.text


def test_history_page_lists_a_completed_scan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(pipeline, "run_scan", lambda request, **kw: _fake_outcome(request))

    client = _client(tmp_path)
    redirect = client.post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    scan_id = _scan_id_from_watch_redirect(redirect.headers["location"])

    response = client.get("/history")

    assert response.status_code == 200
    assert "example.com" in response.text
    assert f'href="/scan/{scan_id}"' in response.text


def test_history_page_shows_a_warning_pill_when_a_scan_had_warnings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run_scan(request, *, raw_dir, on_status=None, on_warning=None):
        if on_warning is not None:
            on_warning("crt.sh: live invocation failed (boom), skipping.")
        return ScanOutcome(
            brief=_fake_outcome(request).brief,
            warnings=("crt.sh: live invocation failed (boom), skipping.",),
        )

    monkeypatch.setattr(pipeline, "run_scan", fake_run_scan)

    client = _client(tmp_path)
    client.post("/scan", data={"target": "example.com", "tools": ["crtsh"]})

    response = client.get("/history")

    assert "1 warning" in response.text


def test_is_safe_scan_id_rejects_traversal_and_path_separators() -> None:
    """A literal ".."/"/" can't actually reach view_scan through a normal
    HTTP client (both browsers and httpx normalise `/scan/..` to `/`
    before the request is even sent) -- tested directly rather than over
    HTTP so the check itself, not the transport layer's own behaviour,
    is what's actually being verified."""
    from glean_osint.web.app import _is_safe_scan_id

    assert _is_safe_scan_id("example-com-20260727T120000Z") is True
    assert _is_safe_scan_id("..") is False
    assert _is_safe_scan_id(".") is False
    assert _is_safe_scan_id("../etc/passwd") is False
    assert _is_safe_scan_id("foo/bar") is False
