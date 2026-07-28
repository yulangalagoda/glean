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

from glean_osint import history, pipeline
from glean_osint.brief import Brief, build_brief
from glean_osint.pipeline import ScanOutcome, ScanRequest
from glean_osint.registry import PRESETS, TOOL_REGISTRY
from glean_osint.schema.entities import Entity, Priority, ProvenanceEntry, ScanMeta
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
    assert "/watch?" in location
    assert "target=example.com" in location
    assert "tools=crtsh" in location
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


def _fake_scored_entity_finding_outcome(request: ScanRequest) -> ScanOutcome:
    """A scan outcome with one real, scored finding -- for tests that
    need entities.json / raw-output / download routes to have something
    to actually serve."""
    entity = Entity(
        id="subdomain:admin.example.com",
        type="subdomain",
        value="admin.example.com",
        provenance=(
            ProvenanceEntry(
                source_tool="crtsh", method="passive", collected_at="2026-07-27T00:00:00Z"
            ),
        ),
        priority=Priority(score=3, rank=1, signals=("sensitive_hostname_pattern",)),
    )
    scan_meta = ScanMeta(
        target=request.target,
        started_at="2026-07-27T00:00:00Z",
        glean_version="0.0.2",
        authorisation=request.authorisation,
        tools_run=(),
    )
    brief = build_brief([entity], [], scan_meta)
    return ScanOutcome(brief=brief, warnings=())


def test_submit_scan_writes_an_entities_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        pipeline, "run_scan", lambda request, **kw: _fake_scored_entity_finding_outcome(request)
    )

    redirect = _client(tmp_path).post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    scan_id = _scan_id_from_watch_redirect(redirect.headers["location"])
    entities = json.loads((tmp_path / scan_id / "entities.json").read_text())

    assert len(entities) == 1
    assert entities[0]["id"] == "subdomain:admin.example.com"


def test_view_scan_response_carries_scan_id_and_report_script(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(pipeline, "run_scan", lambda request, **kw: _fake_outcome(request))

    client = _client(tmp_path)
    redirect = client.post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    scan_id = _scan_id_from_watch_redirect(redirect.headers["location"])
    result = client.get(f"/scan/{scan_id}")

    assert f'data-scan-id="{scan_id}"' in result.text
    assert '<script src="/static/report.js" defer></script>' in result.text
    assert f"/scan/{scan_id}/download/json" in result.text
    assert f"/scan/{scan_id}/download/csv" in result.text
    assert f"/scan/{scan_id}/download/html" in result.text


def test_download_html_serves_the_saved_report_as_an_attachment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(pipeline, "run_scan", lambda request, **kw: _fake_outcome(request))

    client = _client(tmp_path)
    redirect = client.post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    scan_id = _scan_id_from_watch_redirect(redirect.headers["location"])
    response = client.get(f"/scan/{scan_id}/download/html")

    assert response.status_code == 200
    assert response.headers["content-disposition"] == f'attachment; filename="{scan_id}.html"'
    assert response.text.startswith("<!doctype html>")
    # the download is the saved, chrome-free file -- not the wrapped web view
    assert "nav-brand" not in response.text


def test_download_json_returns_findings_and_scan_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        pipeline, "run_scan", lambda request, **kw: _fake_scored_entity_finding_outcome(request)
    )

    client = _client(tmp_path)
    redirect = client.post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    scan_id = _scan_id_from_watch_redirect(redirect.headers["location"])
    response = client.get(f"/scan/{scan_id}/download/json")

    assert response.status_code == 200
    assert response.headers["content-disposition"] == f'attachment; filename="{scan_id}.json"'
    payload = response.json()
    assert payload["target"] == "example.com"
    assert payload["findings"][0]["id"] == "subdomain:admin.example.com"


def test_download_csv_flattens_findings_into_rows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        pipeline, "run_scan", lambda request, **kw: _fake_scored_entity_finding_outcome(request)
    )

    client = _client(tmp_path)
    redirect = client.post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    scan_id = _scan_id_from_watch_redirect(redirect.headers["location"])
    response = client.get(f"/scan/{scan_id}/download/csv")

    assert response.status_code == 200
    assert response.headers["content-disposition"] == f'attachment; filename="{scan_id}.csv"'
    lines = response.text.strip().splitlines()
    assert lines[0] == "id,type,value,score,rank,signals,tools,methods,first_seen"
    assert "subdomain:admin.example.com" in lines[1]
    assert "sensitive_hostname_pattern" in lines[1]


def test_download_json_is_404_for_a_scan_with_no_entities_snapshot(tmp_path: Path) -> None:
    """A scan run before this feature existed (or any other scan
    missing entities.json) degrades to 404, not a crash."""
    scan_id = "example-com-20260101T000000Z"
    history.write_manifest(
        tmp_path / scan_id,
        history.ScanManifest(
            scan_id=scan_id,
            target="example.com",
            started_at="2026-01-01T00:00:00Z",
            tools_run=(),
            authorisation=None,
            findings_count=0,
        ),
    )

    response = _client(tmp_path).get(f"/scan/{scan_id}/download/json")

    assert response.status_code == 404


def test_view_raw_serves_the_archived_output_for_a_tool(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run_scan(request, *, raw_dir, on_status=None, on_warning=None):
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / "crtsh-example.com.json").write_text('[{"name_value": "admin.example.com"}]')
        return _fake_outcome(request)

    monkeypatch.setattr(pipeline, "run_scan", fake_run_scan)

    client = _client(tmp_path)
    redirect = client.post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    scan_id = _scan_id_from_watch_redirect(redirect.headers["location"])
    response = client.get(f"/scan/{scan_id}/raw/crtsh")

    assert response.status_code == 200
    assert "admin.example.com" in response.text
    assert f'href="/scan/{scan_id}"' in response.text  # back link


def test_view_raw_is_404_for_an_unknown_tool_id(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/scan/does-not-exist/raw/not-a-real-tool")
    assert response.status_code == 404


def test_view_raw_is_404_when_no_raw_output_was_archived_for_that_tool(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(pipeline, "run_scan", lambda request, **kw: _fake_outcome(request))

    client = _client(tmp_path)
    redirect = client.post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    scan_id = _scan_id_from_watch_redirect(redirect.headers["location"])
    response = client.get(f"/scan/{scan_id}/raw/subfinder")

    assert response.status_code == 404


def test_index_marks_active_tool_checkboxes_for_the_ethics_warning(tmp_path: Path) -> None:
    """The client-side warning banner (index.html's own JS) reads this
    data-method attribute -- httpx is currently the only active-method
    tool in the registry."""
    response = _client(tmp_path).get("/")

    assert 'data-method="active"' in response.text
    assert 'id="active-warning"' in response.text


def test_index_has_a_target_format_hint_and_a_conditional_format_warning(
    tmp_path: Path,
) -> None:
    response = _client(tmp_path).get("/")

    assert "not a URL or IP address" in response.text
    assert 'id="target-format-hint"' in response.text


def _manifest(scan_id: str, target: str = "example.com") -> history.ScanManifest:
    return history.ScanManifest(
        scan_id=scan_id,
        target=target,
        started_at="2026-07-27T00:00:00Z",
        tools_run=("crtsh",),
        authorisation=None,
        findings_count=1,
    )


def test_history_page_groups_repeat_scans_of_the_same_target(tmp_path: Path) -> None:
    # Two distinct manifests written directly (rather than two real POST
    # /scan calls) -- scan_id_for's timestamp is second-granularity, so
    # two real scans of the same target within the same test's wall-clock
    # second would collide on scan_id, which is a real, separate, known
    # characteristic of scan_id_for, not something this test is about.
    history.write_manifest(
        tmp_path / "example-com-20260727T120000Z", _manifest("example-com-20260727T120000Z")
    )
    history.write_manifest(
        tmp_path / "example-com-20260727T110000Z", _manifest("example-com-20260727T110000Z")
    )

    response = _client(tmp_path).get("/history")

    assert response.status_code == 200
    assert "2 scans" in response.text
    assert "1 earlier scan(s) of this target" in response.text


def test_history_page_has_a_search_input(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/history")
    assert response.status_code == 200  # empty state -- no groups, no search box
    assert 'id="history-search"' not in response.text


def test_history_page_shows_a_search_input_once_scans_exist(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(pipeline, "run_scan", lambda request, **kw: _fake_outcome(request))
    client = _client(tmp_path)
    client.post("/scan", data={"target": "example.com", "tools": ["crtsh"]})

    response = client.get("/history")

    assert 'id="history-search"' in response.text
    assert 'data-target="example.com"' in response.text


def test_history_page_shows_the_actual_warning_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run_scan(request, *, raw_dir, on_status=None, on_warning=None):
        return ScanOutcome(
            brief=_fake_outcome(request).brief,
            warnings=("crt.sh: live invocation failed (boom), skipping.",),
        )

    monkeypatch.setattr(pipeline, "run_scan", fake_run_scan)
    client = _client(tmp_path)
    client.post("/scan", data={"target": "example.com", "tools": ["crtsh"]})

    response = client.get("/history")

    assert "crt.sh: live invocation failed (boom), skipping." in response.text


def test_deleting_a_scan_removes_it_from_history(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(pipeline, "run_scan", lambda request, **kw: _fake_outcome(request))
    client = _client(tmp_path)
    redirect = client.post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    scan_id = _scan_id_from_watch_redirect(redirect.headers["location"])
    assert (tmp_path / scan_id).is_dir()

    response = client.post(f"/scan/{scan_id}/delete", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/history"
    assert not (tmp_path / scan_id).exists()
    assert "No scans yet" in client.get("/history").text


def test_deleting_an_unsafe_scan_id_is_404(tmp_path: Path) -> None:
    response = _client(tmp_path).post("/scan/../etc/delete")
    assert response.status_code == 404


def _seed_scan_with_entities(
    tmp_path: Path, scan_id: str, target: str, entities: list[dict], warnings: tuple = ()
) -> None:
    scan_dir = tmp_path / scan_id
    history.write_manifest(
        scan_dir,
        history.ScanManifest(
            scan_id=scan_id,
            target=target,
            started_at="2026-07-27T00:00:00Z",
            tools_run=("crtsh",),
            authorisation="Owned",
            findings_count=len(entities),
            warnings=warnings,
        ),
    )
    history.write_entities_snapshot(scan_dir, entities)
    (scan_dir / "brief.html").write_text(
        f"<!doctype html><html><body><h1>{target}</h1></body></html>"
    )


def _diff_entity(entity_id: str, value: str, score: float = 3) -> dict:
    return {
        "id": entity_id,
        "type": "subdomain",
        "value": value,
        "attributes": {},
        "provenance": [{"source_tool": "crtsh", "method": "passive", "collected_at": "x"}],
        "priority": {"score": score, "rank": 1, "signals": ["sensitive_hostname_pattern"]},
    }


def test_view_diff_shows_added_removed_and_changed_findings(tmp_path: Path) -> None:
    _seed_scan_with_entities(
        tmp_path,
        "example-com-20260727T090000Z",
        "example.com",
        [
            _diff_entity("subdomain:old.example.com", "old.example.com"),
            _diff_entity("subdomain:api.example.com", "api.example.com", score=2),
        ],
    )
    _seed_scan_with_entities(
        tmp_path,
        "example-com-20260727T120000Z",
        "example.com",
        [
            _diff_entity("subdomain:new.example.com", "new.example.com"),
            _diff_entity("subdomain:api.example.com", "api.example.com", score=5),
        ],
    )

    response = _client(tmp_path).get("/scan/example-com-20260727T120000Z/diff")

    assert response.status_code == 200
    assert "new.example.com" in response.text  # added
    assert "old.example.com" in response.text  # removed
    assert "api.example.com" in response.text  # changed
    assert "priority 2 &rarr; 5" in response.text or "priority 2" in response.text


def test_view_diff_is_404_when_no_previous_scan_exists(tmp_path: Path) -> None:
    _seed_scan_with_entities(
        tmp_path,
        "example-com-20260727T120000Z",
        "example.com",
        [_diff_entity("x", "x.example.com")],
    )

    response = _client(tmp_path).get("/scan/example-com-20260727T120000Z/diff")

    assert response.status_code == 404


def test_view_scan_shows_a_compare_link_only_when_a_previous_scan_exists(
    tmp_path: Path,
) -> None:
    _seed_scan_with_entities(
        tmp_path,
        "example-com-20260727T090000Z",
        "example.com",
        [_diff_entity("x", "x.example.com")],
    )

    response_without_previous = _client(tmp_path).get("/scan/example-com-20260727T090000Z")
    assert "/diff" not in response_without_previous.text

    _seed_scan_with_entities(
        tmp_path,
        "example-com-20260727T120000Z",
        "example.com",
        [_diff_entity("x", "x.example.com")],
    )
    response_with_previous = _client(tmp_path).get("/scan/example-com-20260727T120000Z")
    assert "/scan/example-com-20260727T120000Z/diff" in response_with_previous.text
