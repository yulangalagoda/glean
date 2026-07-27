"""Tests for the web interface (ADR-0011), stage 1.

`create_app(history_root=tmp_path)` isolates every test from the real
`~/.local/share/glean/scans/` -- the crt.sh cache bug earlier this session
is exactly the class of mistake this guards against (real state written
during `pytest` because a test-time override wasn't actually wired
through). `pipeline.run_scan` is monkeypatched at `glean_osint.pipeline`
(module-qualified access in `app.py`, not a bound `from ... import`, for
the same reason) so no real network/subprocess call happens here either.
"""

from __future__ import annotations

import json
from pathlib import Path

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


def test_submit_scan_runs_and_redirects_to_the_results_page(
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
    assert response.headers["location"].startswith("/scan/example-com-")
    assert calls[0].target == "example.com"
    assert calls[0].tools == frozenset({"crtsh"})


def test_view_scan_serves_the_saved_html_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(pipeline, "run_scan", lambda request, **kw: _fake_outcome(request))

    client = _client(tmp_path)
    redirect = client.post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    result = client.get(redirect.headers["location"])

    assert result.status_code == 200
    assert result.text.startswith("<!doctype html>")
    assert "example.com" in result.text


def test_submit_scan_writes_a_manifest(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(pipeline, "run_scan", lambda request, **kw: _fake_outcome(request))

    redirect = _client(tmp_path).post(
        "/scan", data={"target": "example.com", "tools": ["crtsh"]}, follow_redirects=False
    )
    scan_id = redirect.headers["location"].removeprefix("/scan/")
    manifest = json.loads((tmp_path / scan_id / "manifest.json").read_text())

    assert manifest["target"] == "example.com"
    assert manifest["scan_id"] == scan_id


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
