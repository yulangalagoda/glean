"""Tests for the shared web-scan pipeline (ADR-0011).

Every network/subprocess call is injected via monkeypatching `runner`'s
own module-level functions -- the same pattern proven in `test_runner.py`
and `test_cli.py`, and deliberately module-qualified access throughout
`pipeline.py` (`runner.fetch_crtsh_cached(...)`, not a bound `from ...
import`) so that pattern actually works here too.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from glean_osint import pipeline, runner
from glean_osint.pipeline import ScanRequest


def _empty_dnsx_envelope(candidates: list[str], **kwargs: object) -> bytes:
    return b'{"candidates": [], "resolved": []}'


def _stub_all_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "fetch_crtsh_cached", lambda target, **kwargs: b"[]")
    monkeypatch.setattr(
        runner, "run_theharvester", lambda target, **kwargs: b'{"cmd": "", "hosts": []}'
    )
    monkeypatch.setattr(runner, "run_dnsx", _empty_dnsx_envelope)
    monkeypatch.setattr(runner, "run_httpx", lambda hosts, **kwargs: b"")


def test_run_scan_only_invokes_selected_tools(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[str] = []

    def fake_fetch(target: str, **kwargs: object) -> bytes:
        calls.append("crtsh")
        return b"[]"

    monkeypatch.setattr(runner, "fetch_crtsh_cached", fake_fetch)

    def _fail_if_called(*args: object, **kwargs: object) -> bytes:
        raise AssertionError("theHarvester must not be invoked when not selected")

    monkeypatch.setattr(runner, "run_theharvester", _fail_if_called)
    monkeypatch.setattr(runner, "run_dnsx", _fail_if_called)
    monkeypatch.setattr(runner, "run_httpx", _fail_if_called)

    outcome = pipeline.run_scan(
        ScanRequest(target="example.com", tools=frozenset({"crtsh"})), raw_dir=tmp_path
    )

    assert calls == ["crtsh"]
    assert [t.source_tool for t in outcome.brief.scan.tools_run] == ["crtsh"]
    assert outcome.warnings == ()


def test_run_scan_httpx_selection_pulls_in_dnsx_even_without_going_through_the_web_layer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """run_scan defends the httpx-requires-dnsx constraint itself
    (ADR-0011 D4), not just the web form -- a direct ScanRequest(tools=
    {"httpx"}) must still resolve dnsx first."""
    _stub_all_tools(monkeypatch)

    outcome = pipeline.run_scan(
        ScanRequest(target="example.com", tools=frozenset({"httpx"})), raw_dir=tmp_path
    )

    # Both ran: dnsx as the auto-included dependency, httpx because it was
    # explicitly selected. httpx's own findings are empty here only because
    # the stub returns b"" -- the point is dnsx ran *first* to feed it.
    assert {t.source_tool for t in outcome.brief.scan.tools_run} == {"dnsx", "httpx"}
    assert outcome.warnings == ()


def test_run_scan_reports_a_degraded_tool_as_a_warning_not_a_crash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_all_tools(monkeypatch)

    def _unavailable(target: str, **kwargs: object) -> bytes:
        raise runner.ToolUnavailable("theHarvester")

    monkeypatch.setattr(runner, "run_theharvester", _unavailable)

    outcome = pipeline.run_scan(
        ScanRequest(target="example.com", tools=frozenset({"crtsh", "theharvester"})),
        raw_dir=tmp_path,
    )

    assert "theHarvester: live invocation failed" in outcome.warnings[0]
    assert [t.source_tool for t in outcome.brief.scan.tools_run] == ["crtsh"]


def test_run_scan_streams_warnings_via_on_warning_as_well_as_the_final_tuple(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """ADR-0011 Stage 2: a caller streaming progress to a browser needs
    warnings live, not just in the final ScanOutcome once everything's
    already done."""
    _stub_all_tools(monkeypatch)

    def _unavailable(target: str, **kwargs: object) -> bytes:
        raise runner.ToolUnavailable("theHarvester")

    monkeypatch.setattr(runner, "run_theharvester", _unavailable)
    streamed: list[str] = []

    outcome = pipeline.run_scan(
        ScanRequest(target="example.com", tools=frozenset({"crtsh", "theharvester"})),
        raw_dir=tmp_path,
        on_warning=streamed.append,
    )

    assert streamed == list(outcome.warnings)
    assert "theHarvester: live invocation failed" in streamed[0]


def test_run_scan_without_on_warning_still_populates_the_final_tuple(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """on_warning is purely additive -- omitting it must not lose anything
    from the returned warnings tuple."""
    _stub_all_tools(monkeypatch)

    def _unavailable(target: str, **kwargs: object) -> bytes:
        raise runner.ToolUnavailable("theHarvester")

    monkeypatch.setattr(runner, "run_theharvester", _unavailable)

    outcome = pipeline.run_scan(
        ScanRequest(target="example.com", tools=frozenset({"crtsh", "theharvester"})),
        raw_dir=tmp_path,
    )

    assert "theHarvester: live invocation failed" in outcome.warnings[0]


def test_run_scan_folds_crtsh_cache_info_into_warnings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_fetch_cached(target: str, *, info: list[str] | None = None, **kwargs: object) -> bytes:
        if info is not None:
            info.append("crt.sh: using cached response from 5m ago.")
        return b"[]"

    monkeypatch.setattr(runner, "fetch_crtsh_cached", fake_fetch_cached)

    outcome = pipeline.run_scan(
        ScanRequest(target="example.com", tools=frozenset({"crtsh"})), raw_dir=tmp_path
    )

    assert "crt.sh: using cached response from 5m ago." in outcome.warnings


def test_run_scan_calls_on_status_before_each_selected_stage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_all_tools(monkeypatch)
    statuses: list[str] = []

    pipeline.run_scan(
        ScanRequest(target="example.com", tools=frozenset({"crtsh", "dnsx"})),
        raw_dir=tmp_path,
        on_status=statuses.append,
    )

    assert any("crt.sh" in s for s in statuses)
    assert any("dnsx" in s for s in statuses)
    assert not any("theHarvester" in s for s in statuses)  # not selected


def test_run_scan_archives_raw_output_under_the_given_raw_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_all_tools(monkeypatch)

    pipeline.run_scan(
        ScanRequest(target="example.com", tools=frozenset({"crtsh"})), raw_dir=tmp_path
    )

    assert (tmp_path / "crtsh-example.com.json").exists()


def test_run_scan_reads_tool_binary_env_vars(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The web app has no CLI --*-bin options -- $GLEAN_THEHARVESTER_BIN
    etc. are the only way to point at the correct binary here (a real
    bug found live: theHarvester failed through the web UI even with
    the env var exported, since pipeline.py wasn't reading it at all)."""
    monkeypatch.setenv("GLEAN_THEHARVESTER_BIN", "/opt/theHarvester")
    monkeypatch.setenv("GLEAN_DNSX_BIN", "/opt/dnsx")
    monkeypatch.setenv("GLEAN_HTTPX_BIN", "/opt/httpx")
    seen_binaries: dict[str, str] = {}

    def fake_theharvester(target: str, *, binary: str = "theHarvester", **kwargs: object) -> bytes:
        seen_binaries["theharvester"] = binary
        return b'{"cmd": "", "hosts": []}'

    def fake_dnsx(candidates: list[str], *, binary: str = "dnsx", **kwargs: object) -> bytes:
        seen_binaries["dnsx"] = binary
        return b'{"candidates": [], "resolved": []}'

    def fake_httpx(hosts: list[str], *, binary: str = "httpx", **kwargs: object) -> bytes:
        seen_binaries["httpx"] = binary
        return b""

    monkeypatch.setattr(runner, "fetch_crtsh_cached", lambda target, **kwargs: b"[]")
    monkeypatch.setattr(runner, "run_theharvester", fake_theharvester)
    monkeypatch.setattr(runner, "run_dnsx", fake_dnsx)
    monkeypatch.setattr(runner, "run_httpx", fake_httpx)

    pipeline.run_scan(
        ScanRequest(
            target="example.com",
            tools=frozenset({"theharvester", "httpx"}),  # httpx pulls in dnsx too
        ),
        raw_dir=tmp_path,
    )

    assert seen_binaries == {
        "theharvester": "/opt/theHarvester",
        "dnsx": "/opt/dnsx",
        "httpx": "/opt/httpx",
    }


def test_run_scan_respects_authorisation_and_top_n(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_all_tools(monkeypatch)

    outcome = pipeline.run_scan(
        ScanRequest(
            target="example.com",
            tools=frozenset({"crtsh"}),
            authorisation="Owned by operator",
            top_n=2,
        ),
        raw_dir=tmp_path,
    )

    assert outcome.brief.scan.authorisation == "Owned by operator"
