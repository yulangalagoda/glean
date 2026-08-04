"""Tests for the shared web-scan pipeline (ADR-0011).

Every network/subprocess call is injected via monkeypatching `runner`'s
own module-level functions -- the same pattern proven in `test_runner.py`
and `test_cli.py`, and deliberately module-qualified access throughout
`pipeline.py` (`runner.fetch_crtsh_cached(...)`, not a bound `from ...
import`) so that pattern actually works here too.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from glean_osint import pipeline, runner, synthesis
from glean_osint.pipeline import ScanRequest


def _empty_dnsx_envelope(candidates: list[str], **kwargs: object) -> bytes:
    return b'{"candidates": [], "resolved": []}'


def _stub_all_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "fetch_crtsh_cached", lambda target, **kwargs: b"[]")
    monkeypatch.setattr(
        runner, "run_theharvester", lambda target, **kwargs: b'{"cmd": "", "hosts": []}'
    )
    monkeypatch.setattr(runner, "run_subfinder", lambda target, **kwargs: b"")
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


def test_run_scan_subfinder_subdomains_feed_dnsx_candidates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """extract_candidates (runner.py) is already generic over every
    ParseResult regardless of source tool -- confirms subfinder's
    output reaches dnsx with zero changes needed there."""
    monkeypatch.setattr(runner, "fetch_crtsh_cached", lambda target, **kwargs: b"[]")
    monkeypatch.setattr(
        runner,
        "run_subfinder",
        lambda target, **kwargs: (
            b'{"host":"beta.example.com","input":"example.com","source":"crtsh"}\n'
        ),
    )
    seen_candidates: list[str] = []

    def fake_dnsx(candidates: list[str], **kwargs: object) -> bytes:
        seen_candidates.extend(candidates)
        return b'{"candidates": [], "resolved": []}'

    monkeypatch.setattr(runner, "run_dnsx", fake_dnsx)

    outcome = pipeline.run_scan(
        ScanRequest(target="example.com", tools=frozenset({"crtsh", "subfinder", "dnsx"})),
        raw_dir=tmp_path,
    )

    assert "beta.example.com" in seen_candidates
    assert {t.source_tool for t in outcome.brief.scan.tools_run} == {"crtsh", "subfinder", "dnsx"}


def test_run_scan_stage1_tools_actually_run_concurrently(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Proves genuine concurrency, not just that each tool still works in
    isolation: a Barrier(3) can only release once crt.sh, theHarvester,
    and subfinder's fetch calls are all genuinely in flight *at the same
    time*. If Stage 1 ever regressed back to sequential execution, this
    hangs until the timeout and fails instead of silently passing."""
    barrier = threading.Barrier(3, timeout=2)

    def fake_crtsh(target: str, **kwargs: object) -> bytes:
        barrier.wait()
        return b"[]"

    def fake_theharvester(target: str, **kwargs: object) -> bytes:
        barrier.wait()
        return b'{"cmd": "", "hosts": []}'

    def fake_subfinder(target: str, **kwargs: object) -> bytes:
        barrier.wait()
        return b""

    monkeypatch.setattr(runner, "fetch_crtsh_cached", fake_crtsh)
    monkeypatch.setattr(runner, "run_theharvester", fake_theharvester)
    monkeypatch.setattr(runner, "run_subfinder", fake_subfinder)

    outcome = pipeline.run_scan(
        ScanRequest(target="example.com", tools=frozenset({"crtsh", "theharvester", "subfinder"})),
        raw_dir=tmp_path,
    )

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


def test_run_scan_reports_crtsh_cache_info_as_status_not_a_warning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A cache hit is informational, not a problem -- a real bug once
    folded it into `warnings`, so a perfectly healthy scan showed a
    misleading "1 warning" on the history page. Matches the CLI's own
    cyan-vs-yellow treatment of the same messages."""

    def fake_fetch_cached(target: str, *, info: list[str] | None = None, **kwargs: object) -> bytes:
        if info is not None:
            info.append("crt.sh: using cached response from 5m ago.")
        return b"[]"

    monkeypatch.setattr(runner, "fetch_crtsh_cached", fake_fetch_cached)
    statuses: list[str] = []

    outcome = pipeline.run_scan(
        ScanRequest(target="example.com", tools=frozenset({"crtsh"})),
        raw_dir=tmp_path,
        on_status=statuses.append,
    )

    assert "crt.sh: using cached response from 5m ago." in statuses
    assert outcome.warnings == ()


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
    monkeypatch.setenv("GLEAN_SUBFINDER_BIN", "/opt/subfinder")
    monkeypatch.setenv("GLEAN_DNSX_BIN", "/opt/dnsx")
    monkeypatch.setenv("GLEAN_HTTPX_BIN", "/opt/httpx")
    seen_binaries: dict[str, str] = {}

    def fake_theharvester(target: str, *, binary: str = "theHarvester", **kwargs: object) -> bytes:
        seen_binaries["theharvester"] = binary
        return b'{"cmd": "", "hosts": []}'

    def fake_subfinder(target: str, *, binary: str = "subfinder", **kwargs: object) -> bytes:
        seen_binaries["subfinder"] = binary
        return b""

    def fake_dnsx(candidates: list[str], *, binary: str = "dnsx", **kwargs: object) -> bytes:
        seen_binaries["dnsx"] = binary
        return b'{"candidates": [], "resolved": []}'

    def fake_httpx(hosts: list[str], *, binary: str = "httpx", **kwargs: object) -> bytes:
        seen_binaries["httpx"] = binary
        return b""

    monkeypatch.setattr(runner, "fetch_crtsh_cached", lambda target, **kwargs: b"[]")
    monkeypatch.setattr(runner, "run_theharvester", fake_theharvester)
    monkeypatch.setattr(runner, "run_subfinder", fake_subfinder)
    monkeypatch.setattr(runner, "run_dnsx", fake_dnsx)
    monkeypatch.setattr(runner, "run_httpx", fake_httpx)

    pipeline.run_scan(
        ScanRequest(
            target="example.com",
            tools=frozenset({"theharvester", "subfinder", "httpx"}),  # httpx pulls in dnsx too
        ),
        raw_dir=tmp_path,
    )

    assert seen_binaries == {
        "theharvester": "/opt/theHarvester",
        "subfinder": "/opt/subfinder",
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


def _crtsh_with_one_scored_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """crt.sh output that actually produces a top-priority finding, so the
    narration path has something to narrate."""
    import json

    record = {
        "issuer_ca_id": 1,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R11",
        "common_name": "admin.example.com",
        "name_value": "admin.example.com",
        "id": 7100000001,
        "entry_timestamp": "2026-06-01T08:00:00",
        "not_before": "2026-06-01T07:00:00",
        "not_after": "2026-08-30T08:00:00",
        "serial_number": "0000000000000a",
        "result_count": 1,
    }
    payload = json.dumps([record]).encode()
    monkeypatch.setattr(runner, "fetch_crtsh_cached", lambda target, **kwargs: payload)


def test_run_scan_does_not_call_ollama_unless_llm_is_requested(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Narration is opt-in for the same reason --live was: it depends on a
    local Ollama, and a scan must never start depending on one silently."""
    _crtsh_with_one_scored_host(monkeypatch)

    def _fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("synthesize_brief must not run without llm=True")

    monkeypatch.setattr(pipeline.synthesis, "synthesize_brief", _fail)

    outcome = pipeline.run_scan(
        ScanRequest(target="example.com", tools=frozenset({"crtsh"})), raw_dir=tmp_path
    )

    assert outcome.narrated_by is None


def test_run_scan_records_the_model_that_actually_narrated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _crtsh_with_one_scored_host(monkeypatch)

    def fake_synthesis(brief: object, entities: object, **kwargs: object) -> object:
        return synthesis.SynthesisResult(
            brief=brief,  # type: ignore[arg-type]
            narrated_count=1,
            fell_back_count=0,
            invented_ids_dropped=0,
        )

    monkeypatch.setattr(pipeline.synthesis, "synthesize_brief", fake_synthesis)

    outcome = pipeline.run_scan(
        ScanRequest(
            target="example.com", tools=frozenset({"crtsh"}), llm=True, model="llama3.2:latest"
        ),
        raw_dir=tmp_path,
    )

    assert outcome.narrated_by == "llama3.2:latest"
    assert outcome.warnings == ()


def test_run_scan_warns_loudly_when_narration_silently_fell_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`synthesize_brief` degrades to the template on an unreachable Ollama
    rather than raising (ADR-0009) -- correct, but silent. The reader asked
    for model narration and would otherwise be handed template prose with
    nothing at all to distinguish it."""
    _crtsh_with_one_scored_host(monkeypatch)

    def fake_synthesis(brief: object, entities: object, **kwargs: object) -> object:
        return synthesis.SynthesisResult(
            brief=brief,  # type: ignore[arg-type]
            narrated_count=0,
            fell_back_count=3,
            invented_ids_dropped=0,
        )

    monkeypatch.setattr(pipeline.synthesis, "synthesize_brief", fake_synthesis)

    streamed: list[str] = []
    outcome = pipeline.run_scan(
        ScanRequest(target="example.com", tools=frozenset({"crtsh"}), llm=True),
        raw_dir=tmp_path,
        on_warning=streamed.append,
    )

    assert outcome.narrated_by is None, "nothing was narrated, so nothing may be attributed"
    assert any("narration unavailable" in w.lower() for w in outcome.warnings)
    assert any("ollama" in w.lower() for w in outcome.warnings)
    # Streamed live too, not only present in the final tuple.
    assert streamed == list(outcome.warnings)


# ── Cancellation (roadmap item #24) ──────────────────────────────────────


def test_a_cancelled_scan_stops_instead_of_degrading_into_a_warning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The subtle correctness point. Every entry in `_LIVE_INVOCATION_ERRORS`
    means "this one tool failed, carry on with the rest" (ADR-0002 D5). If
    `ScanCancelled` were caught alongside them, cancelling would quietly
    turn into a warning and the remaining stages would keep running -- the
    scan would finish, having ignored the operator entirely.
    """
    _stub_all_tools(monkeypatch)
    token = runner.CancellationToken()
    token.cancel()

    with pytest.raises(runner.ScanCancelled):
        pipeline.run_scan(
            ScanRequest(target="example.com", tools=frozenset({"crtsh", "dnsx"})),
            raw_dir=tmp_path / "raw",
            cancel=token,
        )


def test_cancelling_midway_stops_before_the_next_stage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Cancellation is cooperative, so what matters is that the *next* stage
    never starts. dnsx must not run once the operator has cancelled during
    Stage 1, however far through that stage the scan happened to be.
    """
    _stub_all_tools(monkeypatch)
    token = runner.CancellationToken()
    dnsx_calls: list[object] = []

    def cancel_during_crtsh(target: str, **kwargs: object) -> bytes:
        token.cancel()
        return b"[]"

    def recording_dnsx(candidates: list[str], **kwargs: object) -> bytes:
        dnsx_calls.append(candidates)
        return _empty_dnsx_envelope(candidates)

    monkeypatch.setattr(runner, "fetch_crtsh_cached", cancel_during_crtsh)
    monkeypatch.setattr(runner, "run_dnsx", recording_dnsx)

    with pytest.raises(runner.ScanCancelled):
        pipeline.run_scan(
            ScanRequest(target="example.com", tools=frozenset({"crtsh", "dnsx"})),
            raw_dir=tmp_path / "raw",
            cancel=token,
        )

    assert dnsx_calls == [], "Stage 2 ran after the scan was cancelled"


def test_run_scan_without_a_token_is_completely_unaffected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Cancellation is additive: the CLI and every existing caller pass no
    token, and must behave exactly as before."""
    _stub_all_tools(monkeypatch)

    outcome = pipeline.run_scan(
        ScanRequest(target="example.com", tools=frozenset({"crtsh", "dnsx"})),
        raw_dir=tmp_path / "raw",
    )

    assert outcome.brief.scan.target == "example.com"
