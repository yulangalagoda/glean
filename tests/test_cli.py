"""Tests for the `glean` CLI entrypoint."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from glean_osint import runner as live_runner
from glean_osint.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


def test_top_level_help_lists_scan_as_a_subcommand() -> None:
    """Guards the deliberate `glean scan <domain>` shape (not bare
    `glean <domain>`) — see the module docstring on the callback."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output


def test_scan_requires_at_least_one_tool_input_or_live() -> None:
    result = runner.invoke(app, ["scan", "example.com"])
    assert result.exit_code == 1
    assert "Provide at least one" in result.output


def test_scan_with_both_tools_produces_a_brief() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--crtsh",
            str(FIXTURES / "crtsh-example-com.json"),
            "--theharvester",
            str(FIXTURES / "theharvester-example-com.json"),
        ],
    )
    assert result.exit_code == 0
    assert "# Glean Brief — example.com" in result.output
    assert "## Top priorities" in result.output
    assert "Findings in this brief:" in result.output


def test_scan_reports_skipped_malformed_records() -> None:
    result = runner.invoke(
        app,
        ["scan", "example.com", "--crtsh", str(FIXTURES / "crtsh-example-com.json")],
    )
    assert result.exit_code == 0
    assert "crt.sh: skipped 1 malformed record(s)." in result.output


def test_scan_writes_to_out_file(tmp_path: Path) -> None:
    out_file = tmp_path / "brief.md"
    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--crtsh",
            str(FIXTURES / "crtsh-example-com.json"),
            "--out",
            str(out_file),
        ],
    )
    assert result.exit_code == 0
    assert f"Brief written to {out_file}" in result.output
    assert out_file.read_text().startswith("# Glean Brief — example.com")


def test_scan_rejects_a_nonexistent_file() -> None:
    result = runner.invoke(app, ["scan", "example.com", "--crtsh", "/no/such/file.json"])
    assert result.exit_code != 0


def test_scan_records_authorisation_and_top_n() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--crtsh",
            str(FIXTURES / "crtsh-example-com.json"),
            "--theharvester",
            str(FIXTURES / "theharvester-example-com.json"),
            "--authorisation",
            "Owned by operator",
            "--top-n",
            "2",
        ],
    )
    assert result.exit_code == 0
    assert "**Authorisation:** Owned by operator" in result.output
    assert "**3." not in result.output  # top_n=2 caps "Top priorities" at 2


# --- --live / --active (ADR-0008: the runner) ---------------------------
#
# Every live-invocation function is monkeypatched here — no real network
# access or subprocess execution happens in this suite.


def _empty_dnsx_envelope(candidates: list[str]) -> bytes:
    return b'{"candidates": [], "resolved": []}'


def _empty_theharvester(target: str) -> bytes:
    return b'{"cmd": "", "hosts": []}'


def test_scan_live_alone_satisfies_the_input_guard(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(live_runner, "fetch_crtsh", lambda target: b"[]")
    monkeypatch.setattr(live_runner, "run_theharvester", _empty_theharvester)
    monkeypatch.setattr(live_runner, "run_dnsx", _empty_dnsx_envelope)

    result = runner.invoke(app, ["scan", "example.com", "--live", "--raw-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "# Glean Brief" in result.output


def test_scan_live_without_active_never_invokes_httpx(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(live_runner, "fetch_crtsh", lambda target: b"[]")
    monkeypatch.setattr(live_runner, "run_theharvester", _empty_theharvester)
    monkeypatch.setattr(live_runner, "run_dnsx", _empty_dnsx_envelope)

    def _fail_if_called(*args: object, **kwargs: object) -> bytes:
        raise AssertionError("httpx must not be invoked without --active")

    monkeypatch.setattr(live_runner, "run_httpx", _fail_if_called)

    result = runner.invoke(app, ["scan", "example.com", "--live", "--raw-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "active recon not enabled; pass --active" in result.output


def test_scan_live_with_active_invokes_httpx_and_archives_raw_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(live_runner, "fetch_crtsh", lambda target: b"[]")
    monkeypatch.setattr(live_runner, "run_theharvester", _empty_theharvester)
    dnsx_envelope = (
        b'{"candidates": ["example.com"], '
        b'"resolved": [{"host": "example.com", "a": ["203.0.113.1"]}]}'
    )
    monkeypatch.setattr(live_runner, "run_dnsx", lambda candidates: dnsx_envelope)
    monkeypatch.setattr(
        live_runner,
        "run_httpx",
        lambda resolved_hosts, binary="httpx": (
            b'{"input": "example.com", "failed": false, "port": "443", '
            b'"scheme": "https", "a": ["203.0.113.1"], "tech": ["nginx"]}\n'
        ),
    )

    result = runner.invoke(
        app, ["scan", "example.com", "--live", "--active", "--raw-dir", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert "Active collection (httpx) touched the target." in result.output
    assert (tmp_path / "crtsh-example.com.json").exists()
    assert (tmp_path / "httpx-example.com.jsonl").exists()


def test_scan_live_per_tool_file_overrides_live_invocation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """ADR-0008 D6 mixed mode: a --crtsh file, even with --live, must skip
    live crt.sh invocation for that one tool and ingest the file instead."""

    def _fail_if_called(target: str) -> bytes:
        raise AssertionError("crt.sh must not be invoked live when --crtsh is given")

    monkeypatch.setattr(live_runner, "fetch_crtsh", _fail_if_called)
    monkeypatch.setattr(live_runner, "run_theharvester", _empty_theharvester)
    monkeypatch.setattr(live_runner, "run_dnsx", _empty_dnsx_envelope)

    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--live",
            "--crtsh",
            str(FIXTURES / "crtsh-example-com.json"),
            "--raw-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert "# Glean Brief" in result.output
    # the ingested file is referenced directly, nothing new archived for it
    assert not (tmp_path / "crtsh-example.com.json").exists()


def test_scan_live_degraded_tool_does_not_abort_the_scan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def _unavailable(target: str) -> bytes:
        raise live_runner.ToolUnavailable("theHarvester")

    monkeypatch.setattr(live_runner, "fetch_crtsh", lambda target: b"[]")
    monkeypatch.setattr(live_runner, "run_theharvester", _unavailable)
    monkeypatch.setattr(live_runner, "run_dnsx", _empty_dnsx_envelope)

    result = runner.invoke(app, ["scan", "example.com", "--live", "--raw-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "theHarvester: live invocation failed" in result.output
    assert "# Glean Brief" in result.output
