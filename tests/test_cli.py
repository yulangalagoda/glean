"""Tests for the `glean` CLI entrypoint."""

from pathlib import Path

from typer.testing import CliRunner

from glean_osint.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


def test_top_level_help_lists_scan_as_a_subcommand() -> None:
    """Guards the deliberate `glean scan <domain>` shape (not bare
    `glean <domain>`) — see the module docstring on the callback."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output


def test_scan_requires_at_least_one_tool_input() -> None:
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
