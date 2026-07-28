"""Tests for the `glean` CLI entrypoint."""

import json
import re
import threading
from pathlib import Path

import pytest
from typer.testing import CliRunner

from glean_osint import evaluation, history, synthesis
from glean_osint import runner as live_runner
from glean_osint.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _isolate_crtsh_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Every test in this file must stay fully network-free (see the
    module docstring on the --live section below) -- without this,
    `fetch_crtsh_cached`'s cache directory defaults to the real
    `~/.cache/glean/crtsh/`, which a real bug once let slip through
    undetected (writing fake-but-cache-shaped test data into the
    operator's actual cache directory on every `pytest` run, found only
    by noticing the directory existed after a routine test run)."""
    monkeypatch.setattr(live_runner, "DEFAULT_CRTSH_CACHE_DIR", tmp_path / "crtsh-cache")
    # Same discipline for ADR-0011 D6: a --live scan with no explicit
    # --raw-dir now defaults into the shared history location -- without
    # this, any such test here would write real manifest/brief files
    # into the operator's actual ~/.local/share/glean/scans/.
    monkeypatch.setattr(history, "DEFAULT_HISTORY_ROOT", tmp_path / "history")


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


def test_scan_ingests_a_subfinder_file() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--subfinder",
            str(FIXTURES / "subfinder-example-com.jsonl"),
        ],
    )
    assert result.exit_code == 0
    assert "# Glean Brief — example.com" in result.output
    assert "subfinder" in result.output
    assert "admin.example.com" in result.output


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


def test_scan_writes_html_when_out_has_an_html_extension(tmp_path: Path) -> None:
    """ADR-0010 D2: format follows --out's extension, no new flag."""
    out_file = tmp_path / "brief.html"
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
    written = out_file.read_text()
    assert written.startswith("<!doctype html>")
    assert "Glean Brief — example.com" in written


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


def _many_hosts_crtsh_json(tmp_path: Path, count: int) -> Path:
    """A synthetic crt.sh capture with `count` distinct subdomains -- enough
    to exercise the "Also found" truncation (DEFAULT_ALSO_FOUND_LIMIT=25),
    since the real fixtures only carry a handful of entries."""
    records = [
        {
            "issuer_ca_id": 1,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R11",
            "common_name": f"h{i}.example.com",
            "name_value": f"h{i}.example.com",
            "id": 7100000000 + i,
            "entry_timestamp": "2026-06-01T08:00:00",
            "not_before": "2026-06-01T07:00:00",
            "not_after": "2026-08-30T08:00:00",
            "serial_number": f"{i:014x}",
            "result_count": 1,
        }
        for i in range(count)
    ]
    path = tmp_path / "crtsh-many.json"
    path.write_text(json.dumps(records))
    return path


def test_scan_also_found_is_truncated_by_default(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["scan", "example.com", "--crtsh", str(_many_hosts_crtsh_json(tmp_path, 40))],
    )
    assert result.exit_code == 0
    assert "- _...and " in result.output
    assert "more not shown here._" in result.output


def test_scan_show_all_prints_every_also_found_entry(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["scan", "example.com", "--crtsh", str(_many_hosts_crtsh_json(tmp_path, 40)), "--show-all"],
    )
    assert result.exit_code == 0
    assert "not shown here" not in result.output
    for i in range(40):
        assert f"h{i}.example.com" in result.output


def test_scan_out_file_is_always_complete_regardless_of_show_all(tmp_path: Path) -> None:
    out_file = tmp_path / "brief.md"
    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--crtsh",
            str(_many_hosts_crtsh_json(tmp_path, 40)),
            "--out",
            str(out_file),
        ],
    )
    assert result.exit_code == 0
    written = out_file.read_text()
    assert "not shown here" not in written
    for i in range(40):
        assert f"h{i}.example.com" in written


# --- --live / --active (ADR-0008: the runner) ---------------------------
#
# Every live-invocation function is monkeypatched here — no real network
# access or subprocess execution happens in this suite.


def _empty_dnsx_envelope(candidates: list[str], **kwargs: object) -> bytes:
    return b'{"candidates": [], "resolved": []}'


def _empty_theharvester(target: str, **kwargs: object) -> bytes:
    return b'{"cmd": "", "hosts": []}'


def _empty_subfinder(target: str, **kwargs: object) -> bytes:
    return b""


def test_scan_live_alone_satisfies_the_input_guard(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(live_runner, "fetch_crtsh", lambda target: b"[]")
    monkeypatch.setattr(live_runner, "run_theharvester", _empty_theharvester)
    monkeypatch.setattr(live_runner, "run_subfinder", _empty_subfinder)
    monkeypatch.setattr(live_runner, "run_dnsx", _empty_dnsx_envelope)

    result = runner.invoke(app, ["scan", "example.com", "--live", "--raw-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "# Glean Brief" in result.output


def test_scan_live_invokes_subfinder_and_records_it_in_tools_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(live_runner, "fetch_crtsh", lambda target: b"[]")
    monkeypatch.setattr(live_runner, "run_theharvester", _empty_theharvester)
    monkeypatch.setattr(
        live_runner,
        "run_subfinder",
        lambda target, **kwargs: (
            b'{"host":"beta.example.com","input":"example.com","source":"crtsh"}\n'
        ),
    )
    monkeypatch.setattr(live_runner, "run_dnsx", _empty_dnsx_envelope)

    result = runner.invoke(app, ["scan", "example.com", "--live", "--raw-dir", str(tmp_path)])

    assert result.exit_code == 0
    assert "subfinder (passive)" in result.output
    assert "beta.example.com" in result.output
    assert (tmp_path / "subfinder-example.com.jsonl").exists()


def test_scan_live_stage1_tools_actually_run_concurrently(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Proves genuine concurrency, not just that each tool still works in
    isolation: a Barrier(3) can only release once crt.sh, theHarvester,
    and subfinder's fetch calls are all genuinely in flight *at the same
    time*. If Stage 1 ever regressed back to sequential execution, this
    hangs until the timeout and fails instead of silently passing."""
    barrier = threading.Barrier(3, timeout=2)

    def fake_crtsh(target: str) -> bytes:
        barrier.wait()
        return b"[]"

    def fake_theharvester(target: str, **kwargs: object) -> bytes:
        barrier.wait()
        return b'{"cmd": "", "hosts": []}'

    def fake_subfinder(target: str, **kwargs: object) -> bytes:
        barrier.wait()
        return b""

    monkeypatch.setattr(live_runner, "fetch_crtsh", fake_crtsh)
    monkeypatch.setattr(live_runner, "run_theharvester", fake_theharvester)
    monkeypatch.setattr(live_runner, "run_subfinder", fake_subfinder)
    monkeypatch.setattr(live_runner, "run_dnsx", _empty_dnsx_envelope)

    result = runner.invoke(app, ["scan", "example.com", "--live", "--raw-dir", str(tmp_path)])

    assert result.exit_code == 0


def test_scan_live_without_raw_dir_writes_a_manifest_to_the_shared_history(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """ADR-0011 D6: a --live scan with no explicit --raw-dir now lands in
    the same shared history location the web interface uses, so it's
    browsable from either surface."""
    monkeypatch.setattr(live_runner, "fetch_crtsh", lambda target: b"[]")
    monkeypatch.setattr(live_runner, "run_theharvester", _empty_theharvester)
    monkeypatch.setattr(live_runner, "run_subfinder", _empty_subfinder)
    monkeypatch.setattr(live_runner, "run_dnsx", _empty_dnsx_envelope)

    result = runner.invoke(app, ["scan", "example.com", "--live"])

    assert result.exit_code == 0
    scan_dirs = list((history.DEFAULT_HISTORY_ROOT).iterdir())
    assert len(scan_dirs) == 1
    scan_dir = scan_dirs[0]
    assert scan_dir.name.startswith("example-com-")
    manifest = json.loads((scan_dir / "manifest.json").read_text())
    assert manifest["target"] == "example.com"
    assert manifest["scan_id"] == scan_dir.name
    assert (scan_dir / "brief.html").read_text().startswith("<!doctype html>")
    assert (scan_dir / "raw").is_dir()  # the usual raw archive still lands alongside it


def test_scan_live_with_explicit_raw_dir_skips_the_shared_history(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An explicit --raw-dir signals "put output somewhere else, on my
    own terms" -- it opts out of the shared-history bookkeeping too,
    not just the raw-archive location."""
    monkeypatch.setattr(live_runner, "fetch_crtsh", lambda target: b"[]")
    monkeypatch.setattr(live_runner, "run_theharvester", _empty_theharvester)
    monkeypatch.setattr(live_runner, "run_subfinder", _empty_subfinder)
    monkeypatch.setattr(live_runner, "run_dnsx", _empty_dnsx_envelope)

    result = runner.invoke(
        app, ["scan", "example.com", "--live", "--raw-dir", str(tmp_path / "custom")]
    )

    assert result.exit_code == 0
    assert not history.DEFAULT_HISTORY_ROOT.exists()


def test_scan_live_reports_a_crtsh_cache_hit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fetch_calls = []

    def fake_fetch(target: str) -> bytes:
        fetch_calls.append(target)
        return b"[]"

    monkeypatch.setattr(live_runner, "fetch_crtsh", fake_fetch)
    monkeypatch.setattr(live_runner, "run_theharvester", _empty_theharvester)
    monkeypatch.setattr(live_runner, "run_subfinder", _empty_subfinder)
    monkeypatch.setattr(live_runner, "run_dnsx", _empty_dnsx_envelope)

    # First scan: cold cache, real (fake) fetch happens once.
    result1 = runner.invoke(app, ["scan", "example.com", "--live", "--raw-dir", str(tmp_path)])
    assert result1.exit_code == 0
    assert fetch_calls == ["example.com"]

    # Second scan of the same target: must be served from cache, not re-fetched.
    result2 = runner.invoke(app, ["scan", "example.com", "--live", "--raw-dir", str(tmp_path)])
    assert result2.exit_code == 0
    assert fetch_calls == ["example.com"]  # still just the one call
    assert "crt.sh: using cached response from" in result2.output


def test_scan_live_no_crtsh_cache_always_refetches(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fetch_calls = []

    def fake_fetch(target: str) -> bytes:
        fetch_calls.append(target)
        return b"[]"

    monkeypatch.setattr(live_runner, "fetch_crtsh", fake_fetch)
    monkeypatch.setattr(live_runner, "run_theharvester", _empty_theharvester)
    monkeypatch.setattr(live_runner, "run_subfinder", _empty_subfinder)
    monkeypatch.setattr(live_runner, "run_dnsx", _empty_dnsx_envelope)

    for _ in range(2):
        result = runner.invoke(
            app,
            ["scan", "example.com", "--live", "--no-crtsh-cache", "--raw-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
    assert fetch_calls == ["example.com", "example.com"]  # cache never consulted


def test_scan_live_without_active_never_invokes_httpx(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(live_runner, "fetch_crtsh", lambda target: b"[]")
    monkeypatch.setattr(live_runner, "run_theharvester", _empty_theharvester)
    monkeypatch.setattr(live_runner, "run_subfinder", _empty_subfinder)
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
    monkeypatch.setattr(live_runner, "run_subfinder", _empty_subfinder)
    dnsx_envelope = (
        b'{"candidates": ["example.com"], '
        b'"resolved": [{"host": "example.com", "a": ["203.0.113.1"]}]}'
    )
    monkeypatch.setattr(live_runner, "run_dnsx", lambda candidates, **kwargs: dnsx_envelope)
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
    monkeypatch.setattr(live_runner, "run_subfinder", _empty_subfinder)
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
    def _unavailable(target: str, **kwargs: object) -> bytes:
        raise live_runner.ToolUnavailable("theHarvester")

    monkeypatch.setattr(live_runner, "fetch_crtsh", lambda target: b"[]")
    monkeypatch.setattr(live_runner, "run_theharvester", _unavailable)
    monkeypatch.setattr(live_runner, "run_subfinder", _empty_subfinder)
    monkeypatch.setattr(live_runner, "run_dnsx", _empty_dnsx_envelope)

    result = runner.invoke(app, ["scan", "example.com", "--live", "--raw-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "theHarvester: live invocation failed" in result.output
    assert "# Glean Brief" in result.output


# --- eval (ADR-0006/0007, roadmap E4) -----------------------------------


def _write_ground_truth(path: Path, target: str, entity_ids: list[str]) -> None:
    entries = "\n".join(f'  - entity_id: "{eid}"\n    justification: "test"' for eid in entity_ids)
    path.write_text(
        f'target: "{target}"\n'
        'annotator: "Test Annotator"\n'
        'annotated_at: "2026-01-01T00:00:00Z"\n'
        "blind: true\n"
        "corroboration_sources: []\n"
        f"entries:\n{entries}\n"
    )


def _build_scans_dir(tmp_path: Path) -> Path:
    scans_dir = tmp_path / "scans"
    raw_dir = scans_dir / "example-com" / "raw"
    raw_dir.mkdir(parents=True)
    (raw_dir / "crtsh-example-com.json").write_bytes(
        (FIXTURES / "crtsh-example-com.json").read_bytes()
    )
    (raw_dir / "theharvester-example-com.json").write_bytes(
        (FIXTURES / "theharvester-example-com.json").read_bytes()
    )
    _write_ground_truth(
        scans_dir / "example-com" / "ground_truth.yaml",
        "example.com",
        ["domain:example.com", "subdomain:admin.example.com"],
    )
    return scans_dir


def test_eval_reports_headline_numbers_for_a_target(tmp_path: Path) -> None:
    scans_dir = _build_scans_dir(tmp_path)
    result = runner.invoke(app, ["eval", "--scans-dir", str(scans_dir)])
    assert result.exit_code == 0
    assert "example.com" in result.output
    assert "faithfulness" in result.output
    assert "mean faithfulness=1.000" in result.output
    assert "mean provenance_retention=1.000" in result.output


def _entity_ids_in_prompt(prompt: str) -> list[str]:
    return re.findall(r'"entity_id":\s*"([^"]+)"', prompt)


def test_eval_llm_reports_stage2_faithfulness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--llm wires both narration (synthesis.call_ollama) and stage-2
    judging (evaluation.call_ollama) -- both are the same underlying
    function, imported into two different module namespaces, so both
    need patching independently for a full CLI-level test."""
    scans_dir = _build_scans_dir(tmp_path)

    def fake_narrate(
        prompt: str, *, model: str = "", timeout: float = 0, urlopen: object = None
    ) -> str:
        findings = [
            {"entity_id": eid, "body": "Narrated body.", "why_ranked": "Narrated reason."}
            for eid in _entity_ids_in_prompt(prompt)
        ]
        return json.dumps({"findings": findings})

    def fake_judge(
        prompt: str, *, model: str = "", timeout: float = 0, urlopen: object = None
    ) -> str:
        findings = [
            {"entity_id": eid, "claims": [{"claim": "Narrated body.", "supported": True}]}
            for eid in _entity_ids_in_prompt(prompt)
        ]
        return json.dumps({"findings": findings})

    monkeypatch.setattr(synthesis, "call_ollama", fake_narrate)
    monkeypatch.setattr(evaluation, "call_ollama", fake_judge)

    result = runner.invoke(app, ["eval", "--scans-dir", str(scans_dir), "--llm"])
    assert result.exit_code == 0
    assert "stage2_faith" in result.output
    assert "mean stage2_faithfulness=1.000" in result.output
    assert "unjudged=0" in result.output


def test_eval_requires_a_directory_with_ground_truth_files(tmp_path: Path) -> None:
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    result = runner.invoke(app, ["eval", "--scans-dir", str(empty_dir)])
    assert result.exit_code == 1
    assert "No targets with ground_truth.yaml found" in result.output


def test_eval_skips_a_target_missing_the_blind_attestation(tmp_path: Path) -> None:
    """ADR-0007 D6: a ground-truth file without `blind: true` must not be
    silently trusted -- and one bad target must not abort the report."""
    scans_dir = _build_scans_dir(tmp_path)
    broken_dir = scans_dir / "broken"
    broken_dir.mkdir()
    (broken_dir / "ground_truth.yaml").write_text(
        'target: "broken.example"\n'
        'annotator: "Test"\n'
        'annotated_at: "2026-01-01T00:00:00Z"\n'
        "blind: false\n"
        "corroboration_sources: []\n"
        "entries: []\n"
    )

    result = runner.invoke(app, ["eval", "--scans-dir", str(scans_dir)])
    assert result.exit_code == 0
    assert "broken: evaluation failed" in result.output
    assert "example.com" in result.output
