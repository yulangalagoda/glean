"""Tests for the runner (ADR-0008): live tool invocation.

Every network/subprocess call is injected (via the `urlopen`/`sleep`/`run`
keyword parameters each function already exposes for exactly this reason)
— no real network access or subprocess execution happens in this suite.
"""

from __future__ import annotations

import json
import subprocess
import urllib.error
from pathlib import Path

import pytest

from glean_osint import runner
from glean_osint.adapters.base import ParseResult
from glean_osint.schema.entities import Entity


class _FakeResponse:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._data


def _entity(entity_type: str, value: str, **attributes: object) -> Entity:
    return Entity(
        id=f"{entity_type}:{value}",
        type=entity_type,  # type: ignore[arg-type]
        value=value,
        attributes=attributes,
        provenance=(
            {
                "source_tool": "test",
                "method": "passive",
                "collected_at": "2026-01-01T00:00:00Z",
            }  # type: ignore[arg-type]
        ),
    )


# --- fetch_crtsh ------------------------------------------------------


def test_fetch_crtsh_returns_bytes_on_success() -> None:
    calls = []

    def fake_urlopen(url: str, timeout: float) -> _FakeResponse:
        calls.append(url)
        return _FakeResponse(b'[{"id": 1}]')

    result = runner.fetch_crtsh("example.com", urlopen=fake_urlopen, sleep=lambda _: None)
    assert result == b'[{"id": 1}]'
    assert len(calls) == 1
    assert "example.com" in calls[0]


def test_fetch_crtsh_retries_on_retryable_http_status_then_succeeds() -> None:
    attempts = {"n": 0}

    def fake_urlopen(url: str, timeout: float) -> _FakeResponse:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise urllib.error.HTTPError(url, 502, "Bad Gateway", {}, None)  # type: ignore[arg-type]
        return _FakeResponse(b"[]")

    sleeps: list[float] = []
    result = runner.fetch_crtsh(
        "example.com", urlopen=fake_urlopen, sleep=sleeps.append, base_delay=1.0
    )
    assert result == b"[]"
    assert attempts["n"] == 3
    assert sleeps == [1.0, 2.0]


def test_fetch_crtsh_retries_on_404_specifically() -> None:
    """404 is deliberately retryable — crt.sh returns 200+[] for a genuine
    zero-result query, never a 404, so a 404 is backend flakiness."""
    attempts = {"n": 0}

    def fake_urlopen(url: str, timeout: float) -> _FakeResponse:
        attempts["n"] += 1
        if attempts["n"] < 2:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]
        return _FakeResponse(b"[]")

    result = runner.fetch_crtsh("example.com", urlopen=fake_urlopen, sleep=lambda _: None)
    assert result == b"[]"
    assert attempts["n"] == 2


def test_fetch_crtsh_does_not_retry_non_retryable_status() -> None:
    attempts = {"n": 0}

    def fake_urlopen(url: str, timeout: float) -> _FakeResponse:
        attempts["n"] += 1
        raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)  # type: ignore[arg-type]

    with pytest.raises(urllib.error.HTTPError):
        runner.fetch_crtsh("example.com", urlopen=fake_urlopen, sleep=lambda _: None)
    assert attempts["n"] == 1


def test_fetch_crtsh_retries_on_read_timeout() -> None:
    """Regression: a timeout mid-*read* raises a bare TimeoutError/
    socket.timeout, not urllib.error.URLError -- the original code's
    `except URLError` never caught it, so the retry loop was silently
    skipped entirely (found via real live validation, 2026-07-27)."""
    attempts = {"n": 0}

    def fake_urlopen(url: str, timeout: float) -> _FakeResponse:
        attempts["n"] += 1
        if attempts["n"] < 2:
            raise TimeoutError("The read operation timed out")
        return _FakeResponse(b"[]")

    result = runner.fetch_crtsh("example.com", urlopen=fake_urlopen, sleep=lambda _: None)
    assert result == b"[]"
    assert attempts["n"] == 2


def test_fetch_crtsh_raises_after_exhausting_all_attempts() -> None:
    def fake_urlopen(url: str, timeout: float) -> _FakeResponse:
        raise urllib.error.HTTPError(url, 503, "Unavailable", {}, None)  # type: ignore[arg-type]

    with pytest.raises(urllib.error.HTTPError):
        runner.fetch_crtsh(
            "example.com", urlopen=fake_urlopen, sleep=lambda _: None, max_attempts=3
        )


# --- run_theharvester ---------------------------------------------------


def test_run_theharvester_raises_tool_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "tool_available", lambda name: False)
    with pytest.raises(runner.ToolUnavailable):
        runner.run_theharvester("example.com")


def test_run_theharvester_reads_the_output_file_the_subprocess_wrote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "tool_available", lambda name: True)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert argv[0] == "theHarvester"
        assert "-f" in argv
        prefix = argv[argv.index("-f") + 1]
        Path(f"{prefix}.json").write_bytes(b'{"cmd": "...", "hosts": []}')
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    result = runner.run_theharvester("example.com", run=fake_run)
    assert result == b'{"cmd": "...", "hosts": []}'


# --- run_dnsx -------------------------------------------------------------


def test_run_dnsx_wraps_candidates_and_resolved_into_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "tool_available", lambda name: True)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert argv[0] == "dnsx"
        stdout = b'{"host": "example.com", "a": ["203.0.113.1"]}\n'
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr=b"")

    raw = runner.run_dnsx(["example.com", "www.example.com"], run=fake_run)
    envelope = json.loads(raw)
    assert envelope["candidates"] == ["example.com", "www.example.com"]
    assert envelope["resolved"] == [{"host": "example.com", "a": ["203.0.113.1"]}]


def test_run_dnsx_skips_invocation_for_empty_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "tool_available", lambda name: True)
    calls = []

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    raw = runner.run_dnsx([], run=fake_run)
    assert json.loads(raw) == {"candidates": [], "resolved": []}
    assert calls == []


def test_run_dnsx_raises_tool_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "tool_available", lambda name: False)
    with pytest.raises(runner.ToolUnavailable):
        runner.run_dnsx(["example.com"])


# --- run_httpx --------------------------------------------------------


def test_run_httpx_returns_stdout_directly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "tool_available", lambda name: True)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert argv[0] == "httpx"
        return subprocess.CompletedProcess(
            argv, 0, stdout=b'{"input": "example.com"}\n', stderr=b""
        )

    raw = runner.run_httpx(["example.com"], run=fake_run)
    assert raw == b'{"input": "example.com"}\n'


def test_run_httpx_skips_invocation_for_no_resolved_hosts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "tool_available", lambda name: True)
    calls = []

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    assert runner.run_httpx([], run=fake_run) == b""
    assert calls == []


def test_run_httpx_raises_tool_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "tool_available", lambda name: False)
    with pytest.raises(runner.ToolUnavailable):
        runner.run_httpx(["example.com"])


# --- extract_candidates / extract_resolved_hosts ---------------------


def test_extract_candidates_includes_target_and_deduped_hostnames() -> None:
    results = [
        ParseResult(entities=[_entity("subdomain", "www.example.com")]),
        ParseResult(
            entities=[
                _entity("subdomain", "www.example.com"),  # duplicate across tools
                _entity("subdomain", "*.example.com"),  # wildcard excluded
                _entity("ip_address", "203.0.113.1"),  # wrong type, excluded
            ]
        ),
    ]
    candidates = runner.extract_candidates("example.com", results)
    assert candidates == ["example.com", "www.example.com"]


def test_extract_resolved_hosts_requires_explicit_true() -> None:
    results = [
        ParseResult(
            entities=[
                _entity("domain", "example.com", dns_resolved=True),
                _entity("subdomain", "dead.example.com", dns_resolved=False),
                _entity("subdomain", "unchecked.example.com"),  # no dns_resolved key at all
            ]
        )
    ]
    assert runner.extract_resolved_hosts(results) == ["example.com"]


# --- tool_available / archive_raw --------------------------------------


def test_tool_available_true_for_a_real_binary() -> None:
    assert runner.tool_available("python3") is True


def test_tool_available_false_for_a_nonexistent_binary() -> None:
    assert runner.tool_available("definitely-not-a-real-binary-xyz") is False


def test_archive_raw_writes_file_and_returns_its_path(tmp_path: Path) -> None:
    ref = runner.archive_raw(tmp_path / "raw", "crtsh-example-com.json", b'{"a": 1}')
    assert ref == str(tmp_path / "raw" / "crtsh-example-com.json")
    assert Path(ref).read_bytes() == b'{"a": 1}'
