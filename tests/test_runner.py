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


def _pd_version_reply(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
    """A fake `<binary> -version` reply matching a real ProjectDiscovery
    tool's banner — used to satisfy `_verify_projectdiscovery_binary`
    (ADR-0008) in tests that exercise the real dnsx/httpx invocation path."""
    return subprocess.CompletedProcess(argv, 0, stdout=b"projectdiscovery.io\n", stderr=b"")


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


# --- fetch_crtsh_cached (ADR-0008 D9) -----------------------------------


def test_fetch_crtsh_cached_calls_live_fetch_on_a_cold_cache(tmp_path: Path) -> None:
    calls = []

    def fake_fetch(target: str) -> bytes:
        calls.append(target)
        return b"[]"

    info: list[str] = []
    raw = runner.fetch_crtsh_cached(
        "example.com", cache_dir=tmp_path, fetch=fake_fetch, info=info, now=lambda: 1000.0
    )
    assert raw == b"[]"
    assert calls == ["example.com"]
    assert info == []  # a normal cold-cache live fetch is not a notable event


def test_fetch_crtsh_cached_writes_a_cache_entry_after_a_live_fetch(tmp_path: Path) -> None:
    runner.fetch_crtsh_cached(
        "example.com", cache_dir=tmp_path, fetch=lambda target: b'[{"id":1}]', now=lambda: 1000.0
    )
    assert (tmp_path / "example.com.json").read_bytes() == b'[{"id":1}]'
    meta = json.loads((tmp_path / "example.com.meta.json").read_text(encoding="utf-8"))
    assert meta["fetched_at"] == 1000.0


def test_fetch_crtsh_cached_serves_a_fresh_entry_without_calling_fetch(tmp_path: Path) -> None:
    def fail_if_called(target: str) -> bytes:
        raise AssertionError("must not re-fetch a fresh cache entry")

    runner.fetch_crtsh_cached(
        "example.com", cache_dir=tmp_path, fetch=lambda target: b'["first"]', now=lambda: 1000.0
    )

    info: list[str] = []
    raw = runner.fetch_crtsh_cached(
        "example.com",
        cache_dir=tmp_path,
        ttl=3600.0,
        fetch=fail_if_called,
        info=info,
        now=lambda: 1000.0 + 60.0,  # 1 minute later, well within the 1h ttl
    )
    assert raw == b'["first"]'
    assert info == ["crt.sh: using cached response from 1m ago."]


def test_fetch_crtsh_cached_refetches_once_the_ttl_expires(tmp_path: Path) -> None:
    calls = []

    def fake_fetch(target: str) -> bytes:
        calls.append(target)
        return b'["second"]'

    runner.fetch_crtsh_cached(
        "example.com", cache_dir=tmp_path, fetch=lambda target: b'["first"]', now=lambda: 1000.0
    )

    raw = runner.fetch_crtsh_cached(
        "example.com",
        cache_dir=tmp_path,
        ttl=3600.0,
        fetch=fake_fetch,
        now=lambda: 1000.0 + 3601.0,  # just past the 1h ttl
    )
    assert raw == b'["second"]'
    assert calls == ["example.com"]


def test_fetch_crtsh_cached_falls_back_to_a_stale_entry_when_the_live_fetch_fails(
    tmp_path: Path,
) -> None:
    """The rate-limit failsafe: a real crt.sh outage must not lose the
    source entirely if we've successfully fetched this target before."""

    def failing_fetch(target: str) -> bytes:
        raise urllib.error.HTTPError("url", 502, "Bad Gateway", {}, None)  # type: ignore[arg-type]

    runner.fetch_crtsh_cached(
        "example.com", cache_dir=tmp_path, fetch=lambda target: b'["cached"]', now=lambda: 1000.0
    )

    info: list[str] = []
    raw = runner.fetch_crtsh_cached(
        "example.com",
        cache_dir=tmp_path,
        ttl=0.0,  # force the cache to be considered stale so the live path is tried
        fetch=failing_fetch,
        info=info,
        now=lambda: 1000.0 + 7200.0,  # 2h later
    )
    assert raw == b'["cached"]'
    assert len(info) == 1
    assert "live fetch failed" in info[0]
    assert "stale cached response from 2.0h ago" in info[0]


def test_fetch_crtsh_cached_raises_when_the_live_fetch_fails_with_no_cache_at_all(
    tmp_path: Path,
) -> None:
    def failing_fetch(target: str) -> bytes:
        raise urllib.error.HTTPError("url", 502, "Bad Gateway", {}, None)  # type: ignore[arg-type]

    with pytest.raises(urllib.error.HTTPError):
        runner.fetch_crtsh_cached("example.com", cache_dir=tmp_path, fetch=failing_fetch)


def test_fetch_crtsh_cached_ignores_a_corrupt_cache_entry(tmp_path: Path) -> None:
    (tmp_path / "example.com.json").write_bytes(b"not valid json actually doesn't matter here")
    (tmp_path / "example.com.meta.json").write_text("not valid json")

    calls = []

    def fake_fetch(target: str) -> bytes:
        calls.append(target)
        return b"[]"

    raw = runner.fetch_crtsh_cached("example.com", cache_dir=tmp_path, fetch=fake_fetch)
    assert raw == b"[]"
    assert calls == ["example.com"]


def test_fetch_crtsh_cached_uses_canon_host_as_the_cache_key(tmp_path: Path) -> None:
    """Same target, differently cased/trailing-dotted, must hit the same
    cache entry -- consistent with every adapter's own identity rule
    (ADR-0001 D3)."""
    runner.fetch_crtsh_cached(
        "Example.com.", cache_dir=tmp_path, fetch=lambda target: b'["first"]', now=lambda: 1000.0
    )

    def fail_if_called(target: str) -> bytes:
        raise AssertionError("must reuse the cache entry keyed by the canonical hostname")

    raw = runner.fetch_crtsh_cached(
        "example.com", cache_dir=tmp_path, fetch=fail_if_called, now=lambda: 1000.0 + 1.0
    )
    assert raw == b'["first"]'


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


def test_run_theharvester_uses_the_custom_binary_as_argv0(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real bug: `build_command` always hardcodes "theHarvester" as
    argv[0], so a custom --theharvester-bin used to pass tool_available's
    check but then still exec the bare name, failing with `[Errno 2] No
    such file or directory: 'theHarvester'` even with the option set."""
    monkeypatch.setattr(runner, "tool_available", lambda name: True)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert argv[0] == "/opt/theharvester/theHarvester"
        prefix = argv[argv.index("-f") + 1]
        Path(f"{prefix}.json").write_bytes(b'{"cmd": "...", "hosts": []}')
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    result = runner.run_theharvester(
        "example.com", binary="/opt/theharvester/theHarvester", run=fake_run
    )
    assert result == b'{"cmd": "...", "hosts": []}'


# --- run_subfinder ----------------------------------------------------


def test_run_subfinder_returns_stdout_directly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "tool_available", lambda name: True)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert argv == ["subfinder", "-d", "example.com", "-json", "-silent"]
        return subprocess.CompletedProcess(
            argv, 0, stdout=b'{"host":"www.example.com","input":"example.com","source":"crtsh"}\n'
        )

    result = runner.run_subfinder("example.com", run=fake_run)
    assert result == b'{"host":"www.example.com","input":"example.com","source":"crtsh"}\n'


def test_run_subfinder_returns_empty_stdout_on_zero_results_without_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Confirmed live: subfinder exits 0 with empty stdout when a target
    has no discoverable subdomains -- a legitimate outcome, not a
    failure (same reasoning as dnsx/httpx's own check=False)."""
    monkeypatch.setattr(runner, "tool_available", lambda name: True)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    assert runner.run_subfinder("larnby.com", run=fake_run) == b""


def test_run_subfinder_uses_the_custom_binary_as_argv0(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "tool_available", lambda name: True)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert argv[0] == "/opt/subfinder/subfinder"
        return subprocess.CompletedProcess(argv, 0, stdout=b"")

    runner.run_subfinder("example.com", binary="/opt/subfinder/subfinder", run=fake_run)


def test_run_subfinder_raises_tool_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "tool_available", lambda name: False)
    with pytest.raises(runner.ToolUnavailable):
        runner.run_subfinder("example.com")


# --- run_dnsx -------------------------------------------------------------


def test_run_dnsx_wraps_candidates_and_resolved_into_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "tool_available", lambda name: True)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert argv[0] == "dnsx"
        if argv[1] == "-version":
            return _pd_version_reply(argv)
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


def test_run_dnsx_raises_tool_unavailable_for_an_impostor_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A same-named but unrelated program on PATH must not be silently
    treated as ProjectDiscovery's dnsx (ADR-0008): its `-version` output
    won't carry the real tool's "projectdiscovery.io" banner."""
    monkeypatch.setattr(runner, "tool_available", lambda name: True)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 2, stdout=b"", stderr=b"unrecognized option\n")

    with pytest.raises(runner.ToolUnavailable, match="does not look like"):
        runner.run_dnsx(["example.com"], run=fake_run)


# --- run_httpx --------------------------------------------------------


def test_run_httpx_returns_stdout_directly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "tool_available", lambda name: True)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert argv[0] == "httpx"
        if argv[1] == "-version":
            return _pd_version_reply(argv)
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


def test_run_httpx_raises_tool_unavailable_for_an_impostor_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Confirmed in practice on this project's own machine: the system
    `httpx` is Python's HTTP-client CLI, not ProjectDiscovery's. It used
    to be silently invoked and produce empty output, indistinguishable
    from "ran fine, found nothing." It must now be rejected loudly."""
    monkeypatch.setattr(runner, "tool_available", lambda name: True)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            argv, 2, stdout=b"", stderr=b"Error: No such option: -version\n"
        )

    with pytest.raises(runner.ToolUnavailable, match="does not look like"):
        runner.run_httpx(["example.com"], run=fake_run)


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
