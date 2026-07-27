"""The runner: live tool invocation (ADR-0008).

A 3-stage pipeline, not a flat list of tools — this mirrors the real
dependency chain already visible in each adapter's own `build_command`:

    Stage 1 (independent): crt.sh (HTTP) + theHarvester (subprocess)
    Stage 2 (needs Stage 1's *parsed* hostnames): dnsx
    Stage 3 (needs Stage 2's *parsed* resolved hosts, active-only): httpx

Every invocation function here returns raw bytes (or raises/degrades) —
parsing still happens through each adapter's own `parse`, same as
ingest-only mode. This module only ever touches the network/subprocesses;
it never inspects or interprets tool output itself.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path

from glean_osint.adapters.base import ParseResult
from glean_osint.normalise import canon_host

CRTSH_MAX_ATTEMPTS = 5
CRTSH_BASE_DELAY_SECONDS = 10.0
# 404 included deliberately: real captures this session observed crt.sh
# returning 404 transiently under load, not as a genuine "no records"
# result (an empty match is a 200 with `[]`, never a 404) — retrying on it
# is what let those same requests succeed on a later attempt in practice.
CRTSH_RETRYABLE_STATUSES = frozenset({404, 429, 502, 503, 504})
# A domain with heavy certificate-transparency history genuinely takes a
# while to transfer, not just to look up: a real request for yulan.me (313
# certificates) measured ~70s end to end. The original 30s meant every
# retry attempt timed out identically -- retrying never helps when the
# query itself is just slow, only a longer per-attempt timeout does.
CRTSH_TIMEOUT_SECONDS = 120.0

# Generous default: theHarvester in particular queries several external
# sources and can be slow; dnsx/httpx are usually much faster in practice.
SUBPROCESS_TIMEOUT_SECONDS = 300.0


class ToolUnavailable(Exception):
    """Raised when a subprocess tool isn't on PATH (ADR-0008 D8)."""


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _verify_projectdiscovery_binary(
    binary: str,
    tool_name: str,
    *,
    run: Callable[..., subprocess.CompletedProcess[bytes]],
) -> None:
    """Confirm `binary` is really ProjectDiscovery's `tool_name`, not an
    unrelated program that happens to share the name -- confirmed in
    practice on this project's own machine, where the system `httpx` is
    Python's HTTP-client CLI. That impostor exits non-zero on ProjectDiscovery
    flags with empty stdout, which previously looked identical to "ran fine,
    found nothing": a real, silent data-loss bug (a live scan reported zero
    services/web-tech findings with no warning at all). Every real
    ProjectDiscovery tool prints a "projectdiscovery.io" banner on
    `-version` and exits 0; anything else means the wrong binary is on
    PATH. Same "positive confirmation, never absence-as-evidence"
    discipline used throughout the adapters, applied to tool discovery
    itself.
    """
    completed = run([binary, "-version"], capture_output=True, timeout=10.0, check=False)
    combined = (completed.stdout + completed.stderr).decode("utf-8", errors="replace").lower()
    if "projectdiscovery" not in combined:
        raise ToolUnavailable(
            f"{binary!r} does not look like ProjectDiscovery's {tool_name} (no "
            "'projectdiscovery' banner in `-version` output) -- a different program with "
            f"the same name is likely earlier on PATH; pass --{tool_name}-bin with the "
            "correct path."
        )


def fetch_crtsh(
    target: str,
    *,
    urlopen: Callable[..., object] = urllib.request.urlopen,
    sleep: Callable[[float], None] = time.sleep,
    max_attempts: int = CRTSH_MAX_ATTEMPTS,
    base_delay: float = CRTSH_BASE_DELAY_SECONDS,
    timeout: float = CRTSH_TIMEOUT_SECONDS,
) -> bytes:
    """Fetch crt.sh's JSON output for `target`, with exponential backoff on
    retryable HTTP statuses (ADR-0008 D3) — the same policy already proven
    by hand in `_private/scripts/run_passive_scans.sh` against real
    rate-limiting/flakiness (`502`/`429`/`404` seen in practice).

    Raises the underlying `urllib.error`/`OSError` on total failure; the
    caller treats that as this one tool degrading (ADR-0002 D5), not a
    crash.
    """
    query = urllib.parse.quote(f"%.{target}")
    url = f"https://crt.sh/?q={query}&output=json"
    delay = base_delay

    for attempt in range(1, max_attempts + 1):
        try:
            with urlopen(url, timeout=timeout) as response:  # type: ignore[attr-defined]
                return response.read()  # type: ignore[no-any-return]
        except urllib.error.HTTPError as error:
            if error.code not in CRTSH_RETRYABLE_STATUSES or attempt == max_attempts:
                raise
        except OSError:
            # Covers urllib.error.URLError (itself an OSError subclass:
            # connection failures) and a read timing out mid-response,
            # which raises a bare TimeoutError/socket.timeout that never
            # reaches urlopen's own error handling in the first place —
            # both are exactly the kind of transient failure retrying is
            # for, confirmed by a real read-timeout hitting this path
            # during live validation.
            if attempt == max_attempts:
                raise
        sleep(delay)
        delay *= 2

    raise RuntimeError("unreachable")  # pragma: no cover — loop always returns or raises


# Cert-transparency data for a given target doesn't meaningfully change
# minute to minute -- 1h balances "avoid re-querying crt.sh for the same
# target during a short test/dev session" (the observed rate-limit trigger,
# ADR-0008 D9) against "still see a newly-issued cert reasonably soon."
DEFAULT_CRTSH_CACHE_TTL_SECONDS = 3600.0
DEFAULT_CRTSH_CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", "~/.cache")).expanduser() / (
    "glean/crtsh"
)


def _read_crtsh_cache(cache_dir: Path, key: str) -> tuple[bytes, float] | None:
    data_path, meta_path = cache_dir / f"{key}.json", cache_dir / f"{key}.meta.json"
    try:
        meta = json.loads(meta_path.read_text())
        return data_path.read_bytes(), float(meta["fetched_at"])
    except (OSError, ValueError, KeyError):
        # Missing, partially-written, or corrupt cache entry -- degrade to
        # "no cache", never crash the scan over it (ADR-0002 D5's rule
        # applied to the cache layer itself).
        return None


def _write_crtsh_cache(cache_dir: Path, key: str, raw: bytes, fetched_at: float) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / f"{key}.json").write_bytes(raw)
    (cache_dir / f"{key}.meta.json").write_text(json.dumps({"fetched_at": fetched_at}))


def _format_age(seconds: float) -> str:
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    return f"{seconds / 3600:.1f}h"


def fetch_crtsh_cached(
    target: str,
    *,
    cache_dir: Path | None = None,
    ttl: float = DEFAULT_CRTSH_CACHE_TTL_SECONDS,
    info: list[str] | None = None,
    fetch: Callable[[str], bytes] | None = None,
    now: Callable[[], float] = time.time,
) -> bytes:
    """`fetch_crtsh`, wrapped with an on-disk cache that doubles as a
    rate-limit failsafe (ADR-0008 D9).

    A cache entry fresh enough (within `ttl`) is served directly, no
    network call -- this is what actually reduces load on crt.sh across
    repeated scans of the same target, the observed trigger for real
    `502`/`404` responses in practice. If the live fetch then fails after
    exhausting its own retries (`fetch_crtsh`'s own D3 backoff) and *any*
    cache entry exists, even a stale one, it's served as a last resort
    rather than losing the source for this scan entirely.

    Never prints anything itself -- the spinner-race lesson from earlier
    this session applies here too. A human-readable status string is
    appended to `info` (if given) whenever cache data is actually used
    (fresh hit or stale failsafe), for the caller to report *after* its
    spinner has exited. A normal live fetch with no cache involvement
    appends nothing, keeping output uncluttered on the common path.

    `cache_dir`/`fetch` default to `None` and are resolved to the real
    module-level `DEFAULT_CRTSH_CACHE_DIR`/`fetch_crtsh` *inside* the
    function body, not as bound default-argument values -- a real bug
    found here: a bound default captures the function object/path that
    existed at `runner.py`'s import time, so `monkeypatch.setattr(runner,
    "fetch_crtsh", ...)` in a test silently failed to intercept it,
    making a real network call and writing to the real `~/.cache/glean/`
    during what the test suite's own docstring promises is a fully
    network-free run. Resolving inside the body performs a fresh
    module-global lookup on every call, which monkeypatching *does*
    correctly redirect.
    """
    if cache_dir is None:
        cache_dir = DEFAULT_CRTSH_CACHE_DIR
    if fetch is None:
        fetch = fetch_crtsh
    key = canon_host(target)
    cached = _read_crtsh_cache(cache_dir, key)

    if cached is not None:
        raw, fetched_at = cached
        age = now() - fetched_at
        if age <= ttl:
            if info is not None:
                info.append(f"crt.sh: using cached response from {_format_age(age)} ago.")
            return raw

    try:
        raw = fetch(target)
    except OSError as error:
        if cached is None:
            raise
        stale_raw, fetched_at = cached
        if info is not None:
            info.append(
                f"crt.sh: live fetch failed ({error}); using stale cached response from "
                f"{_format_age(now() - fetched_at)} ago instead (real-time cert data may be "
                "out of date)."
            )
        return stale_raw

    _write_crtsh_cache(cache_dir, key, raw, now())
    return raw


def run_theharvester(
    target: str,
    *,
    binary: str = "theHarvester",
    timeout: float = SUBPROCESS_TIMEOUT_SECONDS,
    run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> bytes:
    """Run theHarvester, returning its exported JSON file's bytes.

    theHarvester only writes parseable output when given `-f <prefix>`
    (ADR-0008 D2) — that flag is supplied here via `TheHarvesterOptions`,
    not hardcoded separately, so the adapter's own `build_command` stays
    the single source of truth for the tool's *flags*. `build_command`
    always hardcodes `"theHarvester"` as argv[0] though, so a custom
    `binary` (e.g. a venv-local path passed via `--theharvester-bin`)
    used to pass the `tool_available` check above but then still exec
    the bare name -- a real bug found live (`[Errno 2] No such file or
    directory: 'theHarvester'` even with the option set). argv[0] is
    substituted with the real `binary` here so the executable actually
    invoked matches the one just verified to exist.
    """
    if not tool_available(binary):
        raise ToolUnavailable(binary)

    from glean_osint.adapters.theharvester import TheHarvesterAdapter, TheHarvesterOptions

    with tempfile.TemporaryDirectory() as tmp:
        prefix = str(Path(tmp) / "out")
        argv = TheHarvesterAdapter().build_command(
            target, TheHarvesterOptions(output_prefix=prefix)
        )
        assert argv is not None
        argv = [binary, *argv[1:]]
        run(argv, capture_output=True, timeout=timeout, check=True)
        return (Path(tmp) / "out.json").read_bytes()


def run_dnsx(
    candidates: list[str],
    *,
    binary: str = "dnsx",
    timeout: float = SUBPROCESS_TIMEOUT_SECONDS,
    run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> bytes:
    """Run dnsx against `candidates`, returning the `{candidates, resolved}`
    envelope `glean_osint.adapters.dnsx` requires (ADR-0008 D1/D2).

    dnsx's own bare `-json` output only ever shows hosts that resolved —
    wrapping it with the candidate list is what turns "never checked" into
    an honestly distinguishable "checked, dead" for the adapter. This is
    the same fix applied to the private capture scripts after the
    2026-07-27 real-data validation found the bug; it's promoted here into
    real code instead of living only in a shell script.
    """
    if not tool_available(binary):
        raise ToolUnavailable(binary)
    if not candidates:
        return json.dumps({"candidates": [], "resolved": []}).encode("utf-8")
    _verify_projectdiscovery_binary(binary, "dnsx", run=run)

    with tempfile.TemporaryDirectory() as tmp:
        hostsfile = Path(tmp) / "hosts.txt"
        hostsfile.write_text("\n".join(candidates) + "\n")
        # check=False: dnsx exiting non-zero because some/all hosts didn't
        # resolve is an entirely normal outcome, not a tool failure.
        completed = run(
            [binary, "-l", str(hostsfile), "-a", "-resp", "-json", "-silent"],
            capture_output=True,
            timeout=timeout,
            check=False,
        )

    resolved: list[object] = []
    for line in completed.stdout.decode("utf-8").splitlines():
        line = line.strip()
        if line:
            resolved.append(json.loads(line))

    return json.dumps({"candidates": candidates, "resolved": resolved}).encode("utf-8")


def run_httpx(
    resolved_hosts: list[str],
    *,
    binary: str = "httpx",
    timeout: float = SUBPROCESS_TIMEOUT_SECONDS,
    run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> bytes:
    """Run httpx against `resolved_hosts` (dnsx's positively-confirmed
    resolutions), returning its JSON-lines output directly.

    Unlike dnsx, httpx's own `failed` field already reports probe failures
    honestly when run with `-probe` — no extra envelope wrapping needed.
    """
    if not tool_available(binary):
        raise ToolUnavailable(binary)
    if not resolved_hosts:
        return b""
    _verify_projectdiscovery_binary(binary, "httpx", run=run)

    with tempfile.TemporaryDirectory() as tmp:
        hostsfile = Path(tmp) / "hosts.txt"
        hostsfile.write_text("\n".join(resolved_hosts) + "\n")
        completed = run(
            [binary, "-l", str(hostsfile), "-json", "-probe", "-td", "-silent"],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    return completed.stdout


def extract_candidates(target: str, results: list[ParseResult]) -> list[str]:
    """Stage 1 -> Stage 2 (ADR-0008 D1): every `domain`/`subdomain` entity's
    canonical value from crt.sh + theHarvester's parsed output, plus the
    apex target itself. Wildcards excluded — dnsx's own adapter already
    treats a literal lookup of one as meaningless (ADR-0001 D4), so there's
    no reason to ask it to try."""
    hosts = {target}
    for result in results:
        for entity in result.entities:
            if entity.type in ("domain", "subdomain") and not entity.value.startswith("*."):
                hosts.add(entity.value)
    return sorted(hosts)


def extract_resolved_hosts(results: list[ParseResult]) -> list[str]:
    """Stage 2 -> Stage 3 (ADR-0008 D1): every host dnsx positively
    confirmed resolves (`dns_resolved is True`, never merely absent)."""
    hosts = {
        entity.value
        for result in results
        for entity in result.entities
        if entity.type in ("domain", "subdomain") and entity.attributes.get("dns_resolved") is True
    }
    return sorted(hosts)


def archive_raw(raw_dir: Path, filename: str, raw: bytes) -> str:
    """Save `raw` under `raw_dir` and return its path as a string, for
    `ToolRun.raw_output_ref` (ADR-0002 D7, ADR-0008 D7 — every live-fetched
    byte stream is archived before parsing, same as ingest-only mode)."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    path = raw_dir / filename
    path.write_bytes(raw)
    return str(path)
