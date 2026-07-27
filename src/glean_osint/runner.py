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

CRTSH_MAX_ATTEMPTS = 5
CRTSH_BASE_DELAY_SECONDS = 10.0
# 404 included deliberately: real captures this session observed crt.sh
# returning 404 transiently under load, not as a genuine "no records"
# result (an empty match is a 200 with `[]`, never a 404) — retrying on it
# is what let those same requests succeed on a later attempt in practice.
CRTSH_RETRYABLE_STATUSES = frozenset({404, 429, 502, 503, 504})
CRTSH_TIMEOUT_SECONDS = 30.0

# Generous default: theHarvester in particular queries several external
# sources and can be slow; dnsx/httpx are usually much faster in practice.
SUBPROCESS_TIMEOUT_SECONDS = 300.0


class ToolUnavailable(Exception):
    """Raised when a subprocess tool isn't on PATH (ADR-0008 D8)."""


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


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
    the single source of truth for the tool's argv.
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
