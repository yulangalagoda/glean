# ADR-0008 — The Runner (Live Tool Invocation)

- **Status:** Accepted — implemented and validated against a real owned target (`larnby.com`) 2026-07-27, two real bugs found and fixed in the process (see the D3/D8 correction notes below); extended 2026-07-27 with D9 (crt.sh response caching / rate-limit failsafe) after real flakiness observed across a full 10-target re-run; extended 2026-07-28 with D1's concurrency correction (Stage 1's three tools now run in parallel, resolving open question 1) after real validation against `hazelmoor.org`
- **Date:** 2026-07-27
- **Scope:** Glean v1 — how `glean scan <domain>` invokes tools live instead of only ingesting pre-fetched files
- **Depends on:** ADR-0002 (adapter contract: `build_command`, `ParseResult`, D5 degradation, D7 raw-output archival), ADR-0001 (entity schema — candidate/resolved host lists are built from *parsed* entities, not raw bytes)
- **Feeds:** the CLI (`glean scan` becomes runnable with zero pre-fetched files — charter MVP goal #1, "no manual steps")

## Context

ADR-0002 D1 made invocation optional per adapter and explicitly deferred its design: "Does the runner (invocation, timeouts, retries) deserve its own ADR, separate from the adapter? (Likely yes as tool count grows.)" (open question 2). With all four adapters now real, that question is no longer hypothetical.

Looking at what's actually committed, the four adapters are not symmetric:

- `crtsh.build_command()` returns `None` — crt.sh is queried over HTTP, not a subprocess at all.
- `theharvester.build_command()` returns a real, immediately-runnable argv — no dependency on anything else.
- `dnsx.build_command()` returns `None` — dnsx needs a *candidate hostname list* assembled from crt.sh's and theHarvester's **parsed** entities before it can run; there is no fixed `dnsx -d target` invocation.
- `httpx.build_command()` returns `None` — httpx needs dnsx's **resolved** hosts before it can run, for the same reason.

So "the runner" is not "call `build_command()` and exec it for each tool" — it's a pipeline with a real dependency chain, discovered directly from the adapters' own contracts, not invented here.

This project's own private capture scripts (`_private/scripts/run_passive_scans.sh`, `run_dnsx_liveness.sh`, `run_httpx_probe.sh`) already implement a working version of this pipeline by hand, including crt.sh retry/backoff logic that was needed in practice (real captures this session hit genuine `502`/`429`/`404` responses). This ADR promotes that proven shape into real, tested code, rather than designing from scratch.

The charter's binding ethics section also matters directly here: "Passive and active reconnaissance clearly separated; active requires explicit opt-in." Under ingest-only operation this was unenforceable in code (the CLI never actually touched the target). Live invocation is the first point where it becomes a real, code-enforceable gate rather than a policy statement.

## Decision

### D1 — Three-stage pipeline, not a flat tool list

1. **Stage 1 (independent, run concurrently):** `crtsh` (HTTP fetch), `theharvester` (subprocess), and `subfinder` (subprocess, added ADR-0002 Validation 2026-07-27). None depends on either of the others or on any prior parse.

**Implementation correction (2026-07-28):** "run concurrently" above was the intended design from the start but was left as open question 1 (below) in the original decision, and the first cut of both `cli.py`'s `scan()` and `pipeline.py`'s `run_scan()` ran Stage 1's tools sequentially. With a third Stage 1 tool added (`subfinder`), the additive wall-clock cost of running independent, potentially slow, real-network tools one after another became concrete enough to fix rather than continue deferring. Implemented via `concurrent.futures.ThreadPoolExecutor(max_workers=3)` in both entry points — safe because these are blocking I/O calls (one HTTP fetch, two subprocesses), and `merge_graph`'s own proven order-independence (ADR-0003 D7) means the final entity graph cannot be affected by which thread finishes first; only `tools_run`'s *display* order needed a deterministic fix-up (a stable sort by a fixed canonical tool order, applied after the concurrent phase). `cli.py` batches each thread's status/warning messages into a list and prints them only after the shared terminal `Spinner` exits (the previously-established "never print from inside an active spinner" rule, extended to threads); `pipeline.py` has no such constraint and calls its `on_status`/`on_warning` callbacks live from each worker thread, since ADR-0011's SSE stream showing genuinely-concurrent events as they happen is the more honest live-progress experience. Proven with a dedicated test in both `tests/test_cli.py` and `tests/test_pipeline.py` using `threading.Barrier(3, timeout=2)` inside each of the three fake tool invocations — a real, meaningful concurrency proof: a regression back to sequential execution would deadlock and time out, not silently pass, since only one "party" would ever reach the barrier at a time under sequential execution.
2. **Stage 2 (depends on Stage 1's parsed entities):** `dnsx`, fed a candidate hostname list built from every `domain`/`subdomain` entity Stage 1 produced (plus the apex target itself), deduplicated by canonical value. Wildcard-prefixed values are excluded before feeding dnsx — the adapter already treats them as unresolvable-in-principle (ADR-0001 D4), so there's no reason to ask.
3. **Stage 3 (depends on Stage 2's parsed entities, active-only):** `httpx`, fed every host from Stage 2 where `attributes.dns_resolved is True`.

The intermediate hostname lists built between stages are a lightweight extraction over `.value`, **not** a substitute for real dedup — every stage's `ParseResult` is retained, and the full pile from all stages passes through `merge_graph` (ADR-0003) exactly once, same as ingest-only mode today.

### D2 — Invocation mechanism differs by tool, and that's fine

- **crt.sh** gets a dedicated HTTP-fetch function in the runner, not `build_command()` — an HTTP GET was never an argv, and forcing it through that method would misrepresent what it is. `CrtshAdapter.build_command()` correctly keeps returning `None`.
- **theHarvester** is executed via its adapter's own `build_command()` output — the one case where the existing per-adapter interface is sufficient as-is.
- **dnsx and httpx** are invoked via runner-constructed commands (write the candidate/resolved list to a temp file, pass via `-l`), not through `build_command()` — those two adapters' `build_command()` stays `None`. This is an honest limitation, not an oversight: the `Adapter` protocol's `build_command()` fits a tool that needs only the target string; dnsx/httpx need dynamically-generated *input data* from a prior stage, which is a fundamentally different shape. Revisit only if a fifth tool needs the same shape (see open questions).

### D3 — Retry/backoff policy: HTTP gets retries, subprocesses get a timeout

crt.sh is a shared free public resource this project has already observed real rate-limiting/flakiness against (`502`/`429`/`404` in real captures this session). It gets exponential backoff (starting at 10s, capped at 5 attempts) on retryable statuses — the exact policy already proven in `run_passive_scans.sh`, promoted here rather than reinvented.

Subprocess tools (theHarvester, dnsx, httpx) get a **wall-clock timeout** instead, no retry. A subprocess that times out is treated as a degraded tool for this scan (D5), not silently retried — subprocess retries are less predictable than an idempotent HTTP GET and risk doubling an active tool's contact with the target, which is exactly the kind of thing the charter's authorisation rules care about.

**Implementation correction (2026-07-27):** live-validating `fetch_crtsh` against a real owned target (`larnby.com`) surfaced two real bugs in the first cut. First, a response that times out mid-*read* (after the connection succeeds, while the body is still arriving) raises a bare `TimeoutError`/`socket.timeout`, not `urllib.error.URLError` — the original code's `except urllib.error.URLError` clause never caught it, so the retry loop was silently skipped entirely and the failure went straight to the CLI's outer catch-all instead. Fixed by catching `OSError` (which `URLError` itself subclasses, along with `TimeoutError`) instead of `URLError` specifically. Second, `404` was left out of the retryable-status set even though the real capture logs quoted above as evidence explicitly show `404` as one of the transient statuses a retry succeeded past — crt.sh returns `200` with an empty `[]` for a genuine zero-result query, never a `404`, so a `404` here is backend flakiness, not a real answer. Fixed by adding it to `CRTSH_RETRYABLE_STATUSES`. Both fixes are exactly the kind of thing this ADR's own validation section says to check for — this is why that check happens before considering the runner done, not after.

### D4 — Active-tool opt-in is a hard CLI gate, not a default

`httpx` — the only active-method tool — never runs unless the caller explicitly passes `--active` **in addition to** `--live` (D6). `glean scan <domain> --live` alone only ever runs the three passive tools (crt.sh, theHarvester, dnsx). This is the literal, code-enforced version of the charter's "active requires explicit opt-in" — the first point where that sentence is actually backed by something other than policy, because it's the first point where the tool can actually reach the target's own infrastructure without the user having pre-fetched the data themselves.

### D5 — Honest degradation extends to invocation, not just parsing

ADR-0002 D5 already requires a failing tool to not abort the scan. This extends the same rule to invocation: a tool that isn't installed, times out, or returns a non-retryable error is **skipped**, a warning is emitted (same `_warn_skipped`-style reporting the CLI already does for parse-time skips), and `scan.tools_run[]` records what was actually attempted versus what produced output. One tool's failure — network, missing binary, timeout — must never abort the others.

### D6 — `--live` is opt-in for now, not a silent default

`glean scan <domain>` with no flags behaves **exactly as it does today** (ingest-only, requires at least one `--crtsh`/`--theharvester`/`--dnsx`/`--httpx` file — unchanged, zero behaviour change, zero new test flakiness). Live invocation is a new, explicit `--live` flag. Per-tool file flags, when given alongside `--live`, override that specific tool's live invocation with the ingested file instead (mixed mode — e.g. live crt.sh + a saved theHarvester run, useful for reproducing or debugging one tool without re-touching the target).

This is deliberately conservative: the charter's MVP goal #1 ("no manual steps") isn't fully closed until `--live` is trustworthy enough to become the default, but flipping that default is a separate decision from building the mechanism, made once this has real running experience behind it (see open questions).

### D7 — Raw output archival (ADR-0002 D7, made concrete for live runs)

Every fetched/subprocess-produced raw byte stream is written to disk **before** parsing, under `./glean-output/<slug>-<timestamp>/raw/<tool>-<slug>.<ext>` by default, overridable via `--raw-dir`. This is deliberately a fresh location, not `eval/scans/` — that directory is specifically the private ground-truth set (ADR-0007), not general end-user scan output. `ToolRun.raw_output_ref` in the scan metadata points here, same field that's already populated for ingest-only mode today.

### D8 — Tool-availability preflight

Before attempting invocation, the runner checks each subprocess tool (`theHarvester`, `dnsx`, and `httpx` if `--active`) is on `PATH`. Missing tools are reported once, upfront, in plain language — not as a raw "file not found" exception surfacing per-subprocess — and then skipped per D5.

**Implementation correction (2026-07-27):** live-validating `--live --active` against a real owned target (`larnby.com`) surfaced a real bug this preflight check didn't catch: this machine also has the unrelated Python `httpx` HTTP-client library's CLI installed at `/usr/bin/httpx` — a genuinely common real-world collision, since `pip install httpx` for that popular async client is everywhere. `tool_available("httpx")` correctly found *something* named `httpx` on `PATH` and passed the preflight check, but it was the wrong program; it errored on ProjectDiscovery httpx's flags and silently returned empty output rather than raising, so the scan "succeeded" with zero service/web_tech findings and no warning at all — the one failure mode D5's degrade-and-warn design doesn't catch, because from the runner's point of view nothing failed. Fixed by adding a `--httpx-bin` CLI option (default `httpx`, overridable) so a user with this exact collision can point at the right binary explicitly, rather than the runner trying to guess. Not generalised to every subprocess tool speculatively — this is the one case with confirmed, real-world collision risk.

### D9 — crt.sh response caching, doubling as a rate-limit failsafe

**Added 2026-07-27**, after real evidence: re-running `glean scan --live --active` against all 10 owned/authorised eval targets back-to-back hit real crt.sh `502 Bad Gateway`/`404 Not Found` responses on 3 of 10 targets, each exhausting all 5 retry attempts (D3) before degrading. All 3 failures landed in the second half of a ~15-minute run that queried crt.sh 10 times in quick succession — this looks like crt.sh's own rate-limiting under repeated querying (not confirmed against crt.sh's own status page, but the timing is suggestive), not independent bad luck. This is also exactly the situation iterative development/testing produces: the same target scanned repeatedly in a short window.

Decision: cache crt.sh's raw JSON response on disk, keyed by `normalise.canon_host(target)`, under `~/.cache/glean/crtsh/` (respecting `$XDG_CACHE_HOME`). Two files per target: `<key>.json` (the raw bytes, byte-identical to what `--crtsh <file>` ingestion already expects — no new parsing path) and `<key>.meta.json` (just `{"fetched_at": <unix time>}`).

Two distinct behaviours, both addressing real problems:
1. **Read-reuse within a TTL** (default 3600s / 1h): a fresh-enough cache entry is served directly, skipping the network call entirely — this is what actually reduces load on crt.sh during repeated scans, the direct cause of the observed rate-limiting.
2. **Stale-cache failsafe**: if the live fetch fails after exhausting all retries (D3) *and* a cache entry exists at all — even one past its TTL — it's served anyway rather than losing the source entirely for this scan. This is deliberately a last resort, not silent: `fetch_crtsh_cached` never prints from inside itself (the D5/spinner-race lesson from earlier this session applies here too — see the CHANGELOG's spinner-race fix), it appends a plain-language status string to an `info: list[str]` the caller reports *after* the spinner exits, same pattern already used for warnings. Cache hits and stale-failsafe use are always visible to the operator, never silently substituted.

Honesty constraint (ADR-0001/ADR-0002's "positive confirmation, never absence-as-evidence" discipline, applied here too): a cached response is not a fabrication — the data really was fetched from crt.sh at some point — but the operator must always be told when they're looking at cached-not-fresh data and roughly how old it is, whether the source was a normal cache hit or a stale-failsafe.

Scoped to crt.sh only, deliberately not generalised to dnsx/httpx: crt.sh is a passive, read-only, third-party certificate-transparency mirror where "the same query returns nearly the same answer within an hour" is a reasonable assumption. dnsx (live DNS resolution) and httpx (active probing) are checking the *current* state of the target itself — caching either would mean silently reporting stale liveness/service data, which defeats the entire point of running them live and risks exactly the kind of stale-data-presented-as-current problem D5/D8's design has been careful to avoid elsewhere. This mirrors D3's existing reasoning for why only crt.sh gets retry/backoff: it's the one tool this project has actually observed real flakiness against.

`--no-crtsh-cache` bypasses the entire mechanism (no read, no write, no stale-failsafe) — exact pre-D9 behaviour, for when an operator wants a guaranteed fresh-or-nothing answer (e.g. reproducing a bug, or verifying a fix just went live at crt.sh's end). `--crtsh-cache-ttl SECONDS` overrides the 1h default; `0` disables read-reuse specifically while leaving the stale-cache failsafe active.

**Implementation correction (2026-07-27):** `fetch_crtsh_cached`'s first cut gave `cache_dir`/`fetch` ordinary bound default-argument values (`cache_dir: Path = DEFAULT_CRTSH_CACHE_DIR`, `fetch: Callable = fetch_crtsh`). Python evaluates default arguments once, at `def`-time — so those defaults were bound to the real cache path and the real `fetch_crtsh` function object the moment `runner.py` was imported, before any test ever ran. The existing `--live` test suite monkeypatches `runner.fetch_crtsh` (the same pattern already proven for `run_theharvester`/`run_dnsx`/`run_httpx`), but that only redirects the *module attribute* — it can't retroactively change a value already captured into a function's defaults. The result: every `--live` CLI test silently made a real network call to crt.sh for `example.com` and wrote real cache files to the operator's actual `~/.cache/glean/crtsh/`, despite this test file's own docstring promising "no real network access... happens in this suite." Caught by noticing the directory existed on disk after a routine `pytest` run, not by a failing assertion — the tests "passed" the whole time because `_LIVE_INVOCATION_ERRORS`-style graceful degradation quietly absorbed whatever the real network call did. Fixed by giving both parameters `None` sentinels and resolving them to the bare module-global name *inside* the function body instead — Python resolves a bare name via the function's `__globals__` (the same dict `monkeypatch.setattr(runner, ...)` mutates) fresh on every call, so this now correctly picks up monkeypatched values. Added a suite-wide `autouse` fixture in `tests/test_cli.py` (`_isolate_crtsh_cache`) redirecting `DEFAULT_CRTSH_CACHE_DIR` to a per-test `tmp_path` as well, so a cache-*write* during a test can never reach the real cache directory even when a future test's fetch mock legitimately succeeds. General lesson, not crt.sh-specific: a bound default that closes over a module-level function/constant is exactly the shape that silently defeats `monkeypatch.setattr` on that same module — worth checking for elsewhere if this pattern is used again.

Considered and deferred: swapping crt.sh for an alternative CT-log API as a hedge against this exact flakiness. Not pursued — crt.sh is free, well-known, and the actual failure mode observed (rate-limiting under repeated querying) is directly addressed by caching without taking on a second HTTP dependency and its own adapter/parsing work for uncertain benefit.

## Consequences

- **Positive:** real "no manual steps" invocation becomes possible for the first time; the passive/active split moves from a policy sentence to an enforced code path; the crt.sh retry/backoff logic already proven by hand in `_private/scripts/` gets promoted into tested, real code instead of living only in an ad hoc shell script; raw output is archived for every live run the same way it already is for ingest-only mode.
- **Costs / accepted limits:** dnsx/httpx's dynamically-generated-input invocation is hand-written in the runner rather than flowing through the uniform `Adapter.build_command()` interface — an accepted asymmetry, not a gap to paper over. A full active scan is inherently slower than a passive-only one, since Stage 3 cannot start before Stage 2 finishes. Only crt.sh gets explicit retry/backoff in v1 — theHarvester/dnsx/httpx rely on their own tool-level behaviour plus the runner's timeout, since this project has only observed real flakiness on crt.sh so far.

### D10 — Live invocation is implied when no input file is given (resolves open question 2)

`glean scan <domain>` exited 1 asking for input, so the charter's own MVP criterion 1 — "runs end-to-end from the CLI: `glean scan <domain>` → one report, no manual steps" — was not met by a literal reading of the command it names. Open question 2 deferred this until `--live` had real running experience; it now has a great deal.

Deliberately **not** "make `--live` default to true". That would mean passing `--crtsh capture.json` also invoked the other tools live, so every existing ingest workflow would silently acquire network calls its operator never asked for — a bad trade for closing a wording gap.

Instead, live is implied in exactly one case: **no per-tool input file was given at all.** That is precisely the invocation that previously did nothing, so nothing that worked before changes behaviour. Hand Glean a file and it ingests, as always; hand it nothing and it fetches, because that is the only reading of the command that does anything useful. `--offline` refuses the fallback explicitly, and `--live` with `--offline` is rejected as contradictory.

The passive/active split is untouched. Only passive tools are reachable this way — `httpx` still requires `--active` (D4), so no default path touches the target directly. That boundary is the charter's ethical spine and is not something a convenience default gets to erode; a test asserts httpx is never invoked on this path.

The implied fallback announces itself on stderr, naming the tools it is about to run. A command that reaches the network should say so rather than leaving the operator to infer it from a delay.

## Open questions

1. ~~Should Stage 1's tools (crt.sh, theHarvester, subfinder) run concurrently (threads) given they're independent and theHarvester/subfinder in particular can be slow, or is sequential simpler to reason about and debug for v1?~~ **Resolved 2026-07-28:** yes, concurrent — see D1's Implementation correction above.
2. ~~Should `--live` eventually become the default (closing MVP goal #1 fully), with something like `--offline` as the explicit opt-out?~~ **Resolved 2026-08-04 — see D10.**
3. Retry/backoff parameters (max attempts, base delay) are hardcoded constants in v1. Promote to a config file (like `config/priority-signals.v1.yaml`) only if a real need for tuning them shows up — avoid premature configurability.
4. A `--dry-run` that prints what *would* be invoked (including whether the active-tool gate is open) without touching the network — useful for auditability before a live active scan, but not built here unless requested.
5. ~~If a fifth tool ever needs dnsx/httpx's "dynamically-generated input" shape, does `build_command()` gain a second, richer signature, or does the runner keep hand-special-casing each one?~~ **Resolved 2026-08-04:** the fifth tool arrived (subfinder) and needed neither — a plain `build_command()` returning `subfinder -d <target> -json -silent` was sufficient, exactly like theHarvester. The dnsx/httpx shape remains the exception rather than an emerging pattern, so the protocol stays as-is.

## Validation

Once implemented, validated the same way every other stage in this project was: real invocation against the owned eval targets, starting passive-only (`--live` without `--active`) against a low-risk target (e.g. `larnby.com`), confirming raw output is actually archived under `./glean-output/`, that a forced crt.sh failure genuinely retries with backoff, and that omitting `--active` genuinely leaves `httpx` un-invoked. A full active run (`--live --active`) is validated last, only against an owned target, after the passive path is confirmed solid.
