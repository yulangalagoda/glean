# ADR-0008 — The Runner (Live Tool Invocation)

- **Status:** Proposed — not yet implemented
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

1. **Stage 1 (independent, run concurrently):** `crtsh` (HTTP fetch) and `theharvester` (subprocess). Neither depends on the other or on any prior parse.
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

## Consequences

- **Positive:** real "no manual steps" invocation becomes possible for the first time; the passive/active split moves from a policy sentence to an enforced code path; the crt.sh retry/backoff logic already proven by hand in `_private/scripts/` gets promoted into tested, real code instead of living only in an ad hoc shell script; raw output is archived for every live run the same way it already is for ingest-only mode.
- **Costs / accepted limits:** dnsx/httpx's dynamically-generated-input invocation is hand-written in the runner rather than flowing through the uniform `Adapter.build_command()` interface — an accepted asymmetry, not a gap to paper over. A full active scan is inherently slower than a passive-only one, since Stage 3 cannot start before Stage 2 finishes. Only crt.sh gets explicit retry/backoff in v1 — theHarvester/dnsx/httpx rely on their own tool-level behaviour plus the runner's timeout, since this project has only observed real flakiness on crt.sh so far.

## Open questions

1. Should Stage 1's two tools (crt.sh, theHarvester) run concurrently (threads) given they're independent and theHarvester in particular can be slow, or is sequential simpler to reason about and debug for v1? (Leaning concurrent, but sequential is an acceptable simpler first cut.)
2. Should `--live` eventually become the default (closing MVP goal #1 fully), with something like `--offline` as the explicit opt-out? Deliberately not decided here — revisit once `--live` has real running experience behind it.
3. Retry/backoff parameters (max attempts, base delay) are hardcoded constants in v1. Promote to a config file (like `config/priority-signals.v1.yaml`) only if a real need for tuning them shows up — avoid premature configurability.
4. A `--dry-run` that prints what *would* be invoked (including whether the active-tool gate is open) without touching the network — useful for auditability before a live active scan, but not built here unless requested.
5. If a fifth tool ever needs dnsx/httpx's "dynamically-generated input" shape, does `build_command()` gain a second, richer signature, or does the runner keep hand-special-casing each one? Deferred until it's a real second case, not a hypothetical one.

## Validation

Once implemented, validated the same way every other stage in this project was: real invocation against the owned eval targets, starting passive-only (`--live` without `--active`) against a low-risk target (e.g. `larnby.com`), confirming raw output is actually archived under `./glean-output/`, that a forced crt.sh failure genuinely retries with backoff, and that omitting `--active` genuinely leaves `httpx` un-invoked. A full active run (`--live --active`) is validated last, only against an owned target, after the passive path is confirmed solid.
