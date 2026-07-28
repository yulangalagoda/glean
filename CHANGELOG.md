# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [SemVer](https://semver.org/). `v0.1.0` is reserved for when the
MVP definition of done (`CHARTER.md` §4) is fully met — nothing before that
point is a real release, just pre-dev groundwork.

## [Unreleased]

### Added
- Project charter, ADRs 0001–0007 (entity schema, adapter contract,
  correlation/dedup, prioritisation rubric, brief contract, evaluation
  protocol, ground-truth protocol) — frozen at v0.1.0 after pilot
  validation against real targets.
- Manual pilot findings (`docs/PILOT_findings.md`) and ground-truth
  validation run against a real target.
- Passive-recon fixture capture (crt.sh, theHarvester) and DNS-liveness
  fixture capture (dnsx) across 6 owned/authorised targets.
- `SECURITY.md` and `docs/ETHICS.md` (responsible-use policy, threat
  model, data governance).
- Engineering standards: Ruff (lint + format), mypy (strict), pytest,
  pre-commit hooks, and CI (`ci.yml`) running all three on push/PR.
- Packaging guard CI job (`package-guard.yml`) asserting docs/`_private`
  never ship in the built wheel.
- First real code: the normalised entity-graph model (`glean_osint.schema`,
  ADR-0001), the shared canonicalisation helpers (`glean_osint.normalise`,
  ADR-0001 D3), the adapter contract (`glean_osint.adapters.base`,
  ADR-0002 D2), and the first adapter, `CrtshAdapter`, with a golden
  fixture test validating its output against the machine-checkable
  entity-graph schema.
- Second adapter, `TheHarvesterAdapter`, proving the contract's honest
  degradation rule (ADR-0002 D3): with no per-source attribution
  available, provenance degrades to a combined-sources label parsed from
  the tool's own invocation, never an invented specific source.
- Deterministic correlation & dedup (`glean_osint.dedup`, ADR-0003):
  exact-id merge, provenance union, attribute-conflict resolution
  (confidence, then active-over-passive, then lexicographic, with losers
  recorded under `_conflicts`), edge dedup, and the before/after
  duplicate-rate MVP gate. A shuffle test caught a real non-determinism
  bug (provenance union order depended on adapter run order); fixed by
  sorting provenance into a canonical order before returning.
- Deterministic prioritisation rubric (`glean_osint.scoring`, ADR-0004):
  additive signal scoring against the versioned, auditable weight table
  (`config/priority-signals.v1.yaml`), the `cert_orphaned`/`cert_superseded`/
  `stale_no_dns` liveness corrections, D3 score clamping, and D4's
  deterministic tie-break ranking. First runtime dependency added
  (`pyyaml`, for the config file). Includes three regression tests that
  reproduce the exact real bugs the ADR's pilot corrections describe, so
  they can't silently reappear.
- The brief contract (`glean_osint.brief`, ADR-0005): `build_brief` /
  `render_markdown` produce the fixed header/top-priorities/also-found/
  provenance-footer skeleton from a scored graph, plus `check_brief_contract`
  — a structural validator for the ADR's own checklist (ordering, provenance
  lines, faithfulness, footer counts) that doubles as the seed of ADR-0006's
  stage-1 deterministic pre-check. Since no LLM is wired in yet, narration
  (headline/body/"why ranked here") is a deterministic template, not a
  model call — swapping in a real LLM later only touches the prose, never
  the skeleton, per the ADR's own framing. `ScanMeta`/`ToolRun` added to
  the schema module to complete ADR-0001 D8's scan-metadata block. First
  full pipeline integration test (adapters → dedup → scoring → brief).
- The evaluation harness (`glean_osint.evaluation`, ADR-0006/0007): D1
  stage 1 faithfulness (structural entity-id check — stage 2's LLM-judge
  atomic-claim check is out of scope until a synthesis step exists), D3
  provenance retention, and D2 prioritisation quality (`overlap@N` Jaccard
  and a documented `nDCG@N` graded-relevance convention, since the ADR
  specifies the metric but not a relevance-grading scheme). `overlap@N` is
  validated against the exact real number from the first ADR-0006/0007
  pilot pass on `yulan.me` (0.5) — the only one of the three that's an
  unambiguous formula with no convention choice to reverse-engineer.
  `GroundTruth` is a plain in-memory structure; ADR-0007's ground-truth
  file schema is still an open question there, so no loader/format is
  invented here.
- Third adapter, `DnsxAdapter` (ADR-0002), feeding ADR-0004's `stale_no_dns`
  liveness signal. dnsx's own output only shows hosts that resolved, so a
  bare-stdout raw input can't distinguish "never checked" from "checked,
  dead" — the adapter's raw input is instead the paired
  `{"candidates": [...], "resolved": [...]}` envelope this project's own
  capture convention already produces
  (`_private/scripts/run_dnsx_liveness.sh`); a candidate absent from
  `resolved` is the only case where `dns_resolved: false` is set (positive
  confirmation, never absence-as-evidence). Wildcard-prefixed candidates
  (`*.example.com`) are excluded entirely per ADR-0001 D4, not asserted
  true or false.
- Fourth adapter, `HttpxAdapter` (ADR-0002), parsing ProjectDiscovery
  httpx's real `-json` line schema. This project's first *active*-method
  adapter — it sends real HTTP requests directly at the target, unlike
  the first three (crt.sh, theHarvester, dnsx), which are all passive.
  httpx's own `failed` field is emitted on every line, so a probe that
  found nothing is reported honestly rather than merely absent (when run
  with `-probe`); adds `service` (`exposes_service`) and `web_tech`
  (`runs_tech`) entities/edges to the graph — the first adapter to use
  either. Wiring this up surfaced a real bug: ADR-0004's D4 tie-break
  precedence table was missing `web_tech` entirely (no adapter had ever
  produced one before), crashing `score_graph` with `KeyError` the
  moment one appeared. Fixed by adding `web_tech` at the end of the
  precedence order plus a module-load-time completeness assertion so a
  future missing entity type fails at import, not deep in a sort
  comparator; documented as a dated pilot correction in the ADR itself,
  consistent with every other correction already recorded there.
- `dnsx` and `httpx` wired into the `glean scan` CLI (`--dnsx`,
  `--httpx`), alongside the already-wired `--crtsh`/`--theharvester` —
  `dnsx` had been built as an adapter in isolation but never actually
  connected to the CLI entrypoint until now.
- The `glean` CLI entrypoint (`glean_osint.cli`, roadmap Workstream E1),
  built on Typer: `glean scan <domain> --crtsh FILE --theharvester FILE`
  runs the full pipeline end to end and renders a brief to stdout or
  `--out`. Deliberately ingest-only — live invocation (fetching crt.sh,
  running theHarvester) isn't built yet; ADR-0002's own open questions
  flag "the runner" (invocation, timeouts, retries) as needing its own
  design pass, not something to improvise here. `scan` is kept as an
  explicit subcommand rather than a bare `glean <domain>` specifically so
  it doesn't collide with the `glean eval` entrypoint the roadmap already
  plans (Workstream E4) — this required an explicit no-op `@app.callback`
  since Typer silently collapses a single-command app to bare-argument
  invocation otherwise.

- `httpx` validated against real data for the first time (2026-07-27), across
  the 5 owned eval targets (`scanme.nmap.org` deliberately excluded — its
  authorisation is scoped to Nmap-style port scanning, not unambiguously
  HTTP-level probing). Result: 0 adapter bugs, 0 skipped records across 12
  real probed hosts. Recorded privately in `_private/planning/target-list.md`
  (raw output stays gitignored, per this project's existing data governance).
- Ground-truth target list reaches **10/10** (roadmap gate F2), adding 4
  new owned targets across 2 repeat profiles (B, D — a second independent
  instance of each, for statistical robustness) and 2 new profiles: E
  (real published contact info, first real-data test of theHarvester's
  email-harvesting path) and F (a non-Cloudflare hosting stack, to check
  nothing in the pipeline is accidentally tuned to one CDN's fingerprint).
  Validating `dnsx` against real data for the first time (prompted by
  this expansion) surfaced a real bug: the private capture script had
  been saving dnsx's bare native output directly, never actually
  assembling the `{candidates, resolved}` envelope `DnsxAdapter` requires
  — so `dnsx` had produced 0 entities against every real capture across
  all targets, this whole time, undetected because the capture script
  was only ever used as an intermediate host list for `httpx`, never run
  through the adapter itself. Fixed the capture script and regenerated
  data for all 10 targets; full detail in `_private/planning/target-list.md`
  and `docs/target-list-policy.md` (new Profiles E/F).
- ADR-0008 (`docs/adr/0008-runner.md`, Accepted): the runner —
  `glean_osint.runner`, live tool invocation — closing ADR-0002's own
  open question on whether the runner deserves its own ADR. Implements
  the 3-stage pipeline (crt.sh + theHarvester independent → dnsx fed
  their parsed hostnames → httpx fed dnsx's resolved hosts, matching the
  real dependency already visible in each adapter's `build_command()`),
  wired into the CLI as `glean scan <domain> --live` (`--active`
  additionally required to invoke `httpx`, the only active-method tool —
  the charter's "active requires explicit opt-in" made code-enforced for
  the first time), crt.sh retry/backoff promoted from the private capture
  scripts into real, tested code, and raw-output archival under
  `./glean-output/` for live runs. A per-tool file option still overrides
  live invocation for that tool (mixed mode). `--live` is opt-in for now,
  not a silent new default. `TheHarvesterAdapter.build_command()` gained
  a `TheHarvesterOptions` parameter (`-f <prefix>`) so it produces a
  genuinely complete, runnable command — it previously couldn't, since
  theHarvester only writes parseable output with that flag.

  Live-validating against a real owned target (`larnby.com`) found two
  real bugs before any test suite could: a response timing out mid-read
  raises a bare `TimeoutError`, not `urllib.error.URLError`, so the
  original retry loop silently never triggered for it (fixed by catching
  `OSError`, which both `URLError` and `TimeoutError` are instances of);
  and `404` needed adding to the retryable-status set, since real capture
  logs already on record show crt.sh returning it transiently under load,
  never as a genuine zero-result answer. A third real issue surfaced the
  same way: this machine also has the unrelated Python `httpx` HTTP-client
  library's CLI on `PATH`, which the tool-availability preflight couldn't
  distinguish from ProjectDiscovery's httpx — it silently ran the wrong
  program and returned empty output with no warning at all. Fixed with a
  `--httpx-bin` CLI option rather than trying to guess. All three
  documented as dated corrections in the ADR itself, and the read-timeout
  and 404 cases now have regression tests (`tests/test_runner.py`).

- Ground-truth annotations (ADR-0007) completed for all 10 targets —
  roadmap gate F2 fully met. Real `ground_truth.yaml` files at
  `eval/scans/<slug>/ground_truth.yaml`, closing ADR-0007's own open
  schema question (a plain YAML mapping directly onto
  `evaluation.GroundTruth`/`GroundTruthEntry`). Annotation packets
  (priority-stripped entity graphs, D2) were generated mechanically
  (`_private/scripts/build_annotation_packets.py`) by running the real
  adapters + dedup — never `score_graph` — against each target's actual
  captured data; every ranking judgment itself came from the named human
  annotator, never the assistant, to avoid the exact "hand-replay of
  ADR-0004's own weight table" circularity this ADR's Context section
  warns against. `yulan.me`'s already-completed 2026-07-23 ranking was
  transcribed into the same schema for consistency (not re-annotated).
  One real, recorded human/code divergence worth watching once real
  `overlap@N`/`nDCG@N` numbers are computed: a confirmed-dead-but-still-
  unexpired-certificate subdomain (`tessno.com`/`brenwick.autos`'s `v2.*`)
  was consistently ranked high by the human annotator as "an anomaly
  worth investigating" — the opposite valence from ADR-0004's own
  `stale_no_dns`/`cert_orphaned` signals, which deprioritise that exact
  pattern.

- `glean eval` (roadmap Workstream E4): a single command that runs the
  full pipeline (adapters → dedup → scoring → brief) against every target
  under `--scans-dir` with both raw captures and a `ground_truth.yaml`,
  and reports the charter's three headline numbers per target and
  averaged across the set. `evaluation.py` gained `load_ground_truth`,
  closing the loop now that ADR-0007's file schema is resolved. First
  real run, across all 10 targets: faithfulness and provenance retention
  are 1.000 everywhere (expected — the template-based brief can't
  fabricate by construction, so this isn't a meaningful pass yet); mean
  `overlap@5 = 0.464`, mean `nDCG@5 = 0.582` — real, substantial
  disagreement between the deterministic rubric and independent human
  judgment, concentrated on exactly the dead-but-still-certed `v2.*`
  subdomain pattern flagged during annotation. Full numbers in
  ADR-0006's Validation section.

- ADR-0009 (`docs/adr/0009-llm-synthesis.md`, Accepted): `glean_osint.synthesis`
  — real Ollama-based LLM narration, replacing `brief.py`'s template
  `body`/`why_ranked` text (`headline` and the rest of the skeleton stay
  template-generated — ADR-0005 already fixed that as contract, not a
  model choice). Only `top_priorities` gets narrated, not the noisy
  `also_found` tail. Invocation is a direct HTTP call to Ollama's local
  API (`format: json`, `temperature: 0`, no new dependency). `--llm
  [--model TAG]` is opt-in on both `glean scan` and `glean eval`, same
  conservative rollout as `--live` (ADR-0008 D6).

  Live-validating against a real target found a real bug on the first
  call: Ollama's `format: json` mode constrains the grammar to a
  top-level JSON *object*, so the originally-requested bare top-level
  array was never actually achievable — all 4 models tested improvised a
  different wrapping shape (one unrelated single-key wrap, two collapsed
  to a single bare finding object ignoring the rest, one guessed
  `{"findings": [...]}`). Fixed by changing the prompt to request that
  exact shape and making the parser defensively unwrap all four real
  shapes seen — regression-tested for each. After the fix:
  `llama3.2:latest`/`llama3.1:8b`/`mistral:latest` all narrate 5/5
  findings correctly; `phi3:latest` (smallest model tested) manages only
  2/5 and gracefully falls back per-finding for the rest — a real,
  legitimate small-model-faithfulness data point, not a bug.

  Also found: running `glean eval --llm` across all 10 ground-truth
  targets produced *identical* faithfulness/provenance-retention/
  prioritisation numbers to the template-only run — not a bug, but a
  real limitation worth having measured rather than assumed. Stage 1
  faithfulness only checks entity-id existence, and `synthesize_brief`
  already discards any invented id before it reaches the brief, so stage
  1 structurally cannot read anything but 1.000 regardless of whether
  the prose is template or real LLM output. The uncaught risk — a real
  entity given a false attribute in its prose — is exactly what stage 2
  (a separate LLM-judge pass, still not built) exists to catch. Full
  writeup in ADR-0009's Validation section.

- Faithfulness stage 2 (ADR-0006 D1/D4): `evaluation.faithfulness_stage2`
  — real atomic-claim entailment checking via a second, different local
  LLM judge (`llama3.1:8b` by default, vs synthesis's `llama3.2:latest`).
  Decomposition and entailment are combined into one judge call per brief
  (not two), reusing `synthesis.call_ollama` and the same `format: json`
  object-wrapping fix from ADR-0009. `glean eval --llm` now reports a
  `stage2_faith` column and mean; `glean scan --llm` is unaffected (stage
  2 is an evaluation-time check, not part of the brief itself).

  First real run, across all 10 ground-truth targets: **mean stage-2
  faithfulness = 0.725**, real variance per target (0.500-1.000), zero
  unjudged findings. Reading actual judge output by hand (`larnby.com`)
  found the judge itself makes real errors — it marked two genuinely true
  claims ("seen independently by multiple tools," where the entity's real
  `seen_by` field did list two tools) as unsupported. This is ADR-0006
  D4's own named risk ("a model judging a model has its own faithfulness
  problem") demonstrated concretely, in the less-obvious direction: the
  judge wrongly *rejecting* a true claim, not wrongly accepting a false
  one. `0.725` is therefore a lower bound on real narrator faithfulness
  for this run, not a precise measurement — recorded as a real, honest
  limitation in ADR-0006's Validation section rather than quietly
  prompt-tuned away same-day.

- Live progress feedback (`glean_osint.progress.Spinner`): `glean scan
  --live`/`--llm` and `glean eval --llm` previously printed nothing at
  all while crt.sh/theHarvester/dnsx/httpx/Ollama calls ran — on a slow
  target (`yulan.me`, ~200 candidate hostnames) this looked identical to
  a hung process. Each stage now announces what it's doing (candidate/
  host counts included where known) with an animated spinner on a real
  terminal, falling back to a single static line when output isn't a tty
  (redirected output, the test suite). A `====` separator marks where
  status output ends and the actual brief/report begins. Pure
  presentation, no business logic — verified not to affect any existing
  behaviour or test output (spinner never starts a background thread
  under non-tty/captured output).

### Fixed
- Spinner/warning race condition: a live-invocation failure (e.g.
  theHarvester unavailable) was printed from *inside* the active
  `Spinner`'s `with` block, so the spinner thread's own `\r`-driven
  redraw raced the warning text and corrupted the terminal line (a real
  target run produced a single garbled line mixing spinner text and the
  warning message). `_invoke_live`/`_resolve_input` now return the
  warning instead of printing it directly; every call site in `scan()`
  prints it only after the `with Spinner(...):` block has exited and
  cleanly cleared its own line.
- "Also found" section flooding the terminal for history-rich targets:
  `yulan.me` produced 529 findings after dedup, dumping hundreds of
  unpaginated markdown bullets. `render_markdown` gained an optional,
  display-only `also_found_limit` parameter (default: unlimited, so
  existing behaviour and tests are unchanged) and `scan` now defaults to
  showing 25 with a "...and N more not shown here." note; a new
  `--show-all` flag prints every entry, and `--out` always writes the
  complete brief regardless of `--show-all`. Both fixes re-verified live
  against `yulan.me` (`--live --active --httpx-bin`): theHarvester
  resolved once on `PATH`, output stayed clean and readable, "Also
  found" truncated to 25/529 with the note, and — with the correct
  ProjectDiscovery `httpx` binary — real IP/service/web-tech findings
  appeared (two `exposed tcp service` findings ranked #1/#2, ahead of
  every subdomain) and `--authorisation` populated the brief header,
  confirming the earlier "no IPs, blank authorisation" report was a
  wrong-`httpx`-binary and missing-flag issue, not a scoring bug — the
  entity-type tie-break (ADR-0004 D4) is working as designed.
- A follow-up plain `--live --active` run (no `--httpx-bin`/PATH
  workarounds — the user's actual shell) surfaced three more real bugs
  the flag-qualified re-verification above had masked:
  1. `crt.sh: live invocation failed (The read operation timed out)` —
     confirmed by hand (`curl` against crt.sh for `yulan.me`: 70s to
     transfer 218KB of a 313-certificate history) that the 30s
     `CRTSH_TIMEOUT_SECONDS` was simply too short for cert-heavy
     targets; every retry attempt was doomed to time out identically,
     since retrying never helps when the query itself is just slow.
     Raised to 120s.
  2. `theHarvester: live invocation failed (theHarvester)` — not a bug,
     but a real usability gap: theHarvester's binary only lives in its
     own venv (`_private/tools/theHarvester/.venv/bin/theHarvester`),
     never on a normal shell's `PATH`. Added `--theharvester-bin`
     (mirrors `--httpx-bin`) so it can be pointed at directly instead
     of requiring a permanent `PATH` edit.
  3. httpx silently produced zero service/web-tech findings with *no
     warning at all* when `--httpx-bin` was omitted and the wrong
     `httpx` resolved from `PATH` — the impostor exits non-zero on
     ProjectDiscovery's flags with empty stdout, which the runner
     previously read as an honest "ran fine, found nothing." Added
     `_verify_projectdiscovery_binary` (`runner.py`): before trusting
     dnsx/httpx output, run `<binary> -version` and require the real
     tool's `projectdiscovery.io` banner; anything else raises
     `ToolUnavailable` with the exact fix (`--httpx-bin`/`--dnsx-bin`)
     instead of degrading silently — the same "positive confirmation,
     never absence-as-evidence" discipline used throughout the
     adapters, applied to tool discovery itself. Added `--dnsx-bin` for
     symmetry/consistency, though dnsx wasn't observed to collide in
     practice. Re-verified live end to end with all three fixes and no
     manual flags beyond the three new `-bin` options: crt.sh,
     theHarvester, dnsx, and httpx (real ProjectDiscovery binary) all
     contributed findings in a single run; a deliberate omission of
     `--httpx-bin` on a follow-up run reproduced the impostor rejection
     on demand, printing the exact `--httpx-bin` fix cleanly (no
     spinner corruption) instead of silently losing data again.
- Plain `--live --active` still required 3 extra flags every run to
  work around the two collisions above (`--theharvester-bin`,
  `--httpx-bin`) — real friction reported immediately after the fixes
  above landed. Gave `--theharvester-bin`/`--dnsx-bin`/`--httpx-bin`
  matching `$GLEAN_THEHARVESTER_BIN`/`$GLEAN_DNSX_BIN`/`$GLEAN_HTTPX_BIN`
  env-var defaults (native `typer`/`click` support) so they can be set
  once in a shell profile instead of retyped every command; the flags
  still work for one-off overrides and show the env var name in
  `--help`. While wiring this up found one more real bug: theHarvester's
  own `build_command` always hardcodes `"theHarvester"` as argv[0], so a
  custom `--theharvester-bin` passed the `tool_available` PATH check but
  then still executed the bare, unqualified name — `[Errno 2] No such
  file or directory: 'theHarvester'` even with the option correctly
  set. Fixed in `run_theharvester` by substituting the verified `binary`
  back into argv[0] before invoking (the adapter's `build_command`
  stays the source of truth for flags only, not the executable path).
  Re-verified live with zero CLI flags, only the three env vars
  exported: all four tools (crt.sh, theHarvester, dnsx, real
  ProjectDiscovery httpx) contributed findings in one clean run.

### Added
- crt.sh response caching, doubling as a rate-limit failsafe (ADR-0008
  D9). Real evidence: re-running `--live --active` against all 10
  ground-truth targets back-to-back hit real crt.sh `502`/`404`
  responses on 3 of 10 targets, each exhausting all 5 retry attempts —
  timing suggests crt.sh's own rate-limiting under repeated querying in
  a short window, exactly the shape of iterative dev/testing.
  `fetch_crtsh_cached` (`runner.py`) serves a fresh-enough (default 1h)
  cached response with no network call at all, and falls back to a
  *stale* cached response as a last resort if the live fetch fails
  after exhausting its own retries and any cache entry exists — never
  silent, always reported to the operator via a plain-language message
  printed after the spinner exits (same "return, don't print inside a
  spinner" discipline as the earlier spinner-race fix). New
  `--crtsh-cache-ttl SECONDS` / `--no-crtsh-cache` flags. Deliberately
  scoped to crt.sh only — dnsx/httpx report the target's *current*
  state, and caching either would silently mask real liveness/service
  changes. Live-verified against `larnby.com`: a cache-hit second scan
  ran ~3.5x faster (15s vs 52.5s) than the cold-cache first scan, purely
  from skipping crt.sh's HTTP round trip.
- Found while wiring up the tests for the cache: a real bug where
  `fetch_crtsh_cached`'s `cache_dir`/`fetch` parameters used ordinary
  bound default arguments (evaluated once at `runner.py`'s import time),
  so `monkeypatch.setattr(runner, "fetch_crtsh", ...)` in the existing
  `--live` test suite silently failed to intercept them — every `--live`
  CLI test was making a real network call to crt.sh for `example.com`
  and writing real cache files to the operator's actual
  `~/.cache/glean/crtsh/`, despite the test file's own docstring
  promising zero real network access. Caught by noticing the directory
  existed on disk after a routine test run, not by a failing assertion.
  Fixed by resolving both parameters from `None` sentinels inside the
  function body (a fresh module-global lookup on every call, which
  monkeypatching does correctly redirect) instead of as bound defaults;
  added an `autouse` fixture in `tests/test_cli.py` redirecting the
  cache directory to a per-test `tmp_path` as defense in depth.
- HTML report view (ADR-0010), the first real GUI-roadmap slice:
  `render_html()` in `brief.py` renders the same `Brief` as
  `render_markdown`, as a single self-contained HTML file (inline CSS,
  no external requests, no JS). `scan --out report.html` writes it; any
  other extension keeps writing markdown as before — no new flag.
  "Also found" shows the *complete* list inside a collapsed
  `<details>` disclosure rather than being truncated — HTML doesn't
  have the terminal's unbounded-scrollback problem `also_found_limit`
  was built for. Light/dark via `prefers-color-scheme`, no colour-only
  signalling, no field not already present in `Finding`/`Brief`.
  Deliberately scoped to the readable-report half of the charter's "GUI"
  roadmap line only — not the separate, larger "prioritised entity
  graph" idea, and not an interactive local server (considered and
  explicitly deferred; see the ADR's Open questions). Validated against
  a real live `yulan.me` scan (528 findings, the same target whose
  terminal dump originally motivated this whole thread) and previewed
  as a published artifact for a human visual check, not just structural
  assertions.
- Interactive web interface, Stage 1 (ADR-0011): bare `glean` (no
  subcommand) now launches a local FastAPI + server-rendered HTML web
  interface at `http://127.0.0.1:8420` — a scan form (target, tool
  toggles + presets, authorisation), a synchronous run (no client-side
  framework or build step; htmx is planned for Stage 2's live progress,
  not needed yet), and a results page reusing `render_html()`
  (ADR-0010) directly. `glean scan ...`/`glean eval ...` are completely
  unaffected — this is additive.
  First runtime dependencies beyond stdlib+typer+pyyaml (FastAPI,
  uvicorn, jinja2, python-multipart) — a deliberate, named departure
  from this project's stdlib-only discipline so far, not an accident.
  New `registry.py` (a real adapter/tool registry, `tool_id`/
  `default_method`/`requires` per tool — the direct enabler of the tool
  list showing up automatically as adapters are added, and of the one
  real structural constraint, httpx requiring dnsx, being enforced
  rather than silently allowed to misbehave); `pipeline.py` (fresh
  orchestration glue reusing every existing building block --
  `runner.py`'s live invocation incl. crt.sh caching, each adapter's
  `parse`, dedup, scoring, `build_brief` -- deliberately *not* a
  refactor of the CLI's own already-tested `scan()` command);
  `history.py` (scan history at a fixed `~/.local/share/glean/scans/`,
  file-based manifests, no database). Server binds to `127.0.0.1` only,
  no auth — a local single-operator tool, and an unauthenticated
  control plane that can trigger active recon must never be reachable
  from the network by default.

  195/195 tests pass (new: registry/pipeline/web-app test files, the
  latter via FastAPI's `TestClient` fully isolated from the real
  `~/.local/share/glean/`), wheel build confirmed to actually package
  the new templates/static assets. Real-data validated: ran real scans
  against `larnby.com` through the actual HTTP form, all four tools
  contributing, results/history/raw-archive all landing correctly.

  Two real bugs found during that validation: (1) the web pipeline
  never read `$GLEAN_THEHARVESTER_BIN`/`$GLEAN_DNSX_BIN`/
  `$GLEAN_HTTPX_BIN` at all -- those env vars were only ever wired
  through the CLI's Typer options, which the web app doesn't go
  through, so a real scan through the form hit the exact same
  binary-collision failures already solved once for the CLI. Fixed by
  having `pipeline.py` read them directly. (2) A bound `from
  glean_osint.pipeline import run_scan` in `web/app.py` would have
  silently defeated test monkeypatching -- the exact class of bug
  found in `fetch_crtsh_cached` earlier this session -- caught this
  time by deliberately checking for the pattern before it caused a
  real problem, not after.

  Stage 2 (SSE live progress) and Stage 3 (history browsing UI) are
  not yet built.
- Interactive web interface, Stage 2 (ADR-0011): `POST /scan` no longer
  blocks until the whole scan finishes -- it now starts the scan as a
  background task and redirects immediately to a new `/scan/{id}/watch`
  page, which opens a Server-Sent Events connection
  (`/scan/{id}/events`) and shows real status updates ("Searching
  certificate transparency logs (crt.sh)...", etc.) as they happen,
  redirecting to the real results page once done. `pipeline.run_scan`
  gained a matching `on_warning` hook alongside the existing
  `on_status`, so degraded-tool warnings stream live too, not just in
  the final summary.

  203/203 tests pass (8 new), ruff/mypy/pre-commit all clean.
  Real-data validated with genuine concurrent timing (not just
  `TestClient`, whose background tasks run synchronously before
  `.post()` returns and so can't exercise a scan actually "still
  running"): fetched the watch page from a real server while a
  `carrowen.xyz` scan was genuinely still executing and confirmed it
  rendered live, and streamed real ordered events via `curl -N` against
  `hazelmoor.org`. The slowest real run (`carrowen.xyz`, all four
  tools) took ~75s, dominated by theHarvester -- exactly the scenario
  this exists for: previously indistinguishable from a hang, now
  visibly progressing.

  Stage 3 (history browsing UI, CLI `--raw-dir` unification) is not
  yet built.
- Interactive web interface, Stage 3 (ADR-0011) — all three stages now
  complete. `history.py` gained its read side (`list_scans`, newest
  first, a corrupt/missing manifest degrades to "not listed" rather
  than crashing); a new `GET /history` page lists every past scan with
  a link to its results; a shared `base.html` + nav bar once three
  pages needed consistent navigation. The real payoff: `cli.py`'s
  `_default_raw_dir` now points at the same fixed
  `~/.local/share/glean/scans/` location the web UI uses instead of
  `./glean-output/`, and a `--live` scan with no explicit `--raw-dir`
  writes a manifest + `brief.html` there too -- a scan run from the
  terminal and one run from the web UI now land in one shared,
  browsable history. `--raw-dir` remains fully overridable, and an
  explicit one opts out of the shared-history bookkeeping entirely,
  not just the raw-archive location. Ingest-only CLI usage (no
  `--live`) is completely unaffected -- zero new side effects, exactly
  as before.

  218/218 tests pass (13 new), ruff/mypy/pre-commit all clean.
  Real-data validated against the actual six scans already accumulated
  on disk from earlier in this session (including one the operator ran
  themselves) -- `/history` correctly listed all of them with working
  links, deliberately checked against real pre-existing state rather
  than a clean slate. Then ran a real `glean scan larnby.com --live`
  from the terminal and confirmed it appeared in the same running
  server's `/history` immediately, no restart needed -- concrete proof
  the shared-history promise holds across both surfaces.

  One accepted limitation: CLI-run manifests always have an empty
  `warnings` list (the CLI prints each warning directly rather than
  collecting them into a list the way the web pipeline does) --
  CLI-run history entries never show the warning pill, even if
  something degraded. Not chased further.

### Fixed
- `/history` showed "1 warning" on scans where nothing had actually
  gone wrong: `pipeline.run_scan` was folding crt.sh's cache-hit/
  stale-failsafe notices (ADR-0008 D9) into the same bucket used for
  real problems, a regression against the CLI's own already-correct
  convention (cache-hit notices print in cyan there, separate from
  real yellow warnings). Fixed by routing them through the existing
  `status()` callback instead -- shown live in neutral style, correctly
  absent from the manifest's `warnings` and the history warning pill.

### Changed
- Redesigned the web interface's navigation: a proper full-width
  header bar (previously the nav sat inside the same constrained
  column as page content), a "Glean" brand mark linking home, and
  active-page highlighting. Consolidated the stylesheet onto CSS
  custom properties for the palette, fixing a real cascade bug found
  in the process (`.hint`'s colour was declared twice with different
  values; the later, hardcoded one was silently winning).

  221/221 tests pass (3 new), ruff/mypy/pre-commit clean. Live-
  validated against a real cache-hit scan (confirmed `warnings: []`
  and no pill on `/history`, the message arriving live as a `status`
  event instead of `warning`) and the active-nav class landing on the
  correct link on both the form and history pages.
- Immediate follow-up: once inside a scan result, the new nav bar was
  gone. `/scan/{id}` serves the exact bytes of the saved `brief.html`,
  deliberately chrome-free by design (ADR-0010) since it's the same
  file `--out report.html` writes to disk for standalone `file://` use
  -- correct for the file, but a dead end when reached through the web
  UI instead. Fixed narrowly: the nav bar and a stylesheet `<link>` are
  now injected into `view_scan`'s HTTP response only, via two targeted
  string replacements on `render_html()`'s own output -- the saved
  file and the CLI's `--out` output stay completely unmodified. The
  stylesheet link lands *before* the report's own inline `<style>`
  block specifically to avoid a cascade conflict (both style the bare
  `body` selector; landing after would have silently stripped the
  report's own 860px-width layout). 222/222 tests pass. Live-validated:
  a real saved report served through the web UI now has the nav bar
  with correctly-ordered CSS, while the file on disk (and a fresh CLI
  `--out report.html`) has zero occurrences of the injected markup.
- Fifth tool: subfinder (passive subdomain discovery), added
  specifically to test whether the tool registry's "add a tool and it
  shows up automatically" promise (ADR-0011 D3) actually holds. It
  does: the web UI's tool list and presets picked it up with zero
  template changes. A real capture (`subfinder -d yulan.me -json
  -silent`, 203 real records) confirmed its JSON-lines shape
  (`{"host","input","source"}`) before any code was written, matching
  every other adapter's pilot-first origin (ADR-0002). New
  `SubfinderAdapter` (subdomain-only, same shape as theHarvester's
  contribution to the graph; `source` -- which of subfinder's own
  internal passive engines found a host, e.g. `"crtsh"`/`"virustotal"`
  -- kept as a real attribute, not fabricated, `source_tool` stays
  uniformly `"subfinder"`), `runner.run_subfinder`, and wiring into
  both `cli.py`'s `scan()` and `pipeline.py`'s `run_scan()` (the two
  places tools are wired per-tool by design, ADR-0008 D2). No changes
  needed to `runner.extract_candidates` (already generic over any
  `ParseResult`) or dedup/scoring.

  One real finding while wiring this up: subfinder v2.14.0's own
  `-version` output doesn't print the `projectdiscovery.io` banner
  `_verify_projectdiscovery_binary` (ADR-0008 D9) checks for, unlike
  dnsx/httpx -- confirmed live before assuming otherwise. Reusing that
  check would have incorrectly rejected the real tool, so it's
  deliberately not applied to subfinder (also no confirmed name-
  collision risk for "subfinder" the way there is for "httpx");
  `tool_available` (PATH existence) plus a new `--subfinder-bin`/
  `$GLEAN_SUBFINDER_BIN` override is the same level of checking
  theHarvester already gets.

  237/237 tests pass (15 new: a golden-fixture adapter test, runner
  invocation tests, pipeline wiring tests, CLI ingest/live tests),
  ruff/mypy/pre-commit `--all-files` all clean. Live-validated end to
  end on both surfaces: `glean scan hazelmoor.org --live` found 3 real
  subdomains (`admin`/`portal`/`vpn`) via subfinder, corroborated by
  crt.sh/dnsx; the same scan submitted through the web form showed
  identical results, with `subfinder` appearing in `tools_run` and the
  rendered report on both the CLI and `/scan/{id}`.
- Stage 1 (crt.sh, theHarvester, subfinder) now runs concurrently instead
  of sequentially, resolving ADR-0008's own long-standing open question 1.
  With a third Stage 1 tool now in place, running each one after another
  had become additive wall-clock time for no real reason -- theHarvester
  and subfinder can each individually take minutes against real targets.
  Implemented with `concurrent.futures.ThreadPoolExecutor(max_workers=3)`
  in both `cli.py`'s `scan()` and `pipeline.py`'s `run_scan()`. Safe by
  construction: `merge_graph`'s own proven order-independence (ADR-0003
  D7, "feeding the same adapter outputs in any order yields a
  byte-identical graph") means concurrency cannot affect the final entity
  graph, only `tools_run`'s cosmetic display order, fixed with a stable
  sort by canonical tool order after the concurrent phase. `cli.py`
  extends the existing "never print from inside an active spinner" rule
  to threads by collecting each worker's status/warning messages into a
  shared list and printing them only after the shared spinner exits;
  `pipeline.py` has no such constraint and streams `on_status`/
  `on_warning` live from each worker thread, since genuinely-concurrent
  SSE events are the more honest live-progress picture for ADR-0011's web
  UI. Proven (not just exercised) with a dedicated test in both
  `tests/test_cli.py` and `tests/test_pipeline.py` using
  `threading.Barrier(3, timeout=2)` inside each of the three fake tool
  invocations -- a regression back to sequential execution would deadlock
  and time out rather than silently pass.

  239/239 tests pass (2 new), ruff/mypy/pre-commit `--all-files` all
  clean. Live-validated: a real `--live` scan of `hazelmoor.org`
  (crt.sh cache-hit, theHarvester and subfinder invoked live) completed
  in 30.6s wall-clock with all three tools' raw output correctly
  archived and no regressions in the resulting brief.
- A batch of real UI feedback addressed across four phases, all
  live-validated against real scans (`hazelmoor.org`), not just tests.
  ADR-0010 D3 (the standalone brief file stays zero-JS, self-contained)
  held throughout -- every interactive element is either inert `data-*`
  markup in the shared `render_html()` output or injected only into the
  web response (`_wrap_scan_result_for_web`), the same pattern already
  established for the nav bar.

  **Brief page interactivity:** copy-to-clipboard buttons on every
  finding value (web-injected, reads the existing `<code>` markup);
  a filter/toggle bar (type, tool, signal-derived facets, active-only)
  driving both the top-priority cards and a new "Also found" *table*
  (replacing the old flat bullet list, still inside the same collapsed
  `<details>`) via `data-type`/`data-tools`/`data-methods`/
  `data-signals` attributes now carried by every finding's markup;
  score-breakdown tooltips (native `title=`, works in the standalone
  file too, zero JS) built from `scoring.WEIGHTS` -- "exposed_service
  (+2), active_only_finding (+1) = 3." instead of an opaque number;
  clickable provenance -- each "Seen by" source is now a
  `<span data-tool>` the web view turns into a link to a new
  `/scan/{id}/raw/{tool}` route serving that tool's whole archived raw
  output, pretty-printed (JSON or JSON-lines, detected not hardcoded);
  and export buttons (HTML/JSON/CSV) wired to new `/scan/{id}/download/*`
  routes. JSON/CSV export needed the underlying entity graph to survive
  past one request's lifetime, so every completed scan (both `cli.py`
  `--live` and the web app) now also writes an `entities.json` snapshot
  (`history.write_entities_snapshot`) alongside `manifest.json`/
  `brief.html` -- this snapshot is also what later powers the diff
  feature below.
- **Scan form**: an inline ethics warning appears the moment an
  active-method tool (per the registry's own `default_method`, not a
  hardcoded tool-id check) is selected -- "this sends real requests
  directly to the target." A target-format hint plus a light,
  non-blocking client-side check flags a pasted URL or path
  ("https://example.com" / "example.com/admin") without ever probing
  the target itself to validate it.
- **Live progress**: turned out most of this was already built (ADR-0011
  Stage 2's SSE stream) -- the real gap was smaller than it looked.
  Added a 3-stage checklist above the existing scrolling log
  (Passive discovery / DNS resolution / Active probing / Scoring,
  showing only the stages this scan's own tool selection will actually
  reach), driven by pattern-matching the same status text the backend
  already sends. Real live testing surfaced an actual bug in the
  existing SSE route while validating this: an early client disconnect
  (tab closed, refresh, network blip) unconditionally popped the scan
  out of `active_scans`, so a reconnect to a genuinely still-running
  scan 404'd as "not found" even though `execute_scan` was still
  working (it holds its own queue reference, so it was never actually
  affected). Fixed by only popping on a genuine terminal `done`/`error`
  event. Confirmed live: cut a real SSE connection short mid-scan,
  reconnected, got a clean `200` and the eventual `done` event instead
  of a `404`.
- **History workspace**: repeat scans of the same target now collapse
  under one heading (`history.group_scans_by_target`) instead of
  reading as unrelated rows, with all-but-the-most-recent tucked behind
  a "N earlier scans" disclosure; a client-side search box filters
  groups by target; the warning pill is now a `<details>` disclosure
  showing the actual warning text, not just a count; and each scan row
  has a delete button (`POST /scan/{id}/delete`, `history.delete_scan`)
  with a native `confirm()` guard before the irreversible removal.
- **Scan-to-scan diff** (new `glean_osint/diff.py`, `diff_entities`):
  the highest-value item from the feedback -- turns history from a log
  into a monitoring tool. Compares two scans' `entities.json` snapshots
  by entity id (ADR-0001's own deterministic id scheme, so "same id"
  really does mean "same real-world thing," not a heuristic match) into
  New / Removed / Changed, where "changed" means a different score,
  signal set, or attributes -- provenance and first/last-seen
  timestamps are deliberately excluded from that comparison, since
  those differ on every real scan by construction and would otherwise
  make every unchanged finding look "changed." `history.previous_scan_for`
  finds the scan immediately older than whichever one you're looking at
  (not always "vs. latest"), and a "Compare to previous scan" link
  appears on a scan's page whenever one exists. Live-validated with two
  real back-to-back scans of `hazelmoor.org` (crt.sh-only, then
  crt.sh+subfinder): correctly reported 0 new/0 removed and 3 changed
  -- subfinder corroborating three subdomains crt.sh had already found,
  each gaining `multi_tool_corroboration` and a real score bump
  (3.0 -> 4.0), exactly the kind of signal this feature exists to surface.

  284/284 tests pass (45 new across `test_brief.py`, `test_history.py`,
  `test_web_app.py`, and a new `test_diff.py`), ruff/mypy/
  pre-commit `--all-files` and a wheel build all clean.

### Notes
- Development has started (`crtsh`, `theharvester`, `dnsx`, `httpx` adapters, dedup,
  scoring, brief, evaluation, CLI, LLM synthesis). All nine ADRs now have
  real code, including both faithfulness stages. Eval target list gate
  met: 10/10, all with real ground-truth annotations (ADR-0007 F2 fully
  met), and `glean eval` (roadmap E4) reproduces all three headline
  numbers from a clean checkout on demand, optionally through real LLM
  narration and judging (`--llm`)
  (`_private/planning/ROADMAP_Pre-Development.md` Workstream D1/D2/D3/E4/F2).
