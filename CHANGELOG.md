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

### Fixed
- **Every non-ASCII character in the web UI was corrupted on Windows.**
  Every `read_text()`/`write_text()` call in the codebase omitted an
  encoding, so Python used the platform default -- UTF-8 on Linux (where
  all development happened, so it never showed), but the ANSI code page
  on Windows. `view_scan` therefore decoded a UTF-8 `brief.html` as
  cp1252 and re-encoded it as UTF-8, double-encoding it: the page title
  rendered as `Glean Brief â€" example.com`, and every em-dash and middot
  in every brief with it. Fixed by making the encoding explicit at all 17
  call sites in `src/` plus the reads in the test suite. Found by simply
  looking at the rendered page on Windows, not by any failing assertion --
  nothing in the suite asserts on a non-ASCII character round-tripping
  through a file.
- **Golden fixtures were being silently rewritten on checkout.** With no
  `.gitattributes` and the common Windows `core.autocrlf=true`, git
  converted every LF to CRLF on disk -- including in `tests/fixtures/`,
  whose exact bytes are the thing under test. This made
  `test_blank_lines_are_ignored_not_skipped` (which asserts a real blank
  line exists in the raw JSON-lines fixture) fail on Windows and pass on
  Linux, for no reason visible anywhere in the code. Added a
  `.gitattributes` pinning the repo to LF and marking `tests/fixtures/**`
  binary. Verified the corruption was cosmetic and had not changed any
  parsed result: the httpx adapter returns byte-identical output
  (21 entities, 15 edges, 5 skipped) from the CRLF and LF forms.
- **The Delete button on `/history` was styled as the primary action.**
  `button[type="submit"]` (specificity 0,1,1) out-specifies `.delete-btn`
  (0,1,0), so Delete -- itself a submit button -- silently inherited the
  solid, high-contrast primary treatment meant for "Run scan". The most
  destructive, irreversible control on the page was rendering as the most
  prominent one. Fixed by scoping that rule with `:not(.delete-btn)`.
- **The history row layout disagreed with itself.** `flex-wrap: wrap`
  plus `margin-left: auto` meant that once a row's content exceeded one
  line the Delete form wrapped and pushed itself hard right -- except on
  rows that also had a warning pill, where a sibling rule cancelled the
  auto margin and pushed it hard *left*. Two adjacent rows placed the
  same control at opposite ends. Replaced with a fixed grid plus an empty
  placeholder cell for rows without warnings; Delete's right edge now
  lands at an identical offset on every row.
- **The live-progress page reported `Scan failed: undefined` on any
  network blip.** A server-sent `event: error` is a `MessageEvent` with a
  real message in `.data`, but `EventSource` *also* fires its own plain
  `Event` named `error` on any transport hiccup -- and that one carries no
  `.data` at all. The single handler treated both alike, printing
  `undefined` and closing a stream whose scan was still running fine. Now
  distinguishes the two, and on a transient drop says "Reconnecting…" and
  waits for the browser's own retry instead of tearing down.

### Added
- Interactive-brief follow-ups, all verified against real rendered pages
  rather than structural assertions alone. Every one is injected into the
  web response only, never into the saved `brief.html` -- re-verified
  after each change that the standalone file contains zero occurrences of
  the injected markup and keeps its own 860px layout (ADR-0010 D3).
  - **Signal facet** on the filter bar. `data-signals` had been emitted on
    every finding since facets were added and read by nothing; since the
    deterministic rubric is the project's whole differentiator, "show me
    everything that fired `sensitive_hostname_pattern`" is arguably the
    most useful of the three filters. Verified narrowing 23 findings to 1.
  - **Sortable, paginated "Also found" table** (25/page). The noisy tail
    recreated the exact unprioritised-pile problem Glean exists to solve,
    just lower down the page. A third click on a column clears the sort
    and restores the renderer's own priority order, which is the
    meaningful default. Filtering and pagination deliberately own separate
    classes (`.hidden` vs `.page-hidden`) so neither can overwrite the
    other's decision -- verified both in effect simultaneously, with a
    filter correctly re-paginating against the reduced set (65 of 115).
  - **Deep-linkable findings**, anchored on ADR-0001's deterministic
    entity id rather than position -- a positional `#finding-3` would
    point at a different host the moment scoring reordered anything, which
    is exactly what makes a shared link worthless. Handles `hashchange`
    as well as load, since clicking an in-page anchor never reloads.
  - **Equivalent terminal command preview** on the scan form, built live
    from form state. Surfaces a real gap between the two surfaces: the
    CLI has no `--tools` flag (`--live` runs every passive tool;
    `--crtsh`/`--subfinder`/... take a file to *ingest*, not a selection),
    so an arbitrary web selection has no exact command-line equivalent.
    Rather than print a command that would quietly do something else, the
    preview names the extra tools `--live` would also run. Quoting uses
    double quotes, not POSIX-idiomatic single quotes: this command gets
    pasted into whatever shell the operator actually uses, and
    `'it'\''s'` is a syntax error in PowerShell.
  - **Re-run a past scan** -- a history link that pre-fills the form
    rather than launching anything. Deliberately not a GET that starts a
    scan: for a tool that can trigger active reconnaissance, that would be
    one stray prefetch away from probing a target nobody authorised today.
  - **History filters** by tool, date range and has-warnings, alongside
    the existing target search. Filtering is per scan row, not per target
    group, so "scans that used httpx" matches one run without dragging in
    its siblings; a group hides only when every row inside it is filtered
    out, its heading count reflects what survived, and the collapsed
    "earlier scans" disclosure auto-opens when the surviving row is inside
    it.
  - **Remembered form defaults** (tools, authorisation) in `localStorage`.
    The target is deliberately never remembered -- silently pre-filling a
    domain is how you scan the wrong host. A server-rendered redisplay
    after a rejected submission is never overwritten with stale values.
  - **Preset state** on the scan form, recomputed from the selection
    rather than remembering the last button clicked, so hand-editing back
    to a preset's exact set correctly re-detects it instead of staying
    stuck on "modified".
  - **Network-exposure banner** (ADR-0011 D8) on every page when `--host`
    is non-loopback, plus a startup warning. An unauthenticated control
    plane that can trigger active recon must not look identical whether
    it's reachable from the network or not. Building it surfaced a latent
    bug: `Jinja2Templates` was a single module-level instance, so two apps
    in one process (exactly what the test suite constructs) would clobber
    each other's flag -- now built per `create_app()`, with isolation
    verified.
  - **Empty states.** A scan that legitimately finds nothing previously
    rendered an expandable "0 additional finding(s)" disclosure wrapping
    an empty table, which reads as a broken page rather than a real
    result.
  - **Accessibility pass:** a skip link, a `:focus-visible` ring across
    the custom controls that were losing the browser default, `aria-sort`
    on sortable headers, `aria-pressed` on the filter pills (whose only
    other state cue was background colour), `aria-current` on the active
    nav link, labelled filter groups and search landmarks, live-region
    result counts, and a `prefers-reduced-motion` guard.

### Changed
- Widened the app from a 640px column to 1100px, with the scan form kept
  narrow (680px) since a single column of short fields reads worse
  stretched. The findings table went from ~810px to 1006px usable.
  Widening the report needed care, because `render_html()` writes its own
  `body { max-width: 860px }` and the site stylesheet is deliberately
  linked *before* it so the report wins ties: the override keys off
  `body[data-scan-id]` (0,1,1), an attribute only the web wrapper ever
  adds, so the file on disk cannot match it and stays exactly as ADR-0010
  D3 requires.
- Made the report's nav bar render identically to every other page's. The
  report constrains `body` itself, so the injected header was trapped
  inside that column -- its bottom border stopped mid-page while every
  other page's spanned the window. Fixed by releasing `body` and
  constraining its children instead, leaving the header the one
  full-width child. Measured on both: identical max-width, padding and
  height, both matching the same centring calculation. Also added
  `scrollbar-gutter: stable`, since a short page and a long one otherwise
  differ by ~15px of viewport and shifted the centred nav between them.
- Distinguished passive from active tools on the scan form. The
  passive/active split is the ethical spine of the project, but both
  badges rendered in identical grey -- ticking the one tool that sends
  real packets at the target looked exactly like ticking a CT-log lookup.
  Now carried by colour *and* border *and* weight, never colour alone,
  with the whole row tinting when an active tool is selected so the
  existing warning has a visible antecedent.
- Copy-to-clipboard buttons are revealed on hover/focus instead of being
  permanently visible. They previously sat between the hostname and the
  rest of the headline (`admin.example.com [Copy] - subdomain, confirmed
  live`), breaking the sentence on every card at once. Opacity rather
  than `display: none`, so there's no reflow on hover and the control
  stays keyboard-reachable.

### Fixed
- **The correlation stage's output was being discarded on every scan.**
  `merge_graph` computed the typed edge set (`resolves_to`, `subdomain_of`,
  `hosts`, ...), `build_brief` borrowed it to phrase a handful of finding
  bodies, and it then went out of scope and was gone. `entities.json`
  preserved the *nodes* of the entity graph and silently dropped every
  *relation* between them, so the deterministic entity-linking that the
  charter names as the project's central claim -- correlation done in code,
  never by the model -- was the one stage with nothing durable to show for
  itself. Nothing downstream (export, diff, or any view) could see how
  findings connect, because by the time anything downstream ran, the
  connections no longer existed anywhere. Fixed by persisting them:
  `history.write_edges_snapshot`/`read_edges_snapshot`, written by both
  `cli.py`'s `--live` path and the web app's `execute_scan`, so a scan run
  from the terminal and one run from the browser archive the identical set
  of files into the shared history (ADR-0011 D6). `pipeline.ScanOutcome`
  gained `edges`/`entities`, since `Brief` deliberately doesn't carry them
  (it's a rendering contract, ADR-0005) and they otherwise had no way out
  of `run_scan`.

  Deliberately a separate `edges.json` rather than a new key inside
  `entities.json`: that file's flat-list shape is load-bearing for
  `diff_entities` and the JSON/CSV exports, and every scan already on disk
  is in it. A missing `edges.json` therefore reads as "relations unknown for
  this scan", never "this scan had no relations" -- `read_edges_snapshot`
  returns `None`, not `[]`, and the graph route says so in as many words.
  Conflating those would be exactly the absence-as-evidence reasoning the
  adapters refuse everywhere else.
- **Only the top N findings were addressable by anchor.** `report.js`
  assigned ids to `.card` elements alone, so every "Also found" row -- the
  large majority of any real scan -- had no anchor, and any inbound deep
  link to one scrolled nowhere and silently did nothing. Found by following
  the new relationship view's own "in brief" link for a rank-6 wildcard
  subdomain (`*.example.com`) and watching it resolve to no element at all.
  Anchors now cover table rows too, and because those rows are paginated,
  the anchor handler asks the pager to turn to the page that actually
  contains the target rather than un-hiding one row behind its back (which
  would leave "Showing 1–25 of N" lying about what is on screen).

### Added
- **Relationship view** (`glean_osint.graph`, `GET /scan/{id}/graph`) --
  the correlation stage made legible now that its output survives the scan.
  Each source entity is shown with its typed relations fanning out beneath
  it (`admin.example.com → resolves to → 203.0.113.2`), ordered by
  `priority.rank` so the ranking the deterministic rubric already computed
  is reused rather than a second, competing notion of importance being
  invented. Filterable by relation type, and filtering hides individual
  relation lines before hiding a cluster, so filtering by `resolves_to`
  shows each source with just its resolution edges rather than showing
  every source that happens to have one somewhere among many.

  Pure and separately tested (`tests/test_graph.py`), same shape as
  `diff.py`: snapshot dicts in, view model out, no I/O and no clock, so it
  works against any archived scan without a migration. Three deliberate
  behaviours, each with a test: an edge pointing at an entity absent from
  the snapshot is flagged `unresolved` rather than dropped (the two files
  disagreeing is worth seeing); a relation type not in `RELATION_LABELS` is
  shown with a humanised fallback rather than discarded, so a new adapter's
  new relation appears the day it is added; and entities with no relations
  at all are counted and reported, since a scan that is mostly unconnected
  nodes is a fact about the scan rather than a rendering problem to hide.

  The anchor slug is shared deliberately: `graph.anchor_slug` mirrors
  `report.js`'s own expression exactly, with a pointer in each direction,
  because two independent transliterations of the same entity id is
  precisely how you get links that work for `admin.example.com` and 404 for
  `*.example.com`. Verified against real seeded scans: all 12 "in brief"
  links on a five-tool scan resolve, wildcard included.

  No graph library, vendored or otherwise -- an indented list with a single
  connecting rule carries the "one source fanning out" reading without a
  canvas, and keeps ADR-0011's own no-external-requests discipline intact.

### Fixed
- **A CLI-run scan never recorded its own warnings.** `scan()` printed each
  degraded-tool message with `typer.secho` and nothing else, so its manifest
  always got `warnings: []` and its `/history` row never showed the warning
  pill -- while the identical failure through the web form did. Since Stage 3
  put both surfaces in one shared history (ADR-0011 D6), two rows of the same
  list meant different things depending on which produced them, and a
  genuinely degraded terminal scan was indistinguishable from a clean one.
  Previously recorded here as an accepted limitation; now fixed. Warnings are
  collected as well as printed, covering all four paths (Stage 1's threaded
  messages, dnsx, httpx, and per-tool malformed-record counts).

  The collection deliberately filters on colour: only `YELLOW` messages are
  recorded. crt.sh cache-hit and stale-failsafe notices travel the same
  channel in cyan and must not count as warnings -- conflating exactly those
  two is what once made `/history` claim "1 warning" on healthy scans.

### Added
- **Surface breakdown in the scan manifest** (`ScanManifest.surface`), shown
  on `/history` beneath each scan's finding count. "531 findings" alone says
  nothing about what was found -- 531 certificates and 531 exposed services
  are wildly different scans. The count is computed by `brief.surface_counts`,
  extracted from what was previously private to `_surface_line`, so the
  history page and the brief header render one computation rather than two
  that can drift; `brief.surface_label` is shared as a Jinja global for the
  same reason, so neither can word it differently ("4 IP addresses" vs
  "4 ips"). The field is defaulted and reassembled from JSON's lists back
  into tuples on read, so every manifest already on disk still loads and
  simply reports no breakdown -- covered by a test that loads a manifest
  written before the field existed.
- Re-run and Delete moved to sit together at the right of each history row,
  after the warning column rather than side-of-it. The pill's width varies
  with its own content, so any control left of it shifted horizontally
  between a warned and an unwarned row; both action controls now share one
  straight edge down the whole list, verified identical across every row.

### Added
- **LLM narration in the web interface** (ADR-0009, closing the gap where
  one of the project's headline features was reachable only from the CLI).
  `ScanRequest` gained `llm`/`model`, `run_scan` calls
  `synthesis.synthesize_brief`, and the scan form has a narration toggle
  with an optional model tag. Opt-in and off by default, for the same
  conservative reason `--live` is: narration depends on a local Ollama, and
  a scan must not start depending on one silently.

  The important part is what happens when it *doesn't* work.
  `synthesize_brief` degrades to the template brief on an unreachable
  Ollama, a malformed response, or a contract violation, and never raises
  -- correct, but completely silent. The operator ticks "narrate with a
  local LLM", gets template prose back, and has nothing to tell them the
  model was never involved. `run_scan` now distinguishes the three real
  outcomes and reports them: total fallback becomes a warning naming the
  model and asking whether Ollama is running with it pulled; partial
  fallback reports the actual ratio ("narrated 3 of 5"); and invented
  finding ids the parser discarded are reported as their own warning.
  Regression-tested for each, including that the warnings stream live
  through `on_warning` rather than only appearing in the final tuple.

  `ScanManifest.narrated_by` records the model that actually produced
  prose, shown as a badge on `/history`. `None` for a template brief *and*
  for a requested-but-failed narration -- what matters downstream is what
  the reader is looking at, not what was asked for. Attribution rather
  than decoration: for a project whose research question is small-model
  faithfulness, a narrated brief with no record of which model wrote it is
  close to useless, and the model tag is not recoverable from the rendered
  brief afterwards.

  The terminal-command preview and the real toggle are now one control
  rather than two that could disagree: ticking it both enables narration
  and adds `--llm` to the preview, with `--model` spelled out only when it
  differs from the CLI's own default.

### Fixed
- The surface breakdown added above competed with six other cells for one
  row's horizontal space, and on a row that also carried a narration badge
  it pushed the Delete button clean off the right edge (measured at -23.8px
  past the row boundary at 1280px wide). Moved to its own full-width grid
  row. Caught by measuring rather than by looking: at the viewport the
  browser pane happened to open at, the mobile breakpoint was active and
  the desktop layout was never exercised.
- Narrow-screen history rows now stack deliberately instead of by accident.
  Seven grid cells were being auto-placed into the three columns the mobile
  rule declared, producing a 0px middle column and near-200px rows; that
  breakpoint now switches to flex, giving each descriptive line the full
  width and wrapping the controls together onto one line.

### Added
- **Per-finding triage** — mark a finding `reviewed`, `flagged`, or a
  `false_positive` and have that survive a reload, turning the brief from a
  report into a workflow. Available on top-priority cards and on every
  "Also found" row (the tail is where dismissing false positives matters
  most). Keyed by ADR-0001's entity id, the same stable key the diff, the
  anchors and the relationship view already use, so a judgment made today
  still attaches to the same real-world thing after a re-scan reorders
  everything.

  Stored in its own `triage.json` per scan rather than in the manifest, a
  deliberate departure from how this was originally sketched. The manifest
  is written exactly once, at the end of a scan, and holds scan metadata;
  triage is mutable, per-entity, and rewritten on every click. Folding a
  growing map of review decisions into a frozen metadata record would mean
  rewriting scan metadata on every UI interaction, with a write race able
  to damage data the operator cannot regenerate. `write_triage` is
  therefore also the one write in this module that is atomic
  (temp file + `os.replace`) — everything alongside it is written once and
  can simply be re-run; review decisions cannot.

  `read_triage` returns `{}` rather than `None` for a missing file, the
  opposite of the entity/edge snapshots, and the asymmetry is intentional:
  the file only ever exists because someone triaged something, so absence
  really does mean "nothing triaged" rather than "unknown". It also drops
  any state outside the allowlist on read, so a hand-edited file can't
  introduce a state the UI has no rendering for.

  Both inputs are validated server-side rather than trusted: `state`
  against `TRIAGE_STATES`, and `entity_id` against the scan's own entity
  snapshot — without the second check a hand-crafted POST could grow the
  file indefinitely with ids corresponding to nothing, and every later read
  would carry them forward. An empty *or absent* `state` clears the entry;
  untriaged is the absence of a record, not a fourth state.

  Triage state is applied as `data-triage` on the finding's own element,
  which makes it a filter facet for free — "show me only what I flagged" is
  most of the point of triaging at all. Verified narrowing 23 findings to 1.
  A false positive is dimmed and struck through rather than hidden: the
  operator's judgment is recorded, not enforced, and a wrong dismissal has
  to stay findable. State is carried by colour *and* border *and*
  strikethrough, never colour alone.

  The write is optimistic with a rollback: the UI updates immediately, and
  if the server rejects it the change is reverted and the control flashes,
  rather than leaving the page claiming a decision that was never stored.
  Verified by forcing a 500 and watching the state revert.

  Current state is embedded in the served page as a JSON `<script>` block
  rather than fetched on load — the server already has it, and a second
  round trip would mean the brief visibly renders every finding as
  untriaged before correcting itself. The payload escapes `</` and `<!--`,
  since it carries operator-supplied entity ids inside a `<script>`.

  As with every other interactive addition, this exists only in the web
  response: the saved `brief.html` and `--out report.html` remain zero-JS
  and untouched (ADR-0010 D3), re-verified after the change.

- The evaluation harness now runs in CI (roadmap Workstream E3), against a
  new committed fixture target at `tests/fixtures/eval/example-com/`. The
  real ground-truth set lives in `eval/scans/`, which is gitignored because
  it names real domains — so the harness that produces this project's
  headline numbers had never once run on a push. The fixture target is
  RFC 2606 `example.com` built from the repo's own golden captures, so it
  is safe to commit and exercises all five adapters end to end.

  Placed under `tests/fixtures/` rather than `eval/scans/` deliberately:
  that directory's "everything in here is private real-domain data" rule
  should stay absolute, and a `.gitignore` negation carved into it is the
  kind of exception that later leaks a hostname nobody meant to publish.

  Its `ground_truth.yaml` is labelled a synthetic fixture and is **not** a
  research data point. The ADR-0007 `blind` attestation is about a named
  human annotator's independence; the annotator field says plainly that
  this is a build fixture rather than borrowing a person's name for it.
  The ranking was written from the merged entity graph with scoring
  deliberately not run, so the attestation holds in its actual meaning.

  What CI gates, and what it deliberately does not: `faithfulness` and
  `provenance_retention` are structural invariants (they must read 1.000
  for any input), so they are asserted hard and a drop fails the build.
  `overlap@N` / `nDCG@N` measure agreement with one annotator's ranking of
  a toy graph and are reported but never asserted — a legitimate
  improvement to the scoring rubric is allowed to move them, and a test
  forbidding that would make the rubric unimprovable.

  A drift guard compares every raw capture in the fixture target
  byte-for-byte against the golden fixture it was copied from
  (`shallow=False`, since size-and-mtime equality is exactly the check that
  would miss a same-length edit). Verified by making one: a single changed
  digit in an IP is caught.
- CI now runs the suite on **Windows as well as Linux**. Two of the six
  defects fixed on 2026-07-28 were invisible on Linux — the platform-default
  encoding corrupting non-ASCII in every rendered brief, and golden fixtures
  rewritten to CRLF on checkout — and both would have failed a Windows job
  immediately. `fail-fast: false`, so a Windows break is never masked by
  cancelling the leg that would have shown it.
- Scans can be cancelled while running (roadmap item #24), from a Cancel
  button on the watch page. Cooperative cancellation is checked between
  stages and at the head of each concurrent Stage 1 worker, so a scan stops
  at the next boundary rather than only when its current tool happens to
  finish.

  The half that actually matters is subprocess termination. A scan's
  wall-clock time is dominated by child processes — theHarvester querying
  external sources runs for minutes — and abandoning the future waiting on
  one does not stop it: the process keeps running, keeps its connections
  open, and keeps touching the target after the operator asked it to stop.
  `subprocess.run` hands back no handle to terminate, so a
  `CancellationToken` tracks the live children and terminates them (SIGTERM,
  escalating to kill after a short grace period). Registration re-checks the
  flag inside the lock, closing a real race where cancelling between spawn
  and registration would find an empty set and orphan the child.

  `ScanCancelled` is deliberately **not** in `_LIVE_INVOCATION_ERRORS`.
  Every entry there means "degrade this one tool and carry on" (ADR-0002
  D5), the exact opposite of what cancelling must do — swallowed there,
  cancelling would become a warning while the remaining stages ran on, and
  the scan would finish having ignored the operator entirely.

  A cancelled scan is **recorded, not erased**: it keeps a manifest marked
  `cancelled` and deliberately has no `brief.html`. Leaving nothing behind
  would make history claim the run never happened, which is materially
  different from "it ran and was stopped", and would leave the partial raw
  captures already on disk unaccounted for. History shows it as cancelled
  with no report link. The cancel route is POST (it kills real processes, so
  no prefetch or crawler should reach it) and idempotent: racing the scan's
  own completion is the normal case for someone who just clicked Cancel, not
  an error worth surfacing.

  Cancellation is additive — with no token every existing caller, including
  the CLI, behaves exactly as before, and the injected `run` seam the runner
  tests rely on is untouched. Tested against **real** child processes rather
  than that seam, since a stub can only ever prove a flag was read, never
  that a process died; spawned via `sys.executable` so the tests run on the
  Windows CI leg too. Live-validated end to end: a real `hazelmoor.org` scan
  was cancelled from the UI with theHarvester mid-flight, and that process
  (confirmed running by pid beforehand) was gone within two seconds, with no
  orphaned recon processes left behind.

### Fixed
- The triage route required its `state` form field, so clearing a finding's
  triage worked from a browser and returned `422` from anything that omits
  empty-valued fields — which is what the test client does, and what caught
  it. Absent and empty now mean the same thing.
- `glean eval` scored a target that parsed **nothing** as a perfect 1.000.
  Both headline metrics are ratios over the findings in a brief, so an empty
  graph makes them vacuously flawless: faithfulness 1.000 because no finding
  is unfaithful, provenance_retention 1.000 because no finding lacks a
  source. Found the hard way — the first CI run of the new eval job reported
  `mean faithfulness=1.000 mean provenance_retention=1.000` and exited 0
  against a fixture target whose raw captures had never been committed
  (a bare `raw/` rule in `.gitignore` matches at every depth, and
  `git status --short` collapses an untracked directory, hiding it). This is
  absence-as-evidence, which the project refuses everywhere else, and it
  would have silently masked a renamed or corrupted capture in the real
  ground-truth set. A target with no entities is now raised rather than
  returned, so `run_eval` degrades it to a per-target warning and exits
  non-zero when every target fails (ADR-0002 D5's discipline). The
  `.gitignore` gained a single narrow exception for the committed CI
  fixture — the "commit only sanitised fixtures, deliberately" case its own
  comment already allows — verified not to re-expose `glean-output/` or
  `eval/scans/`.

  Worth recording that the layered gate behaved correctly: the pytest leg
  caught this (8 failures) while the CLI leg did not, which is the reason
  the numeric assertions were put in a test rather than left to the command.
- `glean eval` never read subfinder. It was added as the fifth adapter
  (ADR-0002) but `_RAW_ADAPTERS` was never extended, so a
  `subfinder-<slug>.jsonl` capture in a target's `raw/` was silently
  ignored — the one adapter the evaluation could not see. No target in the
  existing ground-truth set has a subfinder capture, so this is provably
  inert for the published numbers: re-running the full private set before
  and after gives byte-identical results (mean faithfulness 1.000,
  provenance 1.000, overlap@5 0.464, nDCG@5 0.582). Correct for anything
  captured from now on, and the committed CI fixture asserts that every one
  of the five adapters actually contributes.

### Notes
- Development has started (`crtsh`, `theharvester`, `subfinder`, `dnsx`,
  `httpx` adapters, dedup, scoring, brief, evaluation, CLI, LLM synthesis,
  web interface). All eleven ADRs now have real code, including both
  faithfulness stages. Eval target list gate met: 10/10, all with real
  ground-truth annotations (ADR-0007 F2 fully met), and `glean eval`
  (roadmap E4) reproduces all three headline numbers from a clean checkout
  on demand, optionally through real LLM narration and judging (`--llm`)
  (`_private/planning/ROADMAP_Pre-Development.md` Workstream D1/D2/D3/E4/F2).
- **Cross-platform:** this project was developed entirely on Linux, and the
  first real Windows checkout surfaced two defects invisible there — every
  `read_text`/`write_text` call relying on the platform default encoding,
  and golden fixtures being silently rewritten to CRLF on checkout. Both are
  fixed and guarded (explicit `encoding="utf-8"` throughout, plus a
  `.gitattributes`), but the lesson generalises: a suite that only ever runs
  on one platform will not tell you about the other. A Windows job in CI
  would have caught both years earlier than a human did.
- **Not yet validated against a live Ollama.** The web narration path's
  plumbing, fallback reporting and manifest attribution are tested against a
  stubbed `synthesize_brief`; the model call itself is unchanged code that
  ADR-0009 already validated from the CLI. Worth one real run on a machine
  that has Ollama installed before treating it as proven end to end.
