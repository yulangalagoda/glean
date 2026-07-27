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

### Notes
- Development has started (`crtsh`, `theharvester`, `dnsx`, `httpx` adapters, dedup,
  scoring, brief, evaluation, CLI, LLM synthesis). All nine ADRs now have
  real code, including both faithfulness stages. Eval target list gate
  met: 10/10, all with real ground-truth annotations (ADR-0007 F2 fully
  met), and `glean eval` (roadmap E4) reproduces all three headline
  numbers from a clean checkout on demand, optionally through real LLM
  narration and judging (`--llm`)
  (`_private/planning/ROADMAP_Pre-Development.md` Workstream D1/D2/D3/E4/F2).
