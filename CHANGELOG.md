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

### Notes
- Development has started (`crtsh`, `theharvester`, `dnsx`, `httpx` adapters, dedup,
  scoring, brief, evaluation, CLI, LLM synthesis). All nine ADRs now have
  real code, including both faithfulness stages. Eval target list gate
  met: 10/10, all with real ground-truth annotations (ADR-0007 F2 fully
  met), and `glean eval` (roadmap E4) reproduces all three headline
  numbers from a clean checkout on demand, optionally through real LLM
  narration and judging (`--llm`)
  (`_private/planning/ROADMAP_Pre-Development.md` Workstream D1/D2/D3/E4/F2).
