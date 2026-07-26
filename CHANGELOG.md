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

### Notes
- Development has started (`crtsh`, `theharvester`, `dnsx` adapters, dedup,
  scoring, brief, evaluation, CLI). All seven ADRs now have real code,
  except the LLM synthesis step itself (no Ollama wiring yet) and its
  dependent faithfulness stage 2 — the brief's narration is template-based
  until that exists. Remaining pre-dev gate item: the eval target list is
  at 6/10 (`_private/planning/ROADMAP_Pre-Development.md` Workstream D3).
