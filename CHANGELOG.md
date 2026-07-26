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

### Notes
- Development has started (first adapter, `crtsh`). Remaining pre-dev
  gate item: the eval target list is at 6/10
  (`_private/planning/ROADMAP_Pre-Development.md` Workstream D3).
