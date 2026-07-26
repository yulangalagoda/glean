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

### Notes
- No feature code exists yet beyond the package skeleton
  (`src/glean_osint/__init__.py`). Everything above is pre-development
  groundwork per `_private/planning/ROADMAP_Pre-Development.md`.
