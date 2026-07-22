# ADR-0005 — The One-Page Brief (report contract)

- **Status:** Proposed (v0 — for review)
- **Date:** 2026-07-22
- **Scope:** Glean v1 — the human-facing output of `glean scan`
- **Depends on:** ADR-0001 (entity schema), ADR-0004 (prioritisation)
- **Worked example:** [`docs/schema/example-brief.md`](../schema/example-brief.md) — rendered from [`example-scan.json`](../schema/example-scan.json)

## Context

The entity graph (ADR-0001) is the machine-facing evidence layer. The **brief** is the human-facing product: the thing the charter says an analyst must be able to action **in under two minutes**. Because the evaluation measures properties *of this artifact* (faithfulness, prioritisation quality, provenance retention), its shape has to be fixed before it is generated — a fluid format is unmeasurable.

## Decision

### D1 — The brief is generated, but its skeleton is fixed

The LLM writes the prose, but the **structure, ordering, and the provenance line are contract, not model choices.** The model fills a template; it does not design the document. Fixed sections:

1. **Header** — target, timestamp, Glean version, tools + method, authorisation, one-line surface count.
2. **Top priorities** — the top *N* entities by deterministic `priority.rank` (default N = 5). Each item: the finding, one or two sentences of plain-language "so what," a *"why ranked here"* line drawn from `priority.signals`, and a *"seen by"* provenance line.
3. **Also found** — a short tail of lower-priority entities, one line each, each with its source tool.
4. **Provenance & method** — a closing statement plus the three headline counts.

### D2 — Ordering is dictated by code, never by the model

The order of the "Top priorities" section is the `priority.rank` order from ADR-0004. The LLM may not reorder. This is what makes prioritisation quality measurable against a ground-truth ranking, and what stops the model from quietly promoting a finding it finds interesting.

### D3 — Every surfaced finding must name its source

Each finding carries a *"seen by"* line listing the `source_tool`(s) and method from its provenance array. This is the visible face of the provenance-retention metric: a finding with no source line is a contract violation, caught in code before the brief is emitted.

### D4 — The model narrates only what is in the graph

The LLM's input is the entity graph and nothing else. It may not introduce entities, IPs, services, or claims not present as entities. Any noun in the brief must resolve to an entity id. This is the faithfulness contract, and it is checkable: parse the brief's findings, match each to an entity, count the misses (target: 0).

### D5 — The "why ranked here" line comes from signals, not invention

The justification under each priority is a plain-language rendering of `priority.signals` (e.g. `admin_hostname_pattern` → "admin-named host"). The model translates signals to English; it does not invent a rationale. This is the chain-of-thought-faithfulness angle from the charter made concrete — the stated reason must match the actual scoring signal.

### D6 — Two footer metrics are printed in every brief

Every brief ends with: findings count, findings-with-valid-provenance count, and fabricated-findings count. Printing them makes the trust properties visible to the reader on every run, and doubles as a smoke check during development.

## The contract, as a checklist a generated brief must pass

- [ ] Every finding resolves to an entity id in the graph (faithfulness).
- [ ] "Top priorities" order matches `priority.rank` order exactly (prioritisation).
- [ ] Every finding has a non-empty "seen by" source line (provenance).
- [ ] No entity, IP, service, or email appears that is absent from the graph.
- [ ] The footer counts are computed, not written by the model.
- [ ] It fits on one page / is actionable in under two minutes.

## Consequences

- **Positive:** the format the eval harness parses is stable; each of the three metrics maps to one contract rule, so "did the brief pass" and "what's the score" are the same check; the deterministic/LLM boundary is visible to the reader.
- **Costs:** a rigid template constrains prose style — acceptable, since terse and scannable is the goal for a two-minute read. Rendering into HTML/PDF is a roadmap concern; v1 emits Markdown.

## Open questions

1. Default N for "Top priorities" — 5, or scale with surface size?
2. Should the model get to *merge* two near-identical findings into one line, or is that a contract violation? (Leaning: no — merging is a code/dedup job, already done upstream.)
3. Do we show a numeric priority score to the reader, or only the rank + reason? (Example shows the score in parentheses — decide if that's noise.)

## Validation

`example-brief.md` serves as the golden target when building the generator: the generator's job is to reproduce a brief of this shape from a graph, and the evaluation harness's job is to confirm it did.
