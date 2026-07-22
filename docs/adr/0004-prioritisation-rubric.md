# ADR-0004 — Deterministic Prioritisation Rubric (v1)

- **Status:** Proposed (v0 — for review)
- **Date:** 2026-07-22
- **Scope:** Glean v1 — how each entity gets `priority.score`, `priority.rank`, `priority.signals`
- **Depends on:** ADR-0001 (entity schema)
- **Consumed by:** ADR-0005 (brief ordering + "why ranked here"), the evaluation harness (prioritisation-quality metric)

## Context

The project charter fixes one split: **the ranking is computed by code; the LLM only narrates it.** This ADR defines that code. The rubric must be:

- **Deterministic** — same graph in, same scores out, always. No randomness, no model calls, no wall-clock dependence beyond explicit freshness inputs.
- **Legible** — a human can read a score and understand why. This is a rubric, not a trained model. Legibility is a feature: it's what makes the "why ranked here" line honest and the prioritisation metric interpretable.
- **Versioned** — the weight table is part of the schema contract; changing it is a version bump, because it changes every score in every historical scan.

The rubric is *not* claiming to be a correct threat model. It is claiming to be a **transparent, reproducible ordering** that the evaluation then measures against human judgment. If it disagrees with the human ranking, that gap is a result to report, not a bug to hide.

## Decision

### D1 — Additive signal scoring

Each entity's score is the sum of the weights of the **signals** that fire on it:

```
score(entity) = Σ weight(s)  for each signal s that fires
```

Signals are independent, named boolean tests over the entity and its edges. The set of signals that fired is stored verbatim in `priority.signals`, so the score is always fully explained by its signals — nothing is hidden in the number.

### D2 — The v1 signal table

Weights are small integers for legibility. Positive signals raise priority; negative signals (deprioritisers) lower it.

| Signal | Fires when | Weight | Applies to |
|--------|-----------|:------:|-----------|
| `sensitive_hostname_pattern` | hostname matches admin/vpn/staging/dev/internal/jenkins/gitlab/portal/mail/db/… (curated list) | +3 | subdomain |
| `breach_hit` | an email/entity is linked to a `breach_exposure` | +3 | email_address, breach_exposure |
| `sensitive_port` | service port ∈ {22, 23, 3389, 3306, 5432, 6379, 9200, 27017, 5900, …} (admin/DB/remote) | +2 | service |
| `exposed_service` | any reachable `service` entity exists | +2 | service |
| `cert_expired` | certificate `not_after` < scan time | +2 | certificate |
| `cert_expiring_soon` | certificate expires within 30 days | +1 | certificate |
| `resolves_to_live_ip` | subdomain has a `resolves_to` edge to an IP with ≥1 service | +1 | subdomain |
| `multi_tool_corroboration` | entity has ≥2 distinct `source_tool` values in provenance | +1 | any |
| `active_only_finding` | entity seen *only* via active collection (weaker passive footprint) | +1 | any |
| `wildcard_or_default` | wildcard DNS / placeholder / parked indicator | −1 | subdomain |
| `passive_low_signal` | root domain / published contact with no other signal | −1 | domain, email_address |

The hostname keyword list and port list live in a versioned config file (`config/priority-signals.v1.yaml`), not hard-coded, so they're auditable and tunable without touching logic. Editing them is a rubric version bump.

### D3 — Normalisation to a 0–10 scale

Raw summed scores are clamped to `[0, 10]` for display and cross-scan comparability:

```
priority.score = clamp(raw_score, 0, 10)
```

The pre-clamp raw score is kept internally for tie-breaking. Clamping is a display decision; ranking uses the raw score so no information is lost at the top end.

### D4 — Ranking and deterministic tie-breaks

Entities are ranked by raw score, descending. Ties are broken **deterministically** so the ordering is stable across runs:

1. Higher raw score first.
2. Then a fixed entity-type precedence: `breach_exposure` > `service` > `subdomain` > `certificate` > `ip_address` > `email_address` > `dns_record` > `domain`.
3. Then more provenance sources first (more-corroborated wins).
4. Then lexicographic `id` (final, guarantees total order).

`priority.rank` is the 1-based position in this total order. No two entities can share a rank.

### D5 — Not every entity is ranked into the brief

All entities get a score, but the brief (ADR-0005) surfaces the top *N* and a short tail. Entities scoring ≤ 0 are "also found" / omitted, not "top priorities." Pure infrastructure facts (a TXT record) correctly fall to the bottom without special-casing.

### D6 — The LLM never touches any of this

`priority` is computed and written before the graph is handed to the LLM. The model reads `signals` to produce the "why ranked here" line and reads `rank` to order the brief. It cannot change a score, a rank, or a signal. Any brief whose ordering diverges from `rank` is a contract violation (ADR-0005 check), not a modelling choice.

## How this is evaluated (the point of the whole thing)

The rubric produces a ranking. The **ground-truth set** produces an independent human ranking of "what actually mattered" for each target. The prioritisation-quality metric (rank correlation / nDCG / rank-overlap of the top-N) measures agreement between the two. Three honest outcomes, all reportable:

- High agreement → the transparent rubric captures analyst judgment well.
- Low agreement → an interesting negative result about what a simple rubric misses.
- The LLM's brief order diverging from `rank` → a faithfulness failure, caught by the ADR-0005 check, separate from rubric quality.

Keeping the rubric simple is deliberate: a complex rubric that happens to match the human is uninterpretable; a simple one that mostly matches, with legible misses, is a *result*.

## Consequences

- **Positive:** fully explainable scores; stable, total ordering; signal list is auditable config; the deterministic/LLM boundary is enforced structurally; the prioritisation metric has a clean target.
- **Costs / accepted limits:** the weights are hand-chosen, not learned or validated against ground truth *yet* — that validation is exactly what the eval does. The signal set is infra-scoped and will not generalise to people-OSINT (out of v1 scope anyway). Additive scoring ignores interactions between signals (e.g. admin host *and* sensitive port might deserve super-additive weight) — recorded as a v2 question.

## Open questions

1. Should any signals be multiplicative / interacting, or is additive good enough for v1? (Leaning additive — legibility first.)
2. Final hostname keyword and sensitive-port lists — draft now, but confirm against real scan output.
3. Do we expose `priority.score` to the reader (ADR-0005 Q3) or only `rank` + signals?
4. Should `multi_tool_corroboration` weight scale with the *number* of tools, or stay flat? (Leaning flat for v1.)

## Validation

The weight table is frozen into `config/priority-signals.v1.yaml`, then applied to one real target scored by hand, to confirm the ordering it produces is reasonable before any code computes it.
