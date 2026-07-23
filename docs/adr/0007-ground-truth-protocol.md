# ADR-0007 — Ground-Truth Construction Protocol (v1)

- **Status:** Accepted (v0.1.0 — validated 2026-07-23 with a real blind annotation pass against `yulan.me`; see Validation)
- **Date:** 2026-07-22
- **Scope:** Glean v1 — how the reference "what actually mattered" ranking is produced per target, for the prioritisation-quality metric
- **Depends on:** ADR-0001 (entity schema — the annotator works from this graph), ADR-0004 (prioritisation rubric — the thing being independently checked, not re-derived), ADR-0006 (defines how the comparison is computed once this protocol supplies the reference ranking)
- **Consumed by:** the evaluation harness; roadmap Workstream D3 (assembling the actual ≥10-target list — a separate prerequisite, not solved by this ADR)

## Context

Per the roadmap: "as a solo project you can't lean on inter-rater agreement, so your credibility substitute is a written, pre-registered rubric... Document the honest limitation (single annotator) rather than hiding it." This ADR is that rubric and procedure.

There is a specific trap this design must avoid: **the ground truth must not be a hand-replay of ADR-0004's own weight table.** If the "independent" human ranking is produced by mechanically re-summing the same signals the code already computes, the prioritisation-quality metric measures nothing but arithmetic consistency — of course a rubric agrees with itself when applied twice. ADR-0004's own evaluation section is explicit that the ground-truth ranking must be *independent* human judgment, precisely so a divergence is a real, reportable finding rather than a tautology. This ADR exists to make that independence real and auditable, not just asserted.

## Decision

### D1 — Who produces the ranking, and the limitation this implies

A single named annotator (the project operator) produces the reference ranking, applying the written rubric below. **No inter-rater reliability is measured in v1** — there is no second annotator. This is recorded here explicitly as an accepted limitation, not concealed: every ground-truth file must state "single annotator, no inter-rater agreement measured" in its header. A second annotator on a subset of targets is recorded as post-MVP roadmap material (ADR consequences, below), not required to ship.

### D2 — Annotation input: same evidence, hidden conclusion

The annotator works from the **deduplicated entity graph** for the target (post ADR-0003 dedup, i.e. entity `id`/`type`/`value`/`attributes`/`provenance`/`edges` — the same evidence base ADR-0004's code scores), but with every entity's `priority` field **stripped before the annotator sees it**. This guarantees the comparison is apples-to-apples (same underlying evidence) while the annotator's judgment is formed with zero exposure to the code's own conclusion.

### D3 — The human rubric (independent factors, not a manual replay of ADR-0004)

The annotator ranks entities using their own security judgment, guided by — but not limited to reproducing — factors including:

- **Exposure/reachability** — is this asset actually reachable from the internet, right now?
- **Sensitivity implied by function** — admin/management surfaces, auth endpoints, data-bearing services.
- **Corroboration** — is this seen independently by more than one source, or resting on a single, weaker signal?
- **Freshness/liveness** — a dead, historical artifact should not outrank live infrastructure. (This factor is written in directly as a result of the ADR-0004 pilot finding — a real failure mode the human rubric must not reproduce.)
- **Credential/breach exposure evidence**, where present.
- **Certificate/TLS hygiene** as a secondary signal, not a primary one.
- **Business-context judgment** — anything the annotator can reasonably infer that code cannot (e.g. naming or structure suggesting a customer-facing surface vs. internal tooling).

Overlap with ADR-0004's signal table is expected and fine — both are legitimate security reasoning drawing on the same domain. What makes this independent is *process*, not *topic*: the annotator applies these as a reasoned judgment call per entity, not a mechanical weight-sum. The business-context factor is explicitly flagged as the axis where the human and the code are most likely to diverge — and per ADR-0004's own "three honest outcomes" framing, a real divergence there is a *result*, not a failure of the protocol.

### D4 — Output shape: rank the top slice, not the whole graph

The annotator ranks only the **top ~2×N** entities (N = ADR-0005's brief default of 5, so ~10), each with a one-line justification, in explicit order. Everything else is implicitly unranked / tier-0 — mirroring ADR-0004 D5's own "entities scoring ≤0 don't need individual ranking" philosophy. This keeps annotation cost bounded regardless of graph size (a 200-entity graph costs the same annotation effort as a 20-entity one) without weakening either ADR-0006 metric, since both `overlap@N` and `nDCG@N` only operate on the top-N window.

### D5 — Tie-break

When the annotator genuinely cannot distinguish two entities' priority, the tie is broken using **the same deterministic rule as ADR-0004 D4** (entity-type precedence, then more-corroborated-wins, then lexicographic `id`). Reusing the code's own tie-break avoids inventing a second arbitrary axis, and only ever activates on a genuine judgment tie — it is never a substitute for making the call.

### D6 — Blind annotation (the credibility-critical rule)

The annotator completes and timestamps the full ranking and justifications **before** viewing that scan's computed `priority.rank` or generated brief. Every ground-truth file records the annotation timestamp and a one-line attestation that this order was respected. This is the single rule that makes the comparison meaningful instead of circular — violating it once compromises every number computed against that target.

One honesty caveat, stated rather than hidden: the annotator has necessarily already read ADR-0004's signal table (it's their own design document) and cannot fully un-know it. "Blind to the rubric" is not achievable for a solo project; "blind to this specific scan's computed output" is, and is the meaningful and enforceable form of independence here.

### D7 — Optional corroboration

The annotator **may** consult a secondary passive data source (e.g. Shodan's historical data on the target, published CVE records) to inform a specific judgment call. Whether and which source was consulted must be recorded per entity where used — for auditability, not concealment. Not required for every entity; the roadmap (D4) leaves this genuinely open and this ADR keeps it opt-in rather than forcing a resolution that isn't ready yet.

### D8 — Storage and sensitivity

A ground-truth file necessarily names real target infrastructure — the same sensitivity class as raw scan output. Store per-target ground-truth files under `eval/scans/<target-slug>/ground_truth.yaml` — this path is already covered by the existing `.gitignore` `scans/` rule (matches a directory named `scans` at any depth), so no gitignore change is needed, but this is worth double-checking once the directory actually exists rather than assumed.

## Consequences

- **Positive:** avoids the circularity trap explicitly; bounded annotation cost independent of graph size; the blind-annotation rule is a concrete, checkable process guarantee rather than an aspiration; the single-annotator limitation is disclosed by construction (baked into the file format), not something to remember to mention later.
- **Costs / accepted limits:** genuine inter-rater independence isn't achievable solo — the mitigation is process rigor (blind annotation, written-first rubric) rather than a substitute for a second annotator. Business-context judgment, the richest source of expected human/code divergence, is also the least auditable factor — there's no way to fully separate "good judgment" from "annotator's personal bias" with N=1.

## Open questions

1. Is a top-~10 (2×N) slice the right buffer size, or should it scale with graph size for very large or very small scans?
2. Exact ground-truth file schema (YAML/JSON) — not designed yet, needs to happen alongside D8's directory once real annotation starts.
3. Should corroboration sources (D7) become mandatory rather than optional? Left open per roadmap D4, not resolved here.
4. Post-MVP: a second annotator on a subset of targets, to at least partially measure agreement even though not required now — recorded on the roadmap's slow clock (ADR-0004-style "extra"), not a v1 blocker.

## Validation

**2026-07-23, against `yulan.me`:** first real run of this protocol end-to-end. D1/D6 held: a single named annotator (the project operator) produced a ranking from a priority-stripped entity graph (1 domain, 39 subdomains, 113 certificates), blind to Glean's computed `priority.rank`, timestamped before that computation happened. D2 held: same evidence base, conclusion stripped. D4 held: the annotator's final ranking (3 entities) was shorter than the ~10 ceiling — explicitly permitted, not a protocol violation. D7 (corroboration) was not used. No procedural gap found in the protocol itself; the interesting result of this pass was on the ADR-0006/ADR-0004 side (see `_private/findings/yulan-me-ground-truth-validation.md`), not here.
