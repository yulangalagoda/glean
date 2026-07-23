# ADR-0004 — Deterministic Prioritisation Rubric (v1)

- **Status:** Accepted (v0.1.0 frozen 2026-07-22, corrected and re-validated same day; three further corrections added and re-validated 2026-07-23, see D2)
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
| `cert_superseded` | an expired certificate, where a newer certificate in the graph — still within its validity window — covers at least one of the same hostname(s) | −2 | certificate |
| `cert_orphaned` | an expired certificate whose hostname(s) are independently confirmed non-resolving (`stale_no_dns` fired on the corresponding subdomain entity this scan) and no currently-valid certificate covers any of the same hostname(s) either | −2 | certificate |
| `cert_expiring_soon` | certificate expires within 30 days | +1 | certificate |
| `resolves_to_live_ip` | subdomain has a `resolves_to` edge to an IP with ≥1 service | +1 | subdomain |
| `multi_tool_corroboration` | entity has ≥2 distinct `source_tool` values in provenance | +1 | any |
| `active_only_finding` | entity seen *only* via active collection (weaker passive footprint) | +1 | any |
| `wildcard_or_default` | subdomain entity has `attributes.wildcard_confirmed_active = true` (ADR-0001 D4) — an active probe positively confirmed the wildcard, not merely a wildcard SAN seen in a certificate | −1 | subdomain |
| `passive_low_signal` | root domain / published contact with no other signal | −1 | domain, email_address |
| `stale_no_dns` | a DNS-resolution adapter (`dnsx` or equivalent) **ran and positively confirmed** no current A/AAAA/CNAME record for the hostname | −3 | subdomain, domain |

The hostname keyword list and port list live in a versioned config file (`config/priority-signals.v1.yaml`), not hard-coded, so they're auditable and tunable without touching logic. Editing them is a rubric version bump.

**`stale_no_dns` firing rule (important, not optional detail):** this signal fires only on *positive evidence* of non-resolution from a DNS-resolution tool run in this scan. It must never fire merely because no DNS-resolution adapter was part of the toolset for a given scan — absence of a check is not evidence of staleness, and treating it as such would silently and incorrectly zero out every entity whenever `dnsx` (or equivalent) isn't run. This makes a DNS-resolution adapter effectively non-optional for the MVP toolset: without one, this signal is inert (never fires, never penalises), which is a safe default, not a broken one.

**Pilot correction (2026-07-22) — resolved.** Hand-scoring real entities from a passive-only pilot (crt.sh + theHarvester, no DNS-resolution tool run) originally exposed a gap: `sensitive_hostname_pattern` fired purely on hostname text, with nothing checking whether the entity was currently live. A dead, years-old, spam-era certificate for an admin-sounding subdomain scored *higher* than genuinely live, multi-tool-corroborated infrastructure — reproducing, inside Glean's own rubric, exactly the "noise mistaken for signal" failure the charter opens with. Fixed by adding `stale_no_dns` above (weight −3, chosen to exactly offset `sensitive_hostname_pattern`'s +3 so a dead pattern-matching host nets to 0 and falls out of the ranked brief per D5, rather than needing to be zeroed by a special case).

**Re-validated against the same real data:** a real dead, admin-pattern-matching historical finding now scores `+3 −3 = 0` (falls to "also found," per D5). A real live, two-tool-corroborated host now scores `+1` (`multi_tool_corroboration`, `stale_no_dns` does not fire since it resolves) and correctly outranks the dead entry. Gut-check passes.

**`cert_superseded` firing rule:** fires only when the graph already contains a newer certificate, still within its own validity window, covering at least one of the same hostname(s) as the expired certificate in question. A domain's ordinary certificate-rotation history (a short-lived cert lapsing on schedule after being renewed) must not read as a standalone finding — that's routine hygiene, not signal. Weight sized to exactly offset `cert_expired`'s +2, the same offsetting pattern as `stale_no_dns`/`sensitive_hostname_pattern`, so a superseded-but-otherwise-unremarkable certificate nets to 0 rather than needing a special case.

**Pilot correction (2026-07-23) — resolved.** Hand-scoring a second real target (passive-only: certificate-transparency + search-engine sources, no service/port scan) surfaced a related gap: `cert_expired` fires on *any* expired certificate, with nothing checking whether it had simply been superseded by routine renewal. In the real data, three certificates predating the domain's current registration — ordinary historical residue from a prior owner — each scored +2 purely for being expired, while every currently-live subdomain scored 0 (no positive signal fires for plain liveness without active/service-scan data, since `resolves_to_live_ip` and `exposed_service` both require a discovered `service` entity). The three historical certificates outranked all real current infrastructure, filling the entire "Top priorities" section of a hand-rendered brief with irrelevant, non-actionable certificate history and mentioning none of the actually-live hosts.

A blanket positive "this resolves" signal for subdomains was considered and rejected as the fix: it would flip the failure mode rather than close it, making every ordinary, unremarkable live host register as a "priority" purely for existing — reproducing the noise-as-signal problem from the opposite direction. `cert_superseded` is the narrower, targeted correction: it only suppresses expired certificates that are demonstrably routine (a newer valid one already exists for the same name), leaving `cert_expired` free to still fire at full weight on the case that actually matters — a certificate that expired and was **never** replaced.

**Re-validated against the same real data:** the three previously-flagged historical certificates now score `+2 −2 = 0` and correctly fall out of "Top priorities." No entity in this target's passive-only scan scores positive — the brief's top-priorities section is now empty, which is the honest result for a domain with no sensitive-named hosts, no discovered services, and no genuine signal deviation beyond routine cert-rotation history. Gut-check passes: nothing irrelevant outranks anything real.

**Second correction, same day (2026-07-23) — resolved.** Closing the wildcard-entity open question (ADR-0001 D3/D4) surfaced a precision gap in `wildcard_or_default` itself: as originally worded ("wildcard DNS / placeholder / parked indicator"), it did not say what counts as evidence, which would have meant firing on a wildcard SAN merely appearing in a certificate. Confirmed directly against real infrastructure this session: a wildcard certificate remains visible in CT logs *permanently* even after the underlying DNS wildcard record has been deliberately removed — certificate evidence and current DNS state can and do diverge, in exactly the same shape as the `stale_no_dns` and `cert_superseded` corrections above (passive/historical evidence mistaken for current state). Left as originally worded, this signal would misfire on any domain that ever had a wildcard cert issued, regardless of whether the wildcard is still live. Fixed by requiring `wildcard_or_default` to gate on `attributes.wildcard_confirmed_active` (ADR-0001 D4) — positive evidence from an active probe of an arbitrary, non-predefined subdomain, not mere cert-log presence. No weight change; this is a firing-condition correction, the same category as `stale_no_dns`'s existing "positive evidence only" rule, applied to the wildcard case.

**Third correction, same day (2026-07-23) — resolved.** Surfaced by the ADR-0006/0007 first validation pass: hand-scoring `yulan.me`'s real, naturally-occurring history (a ~2019–2024 legitimate wildcard, then an ~8-month 2024–2025 window where the dropped domain was parked by an unrelated spam operation, then re-registered by the current operator 2026-05) against a blind human ground-truth ranking showed near-zero agreement (`overlap@3 = 0.0`, `nDCG@3 ≈ 0.20`) — the human ranked the live apex and two live work-in-progress subdomains at the top, while Glean's rubric ranked ~57 individual, long-dead, **never-renewed** certificates from the spam-parking era (e.g. a one-off cert for `ww1.yulan.me`, issued 2020, expired 2021, never reissued) at the very top, each scoring +2 from `cert_expired` alone. `cert_superseded` did not catch these because it only fires when a *newer valid* certificate exists for the same hostname — these hostnames were never renewed at all, so there was no successor cert to trigger it. The corresponding *subdomain* entity for each of these dead hosts correctly nets negative (`stale_no_dns`, −3), but the *certificate* entity describing the same real-world dead host had no equivalent counterbalance — the same entity-type blind spot `cert_superseded` closed for the renewal case, left open for the abandonment case. Fixed by adding `cert_orphaned` above (−2, same exact-offset sizing as `cert_superseded`), which requires cross-referencing the certificate's hostname(s) against the corresponding subdomain entity's own `stale_no_dns` result computed in the same scan — the first v1 signal that reads another entity's computed signal rather than only its own attributes.

**Re-validated against the same real data:** re-scoring `yulan.me` with `cert_orphaned` added, `overlap@3` and `nDCG@3` improved substantially (see `_private/findings/yulan-me-ground-truth-validation.md` for the full before/after numbers) — the ~57 orphaned dead certificates now net to 0 and drop out of "Top priorities," and the live, human-flagged entities rise correspondingly. Full result, including what still doesn't match and why, recorded in that file rather than repeated here, per this ADR's own "report honestly either way" principle — a validation pass that only reported the fix without reporting the residual gap would defeat the point of doing this with a real blind annotator.

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
5. ~~Exact weight/sign for the new liveness signal — zero out entirely, or just penalise?~~ **Resolved:** penalised (`stale_no_dns`, −3), not a hard zero — sized to offset `sensitive_hostname_pattern` exactly, so a dead-but-named entity nets to 0 rather than being force-excluded by a special case. A stale finding with other independent signals (e.g. a `breach_hit`) can still surface.
6. ~~Should a plain positive "this resolves" signal exist for subdomains, to counter stale historical noise outranking live infrastructure?~~ **Resolved: no.** Considered and rejected in favour of `cert_superseded` — the actual defect was `cert_expired` misfiring on routine, superseded certificate history, not an absence of a liveness reward. A blanket liveness signal would have traded one noise-as-signal failure for its mirror image (every ordinary live host reading as a priority). See D2's 2026-07-23 correction.
7. `cert_superseded`'s "same hostname" check needs a precise definition once implemented: exact SAN-set match, or "at least one SAN in common"? Leaning toward "at least one SAN in common" for v1 (simpler, and a partial-overlap case — e.g. a wildcard cert superseded by several single-name certs — should still count as routine rotation, not a finding), but not yet exercised against real multi-SAN rotation data.

## Validation

The weight table is frozen into `config/priority-signals.v1.yaml` once implementation begins (not yet created — pre-code phase), then applied to one real target scored by hand, to confirm the ordering it produces is reasonable before any code computes it.

**Pilot result (2026-07-22):** hand-scored against a real target. Gut-check initially **failed** (see the resolved D2 correction note above), **fix designed and re-validated against the same real data same day — now passes.** Status: `Accepted`.
