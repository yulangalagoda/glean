# ADR-0006 — Evaluation Protocol: the Three Numbers (v1)

- **Status:** Accepted — extended 2026-08-04 with a measured judge-reliability figure (flag precision 0.250 over 90 human-labelled claims), resolving open question 5; the accompanying diagnosis was retracted and corrected 2026-08-06, the packet re-labelled (precision 1.000, recall 0.667), and linked-entity evidence added to remove an ambiguity that left recall unreportable; see Validation (v0.1.0 — hand-validated 2026-07-23 against a real target under ADR-0007's protocol; see Validation). **`glean eval` (roadmap E4) built 2026-07-27** — the formulas are no longer hand-computed one target at a time; a single command now runs the full pipeline and reports all three numbers across every target with a ground-truth file.
- **Date:** 2026-07-22
- **Scope:** Glean v1 — the exact, computable definitions of faithfulness, prioritisation quality, and provenance retention
- **Depends on:** ADR-0001 (entity schema — the reference set faithfulness checks against), ADR-0004 (prioritisation rubric — the ranking prioritisation quality is measured against), ADR-0005 (brief contract — the artifact all three metrics are computed over)
- **Consumed by:** the evaluation harness (not yet built); the ground-truth construction protocol (not yet written, roadmap workstream F2)

## Context

The charter fixes three numbers as the MVP's actual contribution — not the tool, the measurement of the tool. ADR-0005 already states the *contract* each metric enforces informally ("every finding resolves to an entity id," "order matches `priority.rank`," "every finding has a seen-by line"). What's missing is the precise, computable **formula** and **procedure** behind each one — this ADR is that specification, per roadmap item F1.

This ADR is grounded in five papers, read specifically to answer this question (roadmap C1/C2):

- **Mezzi, Massacci & Tuma, "Large Language Models Are Unreliable for Cyber Threat Intelligence"** (ICARS 2025; arXiv 2503.23175) — confirms Glean's niche survives: their critique operates on **prose CTI reports** (mean 3,009 words) as *input*, extracting structured entities as *output* — the opposite direction from Glean, which takes a structured entity graph as input and produces a ranked judgment as output. Their extraction precision drops to 0.76 on real reports (vs. 0.83–0.89 on short synthetic text in prior work) specifically *because* the input is long unstructured prose — this is evidence *for* Glean's normalise-before-LLM design, not a pre-emption of it.
- **Yu et al., "Decoupling Reconnaissance and Exploitation..."** (preprint; venue unconfirmed from the PDF itself, cite as preprint pending verification) — Targeted Vulnerability Recall "plateaus at approximately 50.0%, primarily due to failures in parsing unstructured telemetry" (38/70 = 54.3% without a knowledge base), while exploitation success given *correct, clean context* reaches 90%. This is the strongest available citation for the charter's core bet: give a model clean structured input and downstream capability jumps. Directly motivates why Glean deterministically normalises before the LLM ever sees the data.
- **Es et al., "RAGAS: Automated Evaluation of Retrieval Augmented Generation"** (EACL 2024, pp.150–158) — source of the primary faithfulness formula, adapted below.
- **Min et al., "FActScore: Fine-grained Atomic Evaluation of Factual Precision..."** (EMNLP 2023, pp.12076–12100) — near-identical mechanic to RAGAS, formalised more rigorously; its explicit design assumptions map directly onto Glean's architecture (see D1).
- **Manakul et al., "SelfCheckGPT"** (arXiv 2303.08896) — a no-reference, sampling-consistency method. Confirmed **not** the right primary method for Glean (Glean has an actual reference — the entity graph — so a with-reference method is strictly better here), but its consistency-sampling idea is noted as an optional supplementary check (D5).

Note on substitution: the charter cites **RAGIntel, FaithBench, FaithJudge, DeepEval** as method references. None of these exist as local PDFs in `_private/research-papers/` — RAGAS and FActScore (both present, both directly on-topic) are used instead. If the missing papers are obtained later, revisit D1 against them.

## Decision

### D1 — Faithfulness

**Formula (adapted from RAGAS §faithfulness and FActScore):**

```
F = |V| / |S|
```

where `S` is the set of atomic claims extracted from a brief's findings (both "Top priorities" and "Also found" sections), and `V ⊆ S` is the subset entailed by the entity graph. Target per charter: `F = 1.0` (0 fabricated findings).

**Two-stage procedure, cheap-first:**

1. **Deterministic pre-check (no LLM judge needed).** ADR-0005 D1/D4 already constrain the brief so tightly that each finding names exactly one entity and may not merge findings. So the first, free check is structural: parse each finding block, extract the entity `id` it claims to describe, and confirm that `id` exists in the graph. Any finding naming an entity absent from the graph fails immediately — this catches the cheap, obvious fabrication case (an invented host, IP, or email) without invoking a model at all.
2. **Atomic-claim check (LLM judge, RAGAS/FActScore-style) for the surviving findings.** A finding block can still fabricate *content* about a real entity — e.g. "port 443 is running an outdated Apache" when the entity graph only records "port 443 open," nothing about software or version. For each finding that passes stage 1, decompose its prose (the "so what" and "why ranked here" lines) into atomic statements, then check each statement against that specific entity's full record (`attributes`, `provenance`, connected `edges`) for entailment. `S` and `V` above are counted over this decomposed set, pooled across the whole brief.

**Why two-stage:** stage 1 is free, deterministic, and structurally guaranteed never to have false negatives (an absent entity id is unambiguous). Stage 2 is where the real judgment work — and the real risk of an LLM-judging-an-LLM problem — lives, so it's worth confining that expensive/riskier step to only the findings that already passed the cheap gate.

**Explicit non-goal (carried over from FActScore's own stated assumptions):** faithfulness as defined here is a **precision-only** metric — it does not penalise a brief for *omitting* an important finding. That's deliberate and mirrors FActScore's own design assumption. Coverage/recall of what mattered is a separate concern, captured by D2 below. The charter's three numbers are reported separately, not blended into one score, precisely so precision failures and recall failures stay distinguishable.

### D2 — Prioritisation quality

Compares the brief's `priority.rank` order (ADR-0004, computed deterministically, never by the LLM) against an independent human-produced ground-truth ranking for the same scan (method not yet specified — roadmap F2, out of scope for this ADR).

**Primary metric: top-N rank overlap (Jaccard@N).**

```
overlap@N = |rank_glean_topN ∩ rank_human_topN| / |rank_glean_topN ∪ rank_human_topN|
```

Chosen as primary over a correlation coefficient because it's legible — matching ADR-0004's explicit "legibility first" design philosophy — and answers the charter's actual question ("does the top-of-brief match the human-rated priorities") directly, without needing the full ranking to be defined over every entity in a scan (ground-truth labelling effort scales with N, not with total entity count).

**Secondary metric: nDCG@N**, reported alongside for graded/position-sensitive comparison (rewards getting the *order* right within the top N, not just membership). Both numbers get reported; neither is hidden in favour of the more flattering one, per the charter's "report honestly either way" principle (ROADMAP F4).

**Tie handling:** ADR-0004 D4 already gives the Glean-side ranking a total, deterministic order — no ties possible on that side. The human ground-truth ranking's own tie-break rule is not yet specified; it must be pinned in the ground-truth construction protocol (F2) before this metric can be computed for real, and is recorded here as a hard dependency, not silently assumed.

### D3 — Provenance retention

The most mechanical of the three, and already effectively specified by ADR-0005 D3/D6 — this ADR just makes it a formal, computable definition:

```
PR = |findings with ≥1 valid seen-by source| / |total findings surfaced|
```

A finding's "seen by" line is **valid** if every `source_tool` it names has a matching provenance entry on that finding's underlying entity in the graph — i.e. the brief didn't just print *a* source, it printed a *correct* one. Target per charter: 100%. Computed identically to the ADR-0005 D3 contract check; no LLM judge involved, purely structural.

### D4 — Judging procedure for D1's stage 2

Atomic-claim entailment checking (D1 stage 2) requires an LLM judge. This introduces a known risk: using a model to judge a model's faithfulness has its own faithfulness problem (the judge can itself hallucinate agreement). Two mitigations, both consistent with prior art:

- **The judge's task is narrower than typical RAGAS/FActScore use.** Those papers judge prose claims against prose or open-web context; Glean's judge checks a claim against one specific entity's structured, deterministic record. Less room for the judge itself to misread ambiguous context.
- **The judge should be a different (and ideally stronger) model than the one under evaluation** — standard practice in both source papers (both use GPT-4-class judges to evaluate other systems). Whether that judge must itself be a small local model, or may be a larger/cloud model used *only* for scoring (not as the system under test), is recorded as an open question below — it interacts with the reproducibility goals in the roadmap (Workstream E4) and isn't a simple call.

### D5 — Supplementary stability metric (optional, not one of the three headline numbers)

Borrowing Mezzi et al.'s repeated-sampling/confidence-interval approach and SelfCheckGPT's consistency idea: optionally run the same scan's synthesis step N times (fixed temperature where the model supports it) and report how much the fabrication count and top-N ranking vary run to run. Not required for MVP; recorded as roadmap-appropriate "extra," consistent with the charter's operating principle of shipping the small complete thing first.

## Consequences

- **Positive:** all three numbers now have an unambiguous formula, not just a description; the faithfulness check's two-stage design keeps the expensive/risky LLM-judge step to the minimum surface area that actually needs it; the precision/recall separation (D1 vs D2) is explicit and deliberate rather than accidentally conflated; every formula traces to a specific, read (not just cited) paper.
- **Costs / accepted limits:** D2 cannot be executed end-to-end until the ground-truth construction protocol (F2) exists and pins the human ranking's tie-break rule — this ADR specifies the *comparison*, not the *reference* it compares against. D4's judge-model choice is still open and has real reproducibility consequences either way.

## Open questions

1. ~~**Judge model for D1 stage 2**~~ — **resolved 2026-07-27:** a local judge, per the ADR's own leaning — `llama3.1:8b`, a different and larger model than synthesis's default `llama3.2:latest` (D4's "different, ideally stronger" requirement). Real validation (below) found the local judge itself makes real errors, but not the kind that would be fixed by a bigger/cloud judge alone — see Validation for why this is being left as-is rather than immediately escalated to a cloud judge.
2. ~~Exact atomic-claim decomposition prompt template~~ — **resolved 2026-07-27:** decomposition and entailment are combined into a single judge call per brief (not two separate calls), asking the judge to both break each finding's prose into atomic claims *and* verdict each one against that entity's real facts in one pass — bounds cost to one call per brief, matching how ADR-0009's narration call is already batched. Prompt and parsing in `glean_osint.evaluation.build_judge_prompt`/`_parse_judge_response`.
3. ~~nDCG@N vs. overlap@N as the *headline* reported number when only one fits in a summary table~~ — **Resolved 2026-08-04:** the constraint turned out not to bind. `glean eval` reports both per target and both in the summary line, so no choice of a single headline was needed.
4. Ground-truth ranking tie-break rule — explicitly deferred to F2, not decided here.
5. ~~**Whether the judge's own errors need quantifying before `stage2_faith` can be read at face value**~~ — **Resolved 2026-08-04: they did, and now are.** Raised by real validation, which found the judge making real errors of its own (see Validation), and left open on 2026-08-04 with the apparatus built but the measurement outstanding. `glean judge-audit` samples the judge's individual verdicts (retained on `Stage2FaithfulnessResult.claims` rather than summed away) into a packet carrying each claim and the exact evidence the judge was shown; `glean judge-score` scores the judge once a human has labelled them. The headline is precision on the *flagged* class, because flags are the only thing that moves `stage2_faith` below 1.000: a judge that over-flags makes published faithfulness look worse than reality, which is the counter-intuitive direction. Cohen's kappa accompanies raw agreement, since agreement flatters any judge on a skewed set. **The labels are research data and must come from a human annotator — nothing generates them, and scoring refuses a partially-labelled packet rather than treating unlabelled rows as agreement.** A packet of all 90 claims has now been labelled and scored: the judge over-flags roughly three-to-one, so a documented caveat was *not* enough and `stage2_faith` is a loose lower bound rather than an estimate. Numbers and diagnosis are in the Validation entries at the end of this ADR — note that the 2026-08-04 diagnosis of *why* was **retracted on 2026-08-06** when it was checked against the labelled data, and replaced with one the data supports. The measurement itself stands; a fix for the corrected diagnosis is in and awaiting re-measurement.

## Validation

**2026-07-23, against `yulan.me`:** D2's formulas (`overlap@N`, `nDCG@N`) were computed for real against a blind human ground-truth ranking produced under ADR-0007. Result: near-zero initial agreement (`overlap@3 = 0.0`, `nDCG@3 ≈ 0.20`) traced to a real, previously-undiscovered ADR-0004 gap (dead, never-renewed certificates scoring as high as anything in the graph), not a flaw in the metric itself. After fixing that gap (`cert_orphaned`, see ADR-0004 D2), agreement rose substantially (`overlap@3 = 0.5`, `nDCG@3 ≈ 0.43`), with one residual, honestly-reported disagreement left open by design. D1/D3 were checked mechanically only (formulas compute correctly against a hand-rendered brief) — a real fabrication-resistance test still requires an actual LLM-generated brief, not yet built. Full findings: `_private/findings/yulan-me-ground-truth-validation.md` (private — real domain name).

**2026-07-27, `glean eval` across all 10 targets:** first run of the full harness end to end, not hand-computed. D1/D3 (faithfulness stage 1, provenance retention): **1.000 across every target** — expected, not yet a meaningful pass, since the current template-based brief builds every finding directly from a real graph entity and can't fail either check by construction; both only become a real test once real LLM synthesis exists to fabricate something. D2 (prioritisation quality): mean `overlap@5 = 0.464`, mean `nDCG@5 = 0.582` across the set — real, substantial, and expected disagreement, not a bug. The two worst-scoring targets (`brenwick.autos` `overlap@5 = 0.250`; `tessno.com` `overlap@5 = 0.429` but `nDCG@5` drops to `0.378`, i.e. rank order disagrees even where the sets overlap) are exactly the two targets where the annotator independently ranked a confirmed-dead-but-still-unexpired-certificate subdomain (`v2.*`) at or near the top as "an anomaly worth investigating" — the literal opposite of what `stale_no_dns`/`cert_orphaned` are designed to do. Recorded in ADR-0007's Validation section as the pattern-level finding; recorded here as the first real quantification of it. No metric-formula bug found in this pass.

**2026-07-27, `glean eval --llm` across all 10 targets, D1 stage 2 implemented:** first real run of atomic-claim entailment checking, real narration (`llama3.2:latest`) judged by a real, different local model (`llama3.1:8b`, D4). Result: **mean stage2 faithfulness = 0.725**, real variance per target (`0.500`–`1.000`), zero unjudged findings across the whole set (the `format: json` object-wrapping fix from ADR-0009's validation held up at this scale too, not just the one target it was found on).

This number needs a real caveat, found by reading actual judge output rather than trusting the score in isolation (checked by hand against `larnby.com`): **the judge itself made real errors.** Two claims — "seen independently by multiple tools" for `subdomain:*.larnby.com` and for `ip_address:172.67.202.117` — were marked *unsupported* despite each entity's real `seen_by` field genuinely listing two distinct tools (`crt.sh (passive), theHarvester (passive)` and `dnsx (passive), httpx (active)` respectively). Both narrated claims were true and well-supported; the judge was wrong, not the narrator. This is exactly D4's own named risk — "using a model to judge a model's faithfulness has its own faithfulness problem" — now demonstrated concretely, and in the less-discussed direction (the judge wrongly *rejecting* a true claim, not wrongly accepting a false one).

Practical reading of `0.725`: it's a **lower bound** on real narrator faithfulness for this run, not a precise measurement — some fraction of the "unsupported" claims are judge error, not narrator fabrication, and this pass didn't attempt to separate the two (that would need spot-checking judge verdicts by hand at scale, recorded as open question 5). Not fixed here by further prompt-tuning the judge — a single hand-checked example isn't enough signal to responsibly re-tune against without risking overfitting to one case, and the ADR's own "report honestly either way" principle means recording the limitation is the right move, not silently patching it away same-day.

---

**2026-08-04 — the judge measured against a human annotator.**

Open question 5 asked whether a documented caveat about the judge's errors was
enough, or whether its reliability needed quantifying. It needed quantifying,
and now is.

**Method.** Every atomic claim the judge produced across the ten ground-truth
targets — 90 in total, the whole population for this run rather than a sample,
so there is no sampling error — was labelled independently by the project's
annotator using `glean judge-audit`, then scored with `glean judge-score`. The
annotator saw each claim and the same evidence the judge was given; the judge's
own verdict is shown in the packet only so the record stays auditable
afterwards.

| | |
|---|---|
| claims labelled | 90 |
| raw agreement | 0.744 |
| **flag precision** | **0.250** |
| flag recall | 0.778 |
| Cohen's kappa | 0.268 |

**What it says.** The judge flagged 28 claims as unsupported; the annotator
found 9. Of those 28 flags only 7 were right, so **roughly three quarters of
what drags `stage2_faith` down is judge error rather than narrator
fabrication**. It does catch most real problems (recall 0.778 — 7 of 9). Raw
agreement of 0.744 looks respectable and is not: with 90% of claims genuinely
supported, a judge that never flagged anything would score 0.90, which is
exactly why kappa is reported beside it and reads only 0.268.

The consequence for the published number: **`stage2_faith` is a floor, and a
loose one.** The 0.455 recorded in ADR-0009's validation implies true
faithfulness materially higher than that. It stays conservative in the right
direction — it never overstates faithfulness — but it is not an estimate of it.

**Why the judge over-flags — first diagnosis, wrong, corrected 2026-08-06.**
The original entry here blamed evidence scoping: `_judge_finding_facts`
builds the judge's evidence from a single entity, so prose referring to a
*linked* entity (`service: https` living on the `service:` entity) would be
unverifiable, and 13 of the 21 false flags were said to fit that pattern,
predicting precision 0.25 → 0.47.

**That was not checked against the labelled data, and it does not survive
contact with it.** Re-examined claim by claim, **all 21 false flags had
their evidence present in the packet the judge was shown** — zero needed a
linked entity. The specific story told was refuted too: the HTTPS sub-claims
on subdomain findings were *accepted* by the judge, not flagged. The
retraction is recorded rather than quietly edited because the prediction was
published as falsifiable, and this is what refuting it looks like.

**The real pattern, from the same data.** Flag errors sort cleanly by how
the evidence is *shaped*:

| entity type | false flags / human-supported claims |
|---|---|
| service | 1 / 25 (4%) |
| subdomain | 11 / 26 (42%) |
| domain | 4 / 10 (40%) |

A `service` entity carries `port: 443`, `protocol: tcp`, `service: https` —
values that match a claim's own words. A `subdomain` carries
`dns_resolved: true` or `wildcard: true`: **booleans whose meaning lives in
the key name**, while the prose describes the consequence ("resolves to a
live IP"). Reading one off the other takes a semantic step the 8B judge does
not reliably take. Of the 21, 20 sit on entities whose relevant attributes
are boolean-only or empty, the evidence instead sitting in `seen_by` or
`display_value`.

That is the *same* defect that produced the annotation error described
below: evidence presented in a form that does not read as evidence. It
fooled a person and a model in the same way.

**The fix, and what it measured.** `_plain_facts` now renders every fact as
a sentence — `dns_resolved: true` becomes "It resolves in DNS: it is a live
host" — alongside the unchanged structured fields, and the prompt states
that a claim restating a fact in different words is supported. This adds no
information: it is the narrator's own view (`synthesis._finding_facts`)
reworded, and a test asserts the judge is shown no value the narrator was
not. A judge given facts the narrator lacked would ratify invention rather
than check it.

Narration is deterministic (`temperature: 0`) and verified byte-identical
across runs, so the judge is the only thing that changed. On the claims that
survived verbatim and therefore carry the same human labels, flag precision
moves **0.250 → 1.000** and the overall flag rate falls from 31% of claims
to 5–8%.

**Those numbers are not the new headline, and must not be quoted as one.**
Three reasons, all disqualifying on their own. The scored subset is
*selected* — claims whose wording survived a prompt change are the stable,
easy ones. Four prompt variants were compared against these same 90 labels,
so the winner is fitted to them; two variants that sounded stricter scored
*worse* (precision 0.111 and 0.167), which is precisely why the choice had
to be made on data. And a known miss sits in the new output, unlabelled and
so unscored: a wildcard host with no resolution fact, narrated as "resolves
to a live IP", accepted. The permissive example in the prompt names that
exact phrase, and removing it cost more precision than the miss costs
recall — a trade recorded here rather than hidden.

A clean figure requires a human labelling the claims this prompt actually
produces. The packet is generated and waiting.

**Re-measurement is now affordable, which is the point.** Decomposition and
entailment share one call (Q2), so changing the prompt re-derives the claim
list — 43 of 90 original labels no longer applied to any claim. `glean
judge-audit --carry-over` matches claims across runs on
`(target, entity_id, normalised claim text)` and reuses the labels that
still apply, exact matches only: 47 carried, 31 to label. Without it every
prompt change costs a full re-labelling pass, which in practice means the
judge stops being re-measured and its reliability figure goes quietly stale.

**Also observed: the judge is not reproducible.** Two runs of an identical
prompt at `temperature: 0` produced 76 and 78 claims with slightly different
decompositions. Small, but it means `stage2_faith` carries run-to-run noise
independent of anything being measured, and any future comparison of two
judge configurations needs to be larger than that noise.

**A second defect, in the instrument rather than the judge.** The first
annotation pass mislabelled nine claims because the packet presented
`attributes`, `signals` and `seen_by` as one undifferentiated block while the
instructions said only "read the facts". The annotator reasonably read
`attributes` as the data and `signals` as commentary — but a signal is a
*derived fact*, and `resolves to a live IP with an exposed service` fires only
when a service was genuinely found. The packet header now states which fields
count as evidence and why. Recorded because it is a reproducibility hazard:
anyone repeating this method with the old packet would make the same nine
errors.

**Limits of this result, stated plainly.** One annotator, so there is no
inter-rater agreement here either (ADR-0007 Q4 remains open). One judge model
(`llama3.1:8b`) and one narration model. 90 claims is the whole population for
this eval run but a small absolute number, so the precision figure carries wide
uncertainty — the direction and rough magnitude of the bias are the finding,
not the third decimal place.

The labelled packet itself is `_private/judge-audit.yaml` — private, like the
rest of the eval set, because the claims quote briefs about real infrastructure
(`docs/ETHICS.md`). It is regenerable from the private scans with
`glean judge-audit --sample 0`; the labels are not, which is why the file is
kept rather than treated as scratch.

---

**2026-08-06 — the packet labelled, and linked-entity evidence added.**

The packet built after the evidence-presentation fix was labelled in full:
78 claims, **flag precision 1.000, recall 0.667, raw agreement 0.962, kappa
0.780**. Over-flagging is gone — every claim the judge flagged was a real
problem — which is the change that made the next finding visible at all.

**Every remaining disagreement was one thing.** Three claims, all judged
`supported` and labelled `unsupported`. None was a fabrication: each is
*true* in the graph and unverifiable from a single entity. `beta.tessno.com`
resolves to `104.21.9.204`, which exposes `:443` with `service: https`; the
subdomain's own record carries only `dns_resolved: true` and a signal saying
"an exposed service" — never the protocol.

**And the same claim shape was labelled both ways.** Eight claims shared it;
five were marked supported and three unsupported. `www.tessno.com` and
`beta.tessno.com` carry the *identical sentence*, on sibling subdomains of
one target, with identical facts, labelled oppositely. That is not
carelessness — it is an undecidable call, and the annotator had flagged the
same ambiguity in the first pass ("a good chance its HTTPS as the claim say.
however it could be different too"). Left unresolved, it got answered both
ways.

The consequence is what forced the fix. Applied consistently, the same 78
labels give:

| convention | agreement | precision | recall | kappa |
|---|---|---|---|---|
| as labelled (mixed) | 0.962 | 1.000 | 0.667 | 0.780 |
| lenient — all 8 supported | 1.000 | 1.000 | 1.000 | 1.000 |
| strict — all 8 unsupported | 0.897 | 1.000 | 0.429 | 0.552 |

**Precision is robust; recall is not.** It swings 0.429 to 1.000 on nothing
but which convention is applied. A number that unstable is not a measurement
of the judge, so the answer is to remove the ambiguity rather than adjudicate
it: give the judge the evidence, and the question stops being a matter of
convention.

**`_linked_facts`, and the bound that keeps it honest.** A finding's evidence
now includes facts about entities it connects to, two hops (the distance the
real cases sat at: subdomain → IP → service). **Only entities that are
themselves narrated get described.** The narrator receives every top-priority
finding in one batch, so a fact about one of those is a fact the narrator had;
describing anything else would hand the judge evidence the narrator never saw,
and it would ratify invention that happens to be true. The walk still passes
*through* un-narrated nodes, because the connecting hop routinely is one — the
`ip_address` between a subdomain and its service often does not make the top
five. Traversing a node discloses nothing about it.

**This partly reinstates the mechanism retracted above, and the distinction
matters.** The retraction stands exactly as written: linked-entity scoping was
*not* why the judge over-flagged, and all 21 false flags had their evidence in
hand. What was wrong was the symptom it was attached to. The mechanism is real
and explains a different, much smaller effect — one that only became visible
once the over-flagging noise was removed. Right diagnosis, wrong disease.

**A defect this introduced, caught before it shipped.** The first version
walked `subdomain_of`, producing "It is connected, via is a subdomain of then
resolves to, to ip address 104.21.88.220" for `*.hazelmoor.org` — a wildcard
entry that resolves to nothing. It reads as evidence that the wildcard
resolves, and the judge duly accepted "resolves to a live IP address": a real
fabrication ratified by evidence this change had invented. `subdomain_of`
points at a *parent*, and a parent's properties are not the child's. It is now
excluded from traversal while still being described as a first-hop fact, and a
test pins the distinction. Recorded because the failure mode is the exact one
the narrator-equivalence bound exists to prevent, arriving by a route that
bound did not cover.

**Where it stands.** 107 claims (richer evidence decomposes further), 9
flagged. Of 50 carried labels, 4 disagree: two are labels made before the
evidence existed and are worth revisiting, one is a missed fabrication
(`*.yulan.me`, "Resolves to a live IP", no linked facts — the same judge flags
the full sentence on the same entity and accepts the fragment), one is a false
flag on a `web_tech`. **57 claims remain unlabelled, so there is no headline
figure for this configuration yet, and the numbers above must not be quoted as
one.** The residual `*.yulan.me` case is worth noting on its own: it is
decomposition-dependent inconsistency, which no amount of better evidence
fixes.

---

**2026-08-06 (later) — linked evidence labelled, and a hierarchy nobody
intended.**

The linked-evidence packet was labelled in full: 107 claims, **flag precision
0.444, recall 0.500, agreement 0.916, kappa 0.425.** Precision had fallen from
1.000, and the annotator spotted why before any analysis: the judge was
flagging exposed-service claims whose evidence sat right there in
`linked_facts`.

Four of the five false flags were exactly that. The clearest, `#101`: the
claim text was **verbatim identical** to the linked fact it was being checked
against, and the judge called it unsupported.

**The cause was in the prompt, and it was self-inflicted.** The preamble
introduced `plain_facts` as *"everything known about the entity"* and then, a
bullet later, described `linked_facts` as evidence too. The earlier, stronger,
more absolute claim won: anything outside `plain_facts` read as not known.
Putting linked facts in a field of their own made them look like a footnote to
the real evidence.

This is the *same defect, a third time*. The original packet separated
`attributes` from `signals` and a human read signals as commentary. The judge
then read a separate `linked_facts` as lesser. **Splitting evidence into
labelled compartments teaches the reader — human or model — that some
compartments count less, whatever the surrounding prose says.** The fix each
time is the same: one list, one status. Linked facts now append to
`plain_facts`, and since the sentences read "It is connected, via ... to ...",
provenance is still legible without a field implying rank.

Result on the claims carrying existing labels: **flag precision 0.444 → 1.000,
and zero claims flagged despite a connected fact naming a service (was four).**

**The trade-off that keeps reappearing, now recorded as a property rather than
rediscovered.** Across six prompt variants the same curve holds: permissive
wording gives high precision and occasionally accepts a fabrication;
strict wording collapses precision. Two attempts at "strict but targeted"
scored 0.111 and 0.167; a third, tried specifically to catch the one residual
miss, dropped precision from 1.000 to 0.600 and made the judge start
manufacturing claims out of the fact list and then flagging them — violating
the one rule the preamble states twice. The permissive wording is kept
deliberately, with its known cost stated below.

**The known cost.** `*.yulan.me` is a wildcard entry with no resolution fact
and no connected facts at all, narrated as "resolves to a live IP with an
exposed HTTPS service". The current prompt accepts it. That is a real
fabrication passing the judge.

Worth noticing what kind of failure it is: **deterministic and structural.**
An entity with no `resolves_to` edge and no `dns_resolved` attribute cannot
resolve, and no LLM is required to know that. Stage 1 already does structural
checking (D1) and is currently limited to "does this entity exist". Extending
it to a small set of contradiction checks would catch this class outright
rather than hoping a prompt phrasing holds — and would be free, exact and
reproducible, which the judge is none of. Recorded as the direction rather
than built here, because it changes what D1 means and deserves its own
decision.

**Also observed.** The annotator labelled the identical sentence differently
on sibling subdomains again (`beta`/`api.tessno.com` unsupported,
`www.tessno.com` supported, same target, same facts). Those two are labels
made before linked evidence existed and carried forward untouched, which is
the mechanism working as designed — carry-over preserves a ruling rather than
silently re-deciding it — but it means a stale label survives until someone
revisits it. Anything carried across a change of evidence should be re-read,
not just the blanks.

**Status.** The merged-evidence configuration produces 136 claims, of which 52
carry labels and **84 are unlabelled**. There is no published figure for it.
The last fully-labelled configuration is the one measured at the top of this
entry: **107 claims, precision 0.444, recall 0.500** — superseded by a fix
whose effect is measured only on the carried subset.
