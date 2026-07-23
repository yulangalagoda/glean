# ADR-0006 — Evaluation Protocol: the Three Numbers (v1)

- **Status:** Accepted (v0.1.0 — hand-validated 2026-07-23 against a real target under ADR-0007's protocol; see Validation)
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

1. **Judge model for D1 stage 2** — a small local model (consistent with the charter's core thesis, but may judge worse) vs. a fixed, pinned larger/cloud model used only for scoring (better judging, but a reproducibility and "is this still testing what we claim" question). Leaning: attempt a local judge first since it keeps the whole pipeline within the project's own thesis; fall back to a specific pinned cloud model version, documented explicitly, only if local judging proves unreliable in practice.
2. Exact atomic-claim decomposition prompt template — not drafted yet; needs to happen alongside D1's implementation, not before (RAGAS's own finding that JSON-structured judge output is more consistent than free text should inform it).
3. nDCG@N vs. overlap@N as the *headline* reported number when only one fits in a summary table — leaning overlap@N for legibility, nDCG@N always available in full results.
4. Ground-truth ranking tie-break rule — explicitly deferred to F2, not decided here.

## Validation

**2026-07-23, against `yulan.me`:** D2's formulas (`overlap@N`, `nDCG@N`) were computed for real against a blind human ground-truth ranking produced under ADR-0007. Result: near-zero initial agreement (`overlap@3 = 0.0`, `nDCG@3 ≈ 0.20`) traced to a real, previously-undiscovered ADR-0004 gap (dead, never-renewed certificates scoring as high as anything in the graph), not a flaw in the metric itself. After fixing that gap (`cert_orphaned`, see ADR-0004 D2), agreement rose substantially (`overlap@3 = 0.5`, `nDCG@3 ≈ 0.43`), with one residual, honestly-reported disagreement left open by design. D1/D3 were checked mechanically only (formulas compute correctly against a hand-rendered brief) — a real fabrication-resistance test still requires an actual LLM-generated brief, not yet built. Full findings: `_private/findings/yulan-me-ground-truth-validation.md` (private — real domain name).
