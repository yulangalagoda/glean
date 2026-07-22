# Glean — Project Charter

*Phase 0 keystone document. Working title: Glean. Package: [`glean-osint`](https://pypi.org/project/glean-osint/).*

---

## 1. Problem statement

Open-source OSINT automation is mature at **collection** and weak at **judgment**.

Tools such as SpiderFoot, Recon-ng, theHarvester, Amass and Maltego CE can gather
enormous volumes of reconnaissance data from hundreds of sources. But the output of
that collection is, in practice, a flat pile: hundreds to thousands of findings, with
no reliable prioritisation, no clear provenance surfaced to the analyst, and no synthesis
into something a human can act on quickly.

This was confirmed by direct observation. A single `all` scan of one low-value domain
in SpiderFoot produced ~960 findings whose headline "correlations" were nine low-priority
notes about unrelated shared-hosting neighbours — collection succeeded; judgment did not.
The analyst is left to do by hand the very work the tool was meant to save: figure out
what came from where, what matters, and what to ignore.

A recent generation of prototypes (e.g. *OSINT-with-LLM*, *OpenOSINT*, *OSINTai*) bolts a
local LLM onto tool output to auto-write a report. These prove the pattern is buildable,
but they are self-described proofs-of-concept and **none of them evaluate whether the
LLM's synthesis is trustworthy** — whether it invents findings, misranks severity, or
loses provenance.

## 2. Thesis (the contribution)

> **Glean is a local-LLM OSINT synthesis pipeline, built as the vehicle for a systematic
> evaluation of whether small, locally-run models can faithfully prioritise and preserve
> provenance when synthesising structured, multi-tool reconnaissance output.**

The tool is the deliverable; the **evaluation is the research**.

### Why this is novel (and defensible)

Existing security-LLM evaluation work measures faithfulness over **text-to-text** tasks:

- **CTIBench** (NeurIPS 2024) — Q&A / multiple-choice over CTI *knowledge*.
- **RAGIntel** (PeerJ, 2025) — RAG over MITRE ATT&CK *prose*; notably finds models
  underperform on faithfulness and factual correctness.
- General faithfulness machinery — RAGAS, DeepEval, FaithBench, FaithJudge — all built
  for prose inputs and answers.

None of these measure faithfulness over the artifact Glean produces: a
**synthesis-and-prioritisation over a structured entity graph** assembled from multiple
heterogeneous tools. Glean's input is not prose but normalised entity records; its output
is not an answer but a *ranked judgment with provenance*. That input/output combination
is the unmeasured gap.

This positioning also aligns with a chain-of-thought-faithfulness research direction:
does the model's stated prioritisation rationale actually reflect the evidence it was
given, or does it confabulate a justification?

## 3. Scope

### In scope (v1)

- **One entity domain: infrastructure / domain reconnaissance.** Domains, subdomains, IPs,
  DNS, email/breach exposure, web tech. Most testable, least ethically fraught.
- **A small, curated set of 4–6 reputable, actively-maintained FOSS tools** with
  machine-readable output.
- **A normalised entity schema** with provenance (`source_tool`) as a first-class field.
- **Deterministic correlation** (dedup, entity-linking) done in code, not the LLM.
- **Local LLM synthesis** via Ollama, producing a prioritised brief.
- **CLI first.**
- **An evaluation harness** measuring faithfulness, prioritisation quality, and provenance
  retention against a small hand-built ground-truth set.

### Explicitly out of scope (v1)

- People-focused OSINT (usernames, real names, social) — higher legal/abuse risk; deferred.
- GUI / graph visualisation — deferred to roadmap.
- Large or cloud LLMs as the primary engine — the research question is about *small local* models.
- Real-time / continuous monitoring.
- Letting the LLM do the entity-linking/correlation — deliberately kept deterministic.

### Ethics & authorisation (binding)

- For authorised research only: targets owned or explicitly cleared.
- Passive and active reconnaissance clearly separated; active requires explicit opt-in.
- Provenance retained end-to-end so every claim is traceable to its source tool.

## 4. Measurable goals (MVP definition of done)

The MVP is **done** — not "improvable", *done* — when all of the following hold:

1. **Runs end-to-end from the CLI**: `glean scan <domain>` → one report, no manual steps.
2. **Unifies ≥4 FOSS tools** into a single provenance-tracked entity model.
3. **Deterministic dedup** collapses duplicate entities across tools (measured: duplicate
   rate before/after).
4. **Produces a one-page prioritised brief** a human can action in **under 2 minutes**.
5. **Evaluation harness reports three numbers** on a ground-truth set of ≥10 target scans:
   - **Faithfulness**: does the brief contain findings *not* present in the input? (target: 0 fabricated findings)
   - **Prioritisation quality**: does the top-of-brief match the human-rated priorities?
   - **Provenance retention**: is every surfaced finding traceable to its source tool?

Hitting these marks the MVP as complete and defensible. Everything below is *extra*.

## 5. Roadmap (post-MVP — NOT on the MVP critical path)

Captured here so ambition is recorded without blocking the deadline. Nothing in this
section is started until Section 4 is fully met.

- Additional tools; plugin/adapter interface so a new tool is a ~50-line adapter.
- Second entity domain (people OSINT) with the ethics work it requires.
- GUI: prioritised entity graph (fixing the "hairball" problem) + readable report view.
- Performance: async orchestration, caching, rate-limit handling.
- Larger evaluation: more targets, inter-rater agreement, comparison across local models.
- CoT-faithfulness deep-dive: does the model's stated reasoning match the evidence?
- Compare small-local vs large-cloud synthesis on the same faithfulness metrics.

## 6. Operating principle

**Ship the small complete thing first; then compound.** The MVP runs on a fast clock
(weeks). The longer-term contribution — rigorous evaluation of small-model faithfulness on
structured intel — runs on a slower, patient clock, because it is unsolved work and that is
exactly why it matters. Both are real. They are not the same clock.

---

*Foundational references to cite: CTIBench (Alam et al., NeurIPS 2024); RAGIntel (PeerJ 2025);
RAGAS / FaithBench / DeepEval for evaluation method; SpiderFoot as the documented incumbent
case study; OSINT-with-LLM / OpenOSINT / OSINTai as prior-art prototypes.*
