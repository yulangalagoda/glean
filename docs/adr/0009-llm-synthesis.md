# ADR-0009 — LLM Synthesis (Ollama Integration)

- **Status:** Proposed — not yet implemented
- **Date:** 2026-07-27
- **Scope:** Glean v1 — how a real local LLM (via Ollama) replaces the current template-based prose in the brief, without touching anything ADR-0005 already fixed
- **Depends on:** ADR-0005 (brief contract — D1–D6 already specify exactly what the model is and isn't allowed to do; this ADR is purely about *how* a real model gets called and validated, not what it's allowed to say), ADR-0004 (the score/signals the model narrates but never computes), ADR-0006 (faithfulness stage 1 already checks this narration structurally; this is the first time stage 1 has real teeth)
- **Feeds:** the charter's actual thesis (§2) — faithfulness/prioritisation-quality/provenance-retention are only measuring something real once real model output exists to measure

## Context

Every other piece of this project has been built and validated already; this is the one still missing. `brief.py`'s own module docstring has said since it was written: "No LLM is wired into this project yet... swapping in a real LLM later only touches the prose, never the skeleton." ADR-0005 D1–D6 already fully specify that contract — this ADR does not reopen it. What's actually undecided is entirely mechanical: how Ollama gets called, which models, what prompt, and how a real model's output gets validated before it's trusted (the current `check_brief_contract` function was written for exactly this moment — "these checks have real teeth" once a real LLM writes the prose — but has only ever run against trivially-faithful template output until now).

Checked before writing this: Ollama is already installed and running on this machine (v0.24.0, daemon live on `localhost:11434`), with 5 models already pulled — `llama3.1:8b`, `llama3.2:latest`, `mistral:latest`, `phi3:latest`, `phi3:medium` — which already covers the roadmap's "a 7–8B class and a smaller 3–4B class... decide 2–3 models to evaluate, not one" ask (Workstream D1) without any new setup.

## Decision

### D1 — Scope: `body` and `why_ranked` only, never `headline`

Looking at what `brief.py`'s template functions actually produce: `_headline` is a short structural label ("subdomain, confirmed live") — closer to part of the skeleton than to prose. `_body` (a factual sentence) and `_why_ranked` (signals translated to English) are the genuinely prose-shaped parts, and the only ones a model's natural-language variation would meaningfully change. The LLM replaces only `body` and `why_ranked`; `headline`, ordering, provenance lines, and footer counts stay exactly as `build_brief` already computes them — this is the literal, minimal reading of ADR-0005 D1 ("the model narrates only what is in the graph... it does not design the document"), not a new decision.

### D2 — Only `top_priorities` gets narrated, not `also_found`

Narrating every entity in a large graph (`yulan.me` alone has 150+) would make every scan slow and expensive for no real benefit — `also_found` is deliberately the noisy tail, per the charter's own framing, not what a reader is meant to focus on. Only the `top_n` (default 5) `top_priorities` findings go to the model; `also_found` stays template-rendered. This keeps prompt size and latency bounded regardless of graph size, and puts model effort exactly where a human would actually read.

### D3 — Invocation: Ollama's HTTP API directly, no new dependency

`POST http://localhost:11434/api/generate` with `"format": "json"` (Ollama's built-in structured-output mode) and `"stream": false` (one complete response, not chunks to reassemble) and `"options": {"temperature": 0}` (deterministic as practically achievable — this project already cares about reproducibility, roadmap E4). Called via stdlib `urllib`, same choice already made for crt.sh in `runner.py` — no new pip dependency for something a ~10-line HTTP POST already does.

### D4 — Prompt: one call per brief, structured JSON in and out

A single call per scan (not one per finding — bounded cost, and lets the model see all `top_n` findings together for consistent tone) sends a compact JSON array of finding facts (`entity_id`, `type`, `display_value`, the same `attributes` the template already reads, `seen_by`, and — for narrating `why_ranked` — the `priority.signals` list, translated through the *same* `SIGNAL_PHRASES` map the template uses, not raw signal names, so the model is grounded in the identical vocabulary a human reviewing the ADR-0004 rubric would recognise). The system/instruction preamble states the hard rules directly: only narrate the entities given, never invent one, never state a fact not present in the given data, output must be a JSON array of `{entity_id, body, why_ranked}` in the same order.

### D5 — Validation: never trust the model's structure, only its prose

After the call returns:
1. If the response isn't parseable JSON, or isn't a list — discard entirely, fall back to the fully-template brief for this scan (same all-or-nothing degrade as a failed live tool invocation, ADR-0008 D5).
2. Build a map from `entity_id` to `{body, why_ranked}`, keeping only items whose `entity_id` matches an *expected* top-priorities id — any invented id is dropped, not surfaced, and counted (a real, if partial, stage-2-style faithfulness signal: the model tried to narrate something not in the graph).
3. Per finding: if the model supplied a non-empty string for `body` (and `why_ranked`, where applicable), use it; otherwise keep that one finding's template text. This is per-finding graceful degradation, not all-or-nothing — the same philosophy as every other stage of this project (ADR-0002 D5, ADR-0008 D5), just applied one level higher.
4. Run the existing `check_brief_contract` against the result before returning it. It should always pass by construction (D1 above guarantees ordering/provenance/footer counts are untouched), but it's the cheap, already-written final gate, and running it is what the function's own docstring has been waiting for since it was written.

None of this is faithfulness stage 2 (ADR-0006 D1 — an LLM-judge checking a real entity got an *invented attribute*, which needs a separate judge call this ADR doesn't build). Step 2 above is a structural check (does the id exist at all), not a content check (is what's said about it true) — a real stage 2 is future work, tracked as an open question below, not solved here.

### D6 — Degradation and timeouts

Local inference is slow and hardware-dependent — a generous default timeout (120s, configurable) applies to the whole call. A timeout, a connection failure (Ollama not running), or a requested model not being pulled are all treated identically to any other degraded tool: log a warning, fall back to the template brief, never abort the scan. `glean scan` without LLM synthesis must keep working exactly as it does today regardless of whether Ollama is installed at all.

### D7 — CLI: opt-in, same conservative rollout as `--live`

`glean scan <domain> --llm [--model TAG]` (default model: `llama3.2:latest` — the smallest/fastest of the five pulled, for quick iteration; comparing models, per roadmap D1, is just re-running with a different `--model`, not new code). Without `--llm`, behaviour is completely unchanged — zero regression risk, zero new test flakiness, same reasoning as ADR-0008 D6's `--live` rollout.

## Consequences

- **Positive:** the charter's actual thesis becomes measurable for the first time — `glean eval`'s faithfulness/provenance-retention numbers stop being trivially 1.000 the moment `--llm` is used, because there's finally something that could fabricate. Per-finding degradation means one bad model response never blanks out an entire brief. No new runtime dependency. Comparing models is free (just a flag), directly serving the roadmap's "compare across local models" contribution goal.
- **Costs / accepted limits:** only `top_priorities` gets real narration in v1 — `also_found` staying template-only is a deliberate scope cut, not an oversight, but it does mean the faithfulness numbers only ever measure the narrated slice, not the whole brief. Real stage-2 faithfulness (content-level fabrication, not just id-existence) still doesn't exist after this ADR — this only makes stage 1 meaningful, which is real progress but not the whole picture the charter eventually wants.

## Open questions

1. Should `also_found` eventually get narrated too (at least a lighter-weight pass), or does the charter's "one-page brief in under 2 minutes" framing mean the tail is *supposed* to stay terse and template-only forever? Leaning toward the latter, not resolved here.
2. Real stage-2 faithfulness (an LLM-judge checking for invented attributes on an otherwise-real entity) — separate ADR territory once this lands and there's real narrated output to judge.
3. `temperature: 0` is the most-reproducible choice, but some models' `/api/generate` behaviour with `format: json` under temperature 0 can degenerate (repetition loops) — worth confirming empirically per model during implementation, and adjusting per-model if one specific model needs it, rather than assuming the same settings suit all five pulled models equally.
4. Should there be a `--llm-timeout` override exposed, or is the 120s default enough for v1? Deferred until real timing data from actual runs exists.

## Validation

Not yet implemented. Once built, validated the same way every other stage of this project was: real calls against real owned targets (start with a small one, e.g. `larnby.com`, to keep iteration fast), confirming (a) a genuinely broken/unreachable Ollama degrades to the template brief without aborting the scan, (b) a deliberately-malformed model response degrades per-finding rather than blanking the whole brief, (c) `check_brief_contract` passes on real model output, and (d) running `glean eval --llm` afterward produces faithfulness/provenance-retention numbers that are no longer trivially 1.000 — the actual point of building this.
