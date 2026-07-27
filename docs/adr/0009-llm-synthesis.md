# ADR-0009 — LLM Synthesis (Ollama Integration)

- **Status:** Accepted (v0.1.0 — implemented and validated against a real owned target, `larnby.com`, and the full 10-target ground-truth set, 2026-07-27; see Validation)
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
3. ~~`temperature: 0` is the most-reproducible choice, but some models' `/api/generate` behaviour with `format: json` under temperature 0 can degenerate (repetition loops)~~ — **resolved empirically, see Validation:** no repetition loops observed across any of the 4 models actually tested; `temperature: 0` held up fine.
4. Should there be a `--llm-timeout` override exposed, or is the 120s default enough for v1? Deferred until real timing data from actual runs exists — nothing observed close to 120s in practice so far.
5. **New, raised by real validation:** faithfulness stage 1 reads 1.000 under real LLM narration too, not just the template — see Validation. Is that acceptable as "stage 1 correctly does its narrow job" (an accepted limitation, since stage 1 was only ever documented as a structural id-existence check), or does it mean stage 1's number is actively misleading until stage 2 exists, and should be labelled more defensively in `glean eval`'s own output? Not resolved here.

## Validation

**2026-07-27, against `larnby.com` and then the full 10-target ground-truth set, across 4 of the 5 locally-pulled models.**

**Real bug found on the first real call, before any test suite could catch it:** the very first live call (`llama3.2:latest`) returned `narrated=0, fell_back=5` — degradation worked exactly as designed, but the model's actual output was worth reading. Ollama's `format: json` mode constrains generation to a top-level JSON *object*, not any valid JSON value — so the bare top-level array the original prompt asked for was never actually achievable, and every model improvised its own way to reconcile that constraint with the instruction:

- `llama3.2:latest` wrapped the entire array under one synthetic, unrelated single key.
- `llama3.1:8b` and `phi3:latest` both returned a single bare finding object — no array, no wrapper — narrating only the first finding and silently ignoring the "one object per input finding" instruction.
- `mistral:latest` wrapped it under `{"findings": [...]}`, unprompted — the only model that happened to guess a sensible shape.

Fixed by changing the prompt to explicitly request `{"findings": [...]}` (matching the shape `mistral` already produced naturally) and making `_parse_response` defensively unwrap all four real shapes observed (bare list, `findings` key, any single-key object wrapping a list, and a single bare finding object) rather than assuming any one of them — regression-tested for all four in `tests/test_synthesis.py`. After the fix, re-tested against the same 4 models: `llama3.2:latest`, `llama3.1:8b`, and `mistral:latest` all narrated `5/5` findings correctly; `phi3:latest` (the smallest model tested) still only managed `2/5`, gracefully falling back to template text for the other 3 — not a bug, a real and legitimate data point about that model's weaker instruction-following on this exact task. (`phi3:medium` wasn't separately tested in this pass.)

D6 (degradation) confirmed directly: the pre-fix broken run degraded the entire brief to template with zero crash; the per-finding fallback path was exercised for real by `phi3:latest`'s partial response. `check_brief_contract` passed on every real narrated brief produced, as D1 predicted it structurally must.

**The validation section's own prediction — "faithfulness stops being trivially 1.000 the moment `--llm` is used" — turned out to be wrong, and the reason why is the actually interesting result.** Running `glean eval --llm` across all 10 ground-truth targets produced *identical* faithfulness (1.000), provenance retention (1.000), and prioritisation-quality numbers (mean `overlap@5 = 0.464`, mean `nDCG@5 = 0.582`) to the template-only run. This is not a bug: `faithfulness_stage1` only checks whether a finding's entity id exists in the graph, and `synthesize_brief` (D5, step 2) already discards any invented entity id *before* it can ever reach the brief — so as long as that filtering keeps working correctly, stage 1 is structurally incapable of reading anything other than 1.000, whether the narration is template or real LLM prose. Provenance retention and prioritisation quality are equally untouched by design (D1: the model only ever changes `body`/`why_ranked` text, never entity references, ordering, or provenance). The real, uncaught fabrication risk — a real entity given a false *attribute* in its prose (e.g. stating the wrong port, or a reason that doesn't match its actual signals) — is exactly what stage 2 needs an LLM judge to catch, and doesn't exist yet. Recorded as open question 5 above rather than silently left as a misleading number.
