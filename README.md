# Glean

**OSINT synthesis tool** — unifies open-source reconnaissance tools into a single, provenance-tracked, LLM-prioritised intelligence report.

Existing OSINT automation excels at *collection* but fails at *judgment*: results arrive as flat, unprioritised piles with no clear provenance and no sense of what actually matters. Glean addresses that gap — a curated set of reputable FOSS tools, unified into one entity model, with a local LLM producing a prioritised, human-readable brief you can trust.

> Status: early development. Package name reserved on PyPI as [`glean-osint`](https://pypi.org/project/glean-osint/).

## Pipeline

1. **Collect** — run a curated set of maintained FOSS OSINT tools against a target.
2. **Normalise** — merge findings into one provenance-tracked entity schema.
3. **Correlate** — deterministic dedup and entity-linking (in code, not the LLM).
4. **Synthesise** — a prioritised intelligence brief. Template-based by
   default; `--llm` narrates "Top priorities" with a real local model via
   Ollama instead (ADR-0009).
5. **Report** — one readable Markdown output; CLI first, GUI later.

## Quickstart

```
pip install -e ".[dev]"

# Live: actually invoke tools (requires theHarvester/dnsx/httpx installed)
glean scan example.com --live
glean scan example.com --live --active   # also runs httpx (ACTIVE — see below)

# Ingest-only: build the brief from raw output you've already fetched
glean scan example.com \
  --crtsh path/to/crtsh-output.json \
  --theharvester path/to/theharvester-output.json \
  --dnsx path/to/dnsx-envelope.json \
  --httpx path/to/httpx-output.jsonl
```

A per-tool file option overrides live invocation for that specific tool,
even with `--live` (mixed mode). `crt.sh`/`theHarvester`/`dnsx` are
passive; `httpx` is **active** — it sends real HTTP requests at the
target, so it's never invoked without an explicit `--active` flag, and
you should only use it against hosts you're authorised to probe directly
(see [`docs/ETHICS.md`](docs/ETHICS.md)).

Add `--llm [--model TAG]` to narrate "Top priorities" with a real local
model via [Ollama](https://ollama.com) instead of the deterministic
template (requires Ollama running locally with the model pulled).
`headline` and everything else in the brief's structure stay
template-generated regardless — the model only ever writes prose, never
chooses what's included or how it's ordered (ADR-0005). A failed or
malformed model response falls back to the template per-finding, never
aborts the scan.

## Evaluation

```
glean eval [--scans-dir eval/scans] [--top-n 5] [--llm [--model TAG]]
```

Runs the full pipeline against every target under `--scans-dir` that has
both raw tool output (`<slug>/raw/`) and a ground-truth ranking
(`<slug>/ground_truth.yaml`, ADR-0007), then reports the charter's three
headline numbers per target and averaged across the set: faithfulness,
provenance retention, and prioritisation quality (`overlap@N`/`nDCG@N`
against an independent human ranking). Faithfulness/provenance-retention
read 1.0 either way today — real LLM narration (`--llm`) doesn't change
that, since stage 1 only checks whether a finding's entity exists at all
(and invented entities are already filtered before they'd reach the
brief); catching a real entity given a *false* detail in its prose needs
a separate LLM-judge pass (stage 2) this project doesn't have yet.
Prioritisation quality is the metric that's actually meaningful today.

## Scope & ethics

For authorised security research only — targets you own or are explicitly cleared to assess. Passive and active reconnaissance are clearly separated. Full policy and threat model: [`docs/ETHICS.md`](docs/ETHICS.md). Found a vulnerability in Glean itself? See [`SECURITY.md`](SECURITY.md).

## Licence

MIT © Yulan Galagoda
