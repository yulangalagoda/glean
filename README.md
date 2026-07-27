# Glean

**OSINT synthesis tool** — unifies open-source reconnaissance tools into a single, provenance-tracked, LLM-prioritised intelligence report.

Existing OSINT automation excels at *collection* but fails at *judgment*: results arrive as flat, unprioritised piles with no clear provenance and no sense of what actually matters. Glean addresses that gap — a curated set of reputable FOSS tools, unified into one entity model, with a local LLM producing a prioritised, human-readable brief you can trust.

> Status: early development. Package name reserved on PyPI as [`glean-osint`](https://pypi.org/project/glean-osint/).

## Pipeline

1. **Collect** — run a curated set of maintained FOSS OSINT tools against a target.
2. **Normalise** — merge findings into one provenance-tracked entity schema.
3. **Correlate** — deterministic dedup and entity-linking (in code, not the LLM).
4. **Synthesise** — a prioritised intelligence brief. Currently template-based;
   local-LLM narration (via Ollama) is planned but not wired in yet.
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

## Scope & ethics

For authorised security research only — targets you own or are explicitly cleared to assess. Passive and active reconnaissance are clearly separated. Full policy and threat model: [`docs/ETHICS.md`](docs/ETHICS.md). Found a vulnerability in Glean itself? See [`SECURITY.md`](SECURITY.md).

## Licence

MIT © Yulan Galagoda
