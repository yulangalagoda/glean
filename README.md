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
glean scan example.com \
  --crtsh path/to/crtsh-output.json \
  --theharvester path/to/theharvester-output.json \
  --dnsx path/to/dnsx-envelope.json \
  --httpx path/to/httpx-output.jsonl
```

`glean scan` is ingest-only for now: it builds the brief from raw tool
output you've already fetched yourself; live invocation isn't built yet.
`--crtsh`/`--theharvester`/`--dnsx` are passive; `--httpx` is **active** —
it sends real HTTP requests at the target, so only point it at hosts
you're authorised to probe directly (see [`docs/ETHICS.md`](docs/ETHICS.md)).

## Scope & ethics

For authorised security research only — targets you own or are explicitly cleared to assess. Passive and active reconnaissance are clearly separated. Full policy and threat model: [`docs/ETHICS.md`](docs/ETHICS.md). Found a vulnerability in Glean itself? See [`SECURITY.md`](SECURITY.md).

## Licence

MIT © Yulan Galagoda
