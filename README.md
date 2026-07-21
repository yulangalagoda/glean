# Glean

**OSINT synthesis tool** — unifies open-source reconnaissance tools into a single, provenance-tracked, LLM-prioritised intelligence report.

Existing OSINT automation excels at *collection* but fails at *judgment*: results arrive as flat, unprioritised piles with no clear provenance and no sense of what actually matters. Glean addresses that gap — a curated set of reputable FOSS tools, unified into one entity model, with a local LLM producing a prioritised, human-readable brief you can trust.

> Status: early development. Package name reserved on PyPI as [`glean-osint`](https://pypi.org/project/glean-osint/).

## Planned pipeline

1. **Collect** — run a curated set of maintained FOSS OSINT tools against a target.
2. **Normalise** — merge findings into one provenance-tracked entity schema.
3. **Correlate** — deterministic dedup and entity-linking (in code, not the LLM).
4. **Synthesise** — a local LLM (via Ollama) produces a prioritised intelligence brief.
5. **Report** — one readable output; CLI first, GUI later.

## Scope & ethics

For authorised security research only — targets you own or are explicitly cleared to assess. Passive and active reconnaissance are clearly separated.

## Licence

MIT © Yulan Galagoda
