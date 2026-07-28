# Glean

**OSINT synthesis tool** — unifies open-source reconnaissance tools into a single, provenance-tracked, LLM-prioritised intelligence report.

Existing OSINT automation excels at *collection* but fails at *judgment*: results arrive as flat, unprioritised piles with no clear provenance and no sense of what actually matters. Glean addresses that gap — a curated set of reputable FOSS tools, unified into one entity model, with a local LLM producing a prioritised, human-readable brief you can trust.

> Status: early development. Package name reserved on PyPI as [`glean-osint`](https://pypi.org/project/glean-osint/).

## Pipeline

1. **Collect** — run a curated set of maintained FOSS OSINT tools against a target
   (crt.sh, theHarvester, subfinder, dnsx, httpx).
2. **Normalise** — merge findings into one provenance-tracked entity schema.
3. **Correlate** — deterministic dedup and entity-linking (in code, not the LLM).
4. **Synthesise** — a prioritised intelligence brief. Template-based by
   default; `--llm` narrates "Top priorities" with a real local model via
   Ollama instead (ADR-0009).
5. **Report** — Markdown by default; `--out report.html` writes a
   self-contained HTML report instead (ADR-0010). Bare `glean` (no
   subcommand) launches a local web interface (ADR-0011).

## Web interface

```
glean
```

Serves on `http://127.0.0.1:8420` — **localhost only by design**: an
unauthenticated control plane that can trigger active reconnaissance must
not be reachable from the network. Binding elsewhere with `--host` is
possible and puts a standing warning banner on every page.

It is additive, not a replacement — `glean scan` and `glean eval` are
unaffected — and both surfaces write into one shared history, so a scan run
from the terminal shows up in the browser and vice versa.

- **Scan form** — tool selection with presets, an inline ethics warning the
  moment an active-method tool is ticked, and a live preview of the
  equivalent `glean scan ...` command so the UI is never a black box.
- **Live progress** — per-stage checklist and a streaming log over SSE, with
  degraded-tool warnings appearing as they happen.
- **Brief** — the same report `--out report.html` writes, plus filtering by
  type/tool/signal/triage, a sortable and paginated "Also found" table,
  copy-to-clipboard on every value, score breakdowns, clickable provenance
  that opens the tool's real archived output, and per-finding deep links.
- **Relationships** (`/scan/<id>/graph`) — the correlation stage made
  visible: each finding with its typed relations (`resolves_to`,
  `subdomain_of`, `hosts`, …) fanning out beneath it.
- **Triage** — mark findings reviewed / flagged / false-positive; the state
  persists per scan and doubles as a filter.
- **History** — scans grouped by target, filterable by tool, date and
  has-warnings, with scan-to-scan diffing ("3 new subdomains since last
  time"), re-run, and delete.
- **Export** — HTML, JSON and CSV.

Narration with a local LLM is available here too (see below); the model that
actually wrote a brief's prose is recorded and shown against that scan in
the history.

## Quickstart

```
pip install -e ".[dev]"

# Web interface: scan form, live progress, browsable history
glean

# Live: actually invoke tools (requires theHarvester/subfinder/dnsx/httpx installed)
glean scan example.com --live
glean scan example.com --live --active   # also runs httpx (ACTIVE — see below)

# Ingest-only: build the brief from raw output you've already fetched
glean scan example.com \
  --crtsh path/to/crtsh-output.json \
  --theharvester path/to/theharvester-output.json \
  --subfinder path/to/subfinder-output.jsonl \
  --dnsx path/to/dnsx-envelope.json \
  --httpx path/to/httpx-output.jsonl
```

A per-tool file option overrides live invocation for that specific tool,
even with `--live` (mixed mode). `crt.sh`/`theHarvester`/`subfinder`/`dnsx`
are passive; `httpx` is **active** — it sends real HTTP requests at the
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
aborts the scan — and because that fallback is silent by construction, it
is reported explicitly: a run that asked for narration and got none says so
rather than quietly handing back template prose. The same toggle exists on
the web scan form.

Scans run with `--live` (and every scan run from the web interface) are
archived under `~/.local/share/glean/scans/<scan_id>/`: the raw tool output,
the rendered brief, and structured `entities.json` / `edges.json` snapshots
that power export, diffing and the relationships view.

## Evaluation

```
glean eval [--scans-dir eval/scans] [--top-n 5] \
  [--llm [--model TAG] [--judge-model TAG]]
```

Runs the full pipeline against every target under `--scans-dir` that has
both raw tool output (`<slug>/raw/`) and a ground-truth ranking
(`<slug>/ground_truth.yaml`, ADR-0007), then reports the charter's three
headline numbers per target and averaged across the set: faithfulness,
provenance retention, and prioritisation quality (`overlap@N`/`nDCG@N`
against an independent human ranking). Faithfulness stage 1 and
provenance retention read 1.0 either way — stage 1 only checks whether a
finding's entity exists at all, which invented entities are already
filtered out before ever reaching the brief. With `--llm`, a second
faithfulness number (`stage2_faith`) also appears: a real, different
local model judges whether the narrated *prose* actually states only
facts supported by that entity's real data (ADR-0006 D1 stage 2,
ADR-0006 D4 requires the judge to differ from the narration model —
`--judge-model` defaults to a different, larger model than `--model`).
Treat the judge's own output with real skepticism — real validation
found the judge itself makes mistakes (see ADR-0006's Validation
section), so `stage2_faith` is closer to a lower bound on true narrator
faithfulness than an exact figure.

## Scope & ethics

For authorised security research only — targets you own or are explicitly cleared to assess. Passive and active reconnaissance are clearly separated. Full policy and threat model: [`docs/ETHICS.md`](docs/ETHICS.md). Found a vulnerability in Glean itself? See [`SECURITY.md`](SECURITY.md).

## Licence

MIT © Yulan Galagoda
