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

# One command, one report. With no input file given, Glean fetches with the
# passive tools itself (requires theHarvester/subfinder/dnsx installed).
glean scan example.com
glean scan example.com --active          # also runs httpx (ACTIVE — see below)

# Ingest-only: build the brief from raw output you've already fetched.
# Passing any input file means ingest, never live — no --offline needed.
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
against an independent human ranking). The faithfulness column is named
`stage1_faith`, not simply `faithfulness`, because the two stages measure
different things and only one of them runs by default — stage 1 and
provenance retention read 1.0 either way, since stage 1 only checks
whether a finding's entity exists at all and invented entities are
already filtered out before ever reaching the brief. It is therefore
structurally incapable of reading below 1.000, and is not a statement
that the prose is accurate: a real narrated brief has scored
`stage1_faith` 1.000 alongside `stage2_faith` 0.455 on identical text,
with one finding asserting the opposite of its own entity's attributes
(ADR-0009 Validation, 2026-08-04). `glean eval` prints that caveat
alongside the numbers rather than leaving it here, so it travels with
them. With `--llm`, a second faithfulness number (`stage2_faith`) also
appears: a real, different
local model judges whether the narrated *prose* actually states only
facts supported by that entity's real data (ADR-0006 D1 stage 2,
ADR-0006 D4 requires the judge to differ from the narration model —
`--judge-model` defaults to a different, larger model than `--model`).
Treat the judge's own output with real skepticism — real validation
found the judge itself makes mistakes (see ADR-0006's Validation
section), so `stage2_faith` is closer to a lower bound on true narrator
faithfulness than an exact figure.

### Working with a scan in the browser

Beyond reading the brief, a scan's page supports acting on it: copy any
value, filter findings by type/tool/signal, hover a priority score to see
the exact signal breakdown that produced it, and click any source under
"Seen by" to jump to the precise record in the archived tool output that
asserted it.

Two features worth knowing exist, since neither is obvious from the page:

- **Relationships** (in the bar above the report) shows how findings
  connect — which host resolves to which IP, what a certificate covers.
  This is the correlation stage's own output (ADR-0003), which is computed
  on every scan but otherwise only visible as phrasing inside finding text.
- **Triage** — each finding can be marked *Reviewed*, *Flagged* or *False
  positive*. It is stored per finding and kept across re-scans, and is the
  one thing re-running a scan cannot regenerate: everything else in a scan
  is derived from tool output, but an assessment is yours.

History groups repeat scans of a target, and any scan with an earlier run
of the same target offers **Compare to previous scan** — new, removed and
changed findings since last time, which is what turns a one-shot report
into monitoring.

### Reproducing the evaluation

The 10-target ground-truth set is not in this repository — it names real
infrastructure belonging to real people (`docs/ETHICS.md`). One target can
be published, and is:

```bash
glean eval --scans-dir eval/public     # scanme.nmap.org, real capture + real blind ranking
```

That lets you check the harness is real and the numbers come from the shipped
code. It is **not** a substitute for the private set, and
[`eval/public/README.md`](eval/public/README.md) shows why with both sets'
numbers side by side: the target is small enough that prioritisation
saturates at 1.000, against 0.464 / 0.582 on the real set.

### Auditing the judge

`stage2_faith` is produced by an LLM judge that ADR-0006's own validation
found makes real mistakes, so it ships as a lower bound. To put a number on
that:

```bash
glean judge-audit --sample 50 --out judge-audit.yaml   # sample its verdicts
#   ... label each `human_verdict` yourself ...
glean judge-score judge-audit.yaml                     # score the judge
```

The labels have to be yours — the tool builds the packet and scores it, but
never writes a verdict, and refuses to score a partially-labelled one.

## Scope & ethics

For authorised security research only — targets you own or are explicitly cleared to assess. Passive and active reconnaissance are clearly separated. Full policy and threat model: [`docs/ETHICS.md`](docs/ETHICS.md). Found a vulnerability in Glean itself? See [`SECURITY.md`](SECURITY.md).

## Licence

MIT © Yulan Galagoda
