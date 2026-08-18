# Glean

**OSINT synthesis tool** — unifies open-source reconnaissance tools into a single, provenance-tracked, LLM-prioritised intelligence report.

Existing OSINT automation excels at *collection* but fails at *judgment*: results arrive as flat, unprioritised piles with no clear provenance and no sense of what actually matters. Glean addresses that gap — a curated set of reputable FOSS tools, unified into one entity model, with a local LLM producing a prioritised, human-readable brief you can trust.

> Status: early development. Package name reserved on PyPI as [`glean-osint`](https://pypi.org/project/glean-osint/).

## Pipeline

1. **Collect** — run a curated set of maintained FOSS OSINT tools against a target
   (crt.sh, theHarvester, subfinder, dnsx, httpx, Have I Been Pwned).
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
  --httpx path/to/httpx-output.jsonl \
  --hibp path/to/hibp-envelope.json
```

A per-tool file option overrides live invocation for that specific tool,
even with `--live` (mixed mode). `crt.sh`/`theHarvester`/`subfinder`/`dnsx`/`HIBP`
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

### Breach exposure

Have I Been Pwned answers two different questions, and Glean keeps them
apart because they carry different obligations.

**Was this domain itself breached?** Free, keyless, on by default — it names
an organisation, not a person.

**Do addresses found on this target appear in breaches?** A claim about
individuals, so it is opt-in and needs a paid API key:

```bash
glean scan example.com --live --hibp-api-key "$HIBP_API_KEY"
#   or: export HIBP_API_KEY=... and just `glean scan example.com`
```

Only addresses another tool actually found are ever looked up — Glean never
generates one to send to a third party. Without a key the scan still runs,
the domain half still reports, and the brief records what was not collected.
The reasoning is in [`docs/ETHICS.md`](docs/ETHICS.md); it is opt-in because
of the disclosure, not because of the cost.

Breach findings carry `breach_hit`, joint-highest weight in the scoring
rubric, so a breached address outranks an unbreached one on the same page.

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
different things and only one of them runs by default.

Stage 1 is deterministic and has two parts. Entity existence cannot fail
for a generated brief — invented entities are filtered out before a brief
exists — which is why this number read 1.000 regardless of what the prose
said. Since 2026-08-06 a second, structural check runs alongside it and
**can** fail: prose asserting what the graph decides on its own, such as a
wildcard entry narrated as "resolves to a live IP" when nothing records it
resolving. On the ten-target set that gives mean `stage1_faith` 0.990,
catching two real fabrications that the stage-2 judge accepts. Each failure
is listed with its reason, so a sub-1.000 score is auditable without
re-running anything. **Values from before that change are not comparable
with values after it.**

Stage 1 still says nothing about claims that need judgement rather than
lookup, so it is not a statement that the prose is accurate: a real
narrated brief has scored `stage1_faith` 1.000 alongside `stage2_faith`
0.455 on identical text, with one finding asserting the opposite of its own
entity's attributes (ADR-0009 Validation, 2026-08-04). `glean eval` prints
that caveat alongside the numbers rather than leaving it here, so it
travels with them. With `--llm`, a second faithfulness number (`stage2_faith`) also
appears: a real, different
local model judges whether the narrated *prose* actually states only
facts supported by that entity's real data (ADR-0006 D1 stage 2,
ADR-0006 D4 requires the judge to differ from the narration model —
`--judge-model` defaults to a different, larger model than `--model`).
Treat the judge's own output with real skepticism, and with numbers
attached. It has been audited against human labels three times, and the
figures moved a long way:

| audit | claims | flag precision | recall | kappa |
|---|---|---|---|---|
| 2026-08-04, as first shipped | 90 | 0.250 | 0.778 | 0.268 |
| after evidence stated as sentences | 78 | 1.000 | 0.667 | 0.780 |
| after linked-entity evidence added | 107 | 0.444 | 0.500 | 0.425 |
| all of the above, fully labelled | 136 | 0.267 | 0.571 | 0.316 |
| after dropping the judge's invented claims | 86 | 0.800 | 0.571 | 0.642 |
| **after splitting decomposition from judging** | 71 | **0.833** | **0.833** | **0.818** |

The first audit found the judge flagging 28 claims where a person found 9
— **over-flagging roughly three to one**, so most of what pulled
`stage2_faith` down was judge error rather than narrator fabrication.
Every later round traces to how the evidence is *presented* or what gets
*scored*, never to the judge's reasoning. The last is the clearest: the judge
was manufacturing "claims" by copying lines out of its own evidence and then
ruling on them — 50 of 136, carrying 10 of the 11 false flags. Those are now
detected and dropped before scoring (`glean eval` reports how many), which
took precision to 0.800 with recall unchanged.

The last row is the one that moved **recall**, which nothing before it had:
the judge had been ruling on compound sentences, and a single verdict on
"resolves to a live IP *with an exposed HTTPS service*" answers for one half.
Decomposition is now its own call that never sees the evidence.

Worth knowing if you extend this: every material improvement came from
changing what the judge is **shown, asked, or scored on** — never from asking
it the same thing more firmly. Six attempts at better prompt wording produced
0.111, 0.167, 0.444, 0.600 and two regressions.

Two things hold across all of it. `stage2_faith` errs in the safe
direction — it never overstates faithfulness — so it is a **lower bound,
not an estimate**. And the bound's tightness has swung with each change,
so quote it as a floor and cite the audit you mean. See ADR-0006's
Validation section for every round, including a retraction. One real
fabrication still passes the judge in the current set — a wildcard host
narrated as exposing a service — and it is caught by stage 1's structural
check instead, which is the point of having both.

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

`stage2_faith` is produced by an LLM judge, so the number is only as good as
the judge. That is measurable, and has been measured:

```bash
glean judge-audit --sample 50 --out judge-audit.yaml   # sample its verdicts
#   ... label each `human_verdict` yourself ...
glean judge-score judge-audit.yaml                     # score the judge

# After changing the judge prompt, reuse the labels that still apply:
glean judge-audit --sample 0 --out new.yaml --carry-over judge-audit.yaml
```

Carry-over matters more than it looks. Decomposition and judging are one
call, so changing the prompt re-derives the claim list and roughly half the
old labels stop applying to any claim. Matching is on exact claim text, so a
reworded claim comes back blank rather than inheriting a ruling nobody made.

The labels have to be yours — the tool builds the packet and scores it, but
never writes a verdict, and refuses to score a partially-labelled one.

Done once over all 90 claims from the ten-target run: **flag precision 0.250,
recall 0.778, Cohen's kappa 0.268, raw agreement 0.744.** The judge catches
most real problems but flags three false ones for every true one. Raw
agreement looks respectable and is not — with 90% of claims genuinely
supported, flagging nothing at all would score 0.90, which is why kappa is
reported beside it.

Annotation also found *why*, on the second attempt. The first explanation —
that the judge could not see facts on linked entities — was checked against
the labelled claims and **retracted**: all 21 false flags had their evidence
present in what the judge was shown. The pattern that does hold is about the
*shape* of that evidence. A `service` entity carries `port: 443`,
`service: https` — values matching a claim's own words — and was false-
flagged once in 25. A subdomain carries `dns_resolved: true`: a boolean whose
meaning lives in the key name, while the prose says "resolves to a live IP".
Those were false-flagged 11 times in 26.

The fix states every fact as a sentence for the judge ("It resolves in DNS:
it is a live host") without giving it anything the narrator did not have.
Re-labelled in full, that packet scored **flag precision 1.000, recall 0.667,
agreement 0.962, kappa 0.780** over 78 claims: the judge no longer invents
problems.

That in turn exposed the next one. Every remaining disagreement was a claim
that was *true* but spanned two entities — a subdomain resolving to an IP
that exposes an HTTPS service, where the protocol lives on the `service:`
entity. The same claim shape had been labelled both ways, which left recall
anywhere from 0.429 to 1.000 depending only on which convention was applied,
while precision stayed 1.000 throughout. The judge is now given the linked
entities' facts, bounded to entities the narrator itself saw, so the question
is settled by evidence rather than by convention. Labelling that
configuration then caught a further problem: a separate `linked_facts` field
made the judge treat connected evidence as second-class, and it false-flagged
claims whose supporting fact was sitting in it — one of them word-for-word
identical to the fact it was checked against. Evidence is now a single list
rather than labelled compartments, which is the third time that same fix has
been needed. The current configuration is not yet fully labelled and has **no
published figure**. The retraction, the
numbers and the caveats are all in ADR-0006's Validation section.

## Scope & ethics

For authorised security research only — targets you own or are explicitly cleared to assess. Passive and active reconnaissance are clearly separated. Full policy and threat model: [`docs/ETHICS.md`](docs/ETHICS.md). Found a vulnerability in Glean itself? See [`SECURITY.md`](SECURITY.md).

## Licence

MIT © Yulan Galagoda
