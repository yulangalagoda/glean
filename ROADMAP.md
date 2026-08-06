# Roadmap

Forward-looking plan after `v0.1.1`. The only previous planning document
(`_private/planning/ROADMAP_Pre-Development.md`) was the gate for *starting*
to build, and closed long ago.

`v0.1.1` met the charter's §4 MVP bar: one command produces a brief, five
tools are unified, dedup is deterministic and measured, and the evaluation
harness reports three numbers over ten ground-truth targets. What follows is
about making that output *usable* and its evidence *checkable* — not about
adding capability for its own sake.

Ordered by what unblocks what, not by size.

---

## 1. Information architecture — the interface has no hierarchy  ✅ *done*

The biggest gap, and the cheapest to close. The UI is deliberately minimal
and reads cleanly, but minimal is not the same as organised: it currently
gives the user no sense of what belongs with what.

**The scan form is five sibling `<div>`s.** Target, Presets, Tools,
Authorisation and Narration all sit at the same visual level, so a first-time
reader cannot tell that Presets and Tools are two views of one decision,
that Authorisation is a record-keeping obligation rather than a scan
parameter, or that Narration is optional and independent of everything above
it. Grouping these into labelled sections with real hierarchy — what you are
scanning, how you are scanning it, what you want written afterwards — is
mostly restructuring markup, not new behaviour.

**The app opens on New Scan.** There is no landing page. A user arriving at
the tool is immediately asked to fill in a form, before being told what the
tool is or what it has already done for them. A landing page should
summarise recent scans, surface counts and warnings, and offer the routes
onward (new scan, history, relationships) rather than assuming the answer is
always "scan something now".

**There is nowhere to explain the tool.** No About page, no user guide. The
README carries all of it, which is invisible to anyone using the web
interface. In-app pages should cover at minimum: what passive vs active
means and why the distinction is enforced, how to read a brief (priority
score, signals, provenance links), and what the faithfulness numbers do and
do not claim.

*Depends on nothing. Everything below lands inside whatever structure this
establishes, so it goes first.*

## 2. Make the relationship view an actual diagram  ✅ *done*

`/scan/{id}/graph` is currently `<ul class="graph-list">` — a nested list
describing relationships in text. The correlation stage computes a real typed
graph (`edges.json`, ADR-0003) and the charter's "prioritised entity graph"
was always meant to be the fix for the hairball problem; rendering it as a
list keeps the data one step away from the understanding it exists to
produce.

Visual mapping of hosts → IPs → services → certificates is where a reader
stops reading and starts *seeing* the target's shape.

**This needs a decision first** (see Open decisions): ADR-0011 D1 committed
to no build step, no framework and no CDN, so a diagram has to be either
hand-rolled SVG or a single vendored library. That constraint is real and
was chosen for good reasons — it should be honoured or explicitly revised,
not quietly bypassed.

## 3. Wider tool coverage

The adapter contract (ADR-0002) has now been exercised by five tools, and the
registry means a new one appears in the UI with no template changes — that
promise was tested when subfinder was added. Candidates already named in the
ADRs: Amass, BBOT (which would also force ADR-0002 Q3's streaming-parse
question), and a breach source, which would finally exercise the
`breach_exposure` entity type that ADR-0001 Q3 has been unsure about since
the beginning.

Each new tool is cheap individually. The value is coverage: more of the
attack surface seen, and more corroboration between sources, which the
scoring rubric already rewards.

## 4. Identity and feedback  ✅ *done*

- **A logo and visual identity.** The tool is published on PyPI and has a
  public repository; it currently has no mark of its own.
- **Real progress feedback during a scan.** The watch page has a stage
  checklist and a live event stream, but no motion — a scan that takes 30
  seconds looks identical to one that has stalled. A spinner attached to the
  item actually being processed would make the difference visible. Cheap,
  and it addresses the same confusion the queued-vs-running fix addressed
  in history.

## 5. Finish the research claims

Engineering-light, credibility-heavy, and runnable in parallel with all of
the above.

- ~~**Label a judge-audit packet.**~~ ✅ *done* — all 90 claims labelled and
  scored, closing ADR-0006 Q5. Flag precision **0.250**, recall 0.778, kappa
  0.268: the judge over-flags roughly three to one, so `stage2_faith` is a
  loose lower bound rather than an estimate. `glean eval`, the README and
  ADR-0006 now say that with the numbers attached.
- **Fix the judge's evidence scoping** — surfaced *by* the audit above, and
  the highest-value item left in this theme. `_judge_finding_facts` shows
  the judge one entity in isolation, while a finding's prose legitimately
  refers to entities it is linked to; the graph already has the edges
  (ADR-0003). 13 of the 21 false flags fit that pattern, and the fix
  predicts precision **0.25 → 0.47** on the same set. Re-run the audit
  afterwards — the prediction is written down so it can be refuted.
- **A second annotator on a subset** (ADR-0007 Q4) would give at least a
  partial inter-rater agreement figure, which the ground-truth protocol
  currently discloses as absent. The judge audit shares this limit: one
  annotator, so its numbers have no inter-rater check either.

---

## Open decisions

These block work above and are worth settling deliberately.

1. ~~**How to draw the graph**~~ — **decided: hand-rolled SVG.** ADR-0011 D1's
   no-build-step rule holds, nothing is fetched, and the layout lives in
   `graph.build_diagram` as a pure function. The graph turned out regular
   enough (a four-stage flow, tens of nodes after capping) that a general
   force-directed library would have solved a harder problem than this one.
2. **Whether the brief's "also found" tail should be narrated** (ADR-0009
   Q1). Relevant to readable output, and currently leaning "no — the tail is
   supposed to stay terse".

## Deliberately not planned

Recorded so they are not mistaken for oversights: server-side PDF rendering
(ADR-0011 Q3 — the browser prints), user-editable presets (Q2), and an HTML
form for `glean eval`'s aggregate output (ADR-0010 Q2). All remain deferred
for the reasons their ADRs give.

**Authentication and remote access are dropped, not deferred.** There is no
requirement for either: the tool binds to localhost, the OS boundary is the
security boundary, and ADR-0011 D8 already says so deliberately rather than
by omission. Adding a login form would only mean something alongside an
intent to expose the interface over a network, which nothing here needs.
Revisit only if that intent appears.
