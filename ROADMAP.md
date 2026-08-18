# Roadmap

Forward-looking plan, current as of `v0.2.0`. The only previous planning document
(`_private/planning/ROADMAP_Pre-Development.md`) was the gate for *starting*
to build, and closed long ago.

`v0.1.1` met the charter's §4 MVP bar: one command produces a brief, five
tools are unified, dedup is deterministic and measured, and the evaluation
harness reports three numbers over ten ground-truth targets. What follows is
about making that output *usable* and its evidence *checkable* — not about
adding capability for its own sake.

`v0.2.0` (2026-08-10) closed themes 1, 2, 4 and 5, added a sixth tool, and
made both faithfulness numbers mean something they did not before: stage 1
can now fail, and the stage-2 judge's flag precision went 0.250 → 0.800
across four audits. Since the release a fifth and sixth audit took the judge
to **precision 0.833, recall 0.833, kappa 0.818** — the first movement in
recall at all — leaving one shipped limitation outstanding rather than two.

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

## 3. Wider tool coverage  — *breach source done*

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

**A breach source landed first (2026-08-10), out of the listed order and
for a reason.** `breach_exposure` was a declared entity type with no
producer, so `breach_hit` — joint-highest weight in the rubric — had never
fired against real data: the rule most able to dominate a ranking was the
least tested. Amass by contrast is a fourth subdomain source that exercises
nothing new. Have I Been Pwned is now wired, ADR-0001 Q3 is resolved, and
the adapter contract held without a schema, scoring or template change.

Still open: **Amass** (corroboration, cheap) and **BBOT** (which forces
ADR-0002 Q3's streaming-parse question — a real architectural decision, not
just another adapter).

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
- ~~**Fix the judge's evidence scoping**~~ — **retracted.** That item
  rested on a diagnosis that did not survive being checked against the
  labelled claims: all 21 false flags had their evidence already in front
  of the judge, none needed a linked entity. See ADR-0006's Validation
  section for the retraction and the pattern that does hold (boolean
  attributes whose meaning lives in the key name).
- ~~**Label the re-measurement packet.**~~ ✅ *done* — 78 claims labelled:
  **flag precision 1.000, recall 0.667, agreement 0.962, kappa 0.780.**
  Over-flagging is gone. That surfaced the next problem: every remaining
  disagreement was a claim that was *true* but spanned two entities, and the
  same claim shape had been labelled both ways, leaving recall anywhere from
  0.429 to 1.000 depending only on the convention applied.
- ~~**Label the linked-evidence packet.**~~ ✅ *done* — 107 claims:
  precision 0.444, recall 0.500. Precision had *fallen*, because a separate
  `linked_facts` field taught the judge that connected evidence counted for
  less; merging it into the one fact list restored precision to 1.000 on
  the claims carrying labels. Third instance of the same defect, and the
  same fix each time: one list, one status.
- ~~**Label the merged-evidence packet.**~~ ✅ *done* — 136 claims:
  **precision 0.267, recall 0.571, agreement 0.897, kappa 0.316.** Far
  worse than the 1.000 the carried subset had suggested, which is exactly
  the selection bias that subset was flagged for: claims whose wording
  survives a prompt change are the easy ones. Labelling the whole packet
  was the only way to see it.
- ~~**Drop the judge's fact-list echoes before scoring them.**~~ ✅ *done*
  — **flag precision 0.267 → 0.800**, the predicted figure, with recall
  unchanged at 0.571 and kappa 0.316 → 0.642. Re-running produced **0
  claims needing a new label**, so every surviving claim was scored against
  labels written before the change: no fitting, no selection. Fourth audit,
  and the third improvement in a row that came from changing what the judge
  is shown or scored on rather than from better prompt wording.
- **Re-read carried labels after a change of evidence, not just the
  blanks.** Carry-over preserves a ruling by design, so a label made before
  the evidence changed survives until someone revisits it. Two such stale
  labels persisted across three packets before being noticed.
- ~~**Catch structural contradictions in stage 1 rather than asking the
  judge to.**~~ ✅ *done* — ADR-0006 D1 amended with check 1b. Precision
  **1.000** against the human labels and zero false positives on 278
  template-brief findings before adoption; first real run gives mean
  `stage1_faith` **0.990** (`hazelmoor.org` 0.909), catching both wildcard
  fabrications the judge accepts. `stage1_faith` can fail now, and values
  before this change are not comparable with values after it.
- **The judge is decomposition-unstable, and no evidence fixes that.** On
  `*.yulan.me` it has flagged the full sentence and accepted the bare
  fragment "Resolves to a live IP" in the same run; under one variant it
  manufactured claims out of the fact list and then flagged them, which the
  preamble forbids twice. Two runs of an identical prompt at
  `temperature: 0` also give different claim counts. Worth splitting
  decomposition from entailment (ADR-0006 Q2 chose one call for cost) if
  stage 2 is ever to carry a tight number.
- **A second annotator on a subset** (ADR-0007 Q4) would give at least a
  partial inter-rater agreement figure, which the ground-truth protocol
  currently discloses as absent. The judge audit shares this limit: one
  annotator, so its numbers have no inter-rater check either.

---

## Shipped as known limitations in v0.2.0

Recorded here because they are live in a released version, not hypothetical.

1. **A breach finding cannot reach the top of a brief** (ADR-0004 Q8).
   `breach_hit` is joint-highest-weighted but applies only to entities that
   can hold no other signal, so it is always exactly 3.0 against a flagged
   subdomain's 4.0 — `adobe.com`'s 152-million-account breach ranked 1079 of
   31062. Letting the breached *domain* carry the signal is a one-line
   change that alters every target's ranking, so it needs re-measuring
   against the ground-truth set before it lands, the same way `cert_orphaned`
   was.
2. ~~**The stage-2 judge misses two real problems in seven** (recall
   0.571).~~ ✅ **Fixed 2026-08-10 — recall 0.571 → 0.833.** Diagnosis found
   two of the three misses were stale labels and the third is caught by
   stage 1b, so the number overstated the problem; the real defect was
   decomposition, with 24 of 86 claims left as whole undecomposed sentences.
   Decomposition is now a separate call that never sees the evidence.
   Measured on a fully labelled packet: **precision 0.833, recall 0.833,
   kappa 0.818** — best on every metric, and the first time recall moved at
   all. Fact-echoes went 50 → 0 and compound claims 9 → 2.

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
