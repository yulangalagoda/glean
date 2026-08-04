# Public reproduction set

```bash
glean eval --scans-dir eval/public
```

One target: `scanme.nmap.org`, a host [Nmap explicitly provides for public
scanning](https://nmap.org/book/legal-issues.html). Real captures, and a
real blind human ranking (ADR-0007) — not synthetic data.

## What this establishes

That the evaluation harness is real and runnable by someone who is not the
author. You can execute the same command, read the same `ground_truth.yaml`
the metrics are computed against, inspect the raw tool captures the pipeline
parses, and check that the numbers this repository reports are produced by
the code it ships rather than asserted in prose.

## What it does not establish

**The headline research numbers.** Those come from the private 10-target
ground-truth set in `eval/scans/`, which is gitignored because it names real
infrastructure belonging to real people (see `docs/ETHICS.md`). Nothing here
substitutes for it.

The distinction is not a formality, and the numbers make it obvious:

| | this set | the private 10-target set |
|---|---|---|
| stage-1 faithfulness | 1.000 | 1.000 |
| provenance retention | 1.000 | 1.000 |
| overlap@5 | **1.000** | **0.464** |
| nDCG@5 | **1.000** | **0.582** |

`scanme.nmap.org` produces a two-entity graph. With so few findings, Glean's
ranking and the human's agree exactly, and the prioritisation metrics
saturate at 1.000. **That is a property of the target's size, not evidence
that prioritisation works well** — the honest figures for that are 0.464 and
0.582, and they come from targets that cannot be published.

Read the two structural metrics the same way you should read them anywhere
else in this project: stage-1 faithfulness is incapable of dropping below
1.000 by construction (ADR-0006 D1), so its value here confirms the
plumbing, not the prose.

## Why only one target

Every other target in the ground-truth set is real infrastructure that
identifies a real owner. `scanme.nmap.org` is the only one whose data can be
published without that problem — its crt.sh capture is empty and dnsx
resolved nothing but the scan target itself, both checked before committing.

Adding synthetic targets would inflate the count without adding evidence: a
made-up domain with a made-up ranking tells a reader nothing about whether
the tool ranks real findings sensibly. One real, verifiable target is worth
more than five invented ones.

A regression fixture built from synthetic `example.com` data does exist, at
`tests/fixtures/eval/` — but its job is different. It runs in CI to catch
the pipeline breaking, and its ground truth is explicitly labelled as a build
fixture rather than an annotation.
