"""Measuring how reliable the stage-2 judge actually is (ADR-0006 Q5).

`glean eval --llm` reports `stage2_faith`, an LLM judge's verdict on
whether a narrated brief's prose is supported by the entity data behind
it. ADR-0006's own Validation records that the judge makes real mistakes,
so the number ships with a caveat and no measure of how large the caveat
is. A number qualified by "this is sometimes wrong, we don't know how
often" is close to unusable as evidence, which is what open question 5
has been asking about since it was raised.

The missing ingredient is a second opinion. This module builds an
**annotation packet** -- each atomic claim the judge ruled on, its verdict,
and the exact evidence the judge was shown -- for a human to label
independently, then scores the judge against those labels.

Deliberately split that way. The labels are research data and must come
from a person; nothing here generates them, and `score_packet` refuses to
score a packet that still has unlabelled entries rather than quietly
treating "unlabelled" as agreement. What this module contributes is the
apparatus, not the ground truth.

**Which metric matters.** The intuitive reading of `stage2_faith` is
"fraction of claims that are true", but the decision-relevant question is
narrower: when the judge *flags* a claim as unsupported, is it right?
Those flags are the only thing that moves the score below 1.000. So the
headline is precision on the `unsupported` class:

- High flag precision, low recall -> the judge misses fabrications, and
  `stage2_faith` is genuinely a lower bound on faithfulness, exactly as
  the project currently claims.
- Low flag precision -> the judge invents problems, `stage2_faith`
  understates faithfulness, and the published number is pessimistic
  rather than conservative.

Cohen's kappa is reported alongside because raw agreement flatters any
judge on a skewed set: if 90% of claims are genuinely supported, a judge
that says "supported" every time scores 90% agreement while being
worthless at the only job that matters.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

# The two labels a human may assign. Deliberately the same vocabulary the
# judge itself uses, so an annotator is answering the judge's own question
# rather than a paraphrase of it.
SUPPORTED = "supported"
UNSUPPORTED = "unsupported"
VALID_LABELS = frozenset({SUPPORTED, UNSUPPORTED})


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One claim to be labelled, with everything needed to judge it."""

    index: int
    target: str
    entity_id: str
    claim: str
    judge_verdict: str
    entity_facts: str
    human_verdict: str | None = None


@dataclass(frozen=True, slots=True)
class JudgeReliability:
    """How the judge performed against the human labels."""

    labelled: int
    agreed: int
    # Confusion over the decision-relevant class: the judge flagging a
    # claim as unsupported.
    flagged_and_correct: int  # judge said unsupported, human agreed
    flagged_but_wrong: int  # judge said unsupported, human said supported
    missed: int  # judge said supported, human said unsupported

    @property
    def agreement(self) -> float:
        return self.agreed / self.labelled if self.labelled else 1.0

    @property
    def flag_precision(self) -> float | None:
        """Of the claims the judge flagged, how many were genuinely
        unsupported. `None` when it flagged nothing -- undefined, not 1.0,
        because a judge that never flags has not demonstrated precision.
        """
        flagged = self.flagged_and_correct + self.flagged_but_wrong
        return self.flagged_and_correct / flagged if flagged else None

    @property
    def flag_recall(self) -> float | None:
        """Of the genuinely unsupported claims, how many the judge caught.
        `None` when the human found none -- there was nothing to catch, so
        the sample says nothing about recall."""
        real = self.flagged_and_correct + self.missed
        return self.flagged_and_correct / real if real else None

    @property
    def kappa(self) -> float | None:
        """Cohen's kappa: agreement corrected for what chance alone would
        produce. `None` when it is undefined -- with perfect expected
        agreement (both raters using a single label throughout) the
        denominator is zero, and reporting 0.0 there would read as
        "no better than chance" when the truth is "unmeasurable from this
        sample"."""
        n = self.labelled
        if not n:
            return None
        judge_unsup = self.flagged_and_correct + self.flagged_but_wrong
        human_unsup = self.flagged_and_correct + self.missed
        po = self.agreed / n
        pe = ((judge_unsup / n) * (human_unsup / n)) + (
            ((n - judge_unsup) / n) * ((n - human_unsup) / n)
        )
        return None if pe >= 1.0 else (po - pe) / (1 - pe)


def build_packet(
    claims: list[tuple[str, Any]],
    *,
    sample_size: int,
    seed: int,
) -> list[AuditEntry]:
    """Sample claims for annotation.

    `claims` is `(target, ClaimVerdict)` pairs. Sampling is seeded and the
    result is ordered by the draw, so the same seed and inputs reproduce
    the same packet -- a labelled packet that could not be regenerated
    would make the resulting reliability figure unauditable.

    Sampled across all targets rather than per target on purpose: the
    quantity being estimated is the judge's reliability as a component,
    not per-domain behaviour, and stratifying would need a defensible
    reason to weight some targets over others.
    """
    pool = list(claims)
    rng = random.Random(seed)
    rng.shuffle(pool)
    chosen = pool[:sample_size] if sample_size > 0 else pool
    return [
        AuditEntry(
            index=i,
            target=target,
            entity_id=verdict.entity_id,
            claim=verdict.claim,
            judge_verdict=SUPPORTED if verdict.supported else UNSUPPORTED,
            entity_facts=verdict.entity_facts,
        )
        for i, (target, verdict) in enumerate(chosen, start=1)
    ]


def score_packet(entries: list[AuditEntry]) -> JudgeReliability:
    """Score the judge against human labels.

    Raises on an unlabelled or invalidly-labelled entry rather than
    skipping it. Silently dropping unlabelled rows would let a
    half-finished packet produce a confident-looking number over whichever
    claims happened to be done first, which is exactly the kind of
    quietly-wrong result this whole exercise exists to rule out.
    """
    missing = [e.index for e in entries if e.human_verdict is None]
    if missing:
        msg = f"unlabelled entries: {missing} — every claim needs a human_verdict before scoring"
        raise ValueError(msg)
    invalid = [e.index for e in entries if e.human_verdict not in VALID_LABELS]
    if invalid:
        msg = f"invalid human_verdict on entries {invalid} — use {SUPPORTED!r} or {UNSUPPORTED!r}"
        raise ValueError(msg)

    agreed = flagged_ok = flagged_wrong = missed = 0
    for e in entries:
        judge_flagged = e.judge_verdict == UNSUPPORTED
        human_flagged = e.human_verdict == UNSUPPORTED
        if judge_flagged == human_flagged:
            agreed += 1
        if judge_flagged and human_flagged:
            flagged_ok += 1
        elif judge_flagged and not human_flagged:
            flagged_wrong += 1
        elif not judge_flagged and human_flagged:
            missed += 1

    return JudgeReliability(
        labelled=len(entries),
        agreed=agreed,
        flagged_and_correct=flagged_ok,
        flagged_but_wrong=flagged_wrong,
        missed=missed,
    )


def interpret(result: JudgeReliability) -> str:
    """What the numbers mean for `stage2_faith`, in a sentence.

    Written out rather than left to the reader because the direction is
    genuinely counter-intuitive: a judge that over-flags makes the
    published faithfulness look *worse* than reality, not better.
    """
    precision = result.flag_precision
    if precision is None:
        return (
            "The judge flagged nothing in this sample, so its precision is undefined — "
            "this says nothing either way about stage2_faith."
        )
    if precision >= 0.9:
        return (
            f"The judge was right about {precision:.0%} of the claims it flagged, so "
            "stage2_faith is close to a true faithfulness rate rather than a pessimistic one."
        )
    if precision >= 0.5:
        return (
            f"The judge was right about {precision:.0%} of the claims it flagged, so "
            "stage2_faith understates real faithfulness — treat it as a floor, not an estimate."
        )
    return (
        f"The judge was right about only {precision:.0%} of the claims it flagged, so "
        "stage2_faith is dominated by judge error and should not be reported as a "
        "faithfulness measurement without this caveat attached."
    )
