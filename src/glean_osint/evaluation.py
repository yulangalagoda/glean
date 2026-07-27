"""The evaluation harness: the charter's three headline numbers (ADR-0006).

No LLM synthesis step exists yet in this project, so faithfulness's stage 2
(atomic-claim entailment via an LLM judge) is not implemented here — only
stage 1, the deterministic structural pre-check (does each finding resolve
to a real graph entity), which the ADR itself describes as free, exact,
and "structurally guaranteed never to have false negatives." Provenance
retention (D3) and prioritisation quality (D2) are both fully specified,
unambiguous formulas and are implemented in full.

The ground-truth file format (ADR-0007 open question 2) is resolved as of
2026-07-27: a plain YAML file, `load_ground_truth` below reads it into
`GroundTruth`. See `eval/scans/<slug>/ground_truth.yaml` for real examples
and ADR-0007's "Resolved" note for the schema itself.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from glean_osint.brief import Brief


@dataclass(frozen=True, slots=True)
class GroundTruthEntry:
    entity_id: str
    justification: str = ""


@dataclass(frozen=True, slots=True)
class GroundTruth:
    """An independent human ranking of 'what actually mattered' for a scan
    (ADR-0007). `entries` order IS the ranking — index 0 is the top pick."""

    target: str
    annotator: str
    annotated_at: str
    entries: tuple[GroundTruthEntry, ...]

    @property
    def ranked_ids(self) -> tuple[str, ...]:
        return tuple(e.entity_id for e in self.entries)


def load_ground_truth(path: Path) -> GroundTruth:
    """Load a `ground_truth.yaml` file (ADR-0007) into `GroundTruth`.

    Does not validate `blind`/`corroboration_sources` (attestation/audit
    metadata the file format needs, D6/D7) beyond requiring `blind: true`
    to be present — those fields aren't carried onto the in-memory
    dataclass, which only needs the ranking itself.
    """
    data: dict[str, Any] = yaml.safe_load(path.read_text())
    if data.get("blind") is not True:
        msg = f"{path}: missing or false 'blind' attestation (ADR-0007 D6)"
        raise ValueError(msg)
    entries = tuple(
        GroundTruthEntry(entity_id=e["entity_id"], justification=e.get("justification", ""))
        for e in data["entries"]
    )
    return GroundTruth(
        target=data["target"],
        annotator=data["annotator"],
        annotated_at=data["annotated_at"],
        entries=entries,
    )


@dataclass(frozen=True, slots=True)
class FaithfulnessResult:
    """ADR-0006 D1 stage 1 only. `score` is the charter's target-1.0
    metric; stage 2 (content-level fabrication, e.g. a real entity but an
    invented attribute about it) needs an LLM judge this project doesn't
    have yet and is out of scope here."""

    total_claims: int
    supported_claims: int

    @property
    def score(self) -> float:
        return self.supported_claims / self.total_claims if self.total_claims else 1.0


def faithfulness_stage1(brief: Brief, entity_ids: set[str]) -> FaithfulnessResult:
    """A finding is 'supported' (stage 1) iff its entity id exists in the
    graph. Free, deterministic, no LLM judge invoked."""
    all_findings = brief.top_priorities + brief.also_found
    supported = sum(1 for f in all_findings if f.entity.id in entity_ids)
    return FaithfulnessResult(total_claims=len(all_findings), supported_claims=supported)


def provenance_retention(brief: Brief) -> float:
    """ADR-0006 D3: PR = findings with >=1 valid seen-by source / total
    findings surfaced. Target per charter: 1.0 (100%)."""
    all_findings = brief.top_priorities + brief.also_found
    if not all_findings:
        return 1.0
    valid = sum(1 for f in all_findings if f.seen_by and f.entity.provenance)
    return valid / len(all_findings)


@dataclass(frozen=True, slots=True)
class PrioritisationQuality:
    n: int
    overlap_at_n: float
    ndcg_at_n: float


def prioritisation_quality(
    glean_ranked_ids: list[str], ground_truth: GroundTruth, n: int
) -> PrioritisationQuality:
    """ADR-0006 D2: compares Glean's deterministic `priority.rank` order
    against an independent human ranking for the same scan."""
    glean_top_n = glean_ranked_ids[:n]
    human_top_n = list(ground_truth.ranked_ids[:n])
    return PrioritisationQuality(
        n=n,
        overlap_at_n=_overlap_at_n(glean_top_n, human_top_n),
        ndcg_at_n=_ndcg_at_n(glean_top_n, human_top_n),
    )


def _overlap_at_n(glean_top_n: list[str], human_top_n: list[str]) -> float:
    """Jaccard overlap of the two top-N sets — chosen as primary over a
    correlation coefficient for legibility, per ADR-0006 D2."""
    a, b = set(glean_top_n), set(human_top_n)
    union = a | b
    if not union:
        return 1.0  # both empty -> vacuously perfect agreement
    return len(a & b) / len(union)


def _ndcg_at_n(glean_top_n: list[str], human_top_n: list[str]) -> float:
    """Secondary, position-sensitive metric (ADR-0006 D2).

    Graded relevance convention (a documented implementation choice — the
    ADR specifies the metric but not a relevance-grading scheme): the
    human's rank-1 pick gets relevance N, linearly down to 1 for their
    Nth pick; anything absent from the human's list gets 0.
    """
    relevance = {entity_id: len(human_top_n) - i for i, entity_id in enumerate(human_top_n)}
    dcg = sum(
        relevance.get(entity_id, 0) / math.log2(i + 2) for i, entity_id in enumerate(glean_top_n)
    )
    ideal_order = sorted(relevance, key=lambda e: -relevance[e])
    idcg = sum(relevance[entity_id] / math.log2(i + 2) for i, entity_id in enumerate(ideal_order))
    return dcg / idcg if idcg else 1.0
