"""The evaluation harness: the charter's three headline numbers (ADR-0006).

Faithfulness is two-stage (D1). Stage 1 is the deterministic structural
pre-check (does each finding resolve to a real graph entity) — free,
exact, "structurally guaranteed never to have false negatives." Stage 2
(added 2026-07-27, once ADR-0009's real LLM narration existed to judge)
is the atomic-claim entailment check: decompose a finding's prose into
individual factual claims and check each against that entity's real
record via a second, different LLM judge — the actual test of whether
narrated *content*, not just entity choice, can be trusted. Provenance
retention (D3) and prioritisation quality (D2) are both fully specified,
unambiguous formulas and are implemented in full, no LLM involved.

The ground-truth file format (ADR-0007 open question 2) is resolved as of
2026-07-27: a plain YAML file, `load_ground_truth` below reads it into
`GroundTruth`. See `eval/scans/<slug>/ground_truth.yaml` for real examples
and ADR-0007's "Resolved" note for the schema itself.
"""

from __future__ import annotations

import json
import math
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from glean_osint.brief import SIGNAL_PHRASES, Brief, Finding
from glean_osint.synthesis import (
    DEFAULT_TIMEOUT_SECONDS,
    OllamaError,
    call_ollama,
    extract_json_items,
)

# D4: the judge should be a different, ideally stronger model than the one
# under evaluation -- llama3.1:8b vs synthesis's default llama3.2:latest.
DEFAULT_JUDGE_MODEL = "llama3.1:8b"


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
    """ADR-0006 D1 stage 1 only: does each finding's entity exist in the
    graph at all. `score` is the charter's target-1.0 metric. Content-level
    fabrication (a real entity, but a false claim in its prose) is not
    caught here by design — see `Stage2FaithfulnessResult` below, and
    ADR-0009's Validation section for why stage 1 alone reads 1.000
    regardless of narration source."""

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


_JUDGE_PREAMBLE = """You are a fact-checking judge for a security \
reconnaissance brief. You will be given a JSON array of findings, each \
with the finding's stated_text (what a narrator wrote about it) and \
real_facts (the actual, ground-truth data about the underlying entity).

Rules, all mandatory:
- For each finding, break stated_text into its distinct atomic factual \
claims (each claim should assert exactly one fact).
- For each claim, decide whether real_facts directly states or clearly \
implies it. If real_facts doesn't mention something a claim asserts, \
that claim is NOT supported -- do not use outside knowledge, and do not \
give the benefit of the doubt.
- Output a single JSON object of the exact shape {"findings": \
[{"entity_id": ..., "claims": [{"claim": ..., "supported": true|false}, \
...]}, ...]}, one array item per input finding, in the same order.
- Do not add commentary, markdown, or any text outside that JSON object."""


def _judge_finding_facts(finding: Finding) -> dict[str, object]:
    entity = finding.entity
    signals = entity.priority.signals if entity.priority else ()
    signal_phrases = [SIGNAL_PHRASES[s] for s in signals if s in SIGNAL_PHRASES]
    return {
        "entity_id": entity.id,
        "stated_text": {"body": finding.body, "why_ranked": finding.why_ranked},
        "real_facts": {
            "type": entity.type,
            "display_value": finding.display_value,
            "attributes": entity.attributes,
            "seen_by": finding.seen_by,
            "signals": signal_phrases,
        },
    }


def build_judge_prompt(findings: tuple[Finding, ...]) -> str:
    facts = [_judge_finding_facts(f) for f in findings]
    return _JUDGE_PREAMBLE + "\n\nFindings:\n" + json.dumps(facts, indent=2)


def _parse_judge_response(
    raw_text: str, expected_ids: set[str]
) -> dict[str, list[tuple[str, bool]]]:
    """Parse the judge's JSON response into entity_id -> [(claim, supported), ...].

    Reuses `synthesis.extract_json_items` for the same Ollama `format: json`
    object-wrapping quirk documented there (ADR-0009 Validation) -- the
    judge call hits the identical issue. Malformed individual items are
    skipped, never fatal for the whole response (ADR-0002 D5's discipline).
    """
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        return {}
    items = extract_json_items(parsed)

    result: dict[str, list[tuple[str, bool]]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        entity_id = item.get("entity_id")
        if not isinstance(entity_id, str) or entity_id not in expected_ids:
            continue
        claims = item.get("claims")
        if not isinstance(claims, list):
            continue
        parsed_claims: list[tuple[str, bool]] = []
        for claim_item in claims:
            if not isinstance(claim_item, dict):
                continue
            claim_text = claim_item.get("claim")
            supported = claim_item.get("supported")
            if isinstance(claim_text, str) and claim_text.strip() and isinstance(supported, bool):
                parsed_claims.append((claim_text.strip(), supported))
        if parsed_claims:
            result[entity_id] = parsed_claims

    return result


@dataclass(frozen=True, slots=True)
class Stage2FaithfulnessResult:
    """ADR-0006 D1 stage 2: atomic-claim entailment via an LLM judge.

    `score` is precision-only, same convention as `FaithfulnessResult`
    (vacuously 1.0 when there's nothing to judge, not "unknown")."""

    total_claims: int
    supported_claims: int
    judge_model: str
    unjudged_findings: int  # degraded (no usable judge output), not fabricated

    @property
    def score(self) -> float:
        return self.supported_claims / self.total_claims if self.total_claims else 1.0


def faithfulness_stage2(
    brief: Brief,
    *,
    judge_model: str = DEFAULT_JUDGE_MODEL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    urlopen: Callable[..., object] = urllib.request.urlopen,
) -> Stage2FaithfulnessResult:
    """Atomic-claim entailment check for `top_priorities` only.

    `also_found` is never LLM-narrated (ADR-0009 D2) -- its text is always
    template-generated, which stage 1 already covers as trivially faithful
    by construction, so spending a judge call re-confirming that would
    only add cost for a guaranteed result. A judge call (or connection)
    failure degrades to "unjudged" for those findings, never a crash
    (same discipline as every other stage of this project).
    """
    if not brief.top_priorities:
        return Stage2FaithfulnessResult(
            total_claims=0, supported_claims=0, judge_model=judge_model, unjudged_findings=0
        )

    expected_ids = {f.entity.id for f in brief.top_priorities}
    prompt = build_judge_prompt(brief.top_priorities)

    try:
        raw_text = call_ollama(prompt, model=judge_model, timeout=timeout, urlopen=urlopen)
    except OllamaError:
        return Stage2FaithfulnessResult(
            total_claims=0,
            supported_claims=0,
            judge_model=judge_model,
            unjudged_findings=len(brief.top_priorities),
        )

    judged = _parse_judge_response(raw_text, expected_ids)

    total = 0
    supported = 0
    unjudged = 0
    for finding in brief.top_priorities:
        claims = judged.get(finding.entity.id)
        if claims is None:
            unjudged += 1
            continue
        total += len(claims)
        supported += sum(1 for _, ok in claims if ok)

    return Stage2FaithfulnessResult(
        total_claims=total,
        supported_claims=supported,
        judge_model=judge_model,
        unjudged_findings=unjudged,
    )


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
