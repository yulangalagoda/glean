"""The evaluation harness: the charter's three headline numbers (ADR-0006).

Faithfulness is two-stage (D1). Stage 1 is the deterministic half, free
and exact: **1a** checks that each finding resolves to a real graph entity,
and **1b** (added 2026-08-06, `glean_osint.contradictions`) fails prose
asserting what the graph decides on its own — a wildcard narrated as
resolving when nothing records it resolving. 1a cannot fail for a generated
brief; 1b is what lets this number read below 1.000. Stage 2
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
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from glean_osint.brief import SIGNAL_PHRASES, Brief, Finding
from glean_osint.contradictions import Contradiction, check_brief_findings
from glean_osint.schema.entities import Edge, Entity
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
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
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
    """ADR-0006 D1 stage 1: the deterministic checks, no LLM judge.

    Two of them since 2026-08-06. **1a** is the original: does each
    finding's entity exist in the graph. **1b** (`contradictions`) checks
    the prose for assertions the graph decides on its own -- a wildcard
    entry narrated as resolving when nothing records it resolving.

    1a cannot fail for a code-generated brief, which is why this number
    read 1.000 regardless of narration source and could not be quoted as
    evidence the prose was accurate. 1b gives it teeth for the decidable
    subset. Numbers from before that date are not comparable with numbers
    after it."""

    total_claims: int
    supported_claims: int
    contradictions: tuple[Contradiction, ...] = ()

    @property
    def score(self) -> float:
        return self.supported_claims / self.total_claims if self.total_claims else 1.0


def faithfulness_stage1(
    brief: Brief,
    entity_ids: set[str],
    *,
    edges: Sequence[Edge] = (),
    entity_types: dict[str, str] | None = None,
) -> FaithfulnessResult:
    """A finding is supported iff its entity exists AND its prose asserts
    nothing the graph contradicts. Free, deterministic, no judge invoked.

    `edges`/`entity_types` are optional so a caller without a graph still
    gets check 1a, but a caller that has them should pass them: without
    them only the check that cannot fail is running.
    """
    all_findings = brief.top_priorities + brief.also_found
    contradictions = tuple(
        check_brief_findings(all_findings, edges, entity_types or {})
        if edges or entity_types
        else ()
    )
    contradicted = {c.entity_id for c in contradictions}
    supported = sum(
        1 for f in all_findings if f.entity.id in entity_ids and f.entity.id not in contradicted
    )
    return FaithfulnessResult(
        total_claims=len(all_findings),
        supported_claims=supported,
        contradictions=contradictions,
    )


_JUDGE_PREAMBLE = """You are a fact-checking judge for a security \
reconnaissance brief. You will be given a JSON array of findings, each \
with the finding's stated_text (what a narrator wrote about it) and \
real_facts (the actual, ground-truth data about the underlying entity).

Rules, all mandatory:
- For each finding, break stated_text into its distinct atomic factual \
claims (each claim should assert exactly one fact). Decompose only \
stated_text. Never turn a line of real_facts into a claim.
- real_facts.plain_facts is the evidence, one fact per sentence. It \
covers both facts about this entity and facts about entities it connects \
to -- the IP a host resolves to, the service that IP exposes -- and every \
sentence in it counts the same. The other real_facts fields repeat some \
of that data in structured form; they are not a stronger or weaker \
source.
- A claim that restates any of those facts in different words IS \
supported. The wording does not have to match: "resolves to a live IP" is \
supported by a fact saying the host resolves in DNS, "an exposed HTTPS \
service" is supported by a fact naming a connected service with protocol \
https, and a claim about which tool found something is supported by the \
fact listing those tools.
- A claim is NOT supported only when no fact states or implies it -- \
prose asserting a service where no fact mentions one, or a \
characterisation supplied from world knowledge. Do not use outside \
knowledge to fill a gap.
- Output a single JSON object of the exact shape {"findings": \
[{"entity_id": ..., "claims": [{"claim": ..., "supported": true|false}, \
...]}, ...]}, one array item per input finding, in the same order.
- Do not add commentary, markdown, or any text outside that JSON object."""


# Attributes whose meaning lives in the key name rather than the value.
# `dns_resolved: true` records that a host resolves, but reading that off
# the pair requires already knowing what the key means. The 2026-08-04
# judge audit found this is precisely where the judge fails: it false-
# flagged 13 of 26 subdomain claims (and 4 of 10 domain claims) whose
# evidence was a boolean attribute, against 1 of 25 service claims, whose
# attributes (`port: 443`, `service: https`) carry their meaning in the
# value and match a claim's own words. Spelling the boolean ones out is
# not new evidence -- `_headline` already renders `dns_resolved: true` as
# "confirmed live" for human readers, and this says the same thing to the
# judge.
_ATTRIBUTE_SENTENCES: dict[tuple[str, object], str] = {
    ("dns_resolved", True): "It resolves in DNS: it is a live host.",
    ("dns_resolved", False): "It does not resolve in DNS: it is a confirmed dead host.",
    ("wildcard", True): "It is a wildcard DNS entry.",
}


def _readable(value: object) -> str:
    """An attribute value as prose. Lists are the case that matters -- a
    certificate's `san` is one, and `['a', 'b']` reads as syntax rather
    than as the two hostnames it is."""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def _plain_facts(finding: Finding) -> list[str]:
    """Everything known about this entity, one fact per sentence.

    Strictly a restatement of the structured fields below it -- the same
    data the narrator was given (`synthesis._finding_facts`), reworded.
    That equivalence is load-bearing: a judge shown facts the narrator
    never had would start ratifying invention rather than checking it.
    """
    entity = finding.entity
    facts = [f"This finding is a {entity.type.replace('_', ' ')}: {finding.display_value}."]
    for key, value in entity.attributes.items():
        # Only booleans are looked up: the table exists for them, and an
        # attribute value may be a list (a certificate's `san`), which
        # cannot be part of a dict key at all.
        sentence = _ATTRIBUTE_SENTENCES.get((key, value)) if isinstance(value, bool) else None
        facts.append(sentence or f"Its {key.replace('_', ' ')} is {_readable(value)}.")
    if finding.seen_by:
        facts.append(f"It was found by these tools: {finding.seen_by}.")
    signals = entity.priority.signals if entity.priority else ()
    for signal in signals:
        phrase = SIGNAL_PHRASES.get(signal)
        if phrase:
            # Framed as a label rather than a clause: the phrases are
            # fragments of mixed grammar ("service is exposed", "seen
            # independently by multiple tools"), and forcing them into a
            # sentence produces broken English for most of them.
            facts.append(f"Established by the scan: {phrase}.")
    return facts


_RELATION_PHRASES: dict[str, str] = {
    "resolves_to": "resolves to",
    "exposes_service": "exposes",
    "hosts": "hosts",
    "runs_tech": "runs",
    "issued_for": "was issued for",
    "subdomain_of": "is a subdomain of",
    "has_record": "has the DNS record",
    "exposed_in_breach": "was exposed in",
}

# How far to walk from a finding's own entity. Two hops, because that is
# the distance the real disagreements sat at: a subdomain resolves to an
# IP (one hop) which exposes an HTTPS service (two). Deeper would pull in
# most of the graph for a well-connected target and bury the facts that
# bear on the prose.
_LINK_DEPTH = 2
_MAX_LINKED_FACTS = 12

# Relations that may be *passed through* on the way to a second hop.
# `subdomain_of` is excluded, and the exclusion is load-bearing: it points
# at a parent, and a parent's properties are not the child's. Traversing
# it produced "It is connected, via is a subdomain of then resolves to, to
# ip address ..." for a wildcard entry that resolves to nothing -- which
# read as evidence that the wildcard resolves, and made the judge accept a
# genuine fabrication (found in the 2026-08-06 re-run, before it shipped).
# Every other relation means "this entity reaches that one", which does
# compose. `subdomain_of` is still described as a first-hop fact, since
# "it is a subdomain of X" is true and says nothing about resolution.
_NON_TRANSITIVE_RELATIONS = frozenset({"subdomain_of"})


def _describe(entity: Entity, display: str) -> str:
    """A linked entity in one clause: what it is, and its own attributes."""
    label = f"{entity.type.replace('_', ' ')} {display}"
    if not entity.attributes:
        return label
    detail = ", ".join(
        f"{k.replace('_', ' ')} {_readable(v)}" for k, v in entity.attributes.items()
    )
    return f"{label} ({detail})"


def _linked_facts(
    finding: Finding,
    edges_by_source: dict[str, list[Edge]],
    in_brief: dict[str, Finding],
) -> list[str]:
    """Facts about entities this finding is connected to.

    **Only entities that are themselves narrated get described**, and that
    bound is what keeps the judge honest. The narrator is handed every
    top-priority finding in one batch (`synthesis.build_prompt`), so a
    fact about one of those is a fact the narrator had. Describing an
    entity from outside the brief would hand the judge evidence the
    narrator never saw, and it would start ratifying invention that
    happens to be true rather than checking what the narrator could know.

    The walk itself passes *through* entities regardless, because the
    connecting hop is routinely not narrated: a subdomain reaches its
    HTTPS service via an `ip_address` that did not make the top five.
    Traversing a node discloses nothing about it; only the endpoint is
    described.

    Added after the 2026-08-06 audit. With over-flagging fixed, every
    remaining judge/human disagreement was a claim that was *true* but
    unverifiable from one entity alone -- "resolves to a live IP with an
    exposed HTTPS service", where the protocol lives on the linked
    `service:` entity. The annotator resolved that ambiguity both ways
    across otherwise identical claims, which made recall unreportable:
    0.429 to 1.000 depending only on which convention was applied.
    """
    facts: list[str] = []
    seen = {finding.entity.id}
    frontier: list[tuple[str, list[str]]] = [(finding.entity.id, [])]
    for _ in range(_LINK_DEPTH):
        next_frontier: list[tuple[str, list[str]]] = []
        for node_id, chain in frontier:
            for edge in edges_by_source.get(node_id, []):
                if edge.target_id in seen:
                    continue
                seen.add(edge.target_id)
                phrase = _RELATION_PHRASES.get(edge.relation, edge.relation.replace("_", " "))
                onward = [*chain, phrase]
                target = in_brief.get(edge.target_id)
                if target is not None:
                    described = _describe(target.entity, target.display_value)
                    facts.append(
                        f"It {phrase} {described}."
                        if len(onward) == 1
                        else f"It is connected, via {' then '.join(onward)}, to {described}."
                    )
                if edge.relation not in _NON_TRANSITIVE_RELATIONS:
                    next_frontier.append((edge.target_id, onward))
        frontier = next_frontier
    return facts[:_MAX_LINKED_FACTS]


def _judge_finding_facts(
    finding: Finding,
    edges_by_source: dict[str, list[Edge]] | None = None,
    in_brief: dict[str, Finding] | None = None,
) -> dict[str, object]:
    entity = finding.entity
    signals = entity.priority.signals if entity.priority else ()
    signal_phrases = [SIGNAL_PHRASES[s] for s in signals if s in SIGNAL_PHRASES]
    facts = _plain_facts(finding)
    if edges_by_source is not None and in_brief is not None:
        # Appended to the one list rather than given a field of their own.
        # A separate `linked_facts` key made the judge treat them as a
        # weaker source: it false-flagged four claims whose evidence sat
        # there, including one whose text was *verbatim* the linked fact
        # it was being checked against. The preamble had called
        # `plain_facts` "everything known about the entity" and then
        # contradicted itself a bullet later; the earlier, stronger claim
        # won. Same failure as the original `attributes`/`signals` split,
        # and the same fix -- one list, one status. The sentences say
        # "It is connected, via ... to ...", so where a fact came from is
        # still legible without a field implying it counts for less.
        facts += _linked_facts(finding, edges_by_source, in_brief)
    real_facts: dict[str, object] = {
        "plain_facts": facts,
        "type": entity.type,
        "display_value": finding.display_value,
        "attributes": entity.attributes,
        "seen_by": finding.seen_by,
        "signals": signal_phrases,
    }
    return {
        "entity_id": entity.id,
        "stated_text": {"body": finding.body, "why_ranked": finding.why_ranked},
        "real_facts": real_facts,
    }


def _judge_context(
    findings: tuple[Finding, ...], edges: Sequence[Edge]
) -> tuple[dict[str, list[Edge]], dict[str, Finding]]:
    in_brief = {f.entity.id: f for f in findings}
    # Every edge, not just brief-to-brief ones: the walk needs to pass
    # through un-narrated intermediates (see `_linked_facts`). Disclosure
    # is filtered at the endpoint, which is where it matters.
    edges_by_source: dict[str, list[Edge]] = defaultdict(list)
    for edge in edges:
        edges_by_source[edge.source_id].append(edge)
    return edges_by_source, in_brief


def build_judge_prompt(findings: tuple[Finding, ...], edges: Sequence[Edge] = ()) -> str:
    edges_by_source, in_brief = _judge_context(findings, edges)
    facts = [_judge_finding_facts(f, edges_by_source, in_brief) for f in findings]
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
class ClaimVerdict:
    """One atomic claim the judge extracted, and what it decided.

    `entity_id` and `entity_facts` are carried alongside the claim so a
    human re-checking the verdict has the same evidence the judge was
    given, rather than having to reconstruct it from a scan directory.
    """

    entity_id: str
    claim: str
    supported: bool
    entity_facts: str


@dataclass(frozen=True, slots=True)
class Stage2FaithfulnessResult:
    """ADR-0006 D1 stage 2: atomic-claim entailment via an LLM judge.

    `score` is precision-only, same convention as `FaithfulnessResult`
    (vacuously 1.0 when there's nothing to judge, not "unknown")."""

    total_claims: int
    supported_claims: int
    judge_model: str
    unjudged_findings: int  # degraded (no usable judge output), not fabricated
    # Every individual verdict, not just the totals. The counts alone make
    # the judge unauditable: `0.455` says some claims were rejected but not
    # which, so there is no way to check whether the judge was *right* --
    # and ADR-0006's own validation records that it makes real mistakes.
    # Keeping the verdicts is what makes judge reliability measurable at
    # all (open question 5). Defaulted, so nothing that only wants the
    # score is affected.
    claims: tuple[ClaimVerdict, ...] = ()

    @property
    def score(self) -> float:
        return self.supported_claims / self.total_claims if self.total_claims else 1.0


def faithfulness_stage2(
    brief: Brief,
    *,
    edges: Sequence[Edge] = (),
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

    `edges` lets the judge see facts about entities a finding is linked
    to, bounded to entities that are themselves in the brief. Optional and
    empty by default so a caller without a graph still gets a usable
    check, but a caller that has the edges should pass them -- without
    them, true claims spanning two entities are unverifiable and the
    judge's verdict on them means "I cannot see it" rather than "it is
    false" (ADR-0006 Validation, 2026-08-06).
    """
    if not brief.top_priorities:
        return Stage2FaithfulnessResult(
            total_claims=0, supported_claims=0, judge_model=judge_model, unjudged_findings=0
        )

    expected_ids = {f.entity.id for f in brief.top_priorities}
    prompt = build_judge_prompt(brief.top_priorities, edges)

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
    verdicts: list[ClaimVerdict] = []
    edges_by_source, in_brief = _judge_context(brief.top_priorities, edges)
    facts_by_id = {
        f.entity.id: _judge_finding_facts(f, edges_by_source, in_brief)
        for f in brief.top_priorities
    }
    for finding in brief.top_priorities:
        claims = judged.get(finding.entity.id)
        if claims is None:
            unjudged += 1
            continue
        total += len(claims)
        supported += sum(1 for _, ok in claims if ok)
        verdicts.extend(
            ClaimVerdict(
                entity_id=finding.entity.id,
                claim=claim,
                supported=ok,
                entity_facts=json.dumps(facts_by_id[finding.entity.id], sort_keys=True),
            )
            for claim, ok in claims
        )

    return Stage2FaithfulnessResult(
        total_claims=total,
        supported_claims=supported,
        judge_model=judge_model,
        unjudged_findings=unjudged,
        claims=tuple(verdicts),
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
