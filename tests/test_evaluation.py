"""Tests for the evaluation harness (ADR-0006).

Stage-2 faithfulness tests mock the judge call via `urlopen` -- no real
network access happens in this suite.
"""

import json
import math
import urllib.error
from dataclasses import replace
from datetime import datetime, timezone

from glean_osint.brief import Brief, build_brief
from glean_osint.evaluation import (
    GroundTruth,
    GroundTruthEntry,
    build_judge_prompt,
    faithfulness_stage1,
    faithfulness_stage2,
    prioritisation_quality,
    provenance_retention,
)
from glean_osint.schema.entities import Entity, Priority, ProvenanceEntry, ScanMeta
from glean_osint.scoring import score_graph

AS_OF = datetime(2026, 7, 26, tzinfo=timezone.utc)

SCAN = ScanMeta(target="example.com", started_at="2026-07-26T09:00:00Z", glean_version="0.0.2")


def _prov(**kwargs: object) -> ProvenanceEntry:
    defaults: dict[str, object] = {
        "source_tool": "crtsh",
        "method": "passive",
        "collected_at": "2026-07-01T00:00:00Z",
    }
    defaults.update(kwargs)
    return ProvenanceEntry(**defaults)  # type: ignore[arg-type]


def _entity(entity_id: str, entity_type: str, value: str, **kwargs: object) -> Entity:
    kwargs.setdefault("provenance", (_prov(),))
    return Entity(id=entity_id, type=entity_type, value=value, **kwargs)  # type: ignore[arg-type]


# --- Faithfulness (D1 stage 1) -------------------------------------------


def test_faithfulness_stage1_is_perfect_for_a_real_brief() -> None:
    """The ADR's own claim: stage 1 passes trivially for a code-generated
    brief, since every Finding is built directly from a real entity."""
    entities = [
        _entity("domain:example.com", "domain", "example.com"),
        _entity("subdomain:admin.example.com", "subdomain", "admin.example.com"),
    ]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)

    result = faithfulness_stage1(brief, {e.id for e in scored})

    assert result.total_claims == 2
    assert result.supported_claims == 2
    assert result.score == 1.0


def test_faithfulness_stage1_catches_a_finding_absent_from_the_graph() -> None:
    """Proves the formula has real teeth for whenever a future LLM-written
    brief actually does fabricate a finding."""
    entities = [_entity("domain:example.com", "domain", "example.com")]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)

    real_entity_ids = {e.id for e in scored}  # graph does NOT contain the invented id
    tampered_finding = replace(
        brief.also_found[0], entity=_entity("subdomain:invented.example.com", "subdomain", "x")
    )
    tampered = replace(brief, also_found=(tampered_finding,))

    result = faithfulness_stage1(tampered, real_entity_ids)

    assert result.total_claims == 1
    assert result.supported_claims == 0
    assert result.score == 0.0


# --- Provenance retention (D3) --------------------------------------------


def test_provenance_retention_is_perfect_for_a_real_brief() -> None:
    entities = [
        _entity("domain:example.com", "domain", "example.com"),
        _entity("subdomain:admin.example.com", "subdomain", "admin.example.com"),
    ]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)

    assert provenance_retention(brief) == 1.0


def test_provenance_retention_catches_a_missing_seen_by_line() -> None:
    entities = [_entity("domain:example.com", "domain", "example.com")]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)

    stripped = replace(brief.also_found[0], seen_by="")
    tampered = replace(brief, also_found=(stripped,))

    assert provenance_retention(tampered) == 0.0


# --- Prioritisation quality (D2) ------------------------------------------


def test_overlap_at_n_identical_sets_is_perfect() -> None:
    gt = GroundTruth(
        target="example.com",
        annotator="tester",
        annotated_at="2026-07-26T00:00:00Z",
        entries=(GroundTruthEntry("A"), GroundTruthEntry("B"), GroundTruthEntry("C")),
    )
    result = prioritisation_quality(["A", "B", "C"], gt, n=3)
    assert result.overlap_at_n == 1.0
    assert result.ndcg_at_n == 1.0


def test_overlap_at_n_disjoint_sets_is_zero() -> None:
    gt = GroundTruth(
        target="example.com",
        annotator="tester",
        annotated_at="2026-07-26T00:00:00Z",
        entries=(GroundTruthEntry("A"), GroundTruthEntry("B"), GroundTruthEntry("C")),
    )
    result = prioritisation_quality(["X", "Y", "Z"], gt, n=3)
    assert result.overlap_at_n == 0.0
    assert result.ndcg_at_n == 0.0


def test_overlap_and_ndcg_reordered_partial_match() -> None:
    gt = GroundTruth(
        target="example.com",
        annotator="tester",
        annotated_at="2026-07-26T00:00:00Z",
        entries=(GroundTruthEntry("A"), GroundTruthEntry("B"), GroundTruthEntry("C")),
    )
    result = prioritisation_quality(["B", "A", "C"], gt, n=3)
    assert result.overlap_at_n == 1.0  # same set, different order
    assert math.isclose(result.ndcg_at_n, 0.9224945116765986)


def test_ndcg_penalises_a_glean_pick_the_human_did_not_choose() -> None:
    gt = GroundTruth(
        target="example.com",
        annotator="tester",
        annotated_at="2026-07-26T00:00:00Z",
        entries=(GroundTruthEntry("A"), GroundTruthEntry("B"), GroundTruthEntry("C")),
    )
    result = prioritisation_quality(["A", "X", "B"], gt, n=3)
    assert math.isclose(result.overlap_at_n, 2 / 4)  # {A,X,B} vs {A,B,C} -> 2/4
    assert math.isclose(result.ndcg_at_n, 0.8400079830158563)


def test_real_pilot_regression_yulan_me_overlap_at_3() -> None:
    """The exact, documented real result from the first ADR-0006/0007
    validation pass (_private/findings/yulan-me-ground-truth-validation.md,
    'after the fix' section): overlap@3 = 0.5. Glean's top-3 after the
    cert_orphaned fix were the three wildcard/subdomain entities tied at
    score 1, broken by lexicographic id (*, meridian, rampe); the
    annotator's blind top-3 were the apex domain, rampe, and meridian."""
    glean_top3 = [
        "subdomain:*.yulan.me",
        "subdomain:meridian.yulan.me",
        "subdomain:rampe.yulan.me",
    ]
    gt = GroundTruth(
        target="yulan.me",
        annotator="Yulan Galagoda",
        annotated_at="2026-07-23T00:00:00Z",
        entries=(
            GroundTruthEntry("domain:yulan.me", "main site, currently owned and live"),
            GroundTruthEntry("subdomain:rampe.yulan.me", "live, current work-in-progress site"),
            GroundTruthEntry("subdomain:meridian.yulan.me", "live, current work-in-progress site"),
        ),
    )

    result = prioritisation_quality(glean_top3, gt, n=3)

    assert result.overlap_at_n == 0.5


# --- Faithfulness (D1 stage 2) --------------------------------------------


class _FakeResponse:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._data


def _ollama_envelope(response_text: str) -> bytes:
    return json.dumps({"response": response_text}).encode("utf-8")


def _narrated_brief() -> Brief:
    entity = Entity(
        id="domain:example.com",
        type="domain",
        value="example.com",
        provenance=(_prov(),),
        priority=Priority(score=3.0, rank=1, signals=()),
    )
    brief = build_brief([entity], [], SCAN)
    narrated = replace(
        brief.top_priorities[0],
        body="Resolves to a live IP.",
        why_ranked="Seen independently by multiple tools.",
    )
    return replace(brief, top_priorities=(narrated,))


def test_build_judge_prompt_includes_stated_text_and_real_facts() -> None:
    brief = _narrated_brief()
    prompt = build_judge_prompt(brief.top_priorities)

    assert "Resolves to a live IP." in prompt
    assert "domain:example.com" in prompt


def test_faithfulness_stage2_counts_supported_and_unsupported_claims() -> None:
    brief = _narrated_brief()

    def fake_urlopen(request: object, timeout: float) -> _FakeResponse:
        text = json.dumps(
            {
                "findings": [
                    {
                        "entity_id": "domain:example.com",
                        "claims": [
                            {"claim": "Resolves to a live IP.", "supported": True},
                            {"claim": "Runs outdated software.", "supported": False},
                        ],
                    }
                ]
            }
        )
        return _FakeResponse(_ollama_envelope(text))

    result = faithfulness_stage2(brief, urlopen=fake_urlopen)

    assert result.total_claims == 2
    assert result.supported_claims == 1
    assert result.score == 0.5
    assert result.unjudged_findings == 0


def test_faithfulness_stage2_falls_back_to_unjudged_on_ollama_error() -> None:
    brief = _narrated_brief()

    def fake_urlopen(request: object, timeout: float) -> _FakeResponse:
        raise urllib.error.URLError("connection refused")

    result = faithfulness_stage2(brief, urlopen=fake_urlopen)

    assert result.total_claims == 0
    assert result.unjudged_findings == 1
    assert result.score == 1.0  # vacuous, same convention as stage 1


def test_faithfulness_stage2_skips_when_no_top_priorities() -> None:
    entity = Entity(
        id="domain:example.com",
        type="domain",
        value="example.com",
        provenance=(_prov(),),
        priority=Priority(score=0.0, rank=1, signals=()),
    )
    brief = build_brief([entity], [], SCAN)
    assert brief.top_priorities == ()

    def fail_if_called(request: object, timeout: float) -> _FakeResponse:
        raise AssertionError("must not call the judge with no top_priorities")

    result = faithfulness_stage2(brief, urlopen=fail_if_called)
    assert result.total_claims == 0
    assert result.unjudged_findings == 0
