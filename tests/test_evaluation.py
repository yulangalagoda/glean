"""Tests for the evaluation harness (ADR-0006).

Stage-2 faithfulness tests mock the judge call via `urlopen` -- no real
network access happens in this suite.
"""

import json
import math
import urllib.error
from dataclasses import replace
from datetime import datetime, timezone

from glean_osint import synthesis
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
from glean_osint.schema.entities import Edge, Entity, Priority, ProvenanceEntry, ScanMeta
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


# --- What the judge is shown (ADR-0006 Validation, 2026-08-04) ------------


def _all_findings(brief: Brief) -> tuple[object, ...]:
    """Both tiers. These fixtures are single low-scoring entities, which
    land in `also_found`; the prompt builder is tier-agnostic and it is the
    fact rendering under test here, not the ranking."""
    return brief.top_priorities + brief.also_found


def test_boolean_attributes_are_spelled_out_for_the_judge() -> None:
    """The defect the judge audit found: `dns_resolved: true` carries its
    meaning in the key name, and the judge false-flagged claims like
    "resolves to a live IP" whose only evidence was that pair."""
    entities = [
        _entity(
            "subdomain:live.example.com",
            "subdomain",
            "live.example.com",
            attributes={"dns_resolved": True},
        )
    ]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)

    prompt = build_judge_prompt(_all_findings(brief))

    assert "It resolves in DNS: it is a live host." in prompt
    # The structured form stays -- the sentence is an addition, not a
    # replacement, so nothing that read `attributes` before loses it.
    assert '"dns_resolved": true' in prompt


def test_a_dead_host_is_not_described_as_live() -> None:
    entities = [
        _entity(
            "subdomain:dead.example.com",
            "subdomain",
            "dead.example.com",
            attributes={"dns_resolved": False},
        )
    ]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)

    prompt = build_judge_prompt(_all_findings(brief))

    assert "It does not resolve in DNS: it is a confirmed dead host." in prompt
    assert "it is a live host" not in prompt


def test_list_attributes_render_as_values_not_as_python_syntax() -> None:
    """A certificate's `san` is a list. It also cannot be part of a dict
    key, which is why the sentence table is consulted for booleans only."""
    entities = [
        _entity(
            "certificate:serial|issuer",
            "certificate",
            "serial|issuer",
            attributes={"san": ["a.example.com", "b.example.com"]},
        )
    ]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)

    prompt = build_judge_prompt(_all_findings(brief))

    assert "Its san is a.example.com, b.example.com." in prompt


def test_the_judge_is_shown_no_fact_the_narrator_was_not() -> None:
    """Load-bearing equivalence: a judge given facts the narrator never had
    would start ratifying invention instead of checking it. The plain
    sentences must be a restatement of the narrator's own view, so every
    value in them has to appear in the narration prompt too."""
    entities = [
        _entity(
            "subdomain:live.example.com",
            "subdomain",
            "live.example.com",
            attributes={"dns_resolved": True, "wildcard": False},
        ),
        _entity(
            "service:1.2.3.4:443",
            "service",
            "1.2.3.4:443",
            attributes={"port": 443, "protocol": "tcp", "service": "https"},
        ),
    ]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)

    narrator_prompt = synthesis.build_prompt(_all_findings(brief))
    judge_facts = json.loads(build_judge_prompt(_all_findings(brief)).split("Findings:\n", 1)[1])

    for finding in judge_facts:
        for sentence in finding["real_facts"]["plain_facts"]:
            for value in ("live.example.com", "443", "https", "tcp"):
                if value in sentence:
                    assert value in narrator_prompt


def test_linked_facts_reach_a_service_through_an_unnarrated_hop() -> None:
    """The 2026-08-06 disagreements in one test. A subdomain's prose says it
    resolves to a live IP with an exposed HTTPS service; the protocol lives
    on the `service:` entity two hops away, and the `ip_address` in between
    is often not narrated at all. The walk must pass through it."""
    entities = [
        _entity(
            "subdomain:beta.example.com",
            "subdomain",
            "beta.example.com",
            attributes={"dns_resolved": True},
        ),
        _entity("ip_address:1.2.3.4", "ip_address", "1.2.3.4"),
        _entity(
            "service:1.2.3.4:443",
            "service",
            "1.2.3.4:443",
            attributes={"port": 443, "protocol": "tcp", "service": "https"},
        ),
    ]
    edges = [
        Edge(
            source_id="subdomain:beta.example.com",
            target_id="ip_address:1.2.3.4",
            relation="resolves_to",
        ),
        Edge(
            source_id="ip_address:1.2.3.4",
            target_id="service:1.2.3.4:443",
            relation="exposes_service",
        ),
    ]
    scored = score_graph(entities, edges, AS_OF)
    brief = build_brief(scored, edges, SCAN)
    # The intermediate IP is deliberately excluded from what gets narrated.
    findings = tuple(f for f in _all_findings(brief) if f.entity.id != "ip_address:1.2.3.4")

    prompt = build_judge_prompt(findings, edges)

    assert "service https" in prompt
    assert "via resolves to then exposes" in prompt


def test_traversal_discloses_nothing_about_an_entity_outside_the_brief() -> None:
    """Passing through a node must not describe it. The narrator only sees
    narrated findings, so describing an un-narrated entity would let the
    judge ratify a claim the narrator had no basis to make."""
    entities = [
        _entity(
            "subdomain:beta.example.com",
            "subdomain",
            "beta.example.com",
            attributes={"dns_resolved": True},
        ),
        _entity(
            "ip_address:1.2.3.4", "ip_address", "1.2.3.4", attributes={"asn": "AS-SECRET-13335"}
        ),
    ]
    edges = [
        Edge(
            source_id="subdomain:beta.example.com",
            target_id="ip_address:1.2.3.4",
            relation="resolves_to",
        ),
    ]
    scored = score_graph(entities, edges, AS_OF)
    brief = build_brief(scored, edges, SCAN)
    findings = tuple(f for f in _all_findings(brief) if f.entity.id != "ip_address:1.2.3.4")

    prompt = build_judge_prompt(findings, edges)

    assert "AS-SECRET-13335" not in prompt


def test_no_edges_means_no_linked_facts_rather_than_an_error() -> None:
    """`edges` is optional: a caller without a graph still gets a check."""
    entities = [_entity("subdomain:a.example.com", "subdomain", "a.example.com")]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)

    # Checked against the payload, not the whole prompt: the preamble
    # explains connected facts, so a substring test would always match.
    facts = json.loads(build_judge_prompt(_all_findings(brief)).split("Findings:\n", 1)[1])

    assert all(not any("is connected" in s for s in f["real_facts"]["plain_facts"]) for f in facts)


def test_a_parents_resolution_is_not_attributed_to_a_wildcard_child() -> None:
    """A wildcard entry resolves to nothing, but its parent domain does.
    Walking through `subdomain_of` presented the parent's IP as something
    the wildcard reached, and the judge accepted "resolves to a live IP"
    on that basis -- ratifying a real fabrication. Properties do not
    inherit down a containment edge."""
    entities = [
        _entity(
            "subdomain:*.example.com", "subdomain", "*.example.com", attributes={"wildcard": True}
        ),
        _entity("domain:example.com", "domain", "example.com", attributes={"dns_resolved": True}),
        _entity("ip_address:9.9.9.9", "ip_address", "9.9.9.9"),
    ]
    edges = [
        Edge(
            source_id="subdomain:*.example.com",
            target_id="domain:example.com",
            relation="subdomain_of",
        ),
        Edge(
            source_id="domain:example.com", target_id="ip_address:9.9.9.9", relation="resolves_to"
        ),
    ]
    scored = score_graph(entities, edges, AS_OF)
    brief = build_brief(scored, edges, SCAN)

    facts = json.loads(build_judge_prompt(_all_findings(brief), edges).split("Findings:\n", 1)[1])
    wildcard = next(f for f in facts if f["entity_id"] == "subdomain:*.example.com")
    evidence = wildcard["real_facts"]["plain_facts"]

    # The parent itself may be named -- that much is true.
    assert any("is a subdomain of" in fact for fact in evidence)
    # What it resolves to must not be, since the wildcard reaches no IP.
    assert not any("9.9.9.9" in fact for fact in evidence)


# --- Stage 1b: structural contradictions (ADR-0006 D1, 2026-08-06) --------


def test_a_wildcard_narrated_as_resolving_fails_stage_1() -> None:
    """The fabrication six judge-prompt variants could not catch reliably.
    Nothing records `*.example.com` resolving, so prose saying it does is
    decidable without a model."""
    entities = [
        _entity(
            "subdomain:*.example.com", "subdomain", "*.example.com", attributes={"wildcard": True}
        ),
    ]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)
    narrated = replace(
        brief,
        also_found=(
            replace(
                brief.also_found[0],
                body="Wildcard subdomain *.example.com resolves to a live IP.",
            ),
        ),
    )

    result = faithfulness_stage1(
        narrated, {e.id for e in scored}, edges=[], entity_types={e.id: e.type for e in scored}
    )

    assert result.score == 0.0
    assert [c.kind for c in result.contradictions] == ["resolution"]


def test_a_host_that_really_resolves_is_not_flagged() -> None:
    entities = [
        _entity(
            "subdomain:live.example.com",
            "subdomain",
            "live.example.com",
            attributes={"dns_resolved": True},
        ),
    ]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)
    narrated = replace(
        brief,
        also_found=(replace(brief.also_found[0], body="It resolves to a live IP."),),
    )

    result = faithfulness_stage1(
        narrated, {e.id for e in scored}, edges=[], entity_types={e.id: e.type for e in scored}
    )

    assert result.score == 1.0
    assert result.contradictions == ()


def test_a_service_claim_is_supported_through_a_resolves_to_edge() -> None:
    """Reachability, not just the entity's own record -- otherwise every
    subdomain describing its host's service would be flagged."""
    entities = [
        _entity(
            "subdomain:a.example.com",
            "subdomain",
            "a.example.com",
            attributes={"dns_resolved": True},
        ),
        _entity("ip_address:1.2.3.4", "ip_address", "1.2.3.4"),
        _entity(
            "service:1.2.3.4:443",
            "service",
            "1.2.3.4:443",
            attributes={"port": 443, "protocol": "tcp", "service": "https"},
        ),
    ]
    edges = [
        Edge(
            source_id="subdomain:a.example.com",
            target_id="ip_address:1.2.3.4",
            relation="resolves_to",
        ),
        Edge(
            source_id="ip_address:1.2.3.4",
            target_id="service:1.2.3.4:443",
            relation="exposes_service",
        ),
    ]
    scored = score_graph(entities, edges, AS_OF)
    brief = build_brief(scored, edges, SCAN)
    sub = next(
        f
        for f in brief.top_priorities + brief.also_found
        if f.entity.id == "subdomain:a.example.com"
    )
    rest = tuple(
        f
        for f in brief.top_priorities + brief.also_found
        if f.entity.id != "subdomain:a.example.com"
    )
    narrated = replace(
        brief,
        top_priorities=(),
        also_found=(replace(sub, body="Resolves to a live IP with an exposed service."), *rest),
    )

    result = faithfulness_stage1(
        narrated,
        {e.id for e in scored},
        edges=edges,
        entity_types={e.id: e.type for e in scored},
    )

    assert result.contradictions == ()


def test_a_parents_resolution_does_not_excuse_a_wildcards_claim() -> None:
    """Same containment rule as the judge's evidence walk: `subdomain_of`
    is not a path along which resolution reaches the child."""
    entities = [
        _entity(
            "subdomain:*.example.com", "subdomain", "*.example.com", attributes={"wildcard": True}
        ),
        _entity("domain:example.com", "domain", "example.com", attributes={"dns_resolved": True}),
        _entity("ip_address:9.9.9.9", "ip_address", "9.9.9.9"),
    ]
    edges = [
        Edge(
            source_id="subdomain:*.example.com",
            target_id="domain:example.com",
            relation="subdomain_of",
        ),
        Edge(
            source_id="domain:example.com", target_id="ip_address:9.9.9.9", relation="resolves_to"
        ),
    ]
    scored = score_graph(entities, edges, AS_OF)
    brief = build_brief(scored, edges, SCAN)
    wildcard = next(
        f
        for f in brief.top_priorities + brief.also_found
        if f.entity.id == "subdomain:*.example.com"
    )
    rest = tuple(
        f
        for f in brief.top_priorities + brief.also_found
        if f.entity.id != "subdomain:*.example.com"
    )
    narrated = replace(
        brief,
        top_priorities=(),
        also_found=(replace(wildcard, body="It resolves to a live IP."), *rest),
    )

    result = faithfulness_stage1(
        narrated,
        {e.id for e in scored},
        edges=edges,
        entity_types={e.id: e.type for e in scored},
    )

    assert [c.entity_id for c in result.contradictions] == ["subdomain:*.example.com"]


def test_without_a_graph_only_the_entity_existence_check_runs() -> None:
    """Back-compatible by design: a caller with no edges still gets 1a
    rather than an error or a silently wrong flag."""
    entities = [
        _entity(
            "subdomain:*.example.com", "subdomain", "*.example.com", attributes={"wildcard": True}
        ),
    ]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)
    narrated = replace(
        brief,
        also_found=(replace(brief.also_found[0], body="Resolves to a live IP."),),
    )

    result = faithfulness_stage1(narrated, {e.id for e in scored})

    assert result.score == 1.0
    assert result.contradictions == ()


# --- Fact-list echoes (ADR-0006 Validation, 2026-08-10) -------------------


def _judged_brief(claims: list[dict[str, object]]) -> tuple[Brief, object]:
    """A one-finding brief plus a judge that returns exactly `claims`."""
    entities = [
        _entity(
            "subdomain:live.example.com",
            "subdomain",
            "live.example.com",
            attributes={"dns_resolved": True},
        )
    ]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)
    finding = (brief.top_priorities + brief.also_found)[0]
    narrated = replace(
        brief,
        top_priorities=(replace(finding, body="It resolves to a live IP.", why_ranked="live"),),
        also_found=(),
    )

    def urlopen(request: object, timeout: float = 0) -> object:
        return _FakeResponse(
            _ollama_envelope(
                json.dumps(
                    {"findings": [{"entity_id": "subdomain:live.example.com", "claims": claims}]}
                )
            )
        )

    return narrated, urlopen


def test_a_claim_lifted_from_the_evidence_is_dropped_before_scoring() -> None:
    """The judge is told twice to decompose stated_text only, and does it
    anyway: 50 of 136 claims in the 2026-08-10 audit were verbatim copies of
    a fact line, carrying 10 of the 11 false flags. An instruction a model
    can ignore is not a control."""
    brief, urlopen = _judged_brief(
        [
            {"claim": "It resolves to a live IP", "supported": True},
            # Straight out of `plain_facts`, and absent from the prose.
            {"claim": "It resolves in DNS: it is a live host.", "supported": False},
        ]
    )

    result = faithfulness_stage2(brief, urlopen=urlopen)

    assert result.total_claims == 1
    assert result.echoed_claims == 1
    assert result.score == 1.0
    assert [c.claim for c in result.claims] == ["It resolves to a live IP"]


def test_prose_that_happens_to_restate_a_fact_is_kept() -> None:
    """The safety condition. A narrator may restate a fact almost word for
    word; such a claim appears in stated_text and must survive, or the
    filter would silently delete real judgements."""
    brief, _ = _judged_brief([])
    # The prose itself echoes the fact line verbatim, which a narrator may
    # legitimately do.
    finding = brief.top_priorities[0]
    brief = replace(
        brief,
        top_priorities=(replace(finding, body="It resolves in DNS: it is a live host."),),
    )

    def echo_urlopen(request: object, timeout: float = 0) -> object:
        return _FakeResponse(
            _ollama_envelope(
                json.dumps(
                    {
                        "findings": [
                            {
                                "entity_id": "subdomain:live.example.com",
                                "claims": [
                                    {
                                        "claim": "It resolves in DNS: it is a live host.",
                                        "supported": False,
                                    }
                                ],
                            }
                        ]
                    }
                )
            )
        )

    result = faithfulness_stage2(brief, urlopen=echo_urlopen)

    assert result.echoed_claims == 0
    assert result.total_claims == 1
    assert result.score == 0.0


def test_a_finding_of_nothing_but_echoes_counts_as_unjudged() -> None:
    """If every 'claim' came from the evidence, the judge said nothing about
    the prose. Scoring that as a vacuous 1.000 would inflate the metric with
    the judge's own failure."""
    brief, urlopen = _judged_brief(
        [{"claim": "It resolves in DNS: it is a live host.", "supported": False}]
    )

    result = faithfulness_stage2(brief, urlopen=urlopen)

    assert result.total_claims == 0
    assert result.echoed_claims == 1
    assert result.unjudged_findings == 1
