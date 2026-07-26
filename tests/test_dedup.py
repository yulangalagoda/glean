"""Tests for deterministic correlation & dedup (ADR-0003)."""

import itertools
import random
from pathlib import Path

from glean_osint.adapters.base import ParseResult, ScanContext
from glean_osint.adapters.crtsh import CrtshAdapter
from glean_osint.adapters.theharvester import TheHarvesterAdapter
from glean_osint.dedup import merge_graph
from glean_osint.schema.entities import Edge, Entity, ProvenanceEntry


def _prov(**kwargs: object) -> ProvenanceEntry:
    defaults = {
        "source_tool": "crtsh",
        "method": "passive",
        "collected_at": "2026-01-01T00:00:00Z",
    }
    defaults.update(kwargs)
    return ProvenanceEntry(**defaults)  # type: ignore[arg-type]


def test_merge_collapses_exact_id_match_and_unions_provenance() -> None:
    """ADR-0003 D1/D2: same id -> one entity, provenance unioned, attributes
    unioned when they don't conflict, first/last_seen are min/max."""
    crtsh_prov = _prov(
        source_tool="crtsh",
        method="passive",
        collected_at="2026-01-01T00:00:00Z",
        raw_record_ref="$[1]",
    )
    amass_prov = _prov(
        source_tool="amass",
        method="active",
        collected_at="2026-02-01T00:00:00Z",
        raw_record_ref="line:212",
    )
    e1 = Entity(
        id="subdomain:admin.example.com",
        type="subdomain",
        value="admin.example.com",
        provenance=(crtsh_prov,),
    )
    e2 = Entity(
        id="subdomain:admin.example.com",
        type="subdomain",
        value="admin.example.com",
        provenance=(amass_prov,),
        attributes={"resolved_ip": "203.0.113.42"},
    )

    result = merge_graph([ParseResult(entities=[e1, e2])])

    assert len(result.entities) == 1
    merged = result.entities[0]
    # Canonical provenance order is sorted (by source_tool first), not
    # insertion order — "amass" sorts before "crtsh" (ADR-0003 D7).
    assert merged.provenance == (amass_prov, crtsh_prov)
    assert merged.attributes == {"resolved_ip": "203.0.113.42"}
    assert merged.first_seen == "2026-01-01T00:00:00Z"
    assert merged.last_seen == "2026-02-01T00:00:00Z"
    assert result.stats.entities_before == 2
    assert result.stats.entities_after == 1
    assert result.stats.duplicate_rate == 0.5


def test_identical_provenance_entries_collapse() -> None:
    """Exact duplicate provenance (e.g. two adapters both citing the same
    tool/record) is not double-counted (ADR-0003 D2)."""
    prov = _prov(raw_record_ref="$[0]")
    e1 = Entity(id="domain:example.com", type="domain", value="example.com", provenance=(prov,))
    e2 = Entity(id="domain:example.com", type="domain", value="example.com", provenance=(prov,))

    result = merge_graph([ParseResult(entities=[e1, e2])])

    assert len(result.entities) == 1
    assert result.entities[0].provenance == (prov,)


def test_conflict_resolution_prefers_higher_confidence() -> None:
    lo = Entity(
        id="subdomain:x.example.com",
        type="subdomain",
        value="x.example.com",
        provenance=(_prov(confidence=0.5),),
        attributes={"owner": "team-a"},
    )
    hi = Entity(
        id="subdomain:x.example.com",
        type="subdomain",
        value="x.example.com",
        provenance=(_prov(source_tool="amass", confidence=0.9),),
        attributes={"owner": "team-z"},
    )

    merged = merge_graph([ParseResult(entities=[lo, hi])]).entities[0]

    assert merged.attributes["owner"] == "team-z"
    assert merged.attributes["_conflicts"]["owner"] == ["team-a"]


def test_conflict_resolution_prefers_active_over_passive_when_no_confidence() -> None:
    passive = Entity(
        id="subdomain:x.example.com",
        type="subdomain",
        value="x.example.com",
        provenance=(_prov(method="passive"),),
        attributes={"owner": "team-a"},
    )
    active = Entity(
        id="subdomain:x.example.com",
        type="subdomain",
        value="x.example.com",
        provenance=(_prov(source_tool="amass", method="active"),),
        attributes={"owner": "team-z"},
    )

    # team-a sorts before team-z lexicographically, but active must still win.
    merged = merge_graph([ParseResult(entities=[passive, active])]).entities[0]

    assert merged.attributes["owner"] == "team-z"
    assert merged.attributes["_conflicts"]["owner"] == ["team-a"]


def test_conflict_resolution_falls_back_to_lexicographic_order() -> None:
    e1 = Entity(
        id="subdomain:x.example.com",
        type="subdomain",
        value="x.example.com",
        provenance=(_prov(),),
        attributes={"owner": "team-z"},
    )
    e2 = Entity(
        id="subdomain:x.example.com",
        type="subdomain",
        value="x.example.com",
        provenance=(_prov(source_tool="amass"),),
        attributes={"owner": "team-a"},
    )

    merged = merge_graph([ParseResult(entities=[e1, e2])]).entities[0]

    assert merged.attributes["owner"] == "team-a"
    assert merged.attributes["_conflicts"]["owner"] == ["team-z"]


def test_edge_dedup_unions_provenance() -> None:
    domain = Entity(
        id="domain:example.com", type="domain", value="example.com", provenance=(_prov(),)
    )
    sub = Entity(
        id="subdomain:x.example.com", type="subdomain", value="x.example.com", provenance=(_prov(),)
    )
    prov_a = _prov(source_tool="crtsh")
    prov_b = _prov(source_tool="theharvester")
    edge_a = Edge(
        source_id=sub.id, target_id=domain.id, relation="subdomain_of", provenance=(prov_a,)
    )
    edge_b = Edge(
        source_id=sub.id, target_id=domain.id, relation="subdomain_of", provenance=(prov_b,)
    )

    result = merge_graph([ParseResult(entities=[domain, sub], edges=[edge_a, edge_b])])

    assert len(result.edges) == 1
    assert result.edges[0].provenance == (prov_a, prov_b)


def test_dangling_edges_are_dropped_and_counted() -> None:
    sub = Entity(
        id="subdomain:x.example.com", type="subdomain", value="x.example.com", provenance=(_prov(),)
    )
    dangling = Edge(
        source_id=sub.id, target_id="domain:example.com", relation="subdomain_of"
    )  # domain:example.com never emitted

    result = merge_graph([ParseResult(entities=[sub], edges=[dangling])])

    assert result.edges == []
    assert result.stats.dangling_edges_dropped == 1


def test_merge_is_order_independent() -> None:
    """ADR-0003 D7: shuffle the input, assert identical output."""
    entities = [
        Entity(
            id="subdomain:a.example.com",
            type="subdomain",
            value="a.example.com",
            provenance=(_prov(source_tool=f"tool{i}"),),
        )
        for i in range(4)
    ] + [Entity(id="domain:example.com", type="domain", value="example.com", provenance=(_prov(),))]
    edges = [
        Edge(
            source_id="subdomain:a.example.com",
            target_id="domain:example.com",
            relation="subdomain_of",
        )
        for _ in range(3)
    ]

    baseline = merge_graph([ParseResult(entities=entities, edges=edges)])
    baseline_entities = [e.to_dict() for e in baseline.entities]
    baseline_edges = [e.to_dict() for e in baseline.edges]

    rng = random.Random(42)
    for _ in range(10):
        shuffled_entities = entities[:]
        shuffled_edges = edges[:]
        rng.shuffle(shuffled_entities)
        rng.shuffle(shuffled_edges)
        result = merge_graph([ParseResult(entities=shuffled_entities, edges=shuffled_edges)])
        assert [e.to_dict() for e in result.entities] == baseline_entities
        assert [e.to_dict() for e in result.edges] == baseline_edges


def test_merge_is_order_independent_across_parse_result_order() -> None:
    """Same as above, but shuffling which adapter's ParseResult is merged first."""
    a = ParseResult(
        entities=[
            Entity(
                id="domain:example.com", type="domain", value="example.com", provenance=(_prov(),)
            )
        ]
    )
    b = ParseResult(
        entities=[
            Entity(
                id="domain:example.com",
                type="domain",
                value="example.com",
                provenance=(_prov(source_tool="amass", method="active"),),
            )
        ]
    )

    for ordering in itertools.permutations([a, b]):
        result = merge_graph(list(ordering))
        assert len(result.entities) == 1
        assert len(result.entities[0].provenance) == 2


def test_cross_tool_overlap_matches_worked_example() -> None:
    """Integration test mirroring ADR-0003's own worked example: run two
    real adapters against the same target and confirm dedup collapses the
    genuine cross-tool + intra-tool overlap between them."""
    ctx = ScanContext(
        target="example.com",
        collected_at="2026-07-26T20:00:00Z",
        raw_output_ref="raw/example.json",
    )
    fixtures = Path(__file__).parent / "fixtures"
    crtsh_raw = (fixtures / "crtsh-example-com.json").read_bytes()
    th_raw = (fixtures / "theharvester-example-com.json").read_bytes()

    crtsh_result = CrtshAdapter().parse(crtsh_raw, ctx)
    th_result = TheHarvesterAdapter().parse(th_raw, ctx)

    merged = merge_graph([crtsh_result, th_result])

    assert merged.stats.entities_before == 16
    assert merged.stats.entities_after == 10
    assert merged.stats.duplicate_rate == 0.375

    admin = next(e for e in merged.entities if e.id == "subdomain:admin.example.com")
    assert len(admin.provenance) == 3
    assert {p.source_tool for p in admin.provenance} == {"crtsh", "theharvester"}
