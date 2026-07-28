"""Tests for the relationship view model (`glean_osint.graph`).

Pure-function tests, same shape as `test_diff.py`: plain snapshot dicts in
(exactly what `history.read_*_snapshot` returns off disk), view model out.
"""

from __future__ import annotations

from typing import Any

from glean_osint.graph import RELATION_LABELS, anchor_slug, build_graph_view


def entity(
    entity_id: str, value: str, entity_type: str, rank: int | None = None, score: float = 0.0
) -> dict[str, Any]:
    record: dict[str, Any] = {"id": entity_id, "type": entity_type, "value": value}
    if rank is not None:
        record["priority"] = {"score": score, "rank": rank, "signals": []}
    return record


def edge(source: str, target: str, relation: str) -> dict[str, Any]:
    return {"source_id": source, "target_id": target, "relation": relation}


def test_edges_group_under_their_source_ordered_by_priority_rank() -> None:
    """Ordering reuses the rubric's own ranking rather than inventing a
    second one -- the most important finding's relationships come first."""
    entities = [
        entity("subdomain:www.example.com", "www.example.com", "subdomain", rank=2, score=2.0),
        entity("subdomain:admin.example.com", "admin.example.com", "subdomain", rank=1, score=4.0),
        entity("ip_address:203.0.113.1", "203.0.113.1", "ip_address", rank=3),
        entity("ip_address:203.0.113.2", "203.0.113.2", "ip_address", rank=4),
    ]
    edges = [
        edge("subdomain:www.example.com", "ip_address:203.0.113.1", "resolves_to"),
        edge("subdomain:admin.example.com", "ip_address:203.0.113.2", "resolves_to"),
    ]

    view = build_graph_view(entities, edges)

    assert [c.value for c in view.clusters] == ["admin.example.com", "www.example.com"]
    assert view.clusters[0].rank == 1
    assert view.clusters[0].neighbours[0].value == "203.0.113.2"
    assert view.clusters[0].neighbours[0].relation_label == "resolves to"


def test_counts_report_the_real_shape_of_the_graph() -> None:
    entities = [
        entity("subdomain:a.example.com", "a.example.com", "subdomain", rank=1),
        entity("ip_address:203.0.113.1", "203.0.113.1", "ip_address", rank=2),
        entity("email_address:x@example.com", "x@example.com", "email_address", rank=3),
    ]
    edges = [edge("subdomain:a.example.com", "ip_address:203.0.113.1", "resolves_to")]

    view = build_graph_view(entities, edges)

    assert view.entity_count == 3
    assert view.edge_count == 1
    # The email is in the graph but linked to nothing -- a real fact about
    # this scan, reported rather than hidden.
    assert view.unconnected_count == 1
    assert view.relation_counts == (("resolves_to", 1),)


def test_an_edge_pointing_at_a_missing_entity_is_flagged_not_dropped() -> None:
    """The two snapshots disagreeing is worth seeing. Silently dropping the
    edge would make the graph look clean while hiding a real inconsistency."""
    entities = [entity("subdomain:a.example.com", "a.example.com", "subdomain", rank=1)]
    edges = [edge("subdomain:a.example.com", "ip_address:203.0.113.9", "resolves_to")]

    view = build_graph_view(entities, edges)

    assert view.dangling_count == 1
    neighbour = view.clusters[0].neighbours[0]
    assert neighbour.dangling is True
    # Falls back to the raw id rather than inventing a display value.
    assert neighbour.value == "ip_address:203.0.113.9"
    assert neighbour.entity_type == "unknown"


def test_unknown_relation_is_shown_rather_than_discarded() -> None:
    """A new adapter's new relation type must appear the day it's added, not
    the day someone remembers to update RELATION_LABELS."""
    entities = [
        entity("subdomain:a.example.com", "a.example.com", "subdomain", rank=1),
        entity("domain:example.com", "example.com", "domain", rank=2),
    ]
    edges = [edge("subdomain:a.example.com", "domain:example.com", "invented_by_a_new_adapter")]

    view = build_graph_view(entities, edges)

    assert "invented_by_a_new_adapter" not in RELATION_LABELS
    assert view.clusters[0].neighbours[0].relation_label == "invented by a new adapter"
    assert view.relation_counts == (("invented_by_a_new_adapter", 1),)


def test_malformed_edge_records_are_skipped_without_crashing() -> None:
    entities = [entity("subdomain:a.example.com", "a.example.com", "subdomain", rank=1)]
    edges: list[dict[str, Any]] = [
        {"source_id": "subdomain:a.example.com"},  # no target, no relation
        {"target_id": "x", "relation": "resolves_to"},  # no source
        {"source_id": 1, "target_id": 2, "relation": 3},  # wrong types
    ]

    view = build_graph_view(entities, edges)

    assert view.clusters == ()
    assert view.relation_counts == ()


def test_empty_graph_is_representable() -> None:
    view = build_graph_view([], [])
    assert view.clusters == ()
    assert view.entity_count == 0
    assert view.unconnected_count == 0


def test_anchor_slug_matches_the_expression_report_js_uses() -> None:
    """These two must agree or every "in brief" link 404s for the ids that
    differ. Wildcards are the case a naive per-character replacement misses.
    """
    assert anchor_slug("subdomain:admin.example.com") == "f-subdomain-admin-example-com"
    assert anchor_slug("service:203.0.113.1:443") == "f-service-203-0-113-1-443"
    assert anchor_slug("subdomain:*.example.com") == "f-subdomain---example-com"
