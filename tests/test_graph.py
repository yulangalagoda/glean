"""Tests for the relationship view model (`glean_osint.graph`).

Pure-function tests, same shape as `test_diff.py`: plain snapshot dicts in
(exactly what `history.read_*_snapshot` returns off disk), view model out.
"""

from __future__ import annotations

from typing import Any

from glean_osint.graph import RELATION_LABELS, anchor_slug, build_diagram, build_graph_view


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


# ── Diagram layout (roadmap theme 2) ─────────────────────────────────────


def _ent(entity_id: str, entity_type: str, value: str, score: float | None = None) -> dict:
    e: dict = {"id": entity_id, "type": entity_type, "value": value}
    if score is not None:
        e["priority"] = {"score": score, "rank": 1, "signals": []}
    return e


def _edge(src: str, dst: str, relation: str) -> dict:
    return {"source_id": src, "target_id": dst, "relation": relation}


def test_certificates_annotate_a_host_instead_of_taking_boxes() -> None:
    """The decision the layout turns on. Certificates were 313 of 531
    entities on a real scan; drawing each one produces exactly the hairball
    this view exists to replace. A certificate is evidence *about* a host,
    not a step in the chain, so it collapses into a count on the host it
    was issued for.
    """
    entities = [_ent("domain:example.com", "domain", "example.com")]
    edges = []
    for i in range(40):
        entities.append(_ent(f"certificate:{i}", "certificate", f"cert-{i}"))
        edges.append(_edge(f"certificate:{i}", "domain:example.com", "issued_for"))

    diagram = build_diagram(entities, edges)

    assert len(diagram.nodes) == 1  # forty certificates, one box
    assert diagram.badge_total == 40
    assert "40 certs" in diagram.nodes[0].badge


def test_layers_are_capped_by_priority_and_say_what_was_left_out() -> None:
    """Same top-N-plus-a-tail contract the brief uses. Silently dropping
    the rest would make the picture a lie about the scan's size."""
    entities = [_ent("domain:example.com", "domain", "example.com")]
    for i in range(25):
        entities.append(_ent(f"subdomain:h{i}.example.com", "subdomain", f"h{i}.example.com", i))

    diagram = build_diagram(entities, [], max_per_layer=10)

    hosts = [n for n in diagram.nodes if n.entity_type == "subdomain"]
    assert len(hosts) == 10
    assert diagram.hidden_total == 15
    # Highest-scoring survive the cap, not whichever happened to be first.
    assert hosts[0].score == 24
    layer = next(layer for layer in diagram.layers if layer.title == "Hosts")
    assert (layer.shown, layer.hidden) == (10, 15)


def test_every_curve_runs_left_to_right() -> None:
    """`subdomain_of` points child -> parent, against the reading order. A
    curve that ran backwards would make the flow unreadable, so edges are
    normalised to the layout direction rather than the data's direction."""
    entities = [
        _ent("domain:example.com", "domain", "example.com"),
        _ent("subdomain:a.example.com", "subdomain", "a.example.com"),
    ]
    edges = [_edge("subdomain:a.example.com", "domain:example.com", "subdomain_of")]

    diagram = build_diagram(entities, edges)

    assert len(diagram.edges) == 1
    path = diagram.edges[0].path
    start_x = float(path.split(",")[0].lstrip("M"))
    end_x = float(path.rsplit(" ", 1)[-1].split(",")[0])
    assert start_x < end_x


def test_an_edge_to_a_node_that_was_capped_away_is_not_drawn() -> None:
    """A curve trailing off into blank space is worse than no curve."""
    entities = [_ent("domain:example.com", "domain", "example.com")]
    edges = []
    for i in range(15):
        entities.append(_ent(f"subdomain:h{i}.example.com", "subdomain", f"h{i}.example.com", i))
        edges.append(_edge(f"subdomain:h{i}.example.com", "domain:example.com", "subdomain_of"))

    diagram = build_diagram(entities, edges, max_per_layer=5)

    drawn = {n.entity_id for n in diagram.nodes}
    assert len(diagram.edges) == 5
    assert len(drawn) == 6  # the apex plus five hosts


def test_an_empty_graph_lays_out_without_raising() -> None:
    diagram = build_diagram([], [])

    assert diagram.nodes == ()
    assert diagram.edges == ()
    assert diagram.width > 0 and diagram.height > 0


def test_layout_is_deterministic_for_equal_scores() -> None:
    """Same scan, same picture. Ties break alphabetically rather than on
    whatever order the snapshot happened to be written in."""
    entities = [
        _ent(f"subdomain:{c}.example.com", "subdomain", f"{c}.example.com", 1) for c in "cab"
    ]

    first = build_diagram(entities, [])
    again = build_diagram(list(reversed(entities)), [])

    assert [n.label for n in first.nodes] == [n.label for n in again.nodes]
    assert [n.label for n in first.nodes] == ["a.example.com", "b.example.com", "c.example.com"]
