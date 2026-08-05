"""Turn a saved scan's entity + edge snapshots into a browsable view of the
correlation stage's output.

The deterministic correlation is the charter's central claim -- entity
linking is done in code, never by the model -- but until now it was the one
stage with nothing to show for itself. `merge_graph` produced a typed edge
set, `build_brief` borrowed it to phrase a few finding bodies, and it was
then discarded. Persisting edges (`history.write_edges_snapshot`) makes that
work durable; this module makes it legible.

Pure, like `diff.py` and `dedup.py`: dicts in, view model out, no I/O and no
clock. It takes the plain `to_dict()` shapes read back off disk rather than
`Entity`/`Edge` objects, so it stays usable for any scan already archived
without a migration step.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

# MUST stay identical to report.js's own slug expression
# (`id.replace(/[^A-Za-z0-9_-]/g, "-")`). The brief page builds finding
# anchors client-side in JS; this page links to them server-side in Python.
# Two independent transliterations of the same id is how you get links that
# work for `admin.example.com` and silently 404 for `*.example.com`, so the
# rule lives in one named place on each side with a pointer between them.
_ANCHOR_UNSAFE = re.compile(r"[^A-Za-z0-9_-]")


def anchor_slug(entity_id: str) -> str:
    """The `#fragment` that `report.js` gives this entity's card."""
    return "f-" + _ANCHOR_UNSAFE.sub("-", entity_id)


# Read side of the same relation vocabulary the adapters emit (ADR-0001 D6),
# phrased for a human. An unknown relation is shown as-is rather than
# dropped -- a new adapter's new relation type should appear in this view
# the day it's added, not the day someone remembers to update this table.
RELATION_LABELS: dict[str, str] = {
    "resolves_to": "resolves to",
    "subdomain_of": "is a subdomain of",
    "hosts": "hosts",
    "exposes_service": "exposes service",
    "runs_tech": "runs",
    "issued_for": "issued for",
    "exposed_in": "exposed in",
}


@dataclass(frozen=True, slots=True)
class GraphNeighbour:
    relation: str
    relation_label: str
    entity_id: str
    value: str
    entity_type: str
    # True when an edge points at an id absent from the entity snapshot.
    # Surfaced rather than silently dropped: it means the two files
    # disagree, which is worth seeing, not hiding.
    dangling: bool


@dataclass(frozen=True, slots=True)
class GraphCluster:
    entity_id: str
    value: str
    entity_type: str
    rank: int | None
    score: float | None
    neighbours: tuple[GraphNeighbour, ...]
    anchor: str


@dataclass(frozen=True, slots=True)
class GraphView:
    clusters: tuple[GraphCluster, ...]
    relation_counts: tuple[tuple[str, int], ...]
    entity_count: int
    edge_count: int
    # Entities with no relation in either direction. A real number worth
    # showing: a scan that is almost all unconnected nodes means the
    # correlation stage had little to work with, which is information about
    # the scan, not a rendering problem to hide.
    unconnected_count: int
    dangling_count: int


def _label(relation: str) -> str:
    return RELATION_LABELS.get(relation, relation.replace("_", " "))


def _rank_of(entity: dict[str, Any]) -> int | None:
    priority = entity.get("priority")
    if isinstance(priority, dict) and isinstance(priority.get("rank"), int):
        return int(priority["rank"])
    return None


def _score_of(entity: dict[str, Any]) -> float | None:
    priority = entity.get("priority")
    if isinstance(priority, dict) and isinstance(priority.get("score"), int | float):
        return float(priority["score"])
    return None


def build_graph_view(entities: list[dict[str, Any]], edges: list[dict[str, Any]]) -> GraphView:
    """Group edges under their source entity, most important source first.

    Ordering reuses `priority.rank` -- the ranking the deterministic rubric
    already computed -- rather than inventing a second, competing notion of
    which relationship matters most. Entities with no rank (which shouldn't
    happen for a scored graph, but a hand-edited or partial snapshot is not
    worth crashing over) sort last, alphabetically.
    """
    by_id = {e["id"]: e for e in entities if isinstance(e.get("id"), str)}

    grouped: dict[str, list[GraphNeighbour]] = defaultdict(list)
    connected: set[str] = set()
    relation_totals: dict[str, int] = defaultdict(int)
    dangling = 0

    for edge in edges:
        source = edge.get("source_id")
        target = edge.get("target_id")
        relation = edge.get("relation")
        if not isinstance(source, str) or not isinstance(target, str):
            continue
        if not isinstance(relation, str):
            continue
        relation_totals[relation] += 1
        target_entity = by_id.get(target)
        if target_entity is None:
            dangling += 1
        grouped[source].append(
            GraphNeighbour(
                relation=relation,
                relation_label=_label(relation),
                entity_id=target,
                value=str(target_entity["value"]) if target_entity else target,
                entity_type=str(target_entity["type"]) if target_entity else "unknown",
                dangling=target_entity is None,
            )
        )
        connected.add(source)
        if target_entity is not None:
            connected.add(target)

    clusters = []
    for entity_id, neighbours in grouped.items():
        entity = by_id.get(entity_id)
        if entity is None:
            # An edge whose *source* is unknown has nothing to hang under;
            # already counted in `dangling` via its target check above only
            # if the target was missing too, so count it here as well.
            dangling += 1
            continue
        clusters.append(
            GraphCluster(
                entity_id=entity_id,
                value=str(entity.get("value", entity_id)),
                entity_type=str(entity.get("type", "unknown")),
                rank=_rank_of(entity),
                score=_score_of(entity),
                neighbours=tuple(sorted(neighbours, key=lambda n: (n.relation, n.value))),
                anchor=anchor_slug(entity_id),
            )
        )

    clusters.sort(key=lambda c: (c.rank is None, c.rank if c.rank is not None else 0, c.value))

    return GraphView(
        clusters=tuple(clusters),
        relation_counts=tuple(sorted(relation_totals.items(), key=lambda kv: (-kv[1], kv[0]))),
        entity_count=len(by_id),
        edge_count=len(edges),
        unconnected_count=len([e for e in by_id if e not in connected]),
        dangling_count=dangling,
    )


# ── Diagram layout (hand-rolled, no layout library) ──────────────────────
#
# Real scans are dominated by certificates: 313 of 531 entities on one real
# target, 14 of 21 on another. Drawing every node produces exactly the
# "hairball" the charter names as the thing this project exists to fix, so
# the diagram is opinionated about what earns a box.
#
# Two rules do the work:
#
#   1. The flow is infrastructure, left to right --
#      domain -> subdomain -> IP -> service. That is the shape an operator is
#      actually trying to see, and it reads as a sentence: this target has
#      these hosts, which live on these addresses, which expose these things.
#
#   2. Certificates and technologies annotate the node they belong to rather
#      than occupying columns of their own. A certificate is *evidence about*
#      a host, not a stage in the chain, and 313 of them in a column would
#      drown the four nodes that matter. They become a count badge; the full
#      list is still on the brief, one click away.
#
# Within a layer, nodes are ordered by priority score and capped -- the same
# top-N-plus-a-tail contract the brief itself uses (ADR-0005). What is left
# out is stated rather than silently dropped.

_FLOW_LAYERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Target", ("domain",)),
    ("Hosts", ("subdomain",)),
    ("Addresses", ("ip_address",)),
    ("Exposed", ("service", "web_tech", "email_address", "breach_exposure", "dns_record")),
)
# Relations that annotate a node instead of drawing an edge to a new one.
_BADGE_RELATIONS: dict[str, str] = {"issued_for": "cert"}

_NODE_W = 186.0
_NODE_H = 44.0
_COL_GAP = 104.0
_ROW_GAP = 14.0
_PAD = 16.0
_MAX_PER_LAYER = 10


@dataclass(frozen=True, slots=True)
class DiagramNode:
    entity_id: str
    label: str
    title: str
    entity_type: str
    score: float | None
    anchor: str
    badge: str
    x: float
    y: float
    w: float
    h: float


@dataclass(frozen=True, slots=True)
class DiagramEdge:
    path: str
    relation: str
    relation_label: str


@dataclass(frozen=True, slots=True)
class DiagramLayer:
    title: str
    x: float
    shown: int
    hidden: int


@dataclass(frozen=True, slots=True)
class Diagram:
    nodes: tuple[DiagramNode, ...]
    edges: tuple[DiagramEdge, ...]
    layers: tuple[DiagramLayer, ...]
    width: float
    height: float
    hidden_total: int
    badge_total: int


def _truncate(value: str, limit: int = 26) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "\u2026"


def build_diagram(
    entities: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    max_per_layer: int = _MAX_PER_LAYER,
) -> Diagram:
    """Lay out the entity graph as columns of boxes joined by curves.

    Pure: geometry in, geometry out, no I/O and no clock, so the same scan
    always draws the same picture and the layout can be tested without a
    browser.
    """
    by_id = {e["id"]: e for e in entities if isinstance(e.get("id"), str)}

    # Certificates (and anything else in _BADGE_RELATIONS) collapse into a
    # count on whatever they point at.
    badge_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    badge_total = 0
    annotated: set[str] = set()
    for edge in edges:
        kind = _BADGE_RELATIONS.get(str(edge.get("relation")))
        if kind is None:
            continue
        target = str(edge.get("target_id"))
        if target in by_id:
            badge_counts[target][kind] += 1
            badge_total += 1
        annotated.add(str(edge.get("source_id")))

    placed: dict[str, DiagramNode] = {}
    layers: list[DiagramLayer] = []
    max_rows = 0

    for index, (title, types) in enumerate(_FLOW_LAYERS):
        members = [
            e
            for e in entities
            if e.get("type") in types and e["id"] not in annotated and e["id"] in by_id
        ]
        # Highest priority first, then alphabetical so equal scores are
        # stable rather than dependent on dict ordering.
        members.sort(key=lambda e: (-(_score_of(e) or 0.0), str(e.get("value", ""))))
        shown = members[:max_per_layer]
        if not shown:
            continue
        x = _PAD + index * (_NODE_W + _COL_GAP)
        layers.append(
            DiagramLayer(title=title, x=x, shown=len(shown), hidden=len(members) - len(shown))
        )
        for row, entity in enumerate(shown):
            value = str(entity.get("value", entity["id"]))
            counts = badge_counts.get(entity["id"], {})
            badge = " · ".join(f"{n} {k}{'s' if n != 1 else ''}" for k, n in sorted(counts.items()))
            placed[entity["id"]] = DiagramNode(
                entity_id=entity["id"],
                label=_truncate(value),
                title=value,
                entity_type=str(entity.get("type", "")),
                score=_score_of(entity),
                anchor=anchor_slug(entity["id"]),
                badge=badge,
                x=x,
                y=_PAD + 34.0 + row * (_NODE_H + _ROW_GAP),
                w=_NODE_W,
                h=_NODE_H,
            )
        max_rows = max(max_rows, len(shown))

    # Only edges between two drawn nodes get a curve; anything pointing at a
    # node that was capped away would otherwise trail off into blank space.
    drawn: list[DiagramEdge] = []
    for edge in edges:
        relation = str(edge.get("relation"))
        if relation in _BADGE_RELATIONS:
            continue
        src = placed.get(str(edge.get("source_id")))
        dst = placed.get(str(edge.get("target_id")))
        if src is None or dst is None:
            continue
        # `subdomain_of` points child -> parent, against the reading
        # direction; flip it so every curve runs left to right.
        if src.x > dst.x:
            src, dst = dst, src
        x1, y1 = src.x + src.w, src.y + src.h / 2
        x2, y2 = dst.x, dst.y + dst.h / 2
        mid = (x1 + x2) / 2
        drawn.append(
            DiagramEdge(
                path=f"M{x1:.1f},{y1:.1f} C{mid:.1f},{y1:.1f} {mid:.1f},{y2:.1f} {x2:.1f},{y2:.1f}",
                relation=relation,
                relation_label=_label(relation),
            )
        )

    width = (_PAD * 2) + max(len(layers), 1) * _NODE_W + max(len(layers) - 1, 0) * _COL_GAP
    height = _PAD * 2 + 34.0 + max(max_rows, 1) * (_NODE_H + _ROW_GAP)
    return Diagram(
        nodes=tuple(placed.values()),
        edges=tuple(drawn),
        layers=tuple(layers),
        width=width,
        height=height,
        hidden_total=sum(layer.hidden for layer in layers),
        badge_total=badge_total,
    )
