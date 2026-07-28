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
