"""Deterministic correlation & dedup (ADR-0003).

Collapses the pile of per-adapter entities/edges — each adapter forbidden
from deduplicating its own output (ADR-0002 D4) — into one deduplicated
graph. Pure and order-independent: feeding the same adapter outputs in any
order yields a byte-identical graph (ADR-0003 D7), which is exactly what
`tests/test_dedup.py` proves by shuffling input order.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from glean_osint.adapters.base import ParseResult
from glean_osint.schema.entities import Edge, Entity, ProvenanceEntry, Relation


@dataclass(frozen=True, slots=True)
class DedupStats:
    """The charter's before/after duplicate-rate MVP gate (ADR-0003 D6)."""

    entities_before: int
    entities_after: int
    duplicate_rate: float
    dangling_edges_dropped: int


@dataclass(slots=True)
class MergeResult:
    entities: list[Entity]
    edges: list[Edge]
    stats: DedupStats


def merge_graph(results: Iterable[ParseResult]) -> MergeResult:
    """Merge one or more adapters' ParseResults into a deduplicated graph."""
    all_entities: list[Entity] = []
    all_edges: list[Edge] = []
    for result in results:
        all_entities.extend(result.entities)
        all_edges.extend(result.edges)

    entities_before = len(all_entities)

    groups: dict[str, list[Entity]] = defaultdict(list)
    for entity in all_entities:
        groups[entity.id].append(entity)

    merged_entities = [_merge_group(entity_id, group) for entity_id, group in groups.items()]
    merged_entities.sort(key=lambda e: e.id)

    entity_ids = {e.id for e in merged_entities}
    merged_edges, dangling = _merge_edges(all_edges, entity_ids)
    merged_edges.sort(key=lambda e: (e.source_id, e.relation, e.target_id))

    entities_after = len(merged_entities)
    duplicate_rate = (
        (entities_before - entities_after) / entities_before if entities_before else 0.0
    )

    return MergeResult(
        entities=merged_entities,
        edges=merged_edges,
        stats=DedupStats(
            entities_before=entities_before,
            entities_after=entities_after,
            duplicate_rate=duplicate_rate,
            dangling_edges_dropped=dangling,
        ),
    )


def _merge_group(entity_id: str, group: list[Entity]) -> Entity:
    """ADR-0003 D2: id/type/value carried through; provenance unions;
    attributes union with D3 conflict resolution; first/last_seen are the
    min/max collected_at across the unioned provenance."""
    first = group[0]
    provenance = _union_provenance(entity.provenance for entity in group)
    attributes = _merge_attributes(group)

    times = [p.collected_at for p in provenance]
    first_seen = min(times, key=_time_sort_key) if times else None
    last_seen = max(times, key=_time_sort_key) if times else None

    return Entity(
        id=entity_id,
        type=first.type,
        value=first.value,
        provenance=provenance,
        attributes=attributes,
        first_seen=first_seen,
        last_seen=last_seen,
    )


def _union_provenance(
    provenance_lists: Iterable[tuple[ProvenanceEntry, ...]],
) -> tuple[ProvenanceEntry, ...]:
    """Union, collapsing exact duplicates (ADR-0003 D2) and sorted into a
    canonical order — ProvenanceEntry is a frozen, value-equal dataclass, so
    identical entries compare equal regardless of which adapter run produced
    them, but *which adapter ran first* must not affect output order either
    (ADR-0003 D7's determinism guarantee applies to provenance order too,
    not just the top-level entity/edge lists)."""
    seen: set[ProvenanceEntry] = set()
    for entries in provenance_lists:
        seen.update(entries)
    return tuple(sorted(seen, key=_provenance_sort_key))


def _provenance_sort_key(entry: ProvenanceEntry) -> tuple[str, str, str, str, str, float]:
    return (
        entry.source_tool,
        entry.source_module or "",
        entry.method,
        entry.collected_at,
        entry.raw_record_ref or "",
        entry.confidence if entry.confidence is not None else -1.0,
    )


def _time_sort_key(collected_at: str) -> tuple[int, Any]:
    try:
        return (0, datetime.fromisoformat(collected_at.replace("Z", "+00:00")))
    except ValueError:
        # Degrade to lexicographic ordering rather than crash the merge
        # (ADR-0002 D5's "degrade, never crash" discipline applies here too).
        return (1, collected_at)


def _merge_attributes(group: list[Entity]) -> dict[str, Any]:
    """Key-wise union; conflicting keys resolved per ADR-0003 D3, with the
    losing value(s) recorded under `_conflicts`, never silently dropped."""
    candidates: dict[str, list[tuple[Any, Entity]]] = defaultdict(list)
    for entity in group:
        for key, value in entity.attributes.items():
            candidates[key].append((value, entity))

    merged: dict[str, Any] = {}
    conflicts: dict[str, list[Any]] = {}
    for key, pairs in candidates.items():
        distinct = _distinct_by_value(pairs)
        if len(distinct) == 1:
            merged[key] = distinct[0][0]
            continue
        winner, *losers = sorted(distinct, key=_conflict_sort_key)
        merged[key] = winner[0]
        conflicts[key] = [value for value, _ in losers]

    if conflicts:
        merged["_conflicts"] = conflicts
    return merged


def _distinct_by_value(pairs: list[tuple[Any, Entity]]) -> list[tuple[Any, Entity]]:
    distinct: list[tuple[Any, Entity]] = []
    values_seen: list[Any] = []
    for value, entity in pairs:
        if value in values_seen:
            continue
        values_seen.append(value)
        distinct.append((value, entity))
    return distinct


def _conflict_sort_key(pair: tuple[Any, Entity]) -> tuple[float, int, str]:
    """ADR-0003 D3: higher confidence wins, then active over passive, then
    the lexicographically smaller value — a total, deterministic order."""
    value, entity = pair
    prov = entity.provenance[0]
    confidence = prov.confidence if prov.confidence is not None else -1.0
    method_rank = 0 if prov.method == "active" else 1
    return (-confidence, method_rank, str(value))


def _merge_edges(edges: list[Edge], entity_ids: set[str]) -> tuple[list[Edge], int]:
    """ADR-0003 D4: dedup on (source_id, target_id, relation) with unioned
    provenance; drop and count edges whose endpoints didn't survive merge."""
    groups: dict[tuple[str, str, Relation], list[Edge]] = defaultdict(list)
    dangling = 0
    for edge in edges:
        if edge.source_id not in entity_ids or edge.target_id not in entity_ids:
            dangling += 1
            continue
        groups[(edge.source_id, edge.target_id, edge.relation)].append(edge)

    merged = []
    for (source_id, target_id, relation), group in groups.items():
        provenance = _union_provenance(edge.provenance for edge in group)
        merged.append(
            Edge(source_id=source_id, target_id=target_id, relation=relation, provenance=provenance)
        )
    return merged, dangling
