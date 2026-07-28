"""Scan-to-scan entity diffing (ADR-0011 roadmap: turning history into a
monitoring workspace, not just a log).

Compares two scans' persisted entity snapshots (`history.py`'s
`entities.json`, written by Phase 1's export work) by entity id -- the
same deterministic id scheme ADR-0001 already guarantees for every
entity, so "same id in both scans" really does mean "the same
real-world subdomain/service/etc.", not a heuristic match. Pure and
order-independent input handling: only depends on entity id equality
and a stable comparison of the fields a user would actually call a
"change" (type, value, attributes, priority score, priority signals).
`provenance`/`first_seen`/`last_seen` are deliberately excluded from
that comparison -- those differ between any two scans of the same
target by construction (a fresh `collected_at` timestamp every run)
without the entity itself having actually changed, and including them
would make every unchanged entity show up as "changed."
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ChangedEntity:
    entity_id: str
    entity_type: str
    value: str
    old_score: float | None
    new_score: float | None
    old_signals: tuple[str, ...]
    new_signals: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EntityDiff:
    added: tuple[dict[str, Any], ...]
    removed: tuple[dict[str, Any], ...]
    changed: tuple[ChangedEntity, ...]


def _comparable(entity: dict[str, Any]) -> tuple[Any, ...]:
    priority = entity.get("priority") or {}
    return (
        entity.get("type"),
        entity.get("value"),
        json.dumps(entity.get("attributes") or {}, sort_keys=True),
        priority.get("score"),
        tuple(priority.get("signals") or ()),
    )


def diff_entities(older: list[dict[str, Any]], newer: list[dict[str, Any]]) -> EntityDiff:
    """`older`/`newer` are `Entity.to_dict()` lists from two scans of the
    same target, older scan first -- typically
    `history.read_entities_snapshot`'s own output for two scan
    directories. Order in each output list follows the input lists'
    own order (each scan's own rank order, since that's how
    `entities.json` is written) -- not re-sorted here."""
    older_by_id = {e["id"]: e for e in older}
    newer_by_id = {e["id"]: e for e in newer}

    added = tuple(entity for eid, entity in newer_by_id.items() if eid not in older_by_id)
    removed = tuple(entity for eid, entity in older_by_id.items() if eid not in newer_by_id)

    changed = []
    for eid, new_entity in newer_by_id.items():
        old_entity = older_by_id.get(eid)
        if old_entity is None or _comparable(old_entity) == _comparable(new_entity):
            continue
        old_priority = old_entity.get("priority") or {}
        new_priority = new_entity.get("priority") or {}
        changed.append(
            ChangedEntity(
                entity_id=eid,
                entity_type=new_entity.get("type", ""),
                value=new_entity.get("value", ""),
                old_score=old_priority.get("score"),
                new_score=new_priority.get("score"),
                old_signals=tuple(old_priority.get("signals") or ()),
                new_signals=tuple(new_priority.get("signals") or ()),
            )
        )

    return EntityDiff(added=added, removed=removed, changed=tuple(changed))
