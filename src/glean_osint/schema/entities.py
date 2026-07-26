"""The normalised Entity Graph model (ADR-0001, docs/schema/entity-graph.schema.json).

Every adapter parses its tool's raw output into these types. Nothing here
deduplicates, scores, or reasons across tools (ADR-0002 D4) — that happens
in later, tool-agnostic stages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

SCHEMA_VERSION = "0.1.0"

Method = Literal["passive", "active"]

EntityType = Literal[
    "domain",
    "subdomain",
    "ip_address",
    "dns_record",
    "email_address",
    "breach_exposure",
    "service",
    "web_tech",
    "certificate",
]

Relation = Literal[
    "subdomain_of",
    "resolves_to",
    "hosts",
    "has_record",
    "exposes_service",
    "runs_tech",
    "issued_for",
    "exposed_in_breach",
]


def entity_id(entity_type: EntityType, value: str) -> str:
    """The stable identity key convention: '<type>:<canonical_value>' (ADR-0001 D2)."""
    return f"{entity_type}:{value}"


@dataclass(frozen=True, slots=True)
class ProvenanceEntry:
    """One tool's assertion that an entity exists (ADR-0001 D6)."""

    source_tool: str
    method: Method
    collected_at: str
    source_module: str | None = None
    raw_record_ref: str | None = None
    confidence: float | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "source_tool": self.source_tool,
            "method": self.method,
            "collected_at": self.collected_at,
        }
        if self.source_module is not None:
            d["source_module"] = self.source_module
        if self.raw_record_ref is not None:
            d["raw_record_ref"] = self.raw_record_ref
        if self.confidence is not None:
            d["confidence"] = self.confidence
        return d


@dataclass(frozen=True, slots=True)
class Priority:
    """Deterministic prioritisation output (ADR-0001 D7).

    Set only by ADR-0004 scoring code — never by an adapter or the LLM.
    """

    score: float
    rank: int
    signals: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"score": self.score, "rank": self.rank}
        if self.signals:
            d["signals"] = list(self.signals)
        return d


@dataclass(frozen=True, slots=True)
class Entity:
    id: str
    type: EntityType
    value: str
    provenance: tuple[ProvenanceEntry, ...]
    attributes: dict[str, Any] = field(default_factory=dict)
    first_seen: str | None = None
    last_seen: str | None = None
    priority: Priority | None = None

    def __post_init__(self) -> None:
        if not self.provenance:
            msg = f"entity {self.id!r} must have >=1 provenance entry (ADR-0001 D1)"
            raise ValueError(msg)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "attributes": dict(self.attributes),
            "provenance": [p.to_dict() for p in self.provenance],
        }
        if self.first_seen is not None:
            d["first_seen"] = self.first_seen
        if self.last_seen is not None:
            d["last_seen"] = self.last_seen
        if self.priority is not None:
            d["priority"] = self.priority.to_dict()
        return d


@dataclass(frozen=True, slots=True)
class Edge:
    source_id: str
    target_id: str
    relation: Relation
    provenance: tuple[ProvenanceEntry, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation": self.relation,
        }
        if self.provenance:
            d["provenance"] = [p.to_dict() for p in self.provenance]
        return d
