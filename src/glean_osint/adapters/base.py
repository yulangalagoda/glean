"""The adapter contract every tool integration conforms to (ADR-0002 D2).

An adapter is the only tool-specific code in Glean: it turns one tool's raw
output into schema-valid entities and edges, and nothing else — no dedup,
no scoring, no cross-tool reasoning (ADR-0002 D4).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from glean_osint.schema.entities import Edge, Entity, Method


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Scan-wide constants a pure `parse` needs, so it stays pure with respect
    to them (ADR-0002 D2)."""

    target: str
    collected_at: str
    raw_output_ref: str | None = None
    tool_version: str | None = None


@dataclass(slots=True)
class ParseResult:
    entities: list[Entity] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    # Records that couldn't be parsed and were dropped (ADR-0002 D5) — a
    # malformed record is skipped and counted, never fatal.
    skipped: int = 0


class Adapter(Protocol):
    tool_id: str
    default_method: Method

    def build_command(self, target: str, options: object | None = None) -> list[str] | None:
        """Argv to run the tool, or None if this adapter is ingest-only."""
        ...

    def parse(self, raw: bytes, ctx: ScanContext) -> ParseResult:
        """PURE. Same raw in -> same result out. No I/O, no network, no clock
        except ctx.collected_at."""
        ...
