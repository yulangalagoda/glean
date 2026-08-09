"""Structural checks on narrated prose (ADR-0006 D1 stage 1b).

Stage 1 asks only "does this finding's entity exist", which a
code-generated brief cannot fail, so it reads 1.000 by construction. Stage
2 asks whether the prose is true and needs an LLM judge, which three audits
have shown to be unreliable in ways that move with the wording of its
prompt (ADR-0006 Validation).

Between those sits a class this module handles: claims that are decidable
from the graph alone. A wildcard entry narrated as "resolves to a live IP"
when nothing in the scan records it resolving is wrong, and no model is
needed to know that. Six judge-prompt variants failed to catch it reliably
-- permissive wording lets it through, strict wording collapses precision
-- which is the argument for taking it away from the judge entirely.

**What "unfounded" means here, and why it is not absence-as-evidence.**
The project's discipline is that absence never proves something about the
*target*: not finding a service does not mean no service exists. That
discipline is about claims describing the world. Faithfulness asks a
different question -- does the brief state only what its own evidence
supports -- and there, an assertion with no supporting record is precisely
the failure being measured. This module never concludes anything about the
target; it concludes something about the *prose*.

**Every check needs a positive structural test.** A property is
"supported" when a specific attribute, edge or signal records it, so
adding evidence can only ever silence a flag, never create one. Checks
that could not be stated that way were left out rather than approximated.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from glean_osint.brief import Finding
from glean_osint.schema.entities import Edge

# Prose patterns that assert a structured property. Deliberately narrow:
# a missed fabrication costs nothing here (stage 2 still runs), while a
# false flag would put a wrong number in front of a reader, which is the
# failure this whole line of work exists to remove.
_ASSERTS_RESOLUTION = re.compile(
    r"\bresolv\w*\b|\blive ip\b|\bpoints? to (?:a |an )?ip\b", re.IGNORECASE
)
_ASSERTS_SERVICE = re.compile(
    r"\bexposed?\s+(?:\w+\s+)?service\b|\bservice\s+is\s+exposed\b|\bport\s+\d+\b", re.IGNORECASE
)

# Relations along which a property genuinely reaches the source entity.
# `subdomain_of` is excluded for the same reason it is excluded from the
# judge's evidence walk: it points at a parent, and a parent's resolution
# is not the child's (ADR-0006 Validation, 2026-08-06).
_REACHES = frozenset({"resolves_to", "hosts", "exposes_service", "runs_tech"})


@dataclass(frozen=True, slots=True)
class Contradiction:
    """One structurally-unsupported assertion in a finding's prose."""

    entity_id: str
    kind: str  # "resolution" | "service"
    detail: str

    def __str__(self) -> str:
        return f"{self.entity_id}: {self.detail}"


def _reachable(start: str, edges_by_source: dict[str, list[Edge]], depth: int = 2) -> set[str]:
    """Entity ids reachable from `start` along property-bearing relations."""
    seen = {start}
    frontier = [start]
    for _ in range(depth):
        nxt: list[str] = []
        for node in frontier:
            for edge in edges_by_source.get(node, []):
                if edge.relation in _REACHES and edge.target_id not in seen:
                    seen.add(edge.target_id)
                    nxt.append(edge.target_id)
        frontier = nxt
    seen.discard(start)
    return seen


def check_finding(
    finding: Finding,
    edges_by_source: dict[str, list[Edge]],
    entity_types: dict[str, str],
) -> list[Contradiction]:
    """Structural assertions in one finding's prose that nothing supports."""
    entity = finding.entity
    prose = f"{finding.body} {finding.why_ranked}"
    signals = set(entity.priority.signals) if entity.priority else set()
    reachable = _reachable(entity.id, edges_by_source)
    found: list[Contradiction] = []

    if _ASSERTS_RESOLUTION.search(prose):
        resolves = (
            entity.attributes.get("dns_resolved") is True
            # A `service` or `ip_address` is not itself a name that resolves;
            # prose about resolution on those describes the host chain, and
            # `resolves_to_live_ip` covers the case that matters.
            or entity.type in {"ip_address", "service"}
            or any(edge.relation == "resolves_to" for edge in edges_by_source.get(entity.id, []))
            or "resolves_to_live_ip" in signals
        )
        if not resolves:
            found.append(
                Contradiction(
                    entity_id=entity.id,
                    kind="resolution",
                    detail=(
                        "prose asserts DNS resolution, but nothing records it resolving: "
                        "no dns_resolved attribute, no resolves_to edge, no live-IP signal"
                    ),
                )
            )

    if _ASSERTS_SERVICE.search(prose):
        has_service = (
            entity.type == "service"
            or {"exposed_service", "sensitive_port", "resolves_to_live_ip"} & signals
            or any(entity_types.get(target) == "service" for target in reachable)
        )
        if not has_service:
            found.append(
                Contradiction(
                    entity_id=entity.id,
                    kind="service",
                    detail=(
                        "prose asserts an exposed service or port, but no service entity "
                        "is reachable and no service signal is present"
                    ),
                )
            )

    return found


def check_brief_findings(
    findings: Sequence[Finding], edges: Sequence[Edge], entity_types: dict[str, str]
) -> list[Contradiction]:
    """Every structurally-unsupported assertion across a set of findings."""
    edges_by_source: dict[str, list[Edge]] = defaultdict(list)
    for edge in edges:
        edges_by_source[edge.source_id].append(edge)
    return [c for f in findings for c in check_finding(f, edges_by_source, entity_types)]
