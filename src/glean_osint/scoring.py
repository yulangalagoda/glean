"""Deterministic prioritisation rubric (ADR-0004).

Additive signal scoring, computed in code so the LLM only ever narrates a
ranking it did not compute (charter's core split). Deterministic: same
graph + same `as_of` in, same scores out — no randomness, no model calls,
no implicit wall-clock reads (freshness is an explicit input).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import get_args

import yaml

from glean_osint.schema.entities import Edge, Entity, EntityType, Priority

ALL_ENTITY_TYPES: frozenset[EntityType] = frozenset(get_args(EntityType))

# ADR-0004 D2's weight table. Negative weights are deprioritisers.
WEIGHTS: dict[str, int] = {
    "sensitive_hostname_pattern": 3,
    "breach_hit": 3,
    "sensitive_port": 2,
    "exposed_service": 2,
    "cert_expired": 2,
    "cert_superseded": -2,
    "cert_orphaned": -2,
    "cert_expiring_soon": 1,
    "resolves_to_live_ip": 1,
    "multi_tool_corroboration": 1,
    "active_only_finding": 1,
    "wildcard_or_default": -1,
    "passive_low_signal": -1,
    "stale_no_dns": -3,
}

SIGNAL_APPLIES_TO: dict[str, frozenset[EntityType]] = {
    "sensitive_hostname_pattern": frozenset({"subdomain"}),
    "breach_hit": frozenset({"email_address", "breach_exposure"}),
    "sensitive_port": frozenset({"service"}),
    "exposed_service": frozenset({"service"}),
    "cert_expired": frozenset({"certificate"}),
    "cert_superseded": frozenset({"certificate"}),
    "cert_orphaned": frozenset({"certificate"}),
    "cert_expiring_soon": frozenset({"certificate"}),
    "resolves_to_live_ip": frozenset({"subdomain"}),
    "multi_tool_corroboration": ALL_ENTITY_TYPES,
    "active_only_finding": ALL_ENTITY_TYPES,
    "wildcard_or_default": frozenset({"subdomain"}),
    "passive_low_signal": frozenset({"domain", "email_address"}),
    "stale_no_dns": frozenset({"subdomain", "domain"}),
}

# D4's fixed tie-break precedence, highest priority first. `web_tech` sits
# last: it's descriptive metadata about another entity, never itself the
# actionable finding (2026-07-27 pilot correction — see ADR-0004).
_TYPE_PRECEDENCE: tuple[EntityType, ...] = (
    "breach_exposure",
    "service",
    "subdomain",
    "certificate",
    "ip_address",
    "email_address",
    "dns_record",
    "domain",
    "web_tech",
)
_TYPE_RANK = {t: i for i, t in enumerate(_TYPE_PRECEDENCE)}
assert set(_TYPE_PRECEDENCE) == ALL_ENTITY_TYPES, (
    "_TYPE_PRECEDENCE must cover every EntityType or _tie_break_key crashes "
    "the first time that type actually appears in a scan"
)


@dataclass(frozen=True, slots=True)
class SignalConfig:
    sensitive_hostname_keywords: tuple[str, ...]
    sensitive_ports: tuple[int, ...]


_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = _REPO_ROOT / "config" / "priority-signals.v1.yaml"

# A code-level default so score_graph() works standalone (e.g. once packaged,
# where the repo-relative YAML above won't be present) — kept in sync with
# config/priority-signals.v1.yaml by test_scoring.py's consistency check.
DEFAULT_CONFIG = SignalConfig(
    sensitive_hostname_keywords=(
        "admin",
        "vpn",
        "staging",
        "dev",
        "internal",
        "jenkins",
        "gitlab",
        "portal",
        "mail",
        "db",
    ),
    sensitive_ports=(22, 23, 3389, 3306, 5432, 6379, 9200, 27017, 5900),
)


def load_signal_config(path: Path) -> SignalConfig:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return SignalConfig(
        sensitive_hostname_keywords=tuple(
            str(k).lower() for k in data["sensitive_hostname_keywords"]
        ),
        sensitive_ports=tuple(int(p) for p in data["sensitive_ports"]),
    )


@dataclass(frozen=True, slots=True)
class _ScoringContext:
    edges_by_source: dict[str, list[Edge]]
    certificates: tuple[Entity, ...]
    as_of: datetime
    config: SignalConfig


def score_graph(
    entities: list[Entity],
    edges: list[Edge],
    as_of: datetime,
    config: SignalConfig = DEFAULT_CONFIG,
) -> list[Entity]:
    """Score and rank a deduplicated graph (ADR-0004). Returns new Entity
    objects carrying `priority`; input entities are not mutated."""
    as_of = _ensure_aware(as_of)
    edges_by_source: dict[str, list[Edge]] = defaultdict(list)
    for edge in edges:
        edges_by_source[edge.source_id].append(edge)

    certificates = tuple(e for e in entities if e.type == "certificate")
    ctx = _ScoringContext(
        edges_by_source=edges_by_source, certificates=certificates, as_of=as_of, config=config
    )

    fired = _evaluate_self_contained_signals(entities, ctx)
    _evaluate_cert_orphaned(entities, certificates, ctx, fired)
    _evaluate_passive_low_signal(entities, fired)

    scored = []
    for entity in entities:
        names = tuple(sorted(name for name, ids in fired.items() if entity.id in ids))
        raw_score = sum(WEIGHTS[name] for name in names)
        scored.append((entity, raw_score, names))

    scored.sort(key=lambda item: _tie_break_key(item[0], item[1]))

    ranked: list[Entity] = []
    for rank, (entity, raw_score, names) in enumerate(scored, start=1):
        priority = Priority(score=_clamp(raw_score), rank=rank, signals=names)
        ranked.append(replace(entity, priority=priority))
    return ranked


def _evaluate_self_contained_signals(
    entities: list[Entity], ctx: _ScoringContext
) -> dict[str, set[str]]:
    fired: dict[str, set[str]] = defaultdict(set)
    for entity in entities:
        for name, fn in _SELF_CONTAINED_SIGNALS.items():
            if entity.type not in SIGNAL_APPLIES_TO[name]:
                continue
            if fn(entity, ctx):
                fired[name].add(entity.id)
    return fired


def _evaluate_cert_orphaned(
    entities: list[Entity],
    certificates: tuple[Entity, ...],
    ctx: _ScoringContext,
    fired: dict[str, set[str]],
) -> None:
    """The one v1 signal that reads another entity's already-computed
    signal (ADR-0004 D2, 2026-07-23 correction): an expired certificate
    whose hostname(s) are positively confirmed non-resolving, with no
    currently-valid certificate covering the same hostname(s) either."""
    stale_hostnames = {
        e.value
        for e in entities
        if e.type in ("subdomain", "domain") and e.id in fired["stale_no_dns"]
    }
    if not stale_hostnames:
        return

    for cert in certificates:
        if not _cert_expired(cert, ctx):
            continue
        sans = set(cert.attributes.get("san") or [])
        if not sans or not (sans & stale_hostnames):
            continue
        covered_by_valid = any(
            not _cert_expired(other, ctx) and (set(other.attributes.get("san") or []) & sans)
            for other in certificates
            if other.id != cert.id
        )
        if not covered_by_valid:
            fired["cert_orphaned"].add(cert.id)


def _evaluate_passive_low_signal(entities: list[Entity], fired: dict[str, set[str]]) -> None:
    """Fires only on domain/email_address entities with no other signal
    fired (ADR-0004 D2) — evaluated last since it depends on every other
    signal's result for the same entity."""
    for entity in entities:
        if entity.type not in ("domain", "email_address"):
            continue
        if any(entity.id in ids for name, ids in fired.items() if name != "passive_low_signal"):
            continue
        fired["passive_low_signal"].add(entity.id)


def _tie_break_key(entity: Entity, raw_score: int) -> tuple[int, int, int, str]:
    """ADR-0004 D4: raw score desc, then entity-type precedence, then more
    provenance sources first, then lexicographic id — a total order."""
    return (-raw_score, _TYPE_RANK[entity.type], -len(entity.provenance), entity.id)


def _clamp(raw_score: int) -> float:
    return float(max(0, min(10, raw_score)))


def _ensure_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _parse_dt(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return _ensure_aware(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


def _cert_expired(entity: Entity, ctx: _ScoringContext) -> bool:
    not_after = _parse_dt(entity.attributes.get("not_after"))
    return not_after is not None and not_after < ctx.as_of


def _cert_expiring_soon(entity: Entity, ctx: _ScoringContext) -> bool:
    not_after = _parse_dt(entity.attributes.get("not_after"))
    if not_after is None:
        return False
    return ctx.as_of <= not_after <= ctx.as_of + timedelta(days=30)


def _cert_superseded(entity: Entity, ctx: _ScoringContext) -> bool:
    """Fires only when a newer, still-valid certificate in the graph shares
    >=1 SAN with this expired one (ADR-0004 D2/open-question-7's resolved
    'at least one SAN in common' rule) — ordinary renewal, not a finding."""
    if not _cert_expired(entity, ctx):
        return False
    my_sans = set(entity.attributes.get("san") or [])
    if not my_sans:
        return False
    return any(
        not _cert_expired(other, ctx) and (set(other.attributes.get("san") or []) & my_sans)
        for other in ctx.certificates
        if other.id != entity.id
    )


def _sensitive_hostname_pattern(entity: Entity, ctx: _ScoringContext) -> bool:
    host = entity.value.lower().removeprefix("*.")
    return any(kw in host for kw in ctx.config.sensitive_hostname_keywords)


def _breach_hit(entity: Entity, ctx: _ScoringContext) -> bool:
    if entity.type == "breach_exposure":
        return True
    return any(e.relation == "exposed_in_breach" for e in ctx.edges_by_source.get(entity.id, []))


def _sensitive_port(entity: Entity, ctx: _ScoringContext) -> bool:
    port = entity.attributes.get("port")
    return isinstance(port, int) and port in ctx.config.sensitive_ports


def _exposed_service(entity: Entity, ctx: _ScoringContext) -> bool:
    # Applies only to `service` entities (SIGNAL_APPLIES_TO); v1 adapters
    # only ever create a service entity for something actually found open,
    # so its existence in the graph already is the exposure.
    return True


def _resolves_to_live_ip(entity: Entity, ctx: _ScoringContext) -> bool:
    for edge in ctx.edges_by_source.get(entity.id, []):
        if edge.relation != "resolves_to":
            continue
        ip_edges = ctx.edges_by_source.get(edge.target_id, [])
        if any(e.relation == "exposes_service" for e in ip_edges):
            return True
    return False


def _multi_tool_corroboration(entity: Entity, ctx: _ScoringContext) -> bool:
    return len({p.source_tool for p in entity.provenance}) >= 2


def _active_only_finding(entity: Entity, ctx: _ScoringContext) -> bool:
    return bool(entity.provenance) and all(p.method == "active" for p in entity.provenance)


def _wildcard_or_default(entity: Entity, ctx: _ScoringContext) -> bool:
    return entity.attributes.get("wildcard_confirmed_active") is True


def _stale_no_dns(entity: Entity, ctx: _ScoringContext) -> bool:
    # Must never fire merely because no DNS-resolution adapter ran this scan
    # (ADR-0004 D2) — only an explicit False (positive non-resolution).
    return entity.attributes.get("dns_resolved") is False


_SELF_CONTAINED_SIGNALS: dict[str, Callable[[Entity, _ScoringContext], bool]] = {
    "sensitive_hostname_pattern": _sensitive_hostname_pattern,
    "breach_hit": _breach_hit,
    "sensitive_port": _sensitive_port,
    "exposed_service": _exposed_service,
    "cert_expired": _cert_expired,
    "cert_superseded": _cert_superseded,
    "cert_expiring_soon": _cert_expiring_soon,
    "resolves_to_live_ip": _resolves_to_live_ip,
    "multi_tool_corroboration": _multi_tool_corroboration,
    "active_only_finding": _active_only_finding,
    "wildcard_or_default": _wildcard_or_default,
    "stale_no_dns": _stale_no_dns,
}
