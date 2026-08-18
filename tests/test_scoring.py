"""Tests for the deterministic prioritisation rubric (ADR-0004).

Three tests at the bottom (`test_*_regression`) reproduce the exact real
bugs the ADR's own pilot corrections describe, so a future change can't
silently reintroduce them.
"""

from datetime import datetime, timezone

from glean_osint.schema.entities import Edge, Entity, ProvenanceEntry
from glean_osint.scoring import (
    DEFAULT_CONFIG,
    DEFAULT_CONFIG_PATH,
    WEIGHTS,
    load_signal_config,
    score_graph,
)

AS_OF = datetime(2026, 7, 26, tzinfo=timezone.utc)


def _prov(**kwargs: object) -> ProvenanceEntry:
    defaults: dict[str, object] = {
        "source_tool": "crtsh",
        "method": "passive",
        "collected_at": "2026-07-01T00:00:00Z",
    }
    defaults.update(kwargs)
    return ProvenanceEntry(**defaults)  # type: ignore[arg-type]


def _entity(entity_id: str, entity_type: str, value: str, **kwargs: object) -> Entity:
    kwargs.setdefault("provenance", (_prov(),))
    return Entity(id=entity_id, type=entity_type, value=value, **kwargs)  # type: ignore[arg-type]


def _score_of(entities: list[Entity], edges: list[Edge] | None = None) -> dict[str, Entity]:
    ranked = score_graph(entities, edges or [], AS_OF)
    return {e.id: e for e in ranked}


def test_default_config_matches_committed_yaml() -> None:
    """Guards against the code default and the auditable YAML file
    (ADR-0004 D2) drifting apart."""
    assert load_signal_config(DEFAULT_CONFIG_PATH) == DEFAULT_CONFIG


def test_sensitive_hostname_pattern() -> None:
    hit = _entity("subdomain:admin.example.com", "subdomain", "admin.example.com")
    miss = _entity("subdomain:www.example.com", "subdomain", "www.example.com")
    scored = _score_of([hit, miss])

    assert "sensitive_hostname_pattern" in scored[hit.id].priority.signals
    assert "sensitive_hostname_pattern" not in scored[miss.id].priority.signals
    assert scored[hit.id].priority.score == 3


def test_breach_hit_on_email_via_edge_and_on_breach_entity_itself() -> None:
    email = _entity("email_address:security@example.com", "email_address", "security@example.com")
    breach = _entity("breach_exposure:example-2024-leak", "breach_exposure", "example-2024-leak")
    edge = Edge(source_id=email.id, target_id=breach.id, relation="exposed_in_breach")

    scored = _score_of([email, breach], [edge])

    assert "breach_hit" in scored[email.id].priority.signals
    assert "breach_hit" in scored[breach.id].priority.signals


def test_sensitive_port() -> None:
    admin_port = _entity(
        "service:203.0.113.1:3389", "service", "203.0.113.1:3389", attributes={"port": 3389}
    )
    web_port = _entity(
        "service:203.0.113.1:443", "service", "203.0.113.1:443", attributes={"port": 443}
    )
    scored = _score_of([admin_port, web_port])

    assert "sensitive_port" in scored[admin_port.id].priority.signals
    assert "sensitive_port" not in scored[web_port.id].priority.signals
    # exposed_service fires on every service regardless of port.
    assert "exposed_service" in scored[web_port.id].priority.signals


def test_cert_expired_and_cert_expiring_soon_are_mutually_exclusive() -> None:
    expired = _entity(
        "certificate:1|ca",
        "certificate",
        "1|ca",
        attributes={"not_after": "2026-01-01T00:00:00Z", "san": ["x.example.com"]},
    )
    expiring_soon = _entity(
        "certificate:2|ca",
        "certificate",
        "2|ca",
        attributes={"not_after": "2026-08-01T00:00:00Z", "san": ["y.example.com"]},
    )
    healthy = _entity(
        "certificate:3|ca",
        "certificate",
        "3|ca",
        attributes={"not_after": "2027-01-01T00:00:00Z", "san": ["z.example.com"]},
    )
    scored = _score_of([expired, expiring_soon, healthy])

    assert scored[expired.id].priority.signals == ("cert_expired",)
    assert scored[expiring_soon.id].priority.signals == ("cert_expiring_soon",)
    assert scored[healthy.id].priority.signals == ()


def test_cert_superseded_requires_shared_san_and_valid_successor() -> None:
    old = _entity(
        "certificate:old|ca",
        "certificate",
        "old|ca",
        attributes={"not_after": "2026-01-01T00:00:00Z", "san": ["x.example.com"]},
    )
    renewed = _entity(
        "certificate:new|ca",
        "certificate",
        "new|ca",
        attributes={"not_after": "2027-01-01T00:00:00Z", "san": ["x.example.com"]},
    )
    scored = _score_of([old, renewed])

    assert scored[old.id].priority.signals == ("cert_expired", "cert_superseded")
    assert scored[old.id].priority.score == 0  # +2 -2, nets to zero (ADR-0004 D2)


def test_resolves_to_live_ip_requires_ip_with_exposed_service() -> None:
    sub = _entity("subdomain:live.example.com", "subdomain", "live.example.com")
    ip = _entity("ip_address:203.0.113.1", "ip_address", "203.0.113.1")
    svc = _entity("service:203.0.113.1:443", "service", "203.0.113.1:443", attributes={"port": 443})
    edges = [
        Edge(source_id=sub.id, target_id=ip.id, relation="resolves_to"),
        Edge(source_id=ip.id, target_id=svc.id, relation="exposes_service"),
    ]
    scored = _score_of([sub, ip, svc], edges)

    assert "resolves_to_live_ip" in scored[sub.id].priority.signals


def test_resolves_to_live_ip_does_not_fire_without_a_service() -> None:
    sub = _entity("subdomain:quiet.example.com", "subdomain", "quiet.example.com")
    ip = _entity("ip_address:203.0.113.2", "ip_address", "203.0.113.2")
    edges = [Edge(source_id=sub.id, target_id=ip.id, relation="resolves_to")]
    scored = _score_of([sub, ip], edges)

    assert "resolves_to_live_ip" not in scored[sub.id].priority.signals


def test_multi_tool_corroboration() -> None:
    corroborated = _entity(
        "subdomain:x.example.com",
        "subdomain",
        "x.example.com",
        provenance=(_prov(source_tool="crtsh"), _prov(source_tool="theharvester")),
    )
    single = _entity("subdomain:y.example.com", "subdomain", "y.example.com")
    scored = _score_of([corroborated, single])

    assert "multi_tool_corroboration" in scored[corroborated.id].priority.signals
    assert "multi_tool_corroboration" not in scored[single.id].priority.signals


def test_active_only_finding() -> None:
    active = _entity(
        "subdomain:x.example.com",
        "subdomain",
        "x.example.com",
        provenance=(_prov(method="active"),),
    )
    passive = _entity("subdomain:y.example.com", "subdomain", "y.example.com")
    scored = _score_of([active, passive])

    assert "active_only_finding" in scored[active.id].priority.signals
    assert "active_only_finding" not in scored[passive.id].priority.signals


def test_wildcard_or_default_requires_confirmed_active_probe() -> None:
    confirmed = _entity(
        "subdomain:*.example.com",
        "subdomain",
        "*.example.com",
        attributes={"wildcard": True, "wildcard_confirmed_active": True},
    )
    unconfirmed = _entity(
        "subdomain:*.other.com", "subdomain", "*.other.com", attributes={"wildcard": True}
    )
    scored = _score_of([confirmed, unconfirmed])

    assert "wildcard_or_default" in scored[confirmed.id].priority.signals
    assert "wildcard_or_default" not in scored[unconfirmed.id].priority.signals


def test_stale_no_dns_requires_explicit_false_not_mere_absence() -> None:
    """ADR-0004 D2: must never fire merely because no DNS-resolution
    adapter ran — only on positive confirmation of non-resolution."""
    confirmed_dead = _entity(
        "subdomain:dead.example.com",
        "subdomain",
        "dead.example.com",
        attributes={"dns_resolved": False},
    )
    confirmed_live = _entity(
        "subdomain:live.example.com",
        "subdomain",
        "live.example.com",
        attributes={"dns_resolved": True},
    )
    not_checked = _entity("subdomain:unknown.example.com", "subdomain", "unknown.example.com")
    scored = _score_of([confirmed_dead, confirmed_live, not_checked])

    assert "stale_no_dns" in scored[confirmed_dead.id].priority.signals
    assert "stale_no_dns" not in scored[confirmed_live.id].priority.signals
    assert "stale_no_dns" not in scored[not_checked.id].priority.signals


def test_passive_low_signal_fires_only_with_no_other_signal() -> None:
    quiet_domain = _entity("domain:example.com", "domain", "example.com")
    corroborated_domain = _entity(
        "domain:other.com",
        "domain",
        "other.com",
        provenance=(_prov(source_tool="crtsh"), _prov(source_tool="theharvester")),
    )
    scored = _score_of([quiet_domain, corroborated_domain])

    assert scored[quiet_domain.id].priority.signals == ("passive_low_signal",)
    assert "passive_low_signal" not in scored[corroborated_domain.id].priority.signals
    assert "multi_tool_corroboration" in scored[corroborated_domain.id].priority.signals


def test_cert_orphaned_requires_confirmed_dead_host_and_no_successor() -> None:
    dead_cert = _entity(
        "certificate:ww1|ca",
        "certificate",
        "ww1|ca",
        attributes={"not_after": "2021-01-01T00:00:00Z", "san": ["ww1.example.com"]},
    )
    dead_subdomain = _entity(
        "subdomain:ww1.example.com",
        "subdomain",
        "ww1.example.com",
        attributes={"dns_resolved": False},
    )
    scored = _score_of([dead_cert, dead_subdomain])

    assert "cert_orphaned" in scored[dead_cert.id].priority.signals
    assert scored[dead_cert.id].priority.signals == ("cert_expired", "cert_orphaned")
    assert scored[dead_cert.id].priority.score == 0  # +2 -2, nets to zero


def test_cert_orphaned_does_not_fire_if_a_valid_successor_exists() -> None:
    """cert_superseded should be the one that fires here, not cert_orphaned —
    a renewed host is routine rotation, not abandonment."""
    dead_cert = _entity(
        "certificate:old|ca",
        "certificate",
        "old|ca",
        attributes={"not_after": "2021-01-01T00:00:00Z", "san": ["x.example.com"]},
    )
    renewed_cert = _entity(
        "certificate:new|ca",
        "certificate",
        "new|ca",
        attributes={"not_after": "2027-01-01T00:00:00Z", "san": ["x.example.com"]},
    )
    dead_subdomain = _entity(
        "subdomain:x.example.com", "subdomain", "x.example.com", attributes={"dns_resolved": False}
    )
    scored = _score_of([dead_cert, renewed_cert, dead_subdomain])

    assert scored[dead_cert.id].priority.signals == ("cert_expired", "cert_superseded")
    assert "cert_orphaned" not in scored[dead_cert.id].priority.signals


def test_clamp_to_zero_to_ten() -> None:
    many_positives = _entity(
        "subdomain:admin.example.com",
        "subdomain",
        "admin.example.com",
        provenance=(_prov(source_tool="crtsh"), _prov(source_tool="theharvester")),
    )
    scored = _score_of([many_positives])
    assert 0 <= scored[many_positives.id].priority.score <= 10


def test_rank_orders_by_raw_score_descending() -> None:
    high = _entity("subdomain:admin.example.com", "subdomain", "admin.example.com")  # +3
    low = _entity("domain:example.com", "domain", "example.com")  # -1
    scored = _score_of([high, low])

    assert scored[high.id].priority.rank == 1
    assert scored[low.id].priority.rank == 2


def test_tie_break_uses_entity_type_precedence_then_provenance_count_then_id() -> None:
    """ADR-0004 D4: equal raw score (both 0, no signals) -> subdomain before
    certificate before ip_address; then more provenance sources first; then
    lexicographic id."""
    sub = _entity("subdomain:z.example.com", "subdomain", "z.example.com")
    cert = _entity("certificate:z|ca", "certificate", "z|ca")
    ip = _entity("ip_address:203.0.113.9", "ip_address", "203.0.113.9")

    ranked = score_graph([ip, cert, sub], [], AS_OF)
    assert [e.type for e in ranked] == ["subdomain", "certificate", "ip_address"]


def test_signals_stored_verbatim_explain_the_score() -> None:
    """D1: the score is always fully explained by its signals list."""
    entity = _entity(
        "subdomain:admin.example.com",
        "subdomain",
        "admin.example.com",
        provenance=(_prov(source_tool="crtsh"), _prov(source_tool="theharvester")),
    )
    scored = _score_of([entity])
    result = scored[entity.id]

    raw = sum(WEIGHTS[s] for s in result.priority.signals)
    assert result.priority.score == max(0, min(10, raw))


# --- Regression tests reproducing the ADR's real pilot findings ---------


def test_pilot_regression_dead_admin_host_no_longer_outranks_live_infra() -> None:
    """2026-07-22 correction: a dead, admin-pattern hostname must not
    outrank live, multi-tool-corroborated infrastructure."""
    dead_admin = _entity(
        "subdomain:admin.example.com",
        "subdomain",
        "admin.example.com",
        attributes={"dns_resolved": False},
    )
    live_corroborated = _entity(
        "subdomain:app.example.com",
        "subdomain",
        "app.example.com",
        attributes={"dns_resolved": True},
        provenance=(_prov(source_tool="crtsh"), _prov(source_tool="theharvester")),
    )
    scored = _score_of([dead_admin, live_corroborated])

    assert scored[dead_admin.id].priority.score == 0  # +3 sensitive, -3 stale -> nets 0
    assert scored[live_corroborated.id].priority.score == 1  # multi_tool_corroboration
    assert scored[live_corroborated.id].priority.rank < scored[dead_admin.id].priority.rank


def test_pilot_regression_routine_cert_rotation_history_is_not_a_finding() -> None:
    """2026-07-23 correction: an expired-but-renewed certificate must not
    fill 'Top priorities' with routine rotation history."""
    historical = _entity(
        "certificate:2023|godaddy",
        "certificate",
        "2023|godaddy",
        attributes={"not_after": "2024-07-10T00:00:00Z", "san": ["tessno.com"]},
    )
    current = _entity(
        "certificate:2026|le",
        "certificate",
        "2026|le",
        attributes={"not_after": "2026-10-01T00:00:00Z", "san": ["tessno.com"]},
    )
    scored = _score_of([historical, current])

    assert scored[historical.id].priority.score == 0


def test_pilot_regression_orphaned_never_renewed_cert_is_not_a_finding() -> None:
    """2026-07-23 (yulan.me) correction: a certificate for a host that was
    never renewed at all (so cert_superseded can't catch it) must still
    net to zero once the host is confirmed non-resolving."""
    never_renewed = _entity(
        "certificate:ww1-2020|le",
        "certificate",
        "ww1-2020|le",
        attributes={"not_after": "2021-01-01T00:00:00Z", "san": ["ww1.yulan.me"]},
    )
    dead_host = _entity(
        "subdomain:ww1.yulan.me",
        "subdomain",
        "ww1.yulan.me",
        attributes={"dns_resolved": False},
    )
    scored = _score_of([never_renewed, dead_host])

    assert scored[never_renewed.id].priority.score == 0


def test_pilot_regression_web_tech_entity_does_not_crash_scoring() -> None:
    """2026-07-27 (httpx adapter) correction: `web_tech` was missing from
    the D4 tie-break precedence table, so `score_graph` raised `KeyError`
    the first time an adapter actually produced one. It must rank behind
    every other entity type on a raw-score tie (it describes another
    entity; it is never itself the finding)."""
    tech = _entity("web_tech:nginx", "web_tech", "nginx")
    sub = _entity("subdomain:z.example.com", "subdomain", "z.example.com")

    ranked = score_graph([tech, sub], [], AS_OF)
    assert [e.type for e in ranked] == ["subdomain", "web_tech"]


# --- breach_hit reaching the top of a brief (ADR-0004 Q8) -----------------


def _breached_graph() -> tuple[list[Entity], list[Edge]]:
    """A breached apex alongside the noise it has to outrank: a
    sensitive-sounding subdomain corroborated by two tools, which is the
    highest an ordinary finding gets."""
    entities = [
        _entity(
            "domain:example.com",
            "domain",
            "example.com",
            provenance=(_prov(source_tool="crtsh"), _prov(source_tool="hibp")),
        ),
        _entity(
            "breach_exposure:acme",
            "breach_exposure",
            "acme",
            attributes={"breach_name": "Acme"},
            provenance=(_prov(source_tool="hibp"),),
        ),
        _entity(
            "subdomain:staging.example.com",
            "subdomain",
            "staging.example.com",
            provenance=(_prov(source_tool="crtsh"), _prov(source_tool="subfinder")),
        ),
    ]
    edges = [
        Edge(
            source_id="domain:example.com",
            target_id="breach_exposure:acme",
            relation="exposed_in_breach",
        )
    ]
    return entities, edges


def test_a_breached_domain_outranks_sensitive_hostname_noise() -> None:
    """ADR-0004 Q8. Two defects had to be fixed for this to hold: the
    signal was computed for a domain and then suppressed by
    SIGNAL_APPLIES_TO, and at weight 3 it merely tied with name-pattern
    findings — 1079 of them on one real target — losing the lexicographic
    tie-break and staying invisible in the brief."""
    entities, edges = _breached_graph()

    scored = score_graph(entities, edges, AS_OF)
    by_id = {e.id: e for e in scored}

    breached = by_id["domain:example.com"]
    noise = by_id["subdomain:staging.example.com"]

    assert "breach_hit" in breached.priority.signals
    assert breached.priority.score > noise.priority.score
    assert breached.priority.rank == 1


def test_the_breach_entity_itself_still_carries_the_signal() -> None:
    """Widening the signal to the breached subject must not take it away
    from the breach record, which is the thing a reader clicks through to."""
    entities, edges = _breached_graph()

    scored = score_graph(entities, edges, AS_OF)
    breach = next(e for e in scored if e.type == "breach_exposure")

    assert "breach_hit" in breach.priority.signals


def test_an_unbreached_domain_gains_nothing() -> None:
    """The signal is edge-driven, so widening which types may carry it must
    not hand every domain a free three points."""
    entities = [
        _entity(
            "domain:clean.example",
            "domain",
            "clean.example",
            provenance=(_prov(source_tool="crtsh"),),
        )
    ]

    scored = score_graph(entities, [], AS_OF)

    assert "breach_hit" not in scored[0].priority.signals


def test_a_subdomain_is_not_given_the_signal_speculatively() -> None:
    """`subdomain` was deliberately left out of SIGNAL_APPLIES_TO: nothing
    currently produces an `exposed_in_breach` edge from one, and adding a
    type on spec would widen the signal past what any source asserts."""
    from glean_osint.scoring import SIGNAL_APPLIES_TO

    assert "subdomain" not in SIGNAL_APPLIES_TO["breach_hit"]
