"""The one-page brief: Glean's human-facing report contract (ADR-0005).

D1 fixes the skeleton — header, top priorities, also found, provenance
footer — as contract, not a model choice: "the model fills a template; it
does not design the document." No LLM is wired into this project yet, so
the narration here (headline/body per finding, "why ranked here" phrases)
is a deterministic, template-based stand-in. This keeps every contractual
invariant (D2 ordering, D3 provenance lines, D4 faithfulness, D6 footer
counts) enforced by construction; swapping in a real LLM later only
touches the prose, never the skeleton — exactly D1's own framing.

Every `Finding` here is built directly from a real graph `Entity`, so
faithfulness (D4) and provenance (D3) hold trivially for this renderer;
`check_brief_contract` still verifies them structurally rather than
assuming it, since it doubles as the seed of ADR-0006's stage-1
deterministic pre-check, which *does* need to catch a real LLM's mistakes.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import get_args

from glean_osint.schema.entities import Edge, Entity, EntityType, ScanMeta

DEFAULT_TOP_N = 5

# D5: "why ranked here" translates priority.signals to plain English —
# the model (or, for now, this template) translates; it does not invent.
SIGNAL_PHRASES: dict[str, str] = {
    "sensitive_hostname_pattern": "sensitive-sounding hostname",
    "breach_hit": "linked to a breach exposure",
    "sensitive_port": "admin/DB/remote-access port exposed",
    "exposed_service": "service is exposed",
    "cert_expired": "certificate has expired",
    "cert_superseded": "certificate has been renewed (routine rotation)",
    "cert_orphaned": "certificate belongs to a confirmed-dead host",
    "cert_expiring_soon": "certificate expiring within 30 days",
    "resolves_to_live_ip": "resolves to a live IP with an exposed service",
    "multi_tool_corroboration": "seen independently by multiple tools",
    "active_only_finding": "found only via active collection",
    "wildcard_or_default": "wildcard DNS confirmed active",
    "passive_low_signal": "routine passive finding, no other signal",
    "stale_no_dns": "confirmed no longer resolving",
}

TOOL_DISPLAY_NAMES: dict[str, str] = {
    "crtsh": "crt.sh",
    "theharvester": "theHarvester",
    "dnsx": "dnsx",
    "amass": "Amass",
}

_TYPE_LABELS: dict[str, tuple[str, str]] = {
    "domain": ("domain", "domains"),
    "subdomain": ("subdomain", "subdomains"),
    "ip_address": ("IP address", "IP addresses"),
    "dns_record": ("DNS record", "DNS records"),
    "email_address": ("email", "emails"),
    "breach_exposure": ("breach exposure", "breach exposures"),
    "service": ("exposed service", "exposed services"),
    "web_tech": ("web technology", "web technologies"),
    "certificate": ("certificate", "certificates"),
}


@dataclass(frozen=True, slots=True)
class Finding:
    entity: Entity
    # Human-scannable label — NOT always entity.value (e.g. a certificate's
    # value is its internal serial|issuer identity key, not a readable name).
    display_value: str
    headline: str
    body: str
    why_ranked: str  # empty for "also found" entries (D1: only top priorities get one)
    seen_by: str


@dataclass(frozen=True, slots=True)
class Brief:
    scan: ScanMeta
    surface_line: str
    top_priorities: tuple[Finding, ...]
    also_found: tuple[Finding, ...]
    findings_count: int
    findings_with_valid_provenance: int
    fabricated_findings: int


def build_brief(
    entities: list[Entity],
    edges: list[Edge],
    scan: ScanMeta,
    top_n: int = DEFAULT_TOP_N,
) -> Brief:
    """Build a Brief from a *scored* graph (run scoring.score_graph first).

    D2: ordering is `priority.rank`, never a model or caller choice — the
    caller cannot reorder findings, only choose `top_n`.
    """
    if any(e.priority is None for e in entities):
        msg = "build_brief requires a scored graph — run scoring.score_graph first"
        raise ValueError(msg)

    ranked = sorted(entities, key=_rank_of)
    entities_by_id = {e.id: e for e in entities}
    edges_by_source: dict[str, list[Edge]] = defaultdict(list)
    for edge in edges:
        edges_by_source[edge.source_id].append(edge)

    top = [e for e in ranked if _score_of(e) > 0][:top_n]
    top_ids = {e.id for e in top}
    tail = [e for e in ranked if e.id not in top_ids]

    top_priorities = tuple(
        _build_finding(e, edges_by_source, entities_by_id, with_why=True) for e in top
    )
    also_found = tuple(
        _build_finding(e, edges_by_source, entities_by_id, with_why=False) for e in tail
    )

    all_findings = top_priorities + also_found
    findings_count = len(all_findings)
    findings_with_valid_provenance = sum(
        1 for f in all_findings if f.entity.id in entities_by_id and f.entity.provenance
    )
    # Every Finding here is built directly from a real graph Entity — this
    # renderer cannot fabricate. A real LLM-generated brief would compute
    # this by parsing prose against the graph instead (ADR-0006 D1).
    fabricated_findings = 0

    return Brief(
        scan=scan,
        surface_line=_surface_line(entities),
        top_priorities=top_priorities,
        also_found=also_found,
        findings_count=findings_count,
        findings_with_valid_provenance=findings_with_valid_provenance,
        fabricated_findings=fabricated_findings,
    )


def _rank_of(entity: Entity) -> int:
    assert entity.priority is not None  # guaranteed by build_brief's precondition check
    return entity.priority.rank


def _score_of(entity: Entity) -> float:
    assert entity.priority is not None
    return entity.priority.score


def _build_finding(
    entity: Entity,
    edges_by_source: dict[str, list[Edge]],
    entities_by_id: dict[str, Entity],
    with_why: bool,
) -> Finding:
    return Finding(
        entity=entity,
        display_value=_display_value(entity),
        headline=_headline(entity),
        body=_body(entity, edges_by_source, entities_by_id),
        why_ranked=_why_ranked(entity) if with_why else "",
        seen_by=_seen_by(entity),
    )


def _display_value(entity: Entity) -> str:
    if entity.type == "certificate":
        sans = entity.attributes.get("san")
        if sans:
            return ", ".join(sans)
        subject = entity.attributes.get("subject")
        return subject if isinstance(subject, str) and subject else entity.value
    return entity.value


def _headline(entity: Entity) -> str:
    if entity.type == "domain":
        return "root domain"
    if entity.type == "subdomain":
        tags = []
        if entity.attributes.get("wildcard"):
            tags.append("wildcard")
        dns_resolved = entity.attributes.get("dns_resolved")
        if dns_resolved is True:
            tags.append("confirmed live")
        elif dns_resolved is False:
            tags.append("confirmed dead")
        return "subdomain" + (", " + ", ".join(tags) if tags else "")
    if entity.type == "service":
        protocol = entity.attributes.get("protocol", "tcp")
        return f"exposed {protocol} service"
    if entity.type == "certificate":
        return "certificate"
    if entity.type == "email_address":
        return "published contact address"
    if entity.type == "ip_address":
        return "IP address"
    if entity.type == "dns_record":
        record_type = entity.attributes.get("record_type")
        return f"{record_type} record" if record_type else "DNS record"
    if entity.type == "breach_exposure":
        return "breach exposure"
    if entity.type == "web_tech":
        return "web technology"
    return entity.type


def _body(
    entity: Entity, edges_by_source: dict[str, list[Edge]], entities_by_id: dict[str, Entity]
) -> str:
    if entity.type == "domain":
        registrar = entity.attributes.get("registrar")
        return f"Root domain, registrar {registrar}." if registrar else "Root domain."
    if entity.type == "subdomain":
        targets = [
            entities_by_id[e.target_id].value
            for e in edges_by_source.get(entity.id, [])
            if e.relation == "resolves_to" and e.target_id in entities_by_id
        ]
        if targets:
            return f"Resolves to {', '.join(targets)}."
        return "No resolution data available."
    if entity.type == "service":
        port = entity.attributes.get("port")
        protocol = entity.attributes.get("protocol", "tcp")
        service_name = entity.attributes.get("service")
        label = f"Port {port}/{protocol}" if port is not None else "A service"
        if service_name:
            label += f" ({service_name})"
        return f"{label} is reachable."
    if entity.type == "certificate":
        issuer = entity.attributes.get("issuer")
        not_after = entity.attributes.get("not_after")
        bits = []
        if issuer:
            bits.append(f"issued by {issuer}")
        if not_after:
            bits.append(f"expires {not_after}")
        return ("Certificate " + ", ".join(bits) + ".") if bits else "Certificate."
    if entity.type == "email_address":
        return "Published contact address. Useful for disclosure, low risk."
    if entity.type == "ip_address":
        asn = entity.attributes.get("asn")
        return f"IP address (network {asn})." if asn else "IP address."
    if entity.type == "dns_record":
        rdata = entity.attributes.get("rdata")
        return f"DNS record: {rdata}." if rdata else "DNS record."
    if entity.type == "breach_exposure":
        breach_name = entity.attributes.get("breach_name")
        return f"Breach exposure: {breach_name}." if breach_name else "Breach exposure."
    if entity.type == "web_tech":
        product = entity.attributes.get("product")
        return f"Web technology detected: {product}." if product else "Web technology detected."
    return "Finding."


def _why_ranked(entity: Entity) -> str:
    assert entity.priority is not None
    phrases = [SIGNAL_PHRASES[s] for s in entity.priority.signals if s in SIGNAL_PHRASES]
    return " + ".join(phrases) if phrases else "no individual signal"


def _seen_by(entity: Entity) -> str:
    seen: dict[tuple[str, str], None] = {}
    for prov in entity.provenance:
        seen.setdefault((prov.source_tool, prov.method), None)
    parts = [f"{TOOL_DISPLAY_NAMES.get(tool, tool)} ({method})" for tool, method in seen]
    return ", ".join(parts)


def _surface_line(entities: list[Entity]) -> str:
    # A fixed canonical order (matching EntityType's own declaration order),
    # not whatever order `entities` happens to arrive in — the surface line
    # must read the same regardless of how the graph happened to score.
    counts: dict[str, int] = defaultdict(int)
    for entity in entities:
        counts[entity.type] += 1
    parts = []
    for entity_type in get_args(EntityType):
        count = counts.get(entity_type, 0)
        if not count:
            continue
        singular, plural = _TYPE_LABELS.get(entity_type, (entity_type, entity_type + "s"))
        parts.append(f"{count} {singular if count == 1 else plural}")
    return " · ".join(parts)


def render_markdown(brief: Brief) -> str:
    """Render the fixed D1 skeleton as Markdown: header, top priorities,
    also found, provenance footer."""
    lines = [f"# Glean Brief — {brief.scan.target}", ""]
    scan_line = (
        f"**Scan:** {brief.scan.target} · {brief.scan.started_at} · "
        f"Glean v{brief.scan.glean_version}"
    )
    lines.append(scan_line)
    if brief.scan.tools_run:
        tools = ", ".join(
            f"{TOOL_DISPLAY_NAMES.get(t.source_tool, t.source_tool)} ({t.method})"
            for t in brief.scan.tools_run
        )
        lines.append(f"**Tools:** {tools}")
    lines.append(f"**Authorisation:** {brief.scan.authorisation or 'Not recorded'}")
    lines.append(f"**Surface:** {brief.surface_line}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Top priorities")
    lines.append("")
    for i, finding in enumerate(brief.top_priorities, start=1):
        lines.append(
            f"**{i}. `{finding.display_value}` — {finding.headline}.** "
            f"*(priority {finding.entity.priority.score})*"  # type: ignore[union-attr]
        )
        lines.append(finding.body)
        lines.append(f"*Why ranked here:* {finding.why_ranked}.")
        lines.append(f"*Seen by:* {finding.seen_by}.")
        lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Also found")
    lines.append("")
    for finding in brief.also_found:
        body = finding.body.rstrip(".")
        lines.append(f"- **`{finding.display_value}`** — {body} ({finding.seen_by}).")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Provenance & method")
    lines.append("")
    lines.append(_closing_statement(brief))
    lines.append("")
    footer = (
        f"*Findings in this brief: {brief.findings_count}. "
        f"Findings with valid provenance: "
        f"{brief.findings_with_valid_provenance}/{brief.findings_count}. "
        f"Fabricated findings: {brief.fabricated_findings}.*"
    )
    lines.append(footer)
    return "\n".join(lines)


def _closing_statement(brief: Brief) -> str:
    all_findings = brief.top_priorities + brief.also_found
    corroborated = sum(
        1
        for f in all_findings
        if f.entity.priority is not None and "multi_tool_corroboration" in f.entity.priority.signals
    )
    active_tools = sorted({t.source_tool for t in brief.scan.tools_run if t.method == "active"})
    parts = ["Every finding above is traceable to a named source tool and collection method."]
    if corroborated == 1:
        parts.append("1 finding was confirmed by more than one tool.")
    elif corroborated > 1:
        parts.append(f"{corroborated} findings were confirmed by more than one tool.")
    if active_tools:
        names = ", ".join(TOOL_DISPLAY_NAMES.get(t, t) for t in active_tools)
        parts.append(f"Active collection ({names}) touched the target.")
    else:
        parts.append("All collection was passive.")
    return " ".join(parts)


def check_brief_contract(brief: Brief, entities: list[Entity]) -> list[str]:
    """Verify a Brief against ADR-0005's checklist. Returns a list of
    violation descriptions; empty means the brief passes.

    Trivially satisfied by `build_brief`'s own output (every Finding is
    built directly from a real graph Entity) — this exists to be reused
    once a real LLM writes the prose (ADR-0006 D1's stage-1 deterministic
    pre-check), where these checks have real teeth.
    """
    violations: list[str] = []
    entity_ids = {e.id for e in entities}
    all_findings = brief.top_priorities + brief.also_found

    # D4: every finding resolves to a real entity id in the graph.
    for finding in all_findings:
        if finding.entity.id not in entity_ids:
            violations.append(f"finding {finding.entity.id!r} does not resolve to a graph entity")

    # D2: "Top priorities" order matches priority.rank order exactly.
    ranks = [f.entity.priority.rank for f in brief.top_priorities if f.entity.priority is not None]
    if ranks != sorted(ranks):
        violations.append("Top priorities order does not match priority.rank order")

    # D3: every finding has a non-empty "seen by" source line, backed by
    # real provenance.
    for finding in all_findings:
        if not finding.seen_by or not finding.entity.provenance:
            violations.append(
                f"finding {finding.entity.id!r} has no valid 'seen by' provenance line"
            )

    # D6: footer counts are computed, not asserted.
    if brief.findings_count != len(all_findings):
        violations.append("findings_count does not match the actual number of findings rendered")
    expected_valid_provenance = sum(1 for f in all_findings if f.entity.provenance)
    if brief.findings_with_valid_provenance != expected_valid_provenance:
        violations.append("findings_with_valid_provenance does not match the graph")

    return violations
