"""Tests for the brief contract (ADR-0005)."""

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from glean_osint.adapters.base import ScanContext
from glean_osint.adapters.crtsh import CrtshAdapter
from glean_osint.adapters.theharvester import TheHarvesterAdapter
from glean_osint.brief import Finding, build_brief, check_brief_contract, render_markdown
from glean_osint.dedup import merge_graph
from glean_osint.schema.entities import Entity, ProvenanceEntry, ScanMeta, ToolRun
from glean_osint.scoring import score_graph

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


SCAN = ScanMeta(
    target="example.com",
    started_at="2026-07-26T09:00:00Z",
    glean_version="0.0.2",
    authorisation="Root domain owned by operator",
    tools_run=(
        ToolRun(source_tool="crtsh", method="passive"),
        ToolRun(source_tool="theharvester", method="passive"),
    ),
)


def test_build_brief_requires_scored_graph() -> None:
    unscored = _entity("domain:example.com", "domain", "example.com")
    with pytest.raises(ValueError, match="scored graph"):
        build_brief([unscored], [], SCAN)


def test_top_priorities_excludes_zero_and_negative_score() -> None:
    positive = _entity("subdomain:admin.example.com", "subdomain", "admin.example.com")  # +3
    negative = _entity("domain:example.com", "domain", "example.com")  # -1 passive_low_signal
    scored = score_graph([positive, negative], [], AS_OF)

    brief = build_brief(scored, [], SCAN)

    top_ids = {f.entity.id for f in brief.top_priorities}
    tail_ids = {f.entity.id for f in brief.also_found}
    assert positive.id in top_ids
    assert negative.id in tail_ids


def test_top_n_limits_top_priorities() -> None:
    entities = [
        _entity(f"subdomain:admin{i}.example.com", "subdomain", f"admin{i}.example.com")
        for i in range(7)
    ]
    scored = score_graph(entities, [], AS_OF)

    brief = build_brief(scored, [], SCAN, top_n=3)

    assert len(brief.top_priorities) == 3
    assert len(brief.also_found) == 4


def test_top_priorities_are_in_rank_order() -> None:
    entities = [
        _entity(
            "subdomain:admin.example.com",
            "subdomain",
            "admin.example.com",
            provenance=(_prov(source_tool="crtsh"), _prov(source_tool="theharvester")),
        ),  # +3 +1 = 4
        _entity("subdomain:vpn.example.com", "subdomain", "vpn.example.com"),  # +3
    ]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)

    ranks = [f.entity.priority.rank for f in brief.top_priorities]  # type: ignore[union-attr]
    assert ranks == sorted(ranks)
    assert brief.top_priorities[0].entity.id == "subdomain:admin.example.com"


def test_seen_by_lists_distinct_tool_method_pairs_only_once() -> None:
    entity = _entity(
        "subdomain:x.example.com",
        "subdomain",
        "x.example.com",
        provenance=(
            _prov(source_tool="crtsh", raw_record_ref="$[0]"),
            _prov(source_tool="crtsh", raw_record_ref="$[1]"),  # same tool+method, dup ref
            _prov(source_tool="amass", method="active"),
        ),
    )
    scored = score_graph([entity], [], AS_OF)
    brief = build_brief(scored, [], SCAN)
    # multi_tool_corroboration fires (crtsh + amass), so this lands in
    # top_priorities, not also_found — look it up by id across both.
    finding = next(f for f in brief.top_priorities + brief.also_found if f.entity.id == entity.id)

    assert finding.seen_by == "crt.sh (passive), Amass (active)"


def test_surface_line_pluralisation() -> None:
    entities = [
        _entity("domain:example.com", "domain", "example.com"),
        _entity("subdomain:a.example.com", "subdomain", "a.example.com"),
        _entity("subdomain:b.example.com", "subdomain", "b.example.com"),
    ]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)

    assert brief.surface_line == "1 domain · 2 subdomains"


def test_footer_counts_match_actual_findings() -> None:
    entities = [
        _entity("domain:example.com", "domain", "example.com"),
        _entity("subdomain:admin.example.com", "subdomain", "admin.example.com"),
    ]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)

    assert brief.findings_count == 2
    assert brief.findings_with_valid_provenance == 2
    assert brief.fabricated_findings == 0


def test_render_markdown_has_the_fixed_sections_in_order() -> None:
    entities = [
        _entity("domain:example.com", "domain", "example.com"),
        _entity("subdomain:admin.example.com", "subdomain", "admin.example.com"),
    ]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)

    rendered = render_markdown(brief)

    assert rendered.index("## Top priorities") < rendered.index("## Also found")
    assert rendered.index("## Also found") < rendered.index("## Provenance & method")
    assert "**1. `admin.example.com`" in rendered
    assert "*Why ranked here:*" in rendered
    assert "*Seen by:* crt.sh (passive).*" in rendered or "*Seen by:* crt.sh (passive)." in rendered
    assert "Findings in this brief: 2." in rendered


def test_check_brief_contract_passes_on_a_real_build_brief_output() -> None:
    entities = [
        _entity("domain:example.com", "domain", "example.com"),
        _entity("subdomain:admin.example.com", "subdomain", "admin.example.com"),
    ]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)

    assert check_brief_contract(brief, scored) == []


def test_check_brief_contract_catches_entity_not_in_graph() -> None:
    entities = [_entity("domain:example.com", "domain", "example.com")]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)

    fabricated = _entity("subdomain:invented.example.com", "subdomain", "invented.example.com")
    fabricated_scored = score_graph([fabricated], [], AS_OF)[0]
    tampered = replace(
        brief,
        also_found=(
            *brief.also_found,
            Finding(
                entity=fabricated_scored,
                display_value=fabricated_scored.value,
                headline="subdomain",
                body="x",
                why_ranked="",
                seen_by="crt.sh (passive)",
            ),
        ),
    )

    violations = check_brief_contract(tampered, scored)
    assert any("does not resolve to a graph entity" in v for v in violations)


def test_check_brief_contract_catches_out_of_order_top_priorities() -> None:
    entities = [
        _entity("subdomain:admin.example.com", "subdomain", "admin.example.com"),
        _entity("subdomain:vpn.example.com", "subdomain", "vpn.example.com"),
    ]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN, top_n=2)

    reordered = replace(brief, top_priorities=tuple(reversed(brief.top_priorities)))
    violations = check_brief_contract(reordered, scored)

    assert any("does not match priority.rank order" in v for v in violations)


def test_check_brief_contract_catches_bad_footer_counts() -> None:
    entities = [_entity("domain:example.com", "domain", "example.com")]
    scored = score_graph(entities, [], AS_OF)
    brief = build_brief(scored, [], SCAN)

    tampered = replace(brief, findings_count=999)
    violations = check_brief_contract(tampered, scored)

    assert any("findings_count" in v for v in violations)


def test_full_pipeline_produces_a_contract_passing_brief() -> None:
    """Integration test: real adapters -> dedup -> scoring -> brief, for
    the first time end to end."""
    fixtures = Path(__file__).parent / "fixtures"
    ctx = ScanContext(
        target="example.com", collected_at="2026-07-26T20:00:00Z", raw_output_ref="raw/example.json"
    )
    crtsh_result = CrtshAdapter().parse((fixtures / "crtsh-example-com.json").read_bytes(), ctx)
    th_result = TheHarvesterAdapter().parse(
        (fixtures / "theharvester-example-com.json").read_bytes(), ctx
    )

    merged = merge_graph([crtsh_result, th_result])
    scored = score_graph(merged.entities, merged.edges, AS_OF)
    brief = build_brief(scored, merged.edges, SCAN)

    assert check_brief_contract(brief, scored) == []
    rendered = render_markdown(brief)
    assert rendered.startswith("# Glean Brief — example.com")
    assert brief.findings_count == len(scored)
