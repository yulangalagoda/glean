"""Golden-fixture test for the httpx adapter (ADR-0002 checklist).

tests/fixtures/httpx-example-com.jsonl is synthetic, using the RFC 2606
example.com convention, shaped as ProjectDiscovery httpx's real `-json`
line schema (one JSON object per line; field names/types taken from
httpx's own `runner.Result` struct) rather than an invented format.
"""

import json
from pathlib import Path

import jsonschema
import pytest

from glean_osint.adapters.base import ScanContext
from glean_osint.adapters.httpx import HttpxAdapter
from glean_osint.schema import SCHEMA_VERSION

FIXTURES = Path(__file__).parent.parent / "fixtures"
SCHEMA_PATH = Path(__file__).parent.parent.parent / "docs" / "schema" / "entity-graph.schema.json"

CTX = ScanContext(
    target="example.com",
    collected_at="2026-07-26T20:00:00Z",
    raw_output_ref="raw/httpx-example-com.jsonl",
)


@pytest.fixture
def raw_fixture() -> bytes:
    return (FIXTURES / "httpx-example-com.jsonl").read_bytes()


@pytest.fixture
def expected() -> dict:
    return json.loads((FIXTURES / "httpx-example-com.expected.json").read_text(encoding="utf-8"))


def test_matches_golden_fixture(raw_fixture: bytes, expected: dict) -> None:
    result = HttpxAdapter().parse(raw_fixture, CTX)

    assert result.skipped == expected["skipped"]
    assert [e.to_dict() for e in result.entities] == expected["entities"]
    assert [e.to_dict() for e in result.edges] == expected["edges"]


def test_parse_is_pure(raw_fixture: bytes) -> None:
    adapter = HttpxAdapter()
    first = adapter.parse(raw_fixture, CTX)
    second = adapter.parse(raw_fixture, CTX)

    assert [e.to_dict() for e in first.entities] == [e.to_dict() for e in second.entities]
    assert [e.to_dict() for e in first.edges] == [e.to_dict() for e in second.edges]
    assert first.skipped == second.skipped


def test_malformed_records_are_skipped_not_fatal(raw_fixture: bytes) -> None:
    """A non-JSON line, a line missing `input`, a line with a non-bool
    `failed`, and two malformed `tech` entries all degrade the scan,
    never crash it (ADR-0002 D5)."""
    result = HttpxAdapter().parse(raw_fixture, CTX)
    assert result.skipped == 5


def test_blank_lines_are_ignored_not_skipped(raw_fixture: bytes) -> None:
    """A blank line in JSON-lines output is just formatting, not a
    malformed record — must not be counted in `skipped`."""
    assert b"\n\n" in raw_fixture
    result = HttpxAdapter().parse(raw_fixture, CTX)
    assert result.skipped == 5


def test_canonicalisation_does_not_dedup_within_adapter(raw_fixture: bytes) -> None:
    """'www.example.com' and 'WWW.EXAMPLE.COM' canonicalise to the same id
    but must remain two separate entities — dedup is ADR-0003's job."""
    result = HttpxAdapter().parse(raw_fixture, CTX)
    www_ids = [e.id for e in result.entities if e.id == "subdomain:www.example.com"]
    assert len(www_ids) == 2


def test_first_adapter_using_active_method(raw_fixture: bytes) -> None:
    """httpx sends real HTTP requests at the target, unlike the passive
    crt.sh/theHarvester/dnsx adapters — every provenance entry it
    produces must be labelled 'active'."""
    result = HttpxAdapter().parse(raw_fixture, CTX)
    assert result.entities, "fixture should produce at least one entity"
    for entity in result.entities:
        for prov in entity.provenance:
            assert prov.method == "active"


def test_failed_probe_is_positive_confirmation_with_no_enrichment(raw_fixture: bytes) -> None:
    """A `failed: true` row is positive confirmation that nothing served
    HTTP there — the host entity is still recorded (so multi-tool
    corroboration still works), but no service/tech/ip is fabricated."""
    result = HttpxAdapter().parse(raw_fixture, CTX)
    admin_id = "subdomain:admin.example.com"
    assert any(e.id == admin_id for e in result.entities)
    assert not any(
        edge.source_id == admin_id or edge.target_id == admin_id for edge in result.edges
    )
    assert not any(e.type in ("service", "web_tech") and e.id == admin_id for e in result.entities)


def test_missing_port_skips_service_but_keeps_resolution_and_tech(raw_fixture: bytes) -> None:
    """A host with a resolved IP but no `port` field can't form a
    `service:<ip>:<port>` identity — degrade by not fabricating a service,
    while still recording the resolution and any detected tech."""
    result = HttpxAdapter().parse(raw_fixture, CTX)
    by_id = {e.id: e for e in result.entities}
    assert "ip_address:203.0.113.5" in by_id
    assert "web_tech:apache" in by_id
    assert not any(
        e.type == "service" and e.value.startswith("203.0.113.5:") for e in result.entities
    )


def test_entities_and_edges_are_schema_valid(raw_fixture: bytes) -> None:
    result = HttpxAdapter().parse(raw_fixture, CTX)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    document = {
        "schema_version": SCHEMA_VERSION,
        "scan": {
            "target": CTX.target,
            "started_at": CTX.collected_at,
            "glean_version": "0.0.2",
        },
        "entities": [e.to_dict() for e in result.entities],
        "edges": [e.to_dict() for e in result.edges],
    }
    jsonschema.validate(document, schema)


def test_edge_endpoints_exist_in_entities(raw_fixture: bytes) -> None:
    result = HttpxAdapter().parse(raw_fixture, CTX)
    entity_ids = {e.id for e in result.entities}
    for edge in result.edges:
        assert edge.source_id in entity_ids
        assert edge.target_id in entity_ids
