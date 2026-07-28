"""Golden-fixture test for the subfinder adapter (ADR-0002 checklist).

tests/fixtures/subfinder-example-com.jsonl is synthetic, using the RFC 2606
example.com convention, shaped as subfinder's real `-json -silent` output
(one JSON object per line: `{"host", "input", "source"}`) -- confirmed
against a real capture (`subfinder -d yulan.me -json -silent`, 203 real
records, 2026-07-27) before writing this adapter.
"""

import json
from pathlib import Path

import jsonschema
import pytest

from glean_osint.adapters.base import ScanContext
from glean_osint.adapters.subfinder import SubfinderAdapter
from glean_osint.schema import SCHEMA_VERSION

FIXTURES = Path(__file__).parent.parent / "fixtures"
SCHEMA_PATH = Path(__file__).parent.parent.parent / "docs" / "schema" / "entity-graph.schema.json"

CTX = ScanContext(
    target="example.com",
    collected_at="2026-07-26T20:00:00Z",
    raw_output_ref="raw/subfinder-example-com.jsonl",
)


@pytest.fixture
def raw_fixture() -> bytes:
    return (FIXTURES / "subfinder-example-com.jsonl").read_bytes()


@pytest.fixture
def expected() -> dict:
    path = FIXTURES / "subfinder-example-com.expected.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_matches_golden_fixture(raw_fixture: bytes, expected: dict) -> None:
    result = SubfinderAdapter().parse(raw_fixture, CTX)

    assert result.skipped == expected["skipped"]
    assert [e.to_dict() for e in result.entities] == expected["entities"]
    assert [e.to_dict() for e in result.edges] == expected["edges"]


def test_parse_is_pure(raw_fixture: bytes) -> None:
    adapter = SubfinderAdapter()
    first = adapter.parse(raw_fixture, CTX)
    second = adapter.parse(raw_fixture, CTX)

    assert [e.to_dict() for e in first.entities] == [e.to_dict() for e in second.entities]
    assert [e.to_dict() for e in first.edges] == [e.to_dict() for e in second.edges]
    assert first.skipped == second.skipped


def test_malformed_lines_are_skipped_not_fatal(raw_fixture: bytes) -> None:
    """Invalid JSON, a missing "host" field, a non-dict line, and an
    empty "host" string all degrade the scan, never crash it
    (ADR-0002 D5)."""
    result = SubfinderAdapter().parse(raw_fixture, CTX)
    assert result.skipped == 4


def test_canonicalisation_does_not_dedup_within_adapter(raw_fixture: bytes) -> None:
    """'WWW.EXAMPLE.COM' and 'www.example.com' canonicalise to the same
    id but must remain two separate entities -- dedup is ADR-0003's job,
    not this adapter's."""
    result = SubfinderAdapter().parse(raw_fixture, CTX)
    www_ids = [e.id for e in result.entities if e.id == "subdomain:www.example.com"]
    assert len(www_ids) == 2


def test_source_field_is_recorded_as_an_attribute_not_provenance(raw_fixture: bytes) -> None:
    """subfinder's own internal passive engine (e.g. "crtsh",
    "virustotal") is real, captured data -- kept as an attribute for
    traceability, but source_tool stays uniformly "subfinder" (the
    *tool* is the source, matching how CrtshAdapter doesn't distinguish
    internal CT log mirrors either)."""
    result = SubfinderAdapter().parse(raw_fixture, CTX)
    admin = next(e for e in result.entities if e.id == "subdomain:admin.example.com")
    assert admin.attributes["subfinder_source"] == "crtsh"
    assert admin.provenance[0].source_tool == "subfinder"


def test_apex_host_becomes_a_domain_entity_with_no_self_edge(raw_fixture: bytes) -> None:
    result = SubfinderAdapter().parse(raw_fixture, CTX)
    apex = next(e for e in result.entities if e.id == "domain:example.com")
    assert apex.type == "domain"
    assert not any(edge.source_id == apex.id for edge in result.edges)


def test_entities_and_edges_are_schema_valid(raw_fixture: bytes) -> None:
    result = SubfinderAdapter().parse(raw_fixture, CTX)
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
    result = SubfinderAdapter().parse(raw_fixture, CTX)
    entity_ids = {e.id for e in result.entities}
    for edge in result.edges:
        assert edge.source_id in entity_ids
        assert edge.target_id in entity_ids
