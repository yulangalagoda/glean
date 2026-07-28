"""Golden-fixture test for the theHarvester adapter (ADR-0002 checklist).

tests/fixtures/theharvester-example-com.json is synthetic, shaped like the
real captures under eval/scans/*/raw/theharvester-*.json (same cmd/hosts/
emails/shodan structure), using the RFC 2606 example.com convention.
"""

import json
from pathlib import Path

import jsonschema
import pytest

from glean_osint.adapters.base import ScanContext
from glean_osint.adapters.theharvester import TheHarvesterAdapter
from glean_osint.schema import SCHEMA_VERSION

FIXTURES = Path(__file__).parent.parent / "fixtures"
SCHEMA_PATH = Path(__file__).parent.parent.parent / "docs" / "schema" / "entity-graph.schema.json"

CTX = ScanContext(
    target="example.com",
    collected_at="2026-07-26T20:00:00Z",
    raw_output_ref="raw/theharvester-example-com.json",
)


@pytest.fixture
def raw_fixture() -> bytes:
    return (FIXTURES / "theharvester-example-com.json").read_bytes()


@pytest.fixture
def expected() -> dict:
    path = FIXTURES / "theharvester-example-com.expected.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_matches_golden_fixture(raw_fixture: bytes, expected: dict) -> None:
    result = TheHarvesterAdapter().parse(raw_fixture, CTX)

    assert result.skipped == expected["skipped"]
    assert [e.to_dict() for e in result.entities] == expected["entities"]
    assert [e.to_dict() for e in result.edges] == expected["edges"]


def test_parse_is_pure(raw_fixture: bytes) -> None:
    adapter = TheHarvesterAdapter()
    first = adapter.parse(raw_fixture, CTX)
    second = adapter.parse(raw_fixture, CTX)

    assert [e.to_dict() for e in first.entities] == [e.to_dict() for e in second.entities]
    assert [e.to_dict() for e in first.edges] == [e.to_dict() for e in second.edges]
    assert first.skipped == second.skipped


def test_malformed_records_are_skipped_not_fatal(raw_fixture: bytes) -> None:
    """Empty/non-string hosts and invalid emails degrade the scan, never
    crash it (ADR-0002 D5)."""
    result = TheHarvesterAdapter().parse(raw_fixture, CTX)
    assert result.skipped == 4


def test_no_per_source_attribution_degrades_to_combined_label(raw_fixture: bytes) -> None:
    """ADR-0002 D3's pilot correction: theHarvester run with multiple -b
    sources gives no per-record source attribution, so every provenance
    entry must degrade to a combined-sources label parsed from `cmd`,
    never invent a specific source it can't actually attribute."""
    result = TheHarvesterAdapter().parse(raw_fixture, CTX)
    assert result.entities, "fixture should produce at least one entity"
    for entity in result.entities:
        for prov in entity.provenance:
            assert prov.source_module == "combined:crtsh,duckduckgo,otx,certspotter"


def test_canonicalisation_does_not_dedup_within_adapter(raw_fixture: bytes) -> None:
    """'www.example.com' and 'WWW.EXAMPLE.COM' canonicalise to the same id
    but must remain two separate entities — dedup is ADR-0003's job."""
    result = TheHarvesterAdapter().parse(raw_fixture, CTX)
    www_ids = [e.id for e in result.entities if e.id == "subdomain:www.example.com"]
    assert len(www_ids) == 2


def test_entities_and_edges_are_schema_valid(raw_fixture: bytes) -> None:
    result = TheHarvesterAdapter().parse(raw_fixture, CTX)
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
    result = TheHarvesterAdapter().parse(raw_fixture, CTX)
    entity_ids = {e.id for e in result.entities}
    for edge in result.edges:
        assert edge.source_id in entity_ids
        assert edge.target_id in entity_ids
