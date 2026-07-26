"""Golden-fixture test for the crt.sh adapter (ADR-0002 checklist).

tests/fixtures/crtsh-example-com.json is the raw input (a synthetic crt.sh
response shaped like real pilot output, docs/PILOT_findings.md, using the
RFC 2606 reserved example.com domain — same convention as
docs/schema/example-scan.json). crtsh-example-com.expected.json is the
frozen, reviewed-correct normalised output.
"""

import json
from pathlib import Path

import jsonschema
import pytest

from glean_osint.adapters.base import ScanContext
from glean_osint.adapters.crtsh import CrtshAdapter
from glean_osint.schema import SCHEMA_VERSION

FIXTURES = Path(__file__).parent.parent / "fixtures"
SCHEMA_PATH = Path(__file__).parent.parent.parent / "docs" / "schema" / "entity-graph.schema.json"

CTX = ScanContext(
    target="example.com",
    collected_at="2026-07-26T20:00:00Z",
    raw_output_ref="raw/crtsh-example-com.json",
)


@pytest.fixture
def raw_fixture() -> bytes:
    return (FIXTURES / "crtsh-example-com.json").read_bytes()


@pytest.fixture
def expected() -> dict:
    return json.loads((FIXTURES / "crtsh-example-com.expected.json").read_text())


def test_matches_golden_fixture(raw_fixture: bytes, expected: dict) -> None:
    result = CrtshAdapter().parse(raw_fixture, CTX)

    assert result.skipped == expected["skipped"]
    assert [e.to_dict() for e in result.entities] == expected["entities"]
    assert [e.to_dict() for e in result.edges] == expected["edges"]


def test_parse_is_pure(raw_fixture: bytes) -> None:
    """Same raw in -> identical result out (ADR-0002 D2/checklist)."""
    adapter = CrtshAdapter()
    first = adapter.parse(raw_fixture, CTX)
    second = adapter.parse(raw_fixture, CTX)

    assert [e.to_dict() for e in first.entities] == [e.to_dict() for e in second.entities]
    assert [e.to_dict() for e in first.edges] == [e.to_dict() for e in second.edges]
    assert first.skipped == second.skipped


def test_malformed_record_is_skipped_not_fatal(raw_fixture: bytes) -> None:
    """A malformed record degrades the scan, never crashes it (ADR-0002 D5)."""
    result = CrtshAdapter().parse(raw_fixture, CTX)
    assert result.skipped == 1


def test_canonicalisation_does_not_dedup_within_adapter(raw_fixture: bytes) -> None:
    """Mixed-case + trailing-dot input canonicalises to the same id as a
    plain-cased row, but the adapter must NOT collapse them — dedup is
    ADR-0003's job, not the adapter's (ADR-0002 D4)."""
    result = CrtshAdapter().parse(raw_fixture, CTX)
    admin_ids = [e.id for e in result.entities if e.id == "subdomain:admin.example.com"]
    assert len(admin_ids) == 2


def test_entities_and_edges_are_schema_valid(raw_fixture: bytes) -> None:
    """Every produced entity/edge validates against the machine-checkable
    entity-graph schema (ADR-0001)."""
    result = CrtshAdapter().parse(raw_fixture, CTX)
    schema = json.loads(SCHEMA_PATH.read_text())

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
    """Referential integrity: every edge endpoint must reference a real
    entity id (ADR-0001 D5) — JSON Schema can't express this, so it's
    checked here in code."""
    result = CrtshAdapter().parse(raw_fixture, CTX)
    entity_ids = {e.id for e in result.entities}
    for edge in result.edges:
        assert edge.source_id in entity_ids
        assert edge.target_id in entity_ids
