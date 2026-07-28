"""Golden-fixture test for the dnsx adapter (ADR-0002 checklist).

tests/fixtures/dnsx-example-com.json is synthetic, using the RFC 2606
example.com convention, shaped as the {candidates, resolved} envelope this
project's own capture convention produces
(`_private/scripts/run_dnsx_liveness.sh`) rather than dnsx's bare stdout —
see the adapter module docstring for why.
"""

import json
from pathlib import Path

import jsonschema
import pytest

from glean_osint.adapters.base import ScanContext
from glean_osint.adapters.dnsx import DnsxAdapter
from glean_osint.schema import SCHEMA_VERSION

FIXTURES = Path(__file__).parent.parent / "fixtures"
SCHEMA_PATH = Path(__file__).parent.parent.parent / "docs" / "schema" / "entity-graph.schema.json"

CTX = ScanContext(
    target="example.com",
    collected_at="2026-07-26T20:00:00Z",
    raw_output_ref="raw/dnsx-example-com.json",
)


@pytest.fixture
def raw_fixture() -> bytes:
    return (FIXTURES / "dnsx-example-com.json").read_bytes()


@pytest.fixture
def expected() -> dict:
    return json.loads((FIXTURES / "dnsx-example-com.expected.json").read_text(encoding="utf-8"))


def test_matches_golden_fixture(raw_fixture: bytes, expected: dict) -> None:
    result = DnsxAdapter().parse(raw_fixture, CTX)

    assert result.skipped == expected["skipped"]
    assert [e.to_dict() for e in result.entities] == expected["entities"]
    assert [e.to_dict() for e in result.edges] == expected["edges"]


def test_parse_is_pure(raw_fixture: bytes) -> None:
    adapter = DnsxAdapter()
    first = adapter.parse(raw_fixture, CTX)
    second = adapter.parse(raw_fixture, CTX)

    assert [e.to_dict() for e in first.entities] == [e.to_dict() for e in second.entities]
    assert [e.to_dict() for e in first.edges] == [e.to_dict() for e in second.edges]
    assert first.skipped == second.skipped


def test_malformed_records_are_skipped_not_fatal(raw_fixture: bytes) -> None:
    """Empty-string / non-string candidates and a malformed `resolved` row
    degrade the scan, never crash it (ADR-0002 D5)."""
    result = DnsxAdapter().parse(raw_fixture, CTX)
    assert result.skipped == 3


def test_canonicalisation_does_not_dedup_within_adapter(raw_fixture: bytes) -> None:
    """'www.example.com' and 'WWW.EXAMPLE.COM' canonicalise to the same id
    but must remain two separate entities — dedup is ADR-0003's job."""
    result = DnsxAdapter().parse(raw_fixture, CTX)
    www_ids = [e.id for e in result.entities if e.id == "subdomain:www.example.com"]
    assert len(www_ids) == 2


def test_wildcard_candidate_produces_no_entity(raw_fixture: bytes) -> None:
    """A literal DNS lookup of a wildcard pattern is never meaningful
    (ADR-0001 D4): it must be excluded entirely, not asserted true or
    false, and not counted as skipped either."""
    result = DnsxAdapter().parse(raw_fixture, CTX)
    assert not any(e.value.startswith("*.") for e in result.entities)
    assert result.skipped == 3


def test_absent_from_resolved_is_positive_confirmation_of_non_resolution(
    raw_fixture: bytes,
) -> None:
    """A candidate absent from `resolved` sets dns_resolved: false — the
    only case where liveness is asserted false, never merely because it
    wasn't checked (ADR-0004 D2's stale_no_dns discipline)."""
    result = DnsxAdapter().parse(raw_fixture, CTX)
    by_id = {e.id: e for e in result.entities}

    dead = by_id["subdomain:dead.example.com"]
    assert dead.attributes["dns_resolved"] is False
    assert not any(edge.source_id == dead.id for edge in result.edges)

    for resolved_id in (
        "domain:example.com",
        "subdomain:admin.example.com",
    ):
        assert by_id[resolved_id].attributes["dns_resolved"] is True


def test_entities_and_edges_are_schema_valid(raw_fixture: bytes) -> None:
    result = DnsxAdapter().parse(raw_fixture, CTX)
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
    result = DnsxAdapter().parse(raw_fixture, CTX)
    entity_ids = {e.id for e in result.entities}
    for edge in result.edges:
        assert edge.source_id in entity_ids
        assert edge.target_id in entity_ids
