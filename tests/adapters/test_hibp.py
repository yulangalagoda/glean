"""Golden-fixture test for the HIBP adapter (ADR-0002 checklist).

tests/fixtures/hibp-example.json is a synthetic HIBP envelope in the shape
the free domain endpoint and the paid account endpoint actually return,
carrying both halves plus one malformed record.
"""

from __future__ import annotations

import json
from pathlib import Path

from glean_osint.adapters.base import ScanContext
from glean_osint.adapters.hibp import HibpAdapter

FIXTURE = Path(__file__).parent.parent / "fixtures" / "hibp-example.json"

CTX = ScanContext(target="example.com", collected_at="2026-08-06T00:00:00Z")


def _parse() -> object:
    return HibpAdapter().parse(FIXTURE.read_bytes(), CTX)


def test_a_breach_becomes_one_entity_however_many_subjects_hit_it() -> None:
    """`ExampleForum` appears in both halves of the fixture. It is one
    real-world event, so it is one entity with two edges, not two
    entities -- dedup would merge them anyway (ADR-0003), and emitting
    duplicates would inflate the surface count on the way there."""
    result = _parse()

    breaches = [e for e in result.entities if e.type == "breach_exposure"]
    assert sorted(e.id for e in breaches) == [
        "breach_exposure:collection1",
        "breach_exposure:exampleforum",
    ]


def test_the_subject_entity_is_never_invented() -> None:
    """HIBP answers a question about an address; it does not assert the
    address exists. Emitting it would let a breach lookup conjure an email
    no collection tool ever found (ADR-0002 D4)."""
    result = _parse()

    assert not [e for e in result.entities if e.type in {"email_address", "domain"}]
    # The edge still points at the real id, so dedup joins it up when
    # theHarvester or crt.sh contributes that entity.
    assert any(e.source_id == "email_address:admin@example.com" for e in result.edges)


def test_domain_and_account_breaches_hang_off_different_subjects() -> None:
    """The distinction that matters for disclosure: 'this site leaked' is
    not 'this person appeared in someone else's leak'."""
    result = _parse()

    by_source: dict[str, set[str]] = {}
    for edge in result.edges:
        assert edge.relation == "exposed_in_breach"
        by_source.setdefault(edge.source_id, set()).add(edge.target_id)

    assert by_source["domain:example.com"] == {"breach_exposure:exampleforum"}
    assert by_source["email_address:admin@example.com"] == {
        "breach_exposure:exampleforum",
        "breach_exposure:collection1",
    }


def test_the_display_attribute_matches_what_the_brief_already_reads() -> None:
    """`brief._body` has read `breach_name` since ADR-0005. Using that key
    is what lets this tool render with no change to the brief."""
    result = _parse()

    forum = next(e for e in result.entities if e.id == "breach_exposure:exampleforum")
    assert forum.attributes["breach_name"] == "ExampleForum"
    assert forum.attributes["data_classes"] == ["Email addresses", "Passwords", "Usernames"]
    assert forum.attributes["pwn_count"] == 812345


def test_an_email_key_that_is_blank_is_skipped_not_fatal() -> None:
    """ADR-0002 D5: a malformed record is counted and dropped, never fatal."""
    result = _parse()

    assert result.skipped == 1
    assert not any("ignored" in e.id for e in result.entities)


def test_a_bare_array_is_read_as_domain_breaches() -> None:
    """What piping the free endpoint straight to a file gives you."""
    raw = json.dumps([{"Name": "Adobe", "BreachDate": "2013-10-04"}]).encode()

    result = HibpAdapter().parse(raw, CTX)

    assert [e.id for e in result.entities] == ["breach_exposure:adobe"]
    assert [e.source_id for e in result.edges] == ["domain:example.com"]


def test_malformed_json_degrades_to_nothing_rather_than_raising() -> None:
    assert HibpAdapter().parse(b"not json at all", CTX).entities == []


def test_provenance_points_at_the_exact_record() -> None:
    """ADR-0001 D1: every entity carries a reference precise enough to find
    the record that asserted it."""
    result = _parse()

    refs = {p.raw_record_ref for e in result.entities for p in e.provenance}
    assert "$.domain_breaches[0]" in refs
    assert any(r.startswith('$.account_breaches["admin@example.com"]') for r in refs)
