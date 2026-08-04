"""Tests for resolving a `raw_record_ref` back to its exact record."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from glean_osint.adapters.base import Adapter, ScanContext
from glean_osint.adapters.crtsh import CrtshAdapter
from glean_osint.adapters.dnsx import DnsxAdapter
from glean_osint.adapters.httpx import HttpxAdapter
from glean_osint.adapters.subfinder import SubfinderAdapter
from glean_osint.adapters.theharvester import TheHarvesterAdapter
from glean_osint.provenance import resolve_record

_RAW = Path(__file__).parent / "fixtures" / "eval" / "example-com" / "raw"
_CTX = ScanContext(target="example.com", collected_at="2026-08-04T00:00:00Z")

_ADAPTERS: list[tuple[Adapter, str]] = [
    (CrtshAdapter(), "crtsh-example-com.json"),
    (TheHarvesterAdapter(), "theharvester-example-com.json"),
    (SubfinderAdapter(), "subfinder-example-com.jsonl"),
    (DnsxAdapter(), "dnsx-example-com.json"),
    (HttpxAdapter(), "httpx-example-com.jsonl"),
]


@pytest.mark.parametrize("adapter,filename", _ADAPTERS, ids=lambda v: getattr(v, "tool_id", ""))
def test_every_ref_an_adapter_emits_resolves_against_its_own_capture(
    adapter: Adapter, filename: str
) -> None:
    """The property that matters, checked against real captures rather than
    a handful of hand-written refs: anything an adapter writes into
    `raw_record_ref` must be resolvable from the bytes it was parsed from.
    A ref the adapter emits but nothing can resolve is a broken provenance
    link, which is worse than no link on a page whose whole purpose is
    making the provenance claim checkable.
    """
    raw = (_RAW / filename).read_bytes()
    result = adapter.parse(raw, _CTX)

    refs = [p.raw_record_ref for e in result.entities for p in e.provenance if p.raw_record_ref]
    assert refs, f"{filename} produced no refs at all -- the test would pass vacuously"

    unresolvable = [ref for ref in refs if resolve_record(raw, ref) is None]
    assert unresolvable == []


def test_resolved_records_actually_correspond_to_their_entity() -> None:
    """Resolving is not enough -- an off-by-one resolves perfectly well and
    points at the wrong record, which is the failure mode that would quietly
    make provenance lie. Checked by requiring the record to mention the
    entity it justifies.

    Certificates are matched on serial rather than `value`, because a
    certificate's `value` is an internal `serial|issuer` identity key
    (ADR-0001) that never appears verbatim in the source record.
    """
    raw = (_RAW / "crtsh-example-com.json").read_bytes()
    result = CrtshAdapter().parse(raw, _CTX)

    checked = 0
    for entity in result.entities:
        for prov in entity.provenance:
            if not prov.raw_record_ref:
                continue
            record = resolve_record(raw, prov.raw_record_ref)
            assert record is not None
            if entity.type == "certificate":
                serial = entity.value.split("|")[0]
                assert json.loads(record.content)["serial_number"] == serial
            else:
                assert entity.value.lower() in record.content.lower()
            checked += 1
    assert checked > 0


def test_line_refs_are_one_based_and_count_physical_lines() -> None:
    """The JSON-lines adapters number from 1 and count every physical line,
    blank and malformed ones included. Off by one in either direction shows
    the operator a different record than the one that justified the finding.
    """
    raw = b'{"host": "a.example.com"}\n{"host": "b.example.com"}\n'

    first = resolve_record(raw, "line:1")
    second = resolve_record(raw, "line:2")

    assert first is not None and "a.example.com" in first.content
    assert first.line_number == 1
    assert second is not None and "b.example.com" in second.content
    assert resolve_record(raw, "line:0") is None
    assert resolve_record(raw, "line:3") is None


def test_document_refs_are_zero_based() -> None:
    """Document adapters index arrays from 0, unlike the 1-based line refs.
    The asymmetry is deliberate (see the module docstring) and is exactly
    what a well-meaning "consistency" fix would break for every scan
    already archived.
    """
    raw = b'[{"name": "first"}, {"name": "second"}]'

    assert (r := resolve_record(raw, "$[0]")) is not None and "first" in r.content
    assert (r := resolve_record(raw, "$[1]")) is not None and "second" in r.content
    assert resolve_record(raw, "$[2]") is None


def test_a_field_ref_resolves_to_the_bare_field_value() -> None:
    raw = b'[{"name_value": "admin.example.com", "other": 1}]'

    record = resolve_record(raw, "$[0].name_value")

    assert record is not None
    # Not a quoted JSON string: the point is to show the hostname.
    assert record.content == "admin.example.com"


def test_a_keyed_array_ref_resolves() -> None:
    raw = b'{"hosts": ["a.example.com", "b.example.com"], "emails": ["x@example.com"]}'

    assert (r := resolve_record(raw, "$.hosts[1]")) is not None and r.content == "b.example.com"
    assert (r := resolve_record(raw, "$.emails[0]")) is not None and r.content == "x@example.com"
    assert resolve_record(raw, "$.hosts[9]") is None
    assert resolve_record(raw, "$.missing[0]") is None


def test_a_predicate_ref_resolves_to_the_whole_matched_row() -> None:
    """dnsx identifies a resolved row by host rather than position. The
    surrounding row is shown even though the ref narrows to `.a`: an IP
    without its host and status code beside it is not much of a provenance
    answer, and this also keeps the ref resolvable when the narrowed field
    happens to be absent.
    """
    raw = b'{"resolved": [{"host": "a.example.com", "a": ["1.1.1.1"], "status_code": "NOERROR"}]}'

    record = resolve_record(raw, "$.resolved[host=a.example.com].a")

    assert record is not None
    assert "1.1.1.1" in record.content
    assert "NOERROR" in record.content  # the context, not just the field
    assert resolve_record(raw, "$.resolved[host=nope.example.com].a") is None


def test_a_line_ref_pointing_at_unparseable_content_shows_it_verbatim() -> None:
    """Adapters count every physical line, including ones they skipped as
    malformed, so a ref can legitimately land on a line that is not JSON.
    Showing it as-is is both honest and informative -- it is evidence about
    what the tool actually emitted.
    """
    raw = b'{"host": "a.example.com"}\nthis is not json{\n'

    record = resolve_record(raw, "line:2")

    assert record is not None
    assert record.content == "this is not json{"


def test_unresolvable_refs_degrade_to_none_rather_than_raising() -> None:
    """Every one of these is a real possibility -- a truncated capture, a
    ref from an older adapter, a hand-edited file. None of them justifies
    failing a page the operator opened to check a provenance claim; the
    caller falls back to showing the whole capture.
    """
    valid = b'[{"a": 1}]'

    assert resolve_record(valid, "not-a-ref-at-all") is None
    assert resolve_record(valid, "$.nope") is None
    assert resolve_record(b"{ truncated", "$[0]") is None
    assert resolve_record(b"\xff\xfe not utf-8", "line:1") is None
    assert resolve_record(valid, "$[0].missing_field") is None
