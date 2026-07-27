"""Tests for LLM synthesis via Ollama (ADR-0009).

Every Ollama call is injected via `urlopen` -- no real network access
happens in this suite.
"""

from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timezone

import pytest

from glean_osint.brief import build_brief
from glean_osint.schema.entities import Entity, Priority, ProvenanceEntry, ScanMeta
from glean_osint.synthesis import (
    OllamaError,
    _parse_response,
    build_prompt,
    call_ollama,
    synthesize_brief,
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


def _scored_entity(
    entity_id: str, entity_type: str, value: str, rank: int, signals: tuple[str, ...] = ()
) -> Entity:
    return Entity(
        id=entity_id,
        type=entity_type,  # type: ignore[arg-type]
        value=value,
        provenance=(_prov(),),
        priority=Priority(score=3.0, rank=rank, signals=signals),
    )


SCAN = ScanMeta(target="example.com", started_at="2026-07-26T09:00:00Z", glean_version="0.0.2")


class _FakeResponse:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._data


def _ollama_envelope(response_text: str) -> bytes:
    return json.dumps({"response": response_text}).encode("utf-8")


# --- call_ollama --------------------------------------------------------


def test_call_ollama_returns_response_text() -> None:
    def fake_urlopen(request: object, timeout: float) -> _FakeResponse:
        return _FakeResponse(_ollama_envelope('[{"entity_id": "x"}]'))

    result = call_ollama("prompt", urlopen=fake_urlopen)
    assert result == '[{"entity_id": "x"}]'


def test_call_ollama_raises_on_connection_failure() -> None:
    def fake_urlopen(request: object, timeout: float) -> _FakeResponse:
        raise urllib.error.URLError("connection refused")

    with pytest.raises(OllamaError):
        call_ollama("prompt", urlopen=fake_urlopen)


def test_call_ollama_raises_on_malformed_envelope() -> None:
    def fake_urlopen(request: object, timeout: float) -> _FakeResponse:
        return _FakeResponse(b"not json")

    with pytest.raises(OllamaError):
        call_ollama("prompt", urlopen=fake_urlopen)


def test_call_ollama_raises_when_response_field_missing() -> None:
    def fake_urlopen(request: object, timeout: float) -> _FakeResponse:
        return _FakeResponse(json.dumps({"done": True}).encode("utf-8"))

    with pytest.raises(OllamaError):
        call_ollama("prompt", urlopen=fake_urlopen)


# --- build_prompt --------------------------------------------------------


def test_build_prompt_uses_signal_phrases_not_raw_names() -> None:
    entity = _scored_entity(
        "subdomain:admin.example.com",
        "subdomain",
        "admin.example.com",
        1,
        ("sensitive_hostname_pattern",),
    )
    brief = build_brief([entity], [], SCAN)
    prompt = build_prompt(brief.top_priorities)

    assert "sensitive-sounding hostname" in prompt
    assert "sensitive_hostname_pattern" not in prompt
    assert "subdomain:admin.example.com" in prompt


# --- _parse_response -----------------------------------------------------


def test_parse_response_drops_invented_entity_ids() -> None:
    raw = json.dumps(
        [
            {"entity_id": "domain:example.com", "body": "b", "why_ranked": "w"},
            {"entity_id": "domain:invented.com", "body": "b", "why_ranked": "w"},
        ]
    )
    result, invented = _parse_response(raw, {"domain:example.com"})
    assert list(result) == ["domain:example.com"]
    assert invented == 1


def test_parse_response_requires_both_body_and_why_ranked() -> None:
    raw = json.dumps([{"entity_id": "domain:example.com", "body": "only body"}])
    result, invented = _parse_response(raw, {"domain:example.com"})
    assert result == {}
    assert invented == 0


def test_parse_response_handles_malformed_json() -> None:
    result, invented = _parse_response("not json at all", {"domain:example.com"})
    assert result == {}
    assert invented == 0


def test_parse_response_handles_non_list_json() -> None:
    result, invented = _parse_response('{"not": "a list"}', {"domain:example.com"})
    assert result == {}
    assert invented == 0


# Regression tests for real response shapes observed from real local models
# during live validation (2026-07-27) -- Ollama's `format: json` mode
# constrains the grammar to a top-level JSON *object*, so no model ever
# actually returned the bare top-level array the prompt originally asked
# for; each of the four locally-pulled models wrapped it differently.


def test_parse_response_unwraps_the_requested_findings_key() -> None:
    """The prompt now asks for {"findings": [...]} -- mistral:latest
    produced exactly this shape unprompted."""
    raw = json.dumps(
        {"findings": [{"entity_id": "domain:example.com", "body": "b", "why_ranked": "w"}]}
    )
    result, invented = _parse_response(raw, {"domain:example.com"})
    assert result == {"domain:example.com": {"body": "b", "why_ranked": "w"}}
    assert invented == 0


def test_parse_response_unwraps_a_single_bare_finding_object() -> None:
    """llama3.1:8b and phi3:latest both returned one bare finding object
    (no array, no wrapper) instead of narrating every finding given."""
    raw = json.dumps({"entity_id": "domain:example.com", "body": "b", "why_ranked": "w"})
    result, invented = _parse_response(raw, {"domain:example.com"})
    assert result == {"domain:example.com": {"body": "b", "why_ranked": "w"}}
    assert invented == 0


def test_parse_response_unwraps_an_array_under_an_unrelated_key() -> None:
    """llama3.2:latest wrapped the whole array under a synthetic,
    unrelated single key instead of "findings" or a bare array."""
    raw = json.dumps(
        {
            "some unrelated key the model invented": [
                {"entity_id": "domain:example.com", "body": "b", "why_ranked": "w"}
            ]
        }
    )
    result, invented = _parse_response(raw, {"domain:example.com"})
    assert result == {"domain:example.com": {"body": "b", "why_ranked": "w"}}
    assert invented == 0


# --- synthesize_brief ------------------------------------------------


def test_synthesize_brief_replaces_narrated_findings() -> None:
    entity = _scored_entity("domain:example.com", "domain", "example.com", 1)
    brief = build_brief([entity], [], SCAN)

    def fake_urlopen(request: object, timeout: float) -> _FakeResponse:
        text = json.dumps(
            [{"entity_id": "domain:example.com", "body": "LLM body.", "why_ranked": "LLM why."}]
        )
        return _FakeResponse(_ollama_envelope(text))

    result = synthesize_brief(brief, [entity], urlopen=fake_urlopen)
    assert result.narrated_count == 1
    assert result.fell_back_count == 0
    assert result.brief.top_priorities[0].body == "LLM body."
    assert result.brief.top_priorities[0].why_ranked == "LLM why."
    # headline is never touched by synthesis (ADR-0009 D1)
    assert result.brief.top_priorities[0].headline == brief.top_priorities[0].headline


def test_synthesize_brief_falls_back_entirely_on_ollama_error() -> None:
    entity = _scored_entity("domain:example.com", "domain", "example.com", 1)
    brief = build_brief([entity], [], SCAN)

    def fake_urlopen(request: object, timeout: float) -> _FakeResponse:
        raise urllib.error.URLError("connection refused")

    result = synthesize_brief(brief, [entity], urlopen=fake_urlopen)
    assert result.narrated_count == 0
    assert result.fell_back_count == 1
    assert result.brief == brief


def test_synthesize_brief_falls_back_per_finding_for_partial_response() -> None:
    e1 = _scored_entity("domain:example.com", "domain", "example.com", 1)
    e2 = _scored_entity("subdomain:www.example.com", "subdomain", "www.example.com", 2)
    brief = build_brief([e1, e2], [], SCAN)

    def fake_urlopen(request: object, timeout: float) -> _FakeResponse:
        # only narrates one of the two findings
        text = json.dumps(
            [{"entity_id": "domain:example.com", "body": "LLM body.", "why_ranked": "LLM why."}]
        )
        return _FakeResponse(_ollama_envelope(text))

    result = synthesize_brief(brief, [e1, e2], urlopen=fake_urlopen)
    assert result.narrated_count == 1
    assert result.fell_back_count == 1
    by_id = {f.entity.id: f for f in result.brief.top_priorities}
    assert by_id["domain:example.com"].body == "LLM body."
    assert by_id["subdomain:www.example.com"].body == brief.top_priorities[1].body


def test_synthesize_brief_never_touches_also_found() -> None:
    top = _scored_entity("domain:example.com", "domain", "example.com", 1)
    tail = _scored_entity("subdomain:zzz.example.com", "subdomain", "zzz.example.com", 2)
    brief = build_brief([top, tail], [], SCAN, top_n=1)
    assert brief.also_found  # sanity: fixture actually exercises the tail

    def fake_urlopen(request: object, timeout: float) -> _FakeResponse:
        text = json.dumps(
            [{"entity_id": "domain:example.com", "body": "LLM body.", "why_ranked": "LLM why."}]
        )
        return _FakeResponse(_ollama_envelope(text))

    result = synthesize_brief(brief, [top, tail], urlopen=fake_urlopen)
    assert result.brief.also_found == brief.also_found


def test_synthesize_brief_with_no_top_priorities_makes_no_call() -> None:
    entity_zero = Entity(
        id="domain:example.com",
        type="domain",
        value="example.com",
        provenance=(_prov(),),
        priority=Priority(score=0.0, rank=1, signals=()),
    )
    brief = build_brief([entity_zero], [], SCAN)
    assert brief.top_priorities == ()

    def fail_if_called(request: object, timeout: float) -> _FakeResponse:
        raise AssertionError("must not call Ollama with no top_priorities")

    result = synthesize_brief(brief, [entity_zero], urlopen=fail_if_called)
    assert result.narrated_count == 0
    assert result.brief == brief
