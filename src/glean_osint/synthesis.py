"""LLM synthesis via Ollama (ADR-0009).

Replaces `brief.py`'s template `body`/`why_ranked` text for
`top_priorities` findings only -- `headline` and the rest of the
skeleton stay exactly as `build_brief` computed them (ADR-0005 D1: the
model narrates, it does not design the document). `also_found` is
deliberately never narrated (ADR-0009 D2) -- bounded cost regardless of
graph size, and it's the noisy tail, not what a reader focuses on.

Degradation is per-finding, not all-or-nothing: a connection failure or
unparseable response falls back to the whole template brief, but a
response that's valid JSON with only *some* usable items still uses
whatever narration it got and falls back to template text only for the
findings it didn't cover. This is the same "degrade, never crash"
discipline as every other stage of this project (ADR-0002 D5, ADR-0008
D5), applied one level higher.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, replace

from glean_osint.brief import SIGNAL_PHRASES, Brief, Finding, check_brief_contract
from glean_osint.schema.entities import Entity

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "llama3.2:latest"
DEFAULT_TIMEOUT_SECONDS = 120.0

_SYSTEM_PREAMBLE = """You are narrating a security reconnaissance brief. You \
will be given a JSON array of findings, each with an entity_id, type, \
display_value, attributes, seen_by (which tools found it), and signals \
(why it was flagged as a priority).

Rules, all mandatory:
- Only narrate the findings given. Never invent a finding, entity, IP, \
hostname, service, or fact not present in the given data.
- For each finding, write:
  - "body": one factual sentence describing what this finding is, based \
only on its attributes/seen_by.
  - "why_ranked": one short phrase explaining why it's a priority, based \
only on its signals.
- Narrate EVERY finding given, not just the first one.
- Output a single JSON object of the exact shape \
{"findings": [{"entity_id": ..., "body": ..., "why_ranked": ...}, ...]}, \
with one array item per input finding, in the same order.
- Do not add commentary, markdown, or any text outside that JSON object."""


class OllamaError(Exception):
    """The Ollama call itself failed (connection, timeout, HTTP error, bad
    response shape) -- the caller treats this as the scan degrading to
    template narration (ADR-0009 D6), never a crash."""


def call_ollama(
    prompt: str,
    *,
    model: str = DEFAULT_MODEL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    urlopen: Callable[..., object] = urllib.request.urlopen,
) -> str:
    """POST to Ollama's local /api/generate, returning the model's raw
    response text (still a JSON *string* to be parsed separately -- Ollama's
    `format: json` guarantees the text is valid JSON, not that it matches
    the shape we asked for)."""
    payload = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "format": "json",
            "stream": False,
            "options": {"temperature": 0},
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urlopen(request, timeout=timeout) as response:  # type: ignore[attr-defined]
            body = response.read()
    except (urllib.error.URLError, OSError) as error:
        raise OllamaError(str(error)) from error

    try:
        data = json.loads(body)
    except json.JSONDecodeError as error:
        raise OllamaError(f"non-JSON response envelope from Ollama: {error}") from error

    text = data.get("response") if isinstance(data, dict) else None
    if not isinstance(text, str):
        raise OllamaError("Ollama response envelope missing a string 'response' field")
    return text


def _finding_facts(finding: Finding) -> dict[str, object]:
    """The compact, structured facts view of a finding the model sees --
    the same data the template already reads, not raw entity internals."""
    entity = finding.entity
    signals = entity.priority.signals if entity.priority else ()
    signal_phrases = [SIGNAL_PHRASES[s] for s in signals if s in SIGNAL_PHRASES]
    return {
        "entity_id": entity.id,
        "type": entity.type,
        "display_value": finding.display_value,
        "attributes": entity.attributes,
        "seen_by": finding.seen_by,
        "signals": signal_phrases,
    }


def build_prompt(findings: tuple[Finding, ...]) -> str:
    facts = [_finding_facts(f) for f in findings]
    return _SYSTEM_PREAMBLE + "\n\nFindings:\n" + json.dumps(facts, indent=2)


def _extract_items(parsed: object) -> list[object]:
    """Ollama's `format: json` mode constrains the grammar to a top-level
    JSON *object* -- confirmed empirically across all locally-pulled
    models, which return the requested findings array under a variety of
    real shapes rather than ever emitting a bare top-level array (some
    wrap it under "findings" as asked, one wrapped it under an unrelated
    single key, two returned a single bare finding object instead of an
    array at all). This tries each real shape seen in practice, most
    specific first, rather than assuming any one of them.
    """
    if isinstance(parsed, list):
        return parsed
    if not isinstance(parsed, dict):
        return []
    if "entity_id" in parsed:
        # A single bare finding object, not an array (seen from
        # llama3.1:8b and phi3:latest: the model only narrated the first
        # finding and skipped the "array of N" instruction entirely).
        return [parsed]
    findings = parsed.get("findings")
    if isinstance(findings, list):
        return findings
    # Any other single-key-object wrapping (seen from llama3.2:latest,
    # which wrapped the whole array under an unrelated synthetic key).
    for value in parsed.values():
        if isinstance(value, list):
            return value
    return []


def _parse_response(raw_text: str, expected_ids: set[str]) -> tuple[dict[str, dict[str, str]], int]:
    """Parse and validate the model's JSON response.

    Returns (entity_id -> {body, why_ranked}, count of invented ids the
    model tried to narrate that don't exist in this brief -- dropped, never
    surfaced, but counted as a real if partial faithfulness signal).
    Malformed individual items are skipped, never fatal for the whole
    response (ADR-0002 D5's discipline, applied here).
    """
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        return {}, 0
    items = _extract_items(parsed)

    result: dict[str, dict[str, str]] = {}
    invented = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        entity_id = item.get("entity_id")
        if not isinstance(entity_id, str):
            continue
        if entity_id not in expected_ids:
            invented += 1
            continue

        body = item.get("body")
        why_ranked = item.get("why_ranked")
        entry: dict[str, str] = {}
        if isinstance(body, str) and body.strip():
            entry["body"] = body.strip()
        if isinstance(why_ranked, str) and why_ranked.strip():
            entry["why_ranked"] = why_ranked.strip()
        if "body" in entry and "why_ranked" in entry:
            result[entity_id] = entry

    return result, invented


@dataclass(frozen=True, slots=True)
class SynthesisResult:
    brief: Brief
    narrated_count: int
    fell_back_count: int
    invented_ids_dropped: int


def synthesize_brief(
    brief: Brief,
    entities: list[Entity],
    *,
    model: str = DEFAULT_MODEL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    urlopen: Callable[..., object] = urllib.request.urlopen,
) -> SynthesisResult:
    """Replace `top_priorities`' body/why_ranked with real LLM narration.

    Each finding's (body, why_ranked) pair is atomic -- a finding is either
    fully narrated by the model or fully template, never a mix of the two,
    to keep behaviour easy to reason about. Falls back to the entirely
    unmodified template brief if the call itself fails, the response isn't
    parseable, or (should be structurally impossible per D1) the narrated
    result somehow fails `check_brief_contract`.
    """
    if not brief.top_priorities:
        return SynthesisResult(
            brief=brief, narrated_count=0, fell_back_count=0, invented_ids_dropped=0
        )

    expected_ids = {f.entity.id for f in brief.top_priorities}
    prompt = build_prompt(brief.top_priorities)

    try:
        raw_text = call_ollama(prompt, model=model, timeout=timeout, urlopen=urlopen)
    except OllamaError:
        return SynthesisResult(
            brief=brief,
            narrated_count=0,
            fell_back_count=len(brief.top_priorities),
            invented_ids_dropped=0,
        )

    narration, invented = _parse_response(raw_text, expected_ids)

    narrated_count = 0
    fell_back_count = 0
    new_top: list[Finding] = []
    for finding in brief.top_priorities:
        entry = narration.get(finding.entity.id)
        if entry:
            new_top.append(replace(finding, body=entry["body"], why_ranked=entry["why_ranked"]))
            narrated_count += 1
        else:
            new_top.append(finding)
            fell_back_count += 1

    new_brief = replace(brief, top_priorities=tuple(new_top))
    if check_brief_contract(new_brief, entities):
        return SynthesisResult(
            brief=brief,
            narrated_count=0,
            fell_back_count=len(brief.top_priorities),
            invented_ids_dropped=invented,
        )

    return SynthesisResult(
        brief=new_brief,
        narrated_count=narrated_count,
        fell_back_count=fell_back_count,
        invented_ids_dropped=invented,
    )
