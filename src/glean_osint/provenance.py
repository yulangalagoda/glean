"""Resolving a `raw_record_ref` back to the exact record that asserted it.

`ProvenanceEntry.raw_record_ref` (ADR-0001 D6) has been populated by every
adapter since the beginning, but nothing ever read it: the web view served
a tool's *whole* archived capture, leaving the operator to find the one
line that justified a finding. For a project whose central claim is that
every finding is traceable to a named source, "here is the 900-line file
it came from somewhere inside" is a weaker answer than it looks.

Deliberately not a JSONPath implementation, and deliberately not a
dependency. The refs the adapters emit form a small closed grammar of
exactly five shapes, all of them written by this project:

    line:7                       JSON-lines, 1-BASED physical line
    $[3]                         root array element              (0-based)
    $[3].name_value              a field of one                  (0-based)
    $.hosts[2]                   an array under a root key       (0-based)
    $.resolved[host=x.com].a     the element whose `host` is x.com

A real JSONPath engine would accept a far larger language than anything
here can produce, so it would trade a dependency for the ability to
resolve refs that cannot exist.

**The index bases genuinely differ between the two families, and that is
load-bearing rather than an oversight to tidy up.** JSON-lines adapters
count physical lines from 1 (what an editor shows, and blank lines count);
document adapters index arrays from 0 (what JSONPath means). Normalising
them would be a one-line change that silently invalidated the refs already
persisted in every archived scan's `entities.json`, making old scans point
one record off -- which is worse than not resolving them at all, because
it looks like it worked.

Unresolvable refs return `None` rather than raising: the caller falls back
to showing the whole capture, which is exactly the behaviour that existed
before. A provenance link that cannot pinpoint a record must still lead
somewhere useful.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

# JSON-lines: `line:7`. 1-based, counting physical lines (see module docstring).
_LINE_RE = re.compile(r"^line:(\d+)$")
# Root array: `$[3]` or `$[3].name_value`.
_ROOT_INDEX_RE = re.compile(r"^\$\[(\d+)\](?:\.([A-Za-z_][A-Za-z0-9_]*))?$")
# Array under a root key: `$.hosts[2]` or `$.candidates[0].foo`.
_KEY_INDEX_RE = re.compile(
    r"^\$\.([A-Za-z_][A-Za-z0-9_]*)\[(\d+)\](?:\.([A-Za-z_][A-Za-z0-9_]*))?$"
)
# Predicate lookup: `$.resolved[host=admin.example.com].a`. dnsx emits this
# because a resolved row is identified by its host, not by its position.
_KEY_PREDICATE_RE = re.compile(
    r"^\$\.([A-Za-z_][A-Za-z0-9_]*)\[([A-Za-z_][A-Za-z0-9_]*)=(.*)\](?:\.([A-Za-z_][A-Za-z0-9_]*))?$"
)


@dataclass(frozen=True, slots=True)
class ResolvedRecord:
    """One record extracted from an archived capture."""

    ref: str
    content: str
    # Set only for JSON-lines refs, so a caller can say "line 7 of ..."
    # rather than inventing a position for a document-shaped ref.
    line_number: int | None = None


def _dump(value: Any) -> str:
    """Pretty-print a resolved fragment. A bare string resolves to itself
    rather than a quoted JSON string -- `$.hosts[2]` pointing at
    `"admin.example.com"` should read as that hostname, not `"admin..."`.
    """
    if isinstance(value, str):
        return value
    return json.dumps(value, indent=2, ensure_ascii=False)


def _field(value: Any, field: str | None) -> Any | None:
    if field is None:
        return value
    if isinstance(value, dict) and field in value:
        return value[field]
    return None


def _at_index(container: Any, index: int) -> Any | None:
    if isinstance(container, list) and 0 <= index < len(container):
        return container[index]
    return None


def resolve_record(raw: bytes, ref: str) -> ResolvedRecord | None:
    """Extract the record `ref` points at from an archived capture.

    `None` for anything unresolvable -- an unknown ref shape, an index past
    the end, a capture that no longer parses, a field that is not there.
    Every one of those is a real possibility (a capture can be truncated, a
    ref can come from an older adapter), and none of them justifies failing
    a page the operator opened to build trust.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None

    line_match = _LINE_RE.match(ref)
    if line_match:
        lines = text.splitlines()
        number = int(line_match.group(1))
        if not 1 <= number <= len(lines):
            return None
        line = lines[number - 1]
        try:
            content = json.dumps(json.loads(line), indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, ValueError):
            # A ref can legitimately point at a line that does not parse:
            # the adapters count every physical line, including the blank
            # and malformed ones they skip. Showing it verbatim is the
            # honest answer, and is itself informative.
            content = line
        return ResolvedRecord(ref=ref, content=content, line_number=number)

    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None

    root_match = _ROOT_INDEX_RE.match(ref)
    if root_match:
        value = _field(_at_index(document, int(root_match.group(1))), root_match.group(2))
        return None if value is None else ResolvedRecord(ref=ref, content=_dump(value))

    key_match = _KEY_INDEX_RE.match(ref)
    if key_match:
        key, index, field = key_match.group(1), int(key_match.group(2)), key_match.group(3)
        if not isinstance(document, dict):
            return None
        value = _field(_at_index(document.get(key), index), field)
        return None if value is None else ResolvedRecord(ref=ref, content=_dump(value))

    predicate_match = _KEY_PREDICATE_RE.match(ref)
    if predicate_match:
        key, attr, wanted, field = predicate_match.groups()
        if not isinstance(document, dict):
            return None
        rows = document.get(key)
        if not isinstance(rows, list):
            return None
        for row in rows:
            if isinstance(row, dict) and str(row.get(attr)) == wanted:
                # The matched row is shown whole, even though the ref may
                # narrow to a single field (`.a`). Finding the row *is* the
                # provenance answer, and the surrounding record is the
                # context that makes the field mean anything -- an IP is
                # worth little without the host and status code beside it.
                # It also keeps this resolvable when the narrowed field is
                # absent, where returning nothing would drop the operator
                # back to the whole file despite the record being found.
                return ResolvedRecord(ref=ref, content=_dump(row))
        return None

    return None
