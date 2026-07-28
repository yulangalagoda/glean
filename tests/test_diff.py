"""Tests for scan-to-scan entity diffing."""

from __future__ import annotations

from glean_osint.diff import diff_entities


def _entity(entity_id: str, entity_type: str, value: str, score: float, signals: list[str]) -> dict:
    return {
        "id": entity_id,
        "type": entity_type,
        "value": value,
        "attributes": {},
        "provenance": [{"source_tool": "crtsh", "method": "passive", "collected_at": "irrelevant"}],
        "priority": {"score": score, "rank": 1, "signals": signals},
    }


def test_diff_entities_on_identical_snapshots_finds_nothing() -> None:
    entities = [_entity("subdomain:a.example.com", "subdomain", "a.example.com", 3, ["x"])]

    diff = diff_entities(entities, entities)

    assert diff.added == ()
    assert diff.removed == ()
    assert diff.changed == ()


def test_diff_entities_detects_a_new_finding() -> None:
    older = [_entity("subdomain:a.example.com", "subdomain", "a.example.com", 3, ["x"])]
    newer = older + [_entity("subdomain:b.example.com", "subdomain", "b.example.com", 4, ["y"])]

    diff = diff_entities(older, newer)

    assert [e["id"] for e in diff.added] == ["subdomain:b.example.com"]
    assert diff.removed == ()
    assert diff.changed == ()


def test_diff_entities_detects_a_removed_finding() -> None:
    older = [
        _entity("subdomain:a.example.com", "subdomain", "a.example.com", 3, ["x"]),
        _entity("subdomain:b.example.com", "subdomain", "b.example.com", 4, ["y"]),
    ]
    newer = older[:1]

    diff = diff_entities(older, newer)

    assert diff.added == ()
    assert [e["id"] for e in diff.removed] == ["subdomain:b.example.com"]
    assert diff.changed == ()


def test_diff_entities_detects_a_score_and_signal_change() -> None:
    older = [_entity("service:example.com:80", "service", "80/tcp", 2, ["exposed_service"])]
    newer = [
        _entity(
            "service:example.com:80",
            "service",
            "80/tcp",
            3,
            ["exposed_service", "active_only_finding"],
        )
    ]

    diff = diff_entities(older, newer)

    assert diff.added == ()
    assert diff.removed == ()
    assert len(diff.changed) == 1
    change = diff.changed[0]
    assert change.entity_id == "service:example.com:80"
    assert change.old_score == 2
    assert change.new_score == 3
    assert change.old_signals == ("exposed_service",)
    assert change.new_signals == ("exposed_service", "active_only_finding")


def test_diff_entities_detects_an_attribute_only_change() -> None:
    older = [_entity("subdomain:a.example.com", "subdomain", "a.example.com", 3, ["x"])]
    older[0]["attributes"] = {"dns_resolved": False}
    newer = [_entity("subdomain:a.example.com", "subdomain", "a.example.com", 3, ["x"])]
    newer[0]["attributes"] = {"dns_resolved": True}

    diff = diff_entities(older, newer)

    assert len(diff.changed) == 1
    assert diff.changed[0].old_score == diff.changed[0].new_score == 3


def test_diff_entities_ignores_provenance_and_timestamp_only_differences() -> None:
    """A fresh collected_at/first_seen/last_seen on every real scan run
    must never make an otherwise-identical entity show up as "changed"
    -- that would make every finding in every diff look changed, which
    defeats the entire point of the feature."""
    older = [_entity("subdomain:a.example.com", "subdomain", "a.example.com", 3, ["x"])]
    older[0]["first_seen"] = "2026-01-01T00:00:00Z"
    newer = [_entity("subdomain:a.example.com", "subdomain", "a.example.com", 3, ["x"])]
    newer[0]["first_seen"] = "2026-07-27T00:00:00Z"
    newer[0]["provenance"] = [
        {"source_tool": "dnsx", "method": "passive", "collected_at": "2026-07-27T00:00:00Z"}
    ]

    diff = diff_entities(older, newer)

    assert diff.added == ()
    assert diff.removed == ()
    assert diff.changed == ()


def test_diff_entities_preserves_the_newer_scans_own_order_for_additions() -> None:
    older: list[dict] = []
    newer = [
        _entity("subdomain:b.example.com", "subdomain", "b.example.com", 4, []),
        _entity("subdomain:a.example.com", "subdomain", "a.example.com", 2, []),
    ]

    diff = diff_entities(older, newer)

    assert [e["id"] for e in diff.added] == ["subdomain:b.example.com", "subdomain:a.example.com"]
