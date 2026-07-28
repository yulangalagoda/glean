"""Tests for scan history storage (ADR-0011 D6, stage 3)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from glean_osint.history import (
    ScanManifest,
    delete_scan,
    group_scans_by_target,
    list_scans,
    previous_scan_for,
    read_edges_snapshot,
    read_entities_snapshot,
    read_manifest,
    read_triage,
    scan_id_for,
    write_edges_snapshot,
    write_entities_snapshot,
    write_manifest,
    write_triage,
)


def _manifest(scan_id: str, target: str = "example.com") -> ScanManifest:
    return ScanManifest(
        scan_id=scan_id,
        target=target,
        started_at="2026-07-27T00:00:00Z",
        tools_run=("crtsh", "dnsx"),
        authorisation="Owned",
        findings_count=3,
        warnings=("crt.sh: using cached response from 5m ago.",),
    )


def test_scan_id_for_is_a_sortable_slug_plus_timestamp() -> None:
    scan_id = scan_id_for("example.com", datetime(2026, 7, 27, 12, 0, 0, tzinfo=timezone.utc))
    assert scan_id == "example-com-20260727T120000Z"


def test_write_then_read_manifest_round_trips(tmp_path: Path) -> None:
    manifest = _manifest("example-com-20260727T120000Z")
    write_manifest(tmp_path, manifest)

    assert read_manifest(tmp_path) == manifest


def test_read_manifest_returns_none_for_a_missing_file(tmp_path: Path) -> None:
    assert read_manifest(tmp_path) is None


def test_read_manifest_returns_none_for_a_corrupt_file(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text("not valid json at all")
    assert read_manifest(tmp_path) is None


def test_read_manifest_returns_none_for_a_manifest_missing_required_fields(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text('{"scan_id": "x"}')  # missing target etc.
    assert read_manifest(tmp_path) is None


def test_list_scans_on_a_missing_history_root_is_empty(tmp_path: Path) -> None:
    assert list_scans(tmp_path / "does-not-exist") == []


def test_list_scans_on_an_empty_history_root_is_empty(tmp_path: Path) -> None:
    assert list_scans(tmp_path) == []


def test_list_scans_returns_newest_first(tmp_path: Path) -> None:
    for scan_id in [
        "example-com-20260727T090000Z",
        "example-com-20260727T120000Z",
        "example-com-20260727T100000Z",
    ]:
        write_manifest(tmp_path / scan_id, _manifest(scan_id))

    scans = list_scans(tmp_path)

    assert [m.scan_id for m in scans] == [
        "example-com-20260727T120000Z",
        "example-com-20260727T100000Z",
        "example-com-20260727T090000Z",
    ]


def test_list_scans_skips_a_corrupt_entry_rather_than_crashing(tmp_path: Path) -> None:
    write_manifest(
        tmp_path / "example-com-20260727T120000Z", _manifest("example-com-20260727T120000Z")
    )
    corrupt_dir = tmp_path / "example-com-20260727T130000Z"
    corrupt_dir.mkdir()
    (corrupt_dir / "manifest.json").write_text("{not json")

    scans = list_scans(tmp_path)

    assert [m.scan_id for m in scans] == ["example-com-20260727T120000Z"]


def test_list_scans_ignores_a_scan_dir_with_no_manifest_at_all(tmp_path: Path) -> None:
    (tmp_path / "example-com-20260727T120000Z" / "raw").mkdir(parents=True)  # no manifest.json
    assert list_scans(tmp_path) == []


def test_write_then_read_entities_snapshot_round_trips(tmp_path: Path) -> None:
    entities = [{"id": "domain:example.com", "type": "domain", "value": "example.com"}]

    write_entities_snapshot(tmp_path, entities)

    assert read_entities_snapshot(tmp_path) == entities


def test_read_entities_snapshot_returns_none_for_a_missing_file(tmp_path: Path) -> None:
    assert read_entities_snapshot(tmp_path) is None


def test_read_entities_snapshot_returns_none_for_a_corrupt_file(tmp_path: Path) -> None:
    (tmp_path / "entities.json").write_text("not valid json")
    assert read_entities_snapshot(tmp_path) is None


def test_read_entities_snapshot_returns_none_for_a_non_list_payload(tmp_path: Path) -> None:
    (tmp_path / "entities.json").write_text('{"not": "a list"}')
    assert read_entities_snapshot(tmp_path) is None


def test_manifest_surface_breakdown_round_trips_as_tuples(tmp_path: Path) -> None:
    """JSON has no tuples, so the breakdown comes back as a list of lists
    unless it's put back deliberately -- otherwise every consumer sees a
    different shape than the one that was written."""
    manifest = ScanManifest(
        scan_id="example-com-20260728T090000Z",
        target="example.com",
        started_at="2026-07-28T09:00:00Z",
        tools_run=("crtsh",),
        authorisation=None,
        findings_count=3,
        surface=(("domain", 1), ("subdomain", 2)),
    )

    write_manifest(tmp_path, manifest)
    loaded = read_manifest(tmp_path)

    assert loaded is not None
    assert loaded.surface == (("domain", 1), ("subdomain", 2))
    assert loaded == manifest


def test_manifest_written_before_the_surface_field_existed_still_loads(tmp_path: Path) -> None:
    """Every scan already on disk predates this field. It must degrade to
    "no breakdown recorded", never to an unreadable manifest."""
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "scan_id": "example-com-20260727T120000Z",
                "target": "example.com",
                "started_at": "2026-07-27T12:00:00Z",
                "tools_run": ["crtsh"],
                "authorisation": None,
                "findings_count": 8,
                "warnings": [],
            }
        ),
        encoding="utf-8",
    )

    loaded = read_manifest(tmp_path)

    assert loaded is not None
    assert loaded.findings_count == 8
    assert loaded.surface == ()


def test_write_then_read_triage_round_trips(tmp_path: Path) -> None:
    triage = {"subdomain:admin.example.com": "flagged", "domain:example.com": "reviewed"}

    write_triage(tmp_path, triage)

    assert read_triage(tmp_path) == triage


def test_read_triage_of_an_untriaged_scan_is_empty_not_none(tmp_path: Path) -> None:
    """Deliberately asymmetric with the entity/edge snapshots. A missing
    triage file really does mean "nothing triaged" -- the file only ever
    exists because an operator triaged something -- so there's no
    unknown-vs-empty distinction to preserve here."""
    assert read_triage(tmp_path) == {}


def test_read_triage_drops_states_outside_the_allowlist(tmp_path: Path) -> None:
    """A hand-edited file must not be able to introduce states the UI has no
    rendering for, or filter facets nobody can clear."""
    (tmp_path / "triage.json").write_text(
        json.dumps(
            {
                "subdomain:a.example.com": "flagged",
                "subdomain:b.example.com": "definitely-not-a-state",
                "subdomain:c.example.com": 17,
            }
        ),
        encoding="utf-8",
    )

    assert read_triage(tmp_path) == {"subdomain:a.example.com": "flagged"}


def test_read_triage_degrades_on_a_corrupt_file(tmp_path: Path) -> None:
    (tmp_path / "triage.json").write_text("{not json", encoding="utf-8")
    assert read_triage(tmp_path) == {}


def test_write_triage_leaves_no_temp_file_behind(tmp_path: Path) -> None:
    """It's written atomically because, unlike everything else in a scan
    directory, it's rewritten on every triage click -- and it holds the one
    thing re-running the scan cannot regenerate."""
    write_triage(tmp_path, {"domain:example.com": "reviewed"})

    assert (tmp_path / "triage.json").is_file()
    assert list(tmp_path.glob("*.tmp")) == []


def test_write_then_read_edges_snapshot_round_trips(tmp_path: Path) -> None:
    edges = [
        {
            "source_id": "subdomain:www.example.com",
            "target_id": "ip_address:203.0.113.1",
            "relation": "resolves_to",
        }
    ]

    write_edges_snapshot(tmp_path, edges)

    assert read_edges_snapshot(tmp_path) == edges


def test_read_edges_snapshot_returns_none_for_a_scan_archived_before_edges_existed(
    tmp_path: Path,
) -> None:
    """The distinction that matters: a scan with an entity snapshot but no
    edges file has *unknown* relations, not zero relations. Callers must be
    able to tell those apart, so this returns None rather than []."""
    write_entities_snapshot(tmp_path, [{"id": "domain:example.com"}])

    assert read_entities_snapshot(tmp_path) is not None
    assert read_edges_snapshot(tmp_path) is None


def test_read_edges_snapshot_returns_none_for_a_corrupt_file(tmp_path: Path) -> None:
    (tmp_path / "edges.json").write_text("{not json")
    assert read_edges_snapshot(tmp_path) is None


def test_read_edges_snapshot_returns_none_for_a_non_list_payload(tmp_path: Path) -> None:
    (tmp_path / "edges.json").write_text('{"not": "a list"}')
    assert read_edges_snapshot(tmp_path) is None


def test_group_scans_by_target_collapses_repeat_scans(tmp_path: Path) -> None:
    scans = [
        _manifest("yulan-me-20260727T120000Z", target="yulan.me"),
        _manifest("larnby-com-20260727T110000Z", target="larnby.com"),
        _manifest("yulan-me-20260727T100000Z", target="yulan.me"),
    ]

    groups = group_scans_by_target(scans)

    assert [target for target, _ in groups] == ["yulan.me", "larnby.com"]
    yulan_group = dict(groups)["yulan.me"]
    assert [m.scan_id for m in yulan_group] == [
        "yulan-me-20260727T120000Z",
        "yulan-me-20260727T100000Z",
    ]


def test_group_scans_by_target_on_an_empty_list_is_empty() -> None:
    assert group_scans_by_target([]) == []


def test_delete_scan_removes_the_scan_directory(tmp_path: Path) -> None:
    scan_dir = tmp_path / "example-com-20260727T120000Z"
    write_manifest(scan_dir, _manifest(scan_dir.name))
    (scan_dir / "brief.html").write_text("<html></html>")

    delete_scan(scan_dir)

    assert not scan_dir.exists()


def test_delete_scan_on_an_already_missing_directory_does_not_raise(tmp_path: Path) -> None:
    delete_scan(tmp_path / "does-not-exist")


def test_previous_scan_for_returns_the_next_older_scan_of_the_same_target(
    tmp_path: Path,
) -> None:
    write_manifest(
        tmp_path / "example-com-20260727T120000Z", _manifest("example-com-20260727T120000Z")
    )
    write_manifest(
        tmp_path / "example-com-20260727T100000Z", _manifest("example-com-20260727T100000Z")
    )
    write_manifest(
        tmp_path / "example-com-20260727T080000Z", _manifest("example-com-20260727T080000Z")
    )

    previous = previous_scan_for("example-com-20260727T120000Z", tmp_path)

    assert previous is not None
    assert previous.scan_id == "example-com-20260727T100000Z"


def test_previous_scan_for_works_relative_to_an_older_scan_too(tmp_path: Path) -> None:
    write_manifest(
        tmp_path / "example-com-20260727T120000Z", _manifest("example-com-20260727T120000Z")
    )
    write_manifest(
        tmp_path / "example-com-20260727T100000Z", _manifest("example-com-20260727T100000Z")
    )
    write_manifest(
        tmp_path / "example-com-20260727T080000Z", _manifest("example-com-20260727T080000Z")
    )

    previous = previous_scan_for("example-com-20260727T100000Z", tmp_path)

    assert previous is not None
    assert previous.scan_id == "example-com-20260727T080000Z"


def test_previous_scan_for_is_none_for_the_oldest_scan_of_a_target(tmp_path: Path) -> None:
    write_manifest(
        tmp_path / "example-com-20260727T120000Z", _manifest("example-com-20260727T120000Z")
    )

    assert previous_scan_for("example-com-20260727T120000Z", tmp_path) is None


def test_previous_scan_for_ignores_other_targets(tmp_path: Path) -> None:
    write_manifest(
        tmp_path / "example-com-20260727T120000Z", _manifest("example-com-20260727T120000Z")
    )
    write_manifest(
        tmp_path / "other-com-20260727T100000Z",
        _manifest("other-com-20260727T100000Z", target="other.com"),
    )

    assert previous_scan_for("example-com-20260727T120000Z", tmp_path) is None


def test_previous_scan_for_returns_none_for_an_unknown_scan_id(tmp_path: Path) -> None:
    assert previous_scan_for("does-not-exist", tmp_path) is None
