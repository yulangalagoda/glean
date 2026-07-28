"""Tests for scan history storage (ADR-0011 D6, stage 3)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from glean_osint.history import (
    ScanManifest,
    delete_scan,
    group_scans_by_target,
    list_scans,
    previous_scan_for,
    read_entities_snapshot,
    read_manifest,
    scan_id_for,
    write_entities_snapshot,
    write_manifest,
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
