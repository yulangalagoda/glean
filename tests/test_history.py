"""Tests for scan history storage (ADR-0011 D6, stage 3)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from glean_osint.history import ScanManifest, list_scans, read_manifest, scan_id_for, write_manifest


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
