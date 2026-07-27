"""Tests for the tool registry (ADR-0011 D3/D4)."""

from __future__ import annotations

from glean_osint.registry import PRESETS, TOOL_REGISTRY, normalise_selection


def test_normalise_selection_auto_includes_dnsx_when_httpx_selected() -> None:
    """httpx is fed dnsx's confirmed resolutions -- it can't run alone
    (ADR-0008 D1/D9, ADR-0011 D4)."""
    assert normalise_selection(frozenset({"httpx"})) == frozenset({"httpx", "dnsx"})


def test_normalise_selection_leaves_a_dependency_free_subset_unchanged() -> None:
    assert normalise_selection(frozenset({"crtsh", "theharvester"})) == frozenset(
        {"crtsh", "theharvester"}
    )


def test_normalise_selection_dnsx_alone_is_valid() -> None:
    assert normalise_selection(frozenset({"dnsx"})) == frozenset({"dnsx"})


def test_normalise_selection_drops_unknown_tool_ids() -> None:
    """A stale/removed tool id degrades to 'not selected', never a crash
    (ADR-0002 D5's discipline applied here)."""
    assert normalise_selection(frozenset({"crtsh", "nmap"})) == frozenset({"crtsh"})


def test_normalise_selection_empty_stays_empty() -> None:
    assert normalise_selection(frozenset()) == frozenset()


def test_every_preset_references_only_real_tool_ids() -> None:
    for name, tool_ids in PRESETS.items():
        for tool_id in tool_ids:
            assert tool_id in TOOL_REGISTRY, f"preset {name!r} references unknown tool {tool_id!r}"


def test_every_preset_is_already_a_valid_normalised_selection() -> None:
    """A preset shouldn't need normalise_selection to fix it up -- if
    "Full scan" includes httpx, it must already include dnsx too."""
    for name, tool_ids in PRESETS.items():
        selection = frozenset(tool_ids)
        assert normalise_selection(selection) == selection, (
            f"preset {name!r} is not self-consistent"
        )
