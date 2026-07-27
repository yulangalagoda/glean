"""Central tool registry (ADR-0011 D3).

Metadata only -- `tool_id`/`default_method` mirror the `Adapter` protocol's
own fields (ADR-0002), and `requires` captures the one real structural
dependency in the pipeline (httpx needs dnsx's confirmed resolutions,
ADR-0008 D1/D9). This is what lets the web UI's tool list and presets stay
correct as adapters are added, without hand-editing frontend code for every
new tool. The CLI's own `scan()` command keeps its existing, already-tested,
per-tool wiring (ADR-0008 D2: "invocation differs by tool, and that's
fine") -- this registry doesn't replace that, it's the shared catalogue
both surfaces can describe tools *about*.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from glean_osint.schema.entities import Method


@dataclass(frozen=True, slots=True)
class ToolInfo:
    tool_id: str
    display_name: str
    default_method: Method
    # Other tool_ids this one cannot meaningfully run without (ADR-0011 D4).
    requires: tuple[str, ...] = field(default_factory=tuple)


TOOL_REGISTRY: dict[str, ToolInfo] = {
    "crtsh": ToolInfo("crtsh", "crt.sh", "passive"),
    "theharvester": ToolInfo("theharvester", "theHarvester", "passive"),
    "dnsx": ToolInfo("dnsx", "dnsx", "passive"),
    "httpx": ToolInfo("httpx", "httpx", "active", requires=("dnsx",)),
}

# Named shortcuts (ADR-0011 D4) -- just pre-set tool selections, not
# separate pipeline logic. Adding one is a config entry here, nothing else.
PRESETS: dict[str, tuple[str, ...]] = {
    "Passive only": ("crtsh", "theharvester", "dnsx"),
    "Full scan": ("crtsh", "theharvester", "dnsx", "httpx"),
    "Certificate check": ("crtsh",),
}


def normalise_selection(tool_ids: frozenset[str]) -> frozenset[str]:
    """Enforce the one real dependency (ADR-0011 D4): selecting httpx
    always pulls in dnsx too, rather than silently producing a selection
    that can't actually run. Unknown tool ids are dropped, not raised on
    -- a stale/removed tool id in a saved preset degrades to "not
    selected", never a crash (ADR-0002 D5's discipline applied here)."""
    selected = {t for t in tool_ids if t in TOOL_REGISTRY}
    for tool_id in list(selected):
        selected.update(TOOL_REGISTRY[tool_id].requires)
    return frozenset(selected)
