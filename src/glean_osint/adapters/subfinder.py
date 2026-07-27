"""Adapter for subfinder's JSON-lines output (ADR-0002).

A real capture (`-d <target> -json -silent`) shows one JSON object per
line: `{"host": "...", "input": "...", "source": "..."}`. Passive-only,
subdomain-discovery-only tool — no IP/service/cert data, the same shape
theHarvester already contributes to the graph, just via different passive
sources (subfinder's own `source` field records which internal engine
found a given host, e.g. `"crtsh"`/`"virustotal"` — real, captured field
values seen in practice for `yulan.me`, not invented). Recorded as an
entity attribute for extra traceability, not folded into provenance:
`source_tool` stays uniformly `"subfinder"` regardless of which of
subfinder's own internal engines actually found a host, matching how
`CrtshAdapter` doesn't distinguish internal CT log mirrors either — the
*tool* is the source, not its own sub-sources.
"""

from __future__ import annotations

import json

from glean_osint.adapters.base import Adapter, ParseResult, ScanContext
from glean_osint.normalise import canon_host
from glean_osint.schema.entities import Edge, Entity, EntityType, Method, ProvenanceEntry, entity_id


class SubfinderAdapter:
    tool_id = "subfinder"
    default_method: Method = "passive"

    def build_command(self, target: str, options: object | None = None) -> list[str] | None:
        return ["subfinder", "-d", target, "-json", "-silent"]

    def parse(self, raw: bytes, ctx: ScanContext) -> ParseResult:
        target = canon_host(ctx.target)
        result = ParseResult()

        for index, line in enumerate(raw.decode("utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            self._parse_line(line, index, target, ctx, result)

        return result

    def _parse_line(
        self, line: str, index: int, target: str, ctx: ScanContext, result: ParseResult
    ) -> None:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            result.skipped += 1
            return
        if not isinstance(data, dict):
            result.skipped += 1
            return

        raw_host = data.get("host")
        if not isinstance(raw_host, str) or not raw_host.strip():
            result.skipped += 1
            return

        name = canon_host(raw_host)
        entity_type: EntityType = "domain" if name == target else "subdomain"
        host_id = entity_id(entity_type, name)
        source = data.get("source")
        attributes = {"subfinder_source": source} if isinstance(source, str) and source else {}
        prov = ProvenanceEntry(
            source_tool=self.tool_id,
            method=self.default_method,
            collected_at=ctx.collected_at,
            raw_record_ref=f"line:{index}",
        )
        result.entities.append(
            Entity(
                id=host_id,
                type=entity_type,
                value=name,
                attributes=attributes,
                provenance=(prov,),
            )
        )
        if entity_type == "subdomain":
            result.edges.append(
                Edge(
                    source_id=host_id,
                    target_id=entity_id("domain", target),
                    relation="subdomain_of",
                )
            )


# mypy proves SubfinderAdapter structurally satisfies the Adapter protocol.
_conforms: Adapter = SubfinderAdapter()
