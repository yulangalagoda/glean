"""Adapter for dnsx's JSON output (ADR-0002), feeding ADR-0004's
`stale_no_dns` liveness signal.

dnsx, like most DNS resolvers, only emits a line for a hostname that
actually resolved — a dead hostname simply doesn't appear in its output
at all. That's a real problem for Glean: ADR-0004 D2 requires
`stale_no_dns` to fire only on *positive confirmation* of non-resolution,
never merely because a hostname wasn't seen. Output alone can't tell
"never checked" apart from "checked, dead."

So this adapter's raw input isn't dnsx's bare stdout — it's the paired
(candidates asked, hosts that resolved) shape this project's own capture
convention already produces (`_private/scripts/run_dnsx_liveness.sh`):

    {"candidates": ["host1", "host2", ...], "resolved": [<dnsx -json line>, ...]}

A candidate absent from `resolved` is positive confirmation of
non-resolution — the only case where `dns_resolved: false` is set.

Per ADR-0001 D4, a literal DNS lookup of a wildcard pattern (`*.example.com`)
is never meaningful (some resolvers even answer it), so wildcard-prefixed
candidates are excluded from processing entirely here, not asserted true
or false.
"""

from __future__ import annotations

import json
from typing import Any

from glean_osint.adapters.base import Adapter, ParseResult, ScanContext
from glean_osint.normalise import canon_host
from glean_osint.schema.entities import Edge, Entity, EntityType, Method, ProvenanceEntry, entity_id


class DnsxAdapter:
    tool_id = "dnsx"
    default_method: Method = "passive"

    def build_command(self, target: str, options: object | None = None) -> list[str] | None:
        """dnsx needs a candidate host list assembled from other tools'
        output before it can run — not a simple `dnsx -d target` — so
        invocation is deferred to the runner (ADR-0002 open question 2,
        not yet designed)."""
        return None

    def parse(self, raw: bytes, ctx: ScanContext) -> ParseResult:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return ParseResult(skipped=0)
        if not isinstance(data, dict):
            return ParseResult(skipped=0)

        candidates = data.get("candidates")
        resolved_rows = data.get("resolved")
        if not isinstance(candidates, list) or not isinstance(resolved_rows, list):
            return ParseResult(skipped=0)

        target = canon_host(ctx.target)
        result = ParseResult()
        resolved_by_host: dict[str, dict[str, Any]] = {}
        for row in resolved_rows:
            if isinstance(row, dict) and isinstance(row.get("host"), str):
                resolved_by_host[canon_host(row["host"])] = row
            else:
                result.skipped += 1

        for index, raw_name in enumerate(candidates):
            if not isinstance(raw_name, str) or not raw_name.strip():
                result.skipped += 1
                continue
            name = canon_host(raw_name)
            if name.startswith("*."):
                continue  # never meaningful to resolve literally (ADR-0001 D4)

            row = resolved_by_host.get(name)
            entity_type: EntityType = "domain" if name == target else "subdomain"
            host_id = entity_id(entity_type, name)
            prov = ProvenanceEntry(
                source_tool=self.tool_id,
                method=self.default_method,
                collected_at=ctx.collected_at,
                raw_record_ref=f"$.candidates[{index}]",
            )
            attributes: dict[str, Any] = {"dns_resolved": row is not None}
            result.entities.append(
                Entity(
                    id=host_id,
                    type=entity_type,
                    value=name,
                    attributes=attributes,
                    provenance=(prov,),
                )
            )

            if row is not None:
                self._add_resolved_ips(result, host_id, row, ctx)

        return result

    def _add_resolved_ips(
        self, result: ParseResult, host_id: str, row: dict[str, Any], ctx: ScanContext
    ) -> None:
        a_records = row.get("a")
        if not isinstance(a_records, list):
            return
        for ip in a_records:
            if not isinstance(ip, str) or not ip.strip():
                result.skipped += 1
                continue
            ip_id = entity_id("ip_address", ip.strip())
            ip_prov = ProvenanceEntry(
                source_tool=self.tool_id,
                method=self.default_method,
                collected_at=ctx.collected_at,
                raw_record_ref=f"$.resolved[host={row.get('host')}].a",
            )
            result.entities.append(
                Entity(id=ip_id, type="ip_address", value=ip.strip(), provenance=(ip_prov,))
            )
            result.edges.append(Edge(source_id=host_id, target_id=ip_id, relation="resolves_to"))


# mypy proves DnsxAdapter structurally satisfies the Adapter protocol.
_conforms: Adapter = DnsxAdapter()
