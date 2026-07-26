"""Adapter for crt.sh's certificate-transparency JSON endpoint (ADR-0002).

crt.sh's JSON API returns no fingerprint field (confirmed against 604 real
rows during the pilot, docs/PILOT_findings.md) — serial + issuer is the
only available certificate identity, not a fallback (ADR-0001 D3).
"""

from __future__ import annotations

import json

from glean_osint.adapters.base import Adapter, ParseResult, ScanContext
from glean_osint.normalise import canon_host
from glean_osint.schema.entities import Edge, Entity, EntityType, Method, ProvenanceEntry, entity_id

_REQUIRED_FIELDS = ("name_value", "serial_number", "issuer_name")


class CrtshAdapter:
    tool_id = "crtsh"
    default_method: Method = "passive"

    def build_command(self, target: str, options: object | None = None) -> list[str] | None:
        """crt.sh is queried over its HTTP JSON endpoint — ingest-only, nothing
        to invoke locally (ADR-0002 D1)."""
        return None

    def parse(self, raw: bytes, ctx: ScanContext) -> ParseResult:
        try:
            rows = json.loads(raw)
        except json.JSONDecodeError:
            return ParseResult(skipped=0)

        target = canon_host(ctx.target)
        result = ParseResult()

        for index, row in enumerate(rows):
            if not isinstance(row, dict) or any(not row.get(f) for f in _REQUIRED_FIELDS):
                result.skipped += 1
                continue

            names = sorted({canon_host(n) for n in row["name_value"].split("\n") if n.strip()})
            if not names:
                result.skipped += 1
                continue

            serial = row["serial_number"].strip().lower()
            issuer = row["issuer_name"].strip().lower()
            cert_value = f"{serial}|{issuer}"
            cert_id = entity_id("certificate", cert_value)
            cert_prov = ProvenanceEntry(
                source_tool=self.tool_id,
                method=self.default_method,
                collected_at=ctx.collected_at,
                raw_record_ref=f"$[{index}]",
            )
            result.entities.append(
                Entity(
                    id=cert_id,
                    type="certificate",
                    value=cert_value,
                    attributes={
                        "issuer": row.get("issuer_name"),
                        "subject": row.get("common_name"),
                        "not_before": row.get("not_before"),
                        "not_after": row.get("not_after"),
                        "san": names,
                    },
                    provenance=(cert_prov,),
                )
            )

            for name in names:
                entity_type: EntityType = "domain" if name == target else "subdomain"
                host_id = entity_id(entity_type, name)
                host_prov = ProvenanceEntry(
                    source_tool=self.tool_id,
                    method=self.default_method,
                    collected_at=ctx.collected_at,
                    raw_record_ref=f"$[{index}].name_value",
                )
                result.entities.append(
                    Entity(
                        id=host_id,
                        type=entity_type,
                        value=name,
                        attributes={"wildcard": True} if name.startswith("*.") else {},
                        provenance=(host_prov,),
                    )
                )
                result.edges.append(
                    Edge(source_id=cert_id, target_id=host_id, relation="issued_for")
                )
                if entity_type == "subdomain":
                    result.edges.append(
                        Edge(
                            source_id=host_id,
                            target_id=entity_id("domain", target),
                            relation="subdomain_of",
                        )
                    )

        return result


# mypy proves CrtshAdapter structurally satisfies the Adapter protocol (ADR-0002 D2).
_conforms: Adapter = CrtshAdapter()
