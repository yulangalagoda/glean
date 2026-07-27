"""Adapter for theHarvester's JSON export (ADR-0002).

Run with multiple `-b` sources, theHarvester returns a single flat,
already-merged list — there is no way to tell which underlying source
found a given record (pilot correction, docs/PILOT_findings.md / ADR-0002
D3). This adapter degrades honestly: `source_module` becomes a
combined-sources label parsed from the invocation's own `-b` argument
(recorded in the export's `cmd` field), and `raw_record_ref` points at the
coarsest locator theHarvester actually gives — an array position in the
exported JSON.

Scoped to `hosts` and `emails` only: every real run captured for this
project (`eval/scans/*/raw/theharvester-*.json`) only ever populates
`cmd`, `hosts`, and an empty `shodan`. Other theHarvester output fields
(e.g. `ips`, `host:ip` pairs from source modules not used here) are not
handled because there is no real fixture evidencing their shape yet —
add them when a real run does, per this project's own pilot-first
methodology.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from glean_osint.adapters.base import Adapter, ParseResult, ScanContext
from glean_osint.normalise import canon_email, canon_host
from glean_osint.schema.entities import Edge, Entity, EntityType, Method, ProvenanceEntry, entity_id


@dataclass(frozen=True, slots=True)
class TheHarvesterOptions:
    """theHarvester only emits parseable JSON when run with `-f <prefix>`
    (ADR-0008 D2) — without it, `build_command`'s own output wouldn't
    produce anything this adapter's `parse` could read."""

    output_prefix: str


class TheHarvesterAdapter:
    tool_id = "theharvester"
    default_method: Method = "passive"

    def build_command(self, target: str, options: object | None = None) -> list[str] | None:
        argv = ["theHarvester", "-d", target, "-b", "crtsh,duckduckgo,otx,certspotter"]
        if isinstance(options, TheHarvesterOptions):
            argv += ["-f", options.output_prefix]
        return argv

    def parse(self, raw: bytes, ctx: ScanContext) -> ParseResult:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return ParseResult(skipped=0)
        if not isinstance(data, dict):
            return ParseResult(skipped=0)

        target = canon_host(ctx.target)
        source_module = self._source_module(data.get("cmd", ""))
        result = ParseResult()

        for index, raw_host in enumerate(data.get("hosts") or []):
            self._parse_host(result, raw_host, index, target, source_module, ctx)

        for index, raw_email in enumerate(data.get("emails") or []):
            self._parse_email(result, raw_email, index, source_module, ctx)

        return result

    @staticmethod
    def _source_module(cmd: str) -> str:
        tokens = cmd.split()
        for i, tok in enumerate(tokens):
            if tok == "-b" and i + 1 < len(tokens):
                return f"combined:{tokens[i + 1]}"
        return "combined:unknown"

    def _parse_host(
        self,
        result: ParseResult,
        raw_host: object,
        index: int,
        target: str,
        source_module: str,
        ctx: ScanContext,
    ) -> None:
        if not isinstance(raw_host, str) or not raw_host.strip():
            result.skipped += 1
            return

        name = canon_host(raw_host)
        entity_type: EntityType = "domain" if name == target else "subdomain"
        host_id = entity_id(entity_type, name)
        prov = ProvenanceEntry(
            source_tool=self.tool_id,
            source_module=source_module,
            method=self.default_method,
            collected_at=ctx.collected_at,
            raw_record_ref=f"$.hosts[{index}]",
        )
        result.entities.append(
            Entity(
                id=host_id,
                type=entity_type,
                value=name,
                attributes={"wildcard": True} if name.startswith("*.") else {},
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

    def _parse_email(
        self,
        result: ParseResult,
        raw_email: object,
        index: int,
        source_module: str,
        ctx: ScanContext,
    ) -> None:
        if not isinstance(raw_email, str) or "@" not in raw_email:
            result.skipped += 1
            return

        value = canon_email(raw_email)
        prov = ProvenanceEntry(
            source_tool=self.tool_id,
            source_module=source_module,
            method=self.default_method,
            collected_at=ctx.collected_at,
            raw_record_ref=f"$.emails[{index}]",
        )
        result.entities.append(
            Entity(
                id=entity_id("email_address", value),
                type="email_address",
                value=value,
                provenance=(prov,),
            )
        )


# mypy proves TheHarvesterAdapter structurally satisfies the Adapter protocol.
_conforms: Adapter = TheHarvesterAdapter()
