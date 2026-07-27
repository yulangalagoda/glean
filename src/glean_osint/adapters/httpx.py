"""Adapter for ProjectDiscovery httpx's JSON-lines output (ADR-0002).

httpx is fed the concrete hostnames dnsx already confirmed resolve (this
project's `candidates -> resolved -> probed` chain), one HTTP probe per
line of `-json` output. Unlike dnsx, a failed probe doesn't just vanish
from the output — httpx's `failed` field is emitted for every line
(default `false`), so positive confirmation of "probed, nothing served
HTTP" only requires the tool to be run with `-probe` (which forces
failed attempts to be reported instead of silently dropped); a host
absent from the file entirely was never probed at all and must not be
treated as evidence either way.

httpx is this project's first *active*-method adapter: it sends real
HTTP requests directly at the target's infrastructure, unlike the first
three (crt.sh, theHarvester, dnsx), which are all passive. That's exactly
the boundary `docs/ETHICS.md` and the charter's authorisation rules are
built around — running httpx against a target requires the same explicit
active-recon authorisation as any other active tool.

`input` is expected to be a bare hostname (as this project's own
convention feeds httpx: resolved hostnames, not raw URLs) — not the
`url` field, which includes the scheme httpx chose.
"""

from __future__ import annotations

import json
from typing import Any

from glean_osint.adapters.base import Adapter, ParseResult, ScanContext
from glean_osint.normalise import canon_host
from glean_osint.schema.entities import Edge, Entity, EntityType, Method, ProvenanceEntry, entity_id


class HttpxAdapter:
    tool_id = "httpx"
    default_method: Method = "active"

    def build_command(self, target: str, options: object | None = None) -> list[str] | None:
        """httpx needs the resolved host list dnsx already produced, not a
        simple `httpx -d target` — invocation is deferred to the runner
        (ADR-0002 open question 2, not yet designed)."""
        return None

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

        raw_input = data.get("input")
        failed = data.get("failed")
        if not isinstance(raw_input, str) or not raw_input.strip() or not isinstance(failed, bool):
            result.skipped += 1
            return

        name = canon_host(raw_input)
        entity_type: EntityType = "domain" if name == target else "subdomain"
        host_id = entity_id(entity_type, name)
        ref = f"line:{index}"
        prov = ProvenanceEntry(
            source_tool=self.tool_id,
            method=self.default_method,
            collected_at=ctx.collected_at,
            raw_record_ref=ref,
        )
        result.entities.append(Entity(id=host_id, type=entity_type, value=name, provenance=(prov,)))

        if failed:
            return  # positive confirmation: probed, nothing served HTTP here

        ip_id = self._add_resolved_ip(result, host_id, data, ctx, ref)
        self._add_service(result, ip_id, data, ctx, ref)
        self._add_tech(result, host_id, data, ctx, ref)

    def _add_resolved_ip(
        self,
        result: ParseResult,
        host_id: str,
        data: dict[str, Any],
        ctx: ScanContext,
        ref: str,
    ) -> str | None:
        a_records = data.get("a")
        if not isinstance(a_records, list) or not a_records:
            return None
        ip = a_records[0]
        if not isinstance(ip, str) or not ip.strip():
            return None

        ip = ip.strip()
        ip_id = entity_id("ip_address", ip)
        prov = ProvenanceEntry(
            source_tool=self.tool_id,
            method=self.default_method,
            collected_at=ctx.collected_at,
            raw_record_ref=ref,
        )
        result.entities.append(Entity(id=ip_id, type="ip_address", value=ip, provenance=(prov,)))
        result.edges.append(Edge(source_id=host_id, target_id=ip_id, relation="resolves_to"))
        return ip_id

    def _add_service(
        self,
        result: ParseResult,
        ip_id: str | None,
        data: dict[str, Any],
        ctx: ScanContext,
        ref: str,
    ) -> None:
        if ip_id is None:
            return
        port_raw = data.get("port")
        try:
            port = int(port_raw)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return

        ip_value = ip_id.split(":", 1)[1]
        service_value = f"{ip_value}:{port}"
        service_id = entity_id("service", service_value)
        attributes: dict[str, Any] = {"port": port, "protocol": "tcp"}
        scheme = data.get("scheme")
        if isinstance(scheme, str) and scheme.strip():
            attributes["service"] = scheme.strip()
        prov = ProvenanceEntry(
            source_tool=self.tool_id,
            method=self.default_method,
            collected_at=ctx.collected_at,
            raw_record_ref=ref,
        )
        result.entities.append(
            Entity(
                id=service_id,
                type="service",
                value=service_value,
                attributes=attributes,
                provenance=(prov,),
            )
        )
        result.edges.append(Edge(source_id=ip_id, target_id=service_id, relation="exposes_service"))

    def _add_tech(
        self,
        result: ParseResult,
        host_id: str,
        data: dict[str, Any],
        ctx: ScanContext,
        ref: str,
    ) -> None:
        tech = data.get("tech")
        if not isinstance(tech, list):
            return
        for item in tech:
            if not isinstance(item, str) or not item.strip():
                result.skipped += 1
                continue
            name = item.strip()
            tech_id = entity_id("web_tech", name)
            prov = ProvenanceEntry(
                source_tool=self.tool_id,
                method=self.default_method,
                collected_at=ctx.collected_at,
                raw_record_ref=ref,
            )
            result.entities.append(
                Entity(id=tech_id, type="web_tech", value=name, provenance=(prov,))
            )
            result.edges.append(Edge(source_id=host_id, target_id=tech_id, relation="runs_tech"))


# mypy proves HttpxAdapter structurally satisfies the Adapter protocol.
_conforms: Adapter = HttpxAdapter()
