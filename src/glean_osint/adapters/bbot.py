"""Adapter for BBOT's newline-delimited JSON output (ADR-0002, Q3 resolved).

BBOT is the first *firehose* tool in the set: one NDJSON event per line,
every event type it knows, from every module that ran. That is a different
shape from the four subdomain/DNS tools already wired, and it is what
ADR-0002 open question 3 was deferred until — see D-STREAM below.

**Schema captured from BBOT 3.0.1's own serializer**, not from
documentation: `bbot.core.event.base.Event.json()`. Two details in it are
not guessable and are the reason the fixture was machine-generated rather
than hand-written.

*Data lives under two different keys.* A string-valued event serializes as
`{"data": "api.example.com"}`; a dict-valued one as
`{"data_json": {...}}` — `json()` branches on the Python type. `URL` and
`TECHNOLOGY` take the second path, everything else here takes the first.
Reading only `data` silently drops both.

*`module` names the module that found it* (`crt`, `hackertarget`,
`portscan`), which is BBOT's own internal source, not a separate tool.
Recorded as an entity attribute exactly as `SubfinderAdapter` records
`subfinder_source`, and for the same reason: `source_tool` stays uniformly
`"bbot"`, because the *tool* is the source, not its own sub-sources.

**D-STREAM (ADR-0002 Q3): parse line by line, never whole-file.** `parse`
takes `bytes` per the contract, but iterates the buffer a line at a time
and never holds a decoded structure for more than one event. A firehose
run against a large target produces output no single JSON document should
be materialised from, and the same discipline is what lets the parser stay
pure and offline-testable. The contract's `raw: bytes` signature is
unchanged, so this is an implementation choice inside one adapter rather
than a change every other adapter has to follow.

**Unrecognised event types are not `skipped`.** BBOT emits dozens of types
(`FINDING`, `VULNERABILITY`, `WAF`, `STORAGE_BUCKET`, ...) that Glean's
schema has no home for. Those are *ignored*, not counted: `skipped` means
"this record was malformed", and inflating it with "this record was fine
but irrelevant" would make a real parse failure invisible in the noise.
ADR-0002 D5 counts damage, not disinterest.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from glean_osint.adapters.base import Adapter, ParseResult, ScanContext
from glean_osint.normalise import canon_host
from glean_osint.schema.entities import Edge, Entity, EntityType, Method, ProvenanceEntry, entity_id

# Event types this adapter maps. Anything else is ignored by design.
_HANDLED = frozenset({"DNS_NAME", "IP_ADDRESS", "OPEN_TCP_PORT", "EMAIL_ADDRESS", "TECHNOLOGY"})


class BbotAdapter:
    tool_id = "bbot"
    # BBOT spans both methods, so the adapter cannot honestly claim one for
    # every run. Passive is the *default* here because the runner invokes
    # it with `-rf passive` (ADR-0008), which restricts BBOT to modules
    # flagged passive by BBOT itself. Ingesting a capture made some other
    # way is the operator's call, and the brief records the method it was
    # told, so a mislabelled ingest is a mislabelled input, not a silent
    # downgrade.
    default_method: Method = "passive"

    def build_command(self, target: str, options: object | None = None) -> list[str] | None:
        """Passive modules only, NDJSON to stdout-adjacent output.

        `-rf passive` is not a preference: without it BBOT will happily
        port-scan and brute-force, which the charter requires be a separate
        explicit opt-in rather than a default anybody inherits.
        """
        return [
            "bbot",
            "-t",
            target,
            "-p",
            "subdomain-enum",
            "-rf",
            "passive",
            "-om",
            "json",
            "-y",
            "--no-color",
        ]

    def parse(self, raw: bytes, ctx: ScanContext) -> ParseResult:
        target = canon_host(ctx.target)
        result = ParseResult()
        for index, event in self._events(raw, result):
            self._handle(event, index, target, ctx, result)
        return result

    def _events(self, raw: bytes, result: ParseResult) -> Iterator[tuple[int, dict[str, Any]]]:
        """Yield one parsed event per line (D-STREAM).

        A malformed line is counted and skipped, never fatal for the rest
        of the stream — with a firehose, one bad line in ten thousand
        should cost one event, not the run.
        """
        for index, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                result.skipped += 1
                continue
            if not isinstance(event, dict):
                result.skipped += 1
                continue
            yield index, event

    def _handle(
        self,
        event: dict[str, Any],
        index: int,
        target: str,
        ctx: ScanContext,
        result: ParseResult,
    ) -> None:
        event_type = event.get("type")
        if not isinstance(event_type, str) or event_type not in _HANDLED:
            return  # ignored by design, not skipped -- see module docstring

        prov = ProvenanceEntry(
            source_tool=self.tool_id,
            method=self.default_method,
            collected_at=ctx.collected_at,
            raw_record_ref=f"line:{index}",
        )
        module = event.get("module")
        attributes: dict[str, Any] = (
            {"bbot_module": module} if isinstance(module, str) and module else {}
        )

        if event_type == "DNS_NAME":
            self._add_host(event, target, prov, attributes, result)
        elif event_type == "IP_ADDRESS":
            self._add_ip(event, prov, attributes, result)
        elif event_type == "OPEN_TCP_PORT":
            self._add_service(event, prov, attributes, result)
        elif event_type == "EMAIL_ADDRESS":
            self._add_email(event, prov, attributes, result)
        elif event_type == "TECHNOLOGY":
            self._add_technology(event, prov, attributes, result)

    def _add_host(
        self,
        event: dict[str, Any],
        target: str,
        prov: ProvenanceEntry,
        attributes: dict[str, Any],
        result: ParseResult,
    ) -> None:
        raw_name = event.get("data")
        if not isinstance(raw_name, str) or not raw_name.strip():
            result.skipped += 1
            return
        name = canon_host(raw_name)
        entity_type: EntityType = "domain" if name == target else "subdomain"
        host_id = entity_id(entity_type, name)
        result.entities.append(
            Entity(
                id=host_id,
                type=entity_type,
                value=name,
                attributes=dict(attributes),
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
        # `resolved_hosts` is a positive DNS observation carried on the
        # event itself, so the resolves_to edge comes free -- no second
        # lookup, and no inference beyond what BBOT recorded.
        for address in event.get("resolved_hosts") or []:
            if isinstance(address, str) and address.strip():
                result.edges.append(
                    Edge(
                        source_id=host_id,
                        target_id=entity_id("ip_address", address.strip()),
                        relation="resolves_to",
                        provenance=(prov,),
                    )
                )

    def _add_ip(
        self,
        event: dict[str, Any],
        prov: ProvenanceEntry,
        attributes: dict[str, Any],
        result: ParseResult,
    ) -> None:
        value = event.get("data")
        if not isinstance(value, str) or not value.strip():
            result.skipped += 1
            return
        result.entities.append(
            Entity(
                id=entity_id("ip_address", value.strip()),
                type="ip_address",
                value=value.strip(),
                attributes=dict(attributes),
                provenance=(prov,),
            )
        )

    def _add_service(
        self,
        event: dict[str, Any],
        prov: ProvenanceEntry,
        attributes: dict[str, Any],
        result: ParseResult,
    ) -> None:
        """`OPEN_TCP_PORT` -> a `service` entity, keyed like httpx's."""
        host = event.get("host")
        port = event.get("port")
        if not isinstance(host, str) or not host.strip() or not isinstance(port, int):
            result.skipped += 1
            return
        host_value = canon_host(host)
        service_value = f"{host_value}:{port}"
        service_id = entity_id("service", service_value)
        service_attributes = {**attributes, "port": port, "protocol": "tcp"}
        result.entities.append(
            Entity(
                id=service_id,
                type="service",
                value=service_value,
                attributes=service_attributes,
                provenance=(prov,),
            )
        )
        result.edges.append(
            Edge(
                source_id=self._host_id(host_value),
                target_id=service_id,
                relation="exposes_service",
                provenance=(prov,),
            )
        )

    def _add_email(
        self,
        event: dict[str, Any],
        prov: ProvenanceEntry,
        attributes: dict[str, Any],
        result: ParseResult,
    ) -> None:
        value = event.get("data")
        if not isinstance(value, str) or "@" not in value:
            result.skipped += 1
            return
        address = value.strip().lower()
        result.entities.append(
            Entity(
                id=entity_id("email_address", address),
                type="email_address",
                value=address,
                attributes=dict(attributes),
                provenance=(prov,),
            )
        )

    def _add_technology(
        self,
        event: dict[str, Any],
        prov: ProvenanceEntry,
        attributes: dict[str, Any],
        result: ParseResult,
    ) -> None:
        """`TECHNOLOGY` carries its payload under `data_json`, not `data`."""
        payload = event.get("data_json")
        if not isinstance(payload, dict):
            result.skipped += 1
            return
        name = payload.get("technology")
        host = payload.get("host")
        if not isinstance(name, str) or not name.strip():
            result.skipped += 1
            return
        tech_value = name.strip()
        tech_id = entity_id("web_tech", tech_value)
        result.entities.append(
            Entity(
                id=tech_id,
                type="web_tech",
                value=tech_value,
                attributes=dict(attributes),
                provenance=(prov,),
            )
        )
        if isinstance(host, str) and host.strip():
            result.edges.append(
                Edge(
                    source_id=self._host_id(canon_host(host)),
                    target_id=tech_id,
                    relation="runs_tech",
                    provenance=(prov,),
                )
            )

    @staticmethod
    def _host_id(host_value: str) -> str:
        """An edge source id for a host that may be a name or an address.

        BBOT's `host` is whichever the event was about. Guessing wrong
        would produce an edge pointing at an entity nothing else creates,
        which dedup cannot repair (ADR-0003) -- the id convention is the
        join key, so it has to match what the other adapters would emit.
        """
        looks_like_ipv4 = host_value.count(".") == 3 and all(
            part.isdigit() for part in host_value.split(".")
        )
        return entity_id("ip_address" if looks_like_ipv4 else "subdomain", host_value)


# mypy proves BbotAdapter structurally satisfies the Adapter protocol.
_conforms: Adapter = BbotAdapter()
