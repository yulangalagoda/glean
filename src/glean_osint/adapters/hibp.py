"""Adapter for Have I Been Pwned's breach data (ADR-0002, ADR-0001 Q3).

The first source for `breach_exposure`, an entity type declared in ADR-0001
and never produced by anything until now. `breach_hit` carries weight 3 in
the scoring rubric -- joint-highest -- and had therefore never once fired
against real data, so the highest-weighted rule in prioritisation was
entirely untested. That gap, rather than extra subdomain coverage, is why
this tool went in ahead of the others named in the roadmap.

**Two questions, deliberately kept distinct.** HIBP answers both and they
mean different things for a recon brief:

- *Was this domain itself breached?* `GET /breaches?Domain=x` -- the
  target is the site whose user data leaked. Unauthenticated and free.
- *Do emails found on this target appear in breaches?* `GET
  /breachedaccount/{email}` -- the target's people appear in someone
  else's leak. Requires a paid API key.

Both land as `breach_exposure` entities; what differs is what the
`exposed_in_breach` edge hangs off -- the domain in the first case, the
email address in the second. Keeping them separable matters because the
second is a claim about individuals and carries a much heavier disclosure
duty (`docs/ETHICS.md`), so a scan should be able to run the first without
the second.

**Ingest shape.** One JSON envelope carrying both, mirroring the
`{candidates, resolved}` convention dnsx already established rather than
inventing a second one:

    {"domain_breaches": [<breach>, ...],
     "account_breaches": {"a@example.com": [<breach>, ...], ...}}

A bare JSON array is also accepted and read as `domain_breaches`, since
that is exactly what piping the free endpoint's response to a file gives
you and requiring hand-editing before ingest would be a pointless step.
"""

from __future__ import annotations

import json
from typing import Any

from glean_osint.adapters.base import ParseResult, ScanContext
from glean_osint.normalise import canon_host
from glean_osint.schema.entities import Edge, Entity, Method, ProvenanceEntry, entity_id


def _canon_breach(name: str) -> str:
    """HIBP's `Name` is already a stable unique key ('Adobe', 'LinkedIn').
    Lowercased for the id so it follows ADR-0001 D2's convention, with the
    original kept in `breach_name` for display."""
    return name.strip().lower()


class HibpAdapter:
    tool_id = "hibp"
    # Passive: HIBP is queried about the target, never touching it. The
    # target sees no traffic from a HIBP lookup, which is the whole test
    # for the passive/active split (docs/ETHICS.md).
    default_method: Method = "passive"

    def build_command(self, target: str, options: object | None = None) -> list[str] | None:
        """Queried over HTTP, like crt.sh -- nothing to invoke locally."""
        return None

    def parse(self, raw: bytes, ctx: ScanContext) -> ParseResult:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return ParseResult()

        if isinstance(payload, list):
            payload = {"domain_breaches": payload}
        if not isinstance(payload, dict):
            return ParseResult()

        result = ParseResult()
        seen_breaches: set[str] = set()
        target = canon_host(ctx.target)

        domain_rows = payload.get("domain_breaches")
        if isinstance(domain_rows, list):
            self._add_breaches(
                domain_rows,
                subject_id=entity_id("domain", target),
                ref_prefix="$.domain_breaches",
                ctx=ctx,
                result=result,
                seen=seen_breaches,
            )

        account_rows = payload.get("account_breaches")
        if isinstance(account_rows, dict):
            for raw_email, rows in sorted(account_rows.items()):
                email = str(raw_email).strip().lower()
                if not email or not isinstance(rows, list):
                    result.skipped += 1
                    continue
                self._add_breaches(
                    rows,
                    subject_id=entity_id("email_address", email),
                    ref_prefix=f"$.account_breaches[{json.dumps(email)}]",
                    ctx=ctx,
                    result=result,
                    seen=seen_breaches,
                )

        return result

    def _add_breaches(
        self,
        rows: list[Any],
        *,
        subject_id: str,
        ref_prefix: str,
        ctx: ScanContext,
        result: ParseResult,
        seen: set[str],
    ) -> None:
        """Turn one list of HIBP breach objects into entities and edges.

        The subject entity (domain or email) is deliberately NOT created
        here. An adapter emits what its own tool observed (ADR-0002 D4),
        and HIBP does not assert that a domain or an address exists -- it
        answers a question about one it was handed. Emitting the subject
        would let a HIBP lookup invent an email address that no collection
        tool ever found. Dedup joins the edge to the real entity when
        another adapter contributes it (ADR-0003).
        """
        for index, row in enumerate(rows):
            if not isinstance(row, dict) or not str(row.get("Name") or "").strip():
                result.skipped += 1
                continue

            value = _canon_breach(str(row["Name"]))
            breach_id = entity_id("breach_exposure", value)
            provenance = ProvenanceEntry(
                source_tool=self.tool_id,
                method=self.default_method,
                collected_at=ctx.collected_at,
                raw_record_ref=f"{ref_prefix}[{index}]",
            )

            # One entity per breach even when several subjects hit the same
            # one -- the breach is a single real-world event, and dedup
            # would merge duplicates anyway (ADR-0003). The edges are what
            # differ per subject.
            if breach_id not in seen:
                seen.add(breach_id)
                result.entities.append(
                    Entity(
                        id=breach_id,
                        type="breach_exposure",
                        value=value,
                        attributes={
                            # `breach_name` specifically: the brief template
                            # has read that key since ADR-0005, so the
                            # rendering path needs no change for this tool.
                            "breach_name": str(row["Name"]).strip(),
                            "title": row.get("Title"),
                            "breach_date": row.get("BreachDate"),
                            "added_date": row.get("AddedDate"),
                            "pwn_count": row.get("PwnCount"),
                            "data_classes": sorted(
                                str(c) for c in row.get("DataClasses") or [] if str(c).strip()
                            ),
                            "is_verified": row.get("IsVerified"),
                            "is_sensitive": row.get("IsSensitive"),
                            "breached_domain": row.get("Domain") or None,
                        },
                        provenance=(provenance,),
                    )
                )

            result.edges.append(
                Edge(
                    source_id=subject_id,
                    target_id=breach_id,
                    relation="exposed_in_breach",
                    provenance=(provenance,),
                )
            )
