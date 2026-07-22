# ADR-0001 — Normalised Entity Schema (v1, infra/domain scope)

- **Status:** Proposed (v0 — for review, then freeze as Accepted)
- **Date:** 2026-07-22
- **Scope:** Glean v1, infrastructure / domain reconnaissance only
- **Machine-checkable schema:** [`docs/schema/entity-graph.schema.json`](../schema/entity-graph.schema.json)
- **Worked example:** [`docs/schema/example-scan.json`](../schema/example-scan.json) (validates against the schema)
- **Supersedes / feeds:** ADR-0002 (adapter contract), ADR-0003 (correlation/dedup), ADR-0004 (prioritisation), ADR-0005 (report shape) all depend on this.

## Context

Every tool Glean unions produces a different shape of output. The entire project rests on collapsing those shapes into one normalised, deduplicated, provenance-tracked model — the "entity graph" — that the deterministic correlation, the deterministic prioritisation, the LLM synthesis, and the evaluation harness all read from. This model is the keystone: if it is wrong, every adapter and the whole evaluation must be reworked. It therefore has to be frozen before any code that produces or consumes it is written.

Three requirements from the charter are binding on this schema:

1. **Provenance is a first-class field**, retained end-to-end, so every surfaced claim is traceable to its source tool. The provenance-retention metric is computed directly off this schema, so provenance cannot be an afterthought or a free-text note.
2. **Correlation/dedup is deterministic and done in code, not the LLM.** The schema must give the dedup code a stable identity to match on.
3. **Passive vs active collection is separated.** The schema must record, per assertion, how the data was obtained.

## Decision

Glean produces a single **Entity Graph** document per scan: a container of deduplicated `entities` plus directed `edges` between them, wrapped in `scan` metadata. The full structure is defined normatively in the JSON Schema; this ADR records the decisions and rules behind it.

### D1 — One record per real-world entity, with an array of provenance entries

When two tools report the same subdomain, Glean stores **one entity** carrying **two provenance entries**, not two linked records. Rationale: it makes deduplication the natural state of the graph rather than a post-hoc cleanup; it makes the provenance-retention metric fall out almost for free (walk each entity's `provenance` array); and it matches how an analyst thinks ("this host, seen by these sources"). The cost — a slightly richer entity model — is paid once, here.

The invariant: **every entity has at least one provenance entry.** An entity with no source cannot exist in a Glean graph (enforced by `minItems: 1` in the schema). This is the structural guarantee behind "0 fabricated findings."

### D2 — Stable deterministic identity key

Every entity has an `id` of the form `<type>:<canonical_value>` (e.g. `subdomain:admin.example.com`). Two tools reporting the same real-world entity **must** produce the same `id` after canonicalisation. Deduplication is therefore an identity match on `id`, not a fuzzy or LLM-driven merge — satisfying the "deterministic correlation" requirement. The detailed matching/merge behaviour lives in ADR-0003, but it is only possible because identity is defined here.

### D3 — Canonicalisation rules (what makes the `value`)

The `id` and `value` are only stable if canonicalisation is fixed. For v1:

- **Domains / subdomains:** lowercase; strip a trailing dot; IDNA/punycode-normalise internationalised names; no scheme, no port, no path.
- **IP addresses:** validated; IPv6 compressed to its canonical short form; no zone suffix.
- **Email addresses:** lowercase the whole address (v1 treats the local part case-insensitively for dedup — recorded as a known simplification).
- **DNS records:** canonicalise the owning name as a host; record type uppercased (`A`, `MX`, `TXT`, …).
- **Services:** `<ip>:<port>` with port as an integer attribute; protocol lowercased.
- **Certificates:** identity keyed on the certificate fingerprint (SHA-256) when available, else on the serial + issuer.

Canonicalisation happens in the adapter/normalisation layer, never in the LLM.

### D4 — Open per-type `attributes`, closed top-level shape

The top-level entity object is `additionalProperties: false` (a stable, validated envelope), but `attributes` is an open object so each entity type can carry its own detail without a schema version bump. The per-type attribute conventions for v1:

| Type | Typical attributes |
|------|--------------------|
| `domain` | registrar, creation/expiry dates |
| `subdomain` | (mostly relationships; wildcard flag if detected) |
| `ip_address` | asn, network/CIDR, geo (coarse), ptr |
| `dns_record` | record_type, ttl, rdata |
| `email_address` | (source context only) |
| `breach_exposure` | breach_name, breach_date, data_classes |
| `service` | port (int), protocol, service name, banner_ref |
| `web_tech` | product, version, category |
| `certificate` | fingerprint_sha256, issuer, subject, not_before, not_after, san[] |

Adding a **new entity type** to the enum is a schema version bump; adding a new *attribute* is not.

### D5 — Relationships as first-class edges

Relationships (`subdomain_of`, `resolves_to`, `hosts`, `has_record`, `exposes_service`, `runs_tech`, `issued_for`, `exposed_in_breach`) are stored as directed `edges` referencing entity `id`s, not embedded inside entities. Rationale: keeps entity records clean, makes the graph explicit for the eventual GUI on the roadmap, and lets an edge carry its own provenance (which tool asserted the link). Referential integrity — every edge endpoint exists in `entities` — is a document invariant checked in code (JSON Schema can't express it; the validation harness does).

### D6 — Provenance entry shape

Each provenance entry records `source_tool`, optional `source_module`, `method` (`passive`|`active`), `collected_at`, an optional `raw_record_ref` pointing into the archived raw tool output, and an optional `confidence`. The `raw_record_ref` is what makes a surfaced claim traceable all the way to source bytes — the strongest form of the provenance guarantee, and reproducibility insurance.

### D7 — Deterministic priority lives on the entity, LLM never writes it

The optional `priority` object (`score`, `rank`, `signals`) is populated by the ADR-0004 scoring code. The LLM reads it to write narrative; it never sets it. This is the structural expression of the charter's "deterministic score + LLM narrative" split, and it is what lets the evaluation test whether the LLM's narrative is faithful to a ranking it did not invent.

### D8 — Scan metadata and the passive/active ledger

The `scan` block records the target, an `authorisation` note (the basis on which the target was cleared to scan — binding per charter), timing, Glean version, and a `tools_run` ledger giving each tool's version, method, and a pointer to its archived raw output. This block is the reproducibility and audit header for the whole document.

## Consequences

- **Positive:** dedup and provenance-retention become near-trivial to compute; the passive/active separation is machine-enforced; the schema is versioned and machine-validated from day one; adapters have a single, testable target; the deterministic/LLM boundary is structural, not a matter of discipline.
- **Costs / accepted simplifications:** the merged-entity model is slightly more complex to write in adapters; email case-folding may over-merge in rare cases (recorded); `attributes` being open means per-type validation is convention + code, not pure schema. These are deliberate v1 trade-offs.
- **What this locks:** ADR-0002 through ADR-0005 must conform to this. Any change to entity types, the id convention, or the provenance shape is a `schema_version` bump and a new ADR.

## Open questions to resolve before freezing

1. Confirm the entity-type enum is complete enough for the MVP toolset (Amass, theHarvester, crt.sh, BBOT, dnsx) — validated once real tool output is captured.
2. Confirm `certificate` identity on fingerprint is available from crt.sh output in practice.
3. Decide whether `breach_exposure` stays in v1 (needs a passive breach source with acceptable ToS) or defers.

## Validation before freezing

This schema is validated against real output from a lightweight tool such as theHarvester or crt.sh: each field of that output is mapped onto the schema to confirm nothing is lost. Once a representative tool maps cleanly, the status moves to **Accepted** and the schema freezes at v0.1.0.
