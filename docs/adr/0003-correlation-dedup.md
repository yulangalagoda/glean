# ADR-0003 — Deterministic Correlation & Dedup (v1)

- **Status:** Proposed (v0 — for review)
- **Date:** 2026-07-22
- **Scope:** Glean v1 — how the pile of per-adapter entities collapses into one deduplicated graph
- **Depends on:** ADR-0001 (schema, identity), ADR-0002 (adapters emit un-deduped, canonicalised entities)
- **Consumed by:** ADR-0004 (scores the deduped graph), the evaluation harness (dedup-rate metric)

## Context

Each adapter emits entities independently and is forbidden from deduplicating (ADR-0002 D4). So after all adapters run, Glean holds a pile with overlaps: the same subdomain reported by three tools appears three times. This stage collapses that pile into the clean graph everything downstream reads.

Per the project charter, correlation is deterministic and done in code, not the LLM: the model must synthesise over a graph it did not assemble. This stage is therefore pure, rule-based code — no fuzzy matching, no model calls — and the "before/after duplicate rate" it produces is a measured MVP gate.

## Decision

### D1 — Dedup is an exact identity match on `id`

Two entities are the same entity iff they share the same `id`. Because adapters canonicalise before emitting (ADR-0001 D3, ADR-0002 D3), `id` (`<type>:<canonical_value>`) is already stable, so dedup is a group-by on `id` — the simplest deterministic operation possible. No string similarity, no heuristics in v1. If canonicalisation is right, exact match is right; if two things that should merge don't, that's a canonicalisation bug to fix upstream, not a reason to add fuzziness here.

### D2 — Merge procedure for a duplicate group

For each group of entities sharing an `id`, produce **one** merged entity:

- **`id`, `type`, `value`** — identical across the group by definition; carried through.
- **`provenance`** — **union** of all entries in the group. This is the heart of it: the merged `admin.example.com` carries crt.sh's stamp *and* Amass's stamp. Identical provenance entries (same tool, module, method, and raw_record_ref) are collapsed; distinct ones are all kept. An entity's provenance array length = number of independent assertions of its existence.
- **`attributes`** — key-wise union. For a key present in only one source, take it. For a conflicting key, apply D3.
- **`first_seen`** — the **minimum** `collected_at` across the group.
- **`last_seen`** — the **maximum** `collected_at` across the group.
- **`priority`** — not set here; scoring runs after dedup.

### D3 — Attribute conflict resolution (deterministic)

When two sources give different values for the same attribute key:

1. Prefer the value from the provenance entry with higher `confidence` (if present).
2. Else prefer the value from the source seen via the **richer method** (active over passive, since active generally observes rather than infers).
3. Else pick the lexicographically smaller value (final deterministic tiebreak).

In all cases the discarded value is retained under `attributes._conflicts` so a conflict is never silently dropped — it's recorded and auditable. Conflicts are rare in infra scope but must resolve deterministically, never by run order.

### D4 — Edge dedup and endpoint remapping

After entities are merged, edges are deduplicated too. Two edges are the same iff they share `(source_id, target_id, relation)`; duplicates collapse into one with **unioned** provenance (so "both Amass and BBOT asserted this `resolves_to`" is captured). Any edge whose endpoints referred to entities that merged is remapped to the surviving `id`. Edges left dangling (endpoint not in the final entity set) are dropped and counted — a dangling edge is a bug signal, not normal output.

### D5 — Correlation vs dedup: what this stage does and doesn't do

- **Dedup** = collapse the *same* entity seen multiple times (D1–D4). Fully in scope.
- **Correlation / entity-linking** = assert a *relationship between different* entities (this subdomain resolves to this IP). In v1 these edges come from the adapters that observed them; this stage only **dedups and remaps** those edges, it does not infer new relationships. Deterministic derivation of obvious edges (e.g. `subdomain_of` from the name hierarchy) is allowed because it's a pure structural rule — but any inference beyond structural facts is out of v1 scope and, if ever added, stays deterministic and code-based. The LLM never creates or edits edges.

### D6 — The dedup-rate metric (an MVP gate)

The charter requires measuring duplicate rate before/after. Definition:

```
entities_before = total entities emitted by all adapters (pre-merge, with overlaps)
entities_after  = distinct entities after D1–D3
duplicate_rate  = (entities_before - entities_after) / entities_before
```

All three numbers are reported per scan. `duplicate_rate` quantifies how much cross-tool overlap the union actually had — evidence that unifying multiple tools does real work, and a regression guard (if a canonicalisation change suddenly drops the rate to zero, something broke).

### D7 — Determinism end to end

Grouping, merge order, conflict resolution, and edge handling are all order-independent: feeding the same adapter outputs in any order yields a byte-identical graph (modulo a final stable sort of entities by `id` and edges by `(source_id, relation, target_id)`). This is testable directly — shuffle the input, assert identical output.

## Worked example (matches `example-scan.json`)

theHarvester, crt.sh, and Amass each emit `admin.example.com`:
- crt.sh → `subdomain:admin.example.com`, provenance {crtsh, passive}
- Amass → `subdomain:admin.example.com`, provenance {amass, active}

Same `id` → one merged entity, provenance = [crtsh/passive, amass/active], `first_seen` = the crt.sh time (earlier), `last_seen` = the Amass time (later). That is exactly the entity in the example file — two stamps, one record. The `multi_tool_corroboration` signal (ADR-0004) then fires on it precisely *because* dedup unioned the provenance.

## Consequences

- **Positive:** dedup is the simplest possible correct operation (group-by on a stable key); provenance union makes corroboration and the provenance-retention metric fall out for free; conflicts are recorded not dropped; determinism is directly testable by input-shuffling; the before/after metric is a built-in regression guard.
- **Costs / accepted limits:** exact-match dedup will *miss* semantically-equal-but-differently-written entities if canonicalisation didn't catch them (e.g. a trailing-dot FQDN that slipped through) — the fix is always upstream in canonicalisation, keeping this stage clean. No fuzzy/probabilistic entity resolution in v1 (e.g. "are these two IPs the same host behind a CDN") — deliberately deferred; it's exactly the kind of judgment that would blur the deterministic boundary.

## Open questions

1. Do near-miss cases (www.x.com vs x.com, apex vs www) need a canonicalisation rule or are they genuinely distinct entities? (Leaning: distinct — they *are* different hosts; a `subdomain_of`/alias edge is the right model, not a merge.)
2. Should `attributes._conflicts` surface in the brief at all, or stay internal? (Leaning internal for v1.)
3. CDN / shared-hosting IPs — the SpiderFoot "shared-hosting neighbours" noise the charter calls out. Confirm the rubric deprioritises these rather than the dedup stage merging them (it must not merge distinct hosts).

## Validation

Dedup is implemented as a pure function over a list of `ParseResult`s and tested by **shuffling adapter output order and asserting identical graphs**, plus a golden test on a two-tool overlap (the `admin.example.com` case). Implementing it alongside the first adapters makes the before/after metric available from the first multi-tool scan.
