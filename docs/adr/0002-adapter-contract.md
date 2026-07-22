# ADR-0002 — The Adapter Contract (v1)

- **Status:** Proposed (v0 — for review)
- **Date:** 2026-07-22
- **Scope:** Glean v1 — the interface every tool integration conforms to
- **Depends on:** ADR-0001 (entity schema)
- **Feeds:** ADR-0003 (dedup consumes adapter output), the testing strategy (adapters are the primary unit-test surface)

## Context

An adapter is the only tool-specific code in Glean. It translates **one** tool's raw output into schema-valid entities and edges with provenance. Everything downstream — dedup, scoring, LLM, eval — is tool-agnostic and reads only the normalised graph. The charter promises "a new tool is a ~50-line adapter"; that is only achievable if the contract every adapter satisfies is fixed first. This ADR is that contract.

The guiding principle: **adapters are dumb, pure, and local.** An adapter knows how to read *its* tool's bytes and nothing else. It does not know other tools exist, does not deduplicate, does not score, does not call the LLM. Keeping adapters this thin is what makes them small, testable offline, and safe to add.

## Decision

### D1 — Two responsibilities, one optional

An adapter has at most two parts, and only the second is mandatory:

1. **Invocation (optional):** build the command to run the tool against a target. An adapter may be *ingest-only* — Glean feeds it raw output the user produced separately — in which case it skips this.
2. **Parsing (mandatory):** a **pure function** from raw tool output to normalised entities and edges. This is the heart of the adapter and the thing tests hit.

Separating these means the parser is offline-testable against a saved fixture with no tool installed, no network, and no target touched.

### D2 — The interface

```python
class Adapter(Protocol):
    tool_id: str          # canonical source_tool, e.g. "theharvester"
    default_method: Method # "passive" | "active"

    def build_command(self, target: str, options: Options) -> list[str] | None:
        """Argv to run the tool, or None if this adapter is ingest-only."""

    def parse(self, raw: bytes, ctx: ScanContext) -> ParseResult:
        """PURE. Same raw in -> same result out. No I/O, no network, no clock
        except ctx.collected_at. Returns entities + edges, each stamped with
        provenance for this tool."""
```

`ParseResult` is `(entities: list[Entity], edges: list[Edge])`. `ScanContext` carries the scan-wide constants a stamp needs (`collected_at`, `raw_output_ref`, resolved `tool_version`, target) so `parse` stays pure with respect to them.

### D3 — What every adapter MUST do

- **Emit schema-valid entities only** (ADR-0001). Each entity: correct `type`, canonicalised `value`, id of the form `<type>:<canonical_value>`.
- **Canonicalise before emitting** (ADR-0001 D3): lowercase hosts, compress IPv6, lowercase emails, etc. Canonicalisation is the *adapter's* job so identity is stable before dedup ever runs.
- **Stamp exactly one provenance entry per assertion**, carrying this adapter's `tool_id`, its `method`, `collected_at` from the context, and a `raw_record_ref` pointing back into the archived raw output (line number, JSON path, record id — whatever locates the source bytes).
- **Declare method honestly.** If a tool has both passive and active modes, the adapter sets `method` per record, not globally.
- **Be deterministic.** Same raw bytes → identical `ParseResult`. No randomness, no ordering dependence on dict iteration, no ambient time.

### D4 — What every adapter MUST NOT do

- **Not deduplicate** — not within its own output and never against another tool's. Emitting the same subdomain twice is fine; dedup (ADR-0003) collapses it. (This keeps the *before* number honest for the dedup-rate metric.)
- **Not set `priority`** — scoring is a later, global stage (ADR-0004).
- **Not merge, cross-reference, or reason across tools.**
- **Not call the LLM.**
- **Not invent fields** the tool didn't provide. Absent data is absent, not guessed. This is the faithfulness guarantee starting at the source.

### D5 — Error handling: degrade, never crash the scan

A malformed or partial record is skipped and logged with its `raw_record_ref`; the adapter emits everything it *could* parse and reports a count of what it dropped. One bad record must not abort a scan, and one failing tool must not abort the others. Partial output is a normal, first-class outcome — recon tools time out and half-finish routinely.

### D6 — Registration: adding a tool is declarative

Adapters self-register (entry point / registry decorator) under their `tool_id`. Adding a tool is: write the adapter, register it, drop a golden fixture. No changes to the orchestrator, dedup, scoring, or brief code. This is the structural payoff of the contract and the literal meaning of "~50-line adapter."

### D7 — Raw output is always archived

Whether Glean ran the tool or ingested it, the raw bytes are saved and referenced from `scan.tools_run[].raw_output_ref`. `raw_record_ref` in each provenance entry points into that archive. This is the reproducibility + provenance backbone: every claim in the final brief can be walked back to source bytes.

## The contract as a checklist a new adapter must pass

- [ ] `parse` is pure: same fixture in → identical entities/edges out.
- [ ] Every entity validates against `entity-graph.schema.json`.
- [ ] Every entity's `value` is canonicalised per ADR-0001 D3.
- [ ] Every entity has exactly one provenance entry with this tool's id, method, and a `raw_record_ref`.
- [ ] No dedup, no scoring, no cross-tool logic, no invented fields.
- [ ] Malformed records are skipped and counted, not fatal.
- [ ] A golden fixture (raw input → expected output) is committed.

## Consequences

- **Positive:** adapters are tiny and offline-testable; the fleet of tools is a set of interchangeable parts; the dedup-rate and faithfulness metrics are protected at the source (no early dedup, no invented data); a contributor can add a tool without understanding the rest of the system.
- **Costs / accepted limits:** requiring pure parsing means invocation quirks (timeouts, rate limits, API keys) live outside `parse`, in the runner — slightly more moving parts. Canonicalisation logic is duplicated risk across adapters; mitigated by a shared canonicalisation helper library all adapters call (so the *rules* live once even though each adapter invokes them).

## Open questions

1. Shared canonicalisation helpers — a `glean.normalise` module every adapter imports, to guarantee identical rules. (Leaning yes; almost required for id stability.)
2. Does the runner (invocation, timeouts, retries) deserve its own ADR, separate from the adapter? (Likely yes as tool count grows.)
3. Streaming vs whole-file parse for firehose tools like BBOT (NDJSON) — parse line-by-line to bound memory? (Defer until BBOT is wired.)

## Validation

The first adapter is written against a saved fixture from the smallest tool (theHarvester or crt.sh JSON). That single adapter validates this contract, the entity schema, and the canonicalisation rules at once, and produces the first golden fixture for the test suite.
