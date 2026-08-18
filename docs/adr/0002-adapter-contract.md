# ADR-0002 — The Adapter Contract (v1)

- **Status:** Accepted — pilot-tested 2026-07-22 (one correction found and applied, see D3 note and `docs/PILOT_findings.md`), and validated against five real, conforming adapters since (crt.sh, theHarvester, dnsx, httpx, subfinder — the last added 2026-07-27 as a real test of whether a new tool could be added cleanly against this contract; see Validation)
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
- **Stamp exactly one provenance entry per assertion**, carrying this adapter's `tool_id`, its `method`, `collected_at` from the context, and a `raw_record_ref` pointing back into the archived raw output (line number, JSON path, record id — whatever locates the source bytes). **Pilot correction (2026-07-22):** not every tool supports this at record granularity. theHarvester's JSON output, when run with multiple `-b` sources, returns a single flat merged host list with no per-source or per-record attribution — there is no way to know which of `crtsh`/`otx`/`duckduckgo` found a given host. An adapter for a tool like this MUST degrade honestly: `source_module` becomes a combined-sources label (e.g. `"combined:crtsh,otx,duckduckgo"`) and `raw_record_ref` points at the coarsest locator the tool actually gives (e.g. array position in the output file), not a specific underlying engine. This is not a contract violation — it's the contract correctly reflecting a real tool limitation. Adapters must not invent finer-grained provenance than the tool actually supports.
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

1. ~~Shared canonicalisation helpers — a `glean.normalise` module every adapter imports, to guarantee identical rules.~~ **Resolved 2026-08-04:** built as `glean_osint/normalise.py`, imported by every adapter. The leaning was right for the reason given — id stability across tools depends on all five canonicalising identically, which is what makes `merge_graph`'s exact-id merge work at all.
2. ~~Does the runner (invocation, timeouts, retries) deserve its own ADR, separate from the adapter?~~ **Resolved 2026-08-04:** yes — ADR-0008, which turned out to carry considerably more than invocation mechanics (three-stage pipeline, the active-tool gate, crt.sh caching, concurrency, cancellation). Folding that into this ADR would have buried it.
3. ~~Streaming vs whole-file parse for firehose tools like BBOT (NDJSON)~~ — **Resolved 2026-08-18, now that BBOT is wired: line-by-line, and the contract did not need to change.** `parse(raw: bytes)` stays exactly as specified; `BbotAdapter` simply iterates the buffer a line at a time and never holds more than one decoded event. That keeps the streaming decision *inside the one adapter that needs it* rather than forcing five other adapters to adopt an iterator signature for a problem they do not have — the contract's job is to make parsing pure and offline-testable, and it does that either way. A test pins the behaviour by asserting no single `json.loads` call ever sees the whole buffer, so a future refactor to a whole-file parse fails loudly rather than silently reintroducing the memory profile this question was about.

   Wiring BBOT also forced a second, unanticipated decision worth recording here: **an unrecognised event type is ignored, not counted as `skipped`.** A firehose emits dozens of types (`FINDING`, `VULNERABILITY`, `STORAGE_BUCKET`, ...) that this schema has no home for. D5's `skipped` counter means *this record was malformed*; folding "well-formed but irrelevant" into it would bury a genuine parse failure under thousands of uninteresting events and make the one number that reports damage useless on exactly the tool that generates the most volume.

## Validation

The first adapter is written against a saved fixture from the smallest tool (theHarvester or crt.sh JSON). That single adapter validates this contract, the entity schema, and the canonicalisation rules at once, and produces the first golden fixture for the test suite.

**Update (2026-07-27):** five real adapters now conform to this contract — crt.sh, theHarvester, dnsx, httpx, and subfinder (`SubfinderAdapter`, `src/glean_osint/adapters/subfinder.py`). subfinder was added specifically as a test of whether a new tool integrates cleanly: a real capture (`subfinder -d yulan.me -json -silent`, 203 real records) confirmed its JSON-lines shape before any code was written, matching every other adapter's own pilot-first origin. It needed no changes to this contract, `runner.extract_candidates` (already generic over any `ParseResult` regardless of source tool), or the dedup/scoring stages — only a new adapter file, a `run_subfinder` in `runner.py`, and wiring into the two call sites (`cli.py`'s `scan()`, `pipeline.py`'s `run_scan()`) that already exist per-tool by design (ADR-0008 D2: "invocation differs by tool, and that's fine"). The one new thing subfinder's addition surfaced: not every ProjectDiscovery-family tool's `-version` output includes the `projectdiscovery.io` banner `_verify_projectdiscovery_binary` (ADR-0008 D9) checks for — confirmed live that subfinder v2.14.0 doesn't print it, so that check was deliberately not reused for subfinder (no confirmed name-collision risk for "subfinder" either, unlike httpx's), rather than forcing a check that would incorrectly reject the real tool.
