# ADR-0010 — HTML Report View

- **Status:** Accepted — implemented and validated against real data (`example.com` fixtures, then a real live `yulan.me` scan, 528 findings) 2026-07-27; see Validation
- **Date:** 2026-07-27
- **Scope:** Glean v1 — a readable, single-file HTML rendering of the same `Brief` the terminal already prints as markdown; explicitly *not* the charter's separate "prioritised entity graph" idea
- **Depends on:** ADR-0005 (the brief contract — `Brief`/`Finding`/footer counts are the one source of truth this renders, unchanged), the terminal-UX work earlier this session (`render_markdown`'s `also_found_limit`, `SECTION_BREAK`)
- **Feeds:** charter §5 roadmap item "GUI... + readable report view" (the readable-report half only)

## Context

Real user feedback, twice, both explicitly deferred rather than acted on at the time: after the first large real scan (`yulan.me`, 522 findings), "everything is in a markdown style which is really hard to get a grasp from via the terminal. maybe its ok if we are moving this to a web interface later. then it wont be a problem. for now its ok." The MVP definition of done (`CHARTER.md` §4) is now fully met — all 5 measurable goals hold, validated against real infrastructure — so this deferred item is next in line rather than blocking anything.

The charter's own roadmap (§5) bundles two different things under "GUI": *"prioritised entity graph (fixing the 'hairball' problem) + readable report view."* These are not the same problem. The readable-report half is what the actual user complaint was about — markdown rendered raw in a terminal is genuinely hard to skim, especially past ~25 findings even with the truncation fix already shipped. The entity-graph half is a separate, much bigger, more speculative feature (interactive graph layout, a "hairball" only shows up on graphs dense enough to need one) that nothing in this project's real usage so far has actually demonstrated a need for. Scoping this ADR to the report view only, and treating the graph as a distinct future decision, keeps this a tractable next step instead of reopening the whole GUI question at once.

## Decision

### D1 — Scope: a readable static report, not the entity graph

This ADR covers only a second renderer for the exact same `Brief` object `render_markdown` already consumes — no interactive graph, no new data collected, no new entity/edge model. The charter's "hairball problem" graph is explicitly deferred (see Open questions) until real usage actually shows findings feel disconnected without one, not built speculatively now.

### D2 — Format selection: infer from `--out`'s file extension, no new flag

`glean scan <domain> --out report.html` writes HTML; `--out report.md` (or any other extension) keeps writing markdown, exactly as today. No `--html`/`--format` flag — one already-existing option, read a little more carefully, is simpler than a second option that could disagree with it. Terminal stdout (no `--out` at all) always stays markdown: HTML isn't meaningfully "printable" to a terminal, and changing default stdout behaviour isn't part of this complaint (the complaint was about *files/scrollback*, and `--out` already exists for exactly "give me something to actually read").

### D3 — Self-contained static file, no server

A single `.html` file: inline `<style>`, no external requests, no build step, no JS framework — opens directly via `file://` in any browser, or attach/share as one file. No local server (`glean serve` or similar) in v1 — nothing about the current complaint needs live interactivity, and a server is a meaningfully bigger surface (process lifecycle, port binding, another thing that can silently fail) for a problem "open the file I already have" already solves.

### D4 — Same data, a second presentation only

`render_html(brief: Brief) -> str` lives beside `render_markdown` in `brief.py`, takes the identical `Brief`/`Finding`/`ScanMeta` input, and asserts nothing about it that `render_markdown` doesn't already assert (same footer counts, same ordering, same provenance strings). This is deliberately not a new data model or a new pass over the entity graph — it's presentation-only, so the two renderers can never disagree about the underlying facts, only how they're laid out. A cheap consistency test (both renderers mention the same set of entity ids/counts) guards against the two drifting apart as `Brief`'s shape evolves.

### D5 — "Also found": full list, collapsed by default, not truncated

The terminal's `also_found_limit`/`--show-all` split (this session) exists because a terminal has no good way to show 500 lines without them all hitting the scrollback at once. HTML doesn't have that constraint — a native `<details>/<summary>` disclosure can hold the *complete* list, collapsed by default (so the page isn't overwhelming on first look), and expand in one click with the browser's own scrolling inside it. No arbitrary numeric cap, no "...and N more not shown here." — strictly better than the terminal workaround once the medium allows it.

### D6 — Plain, accessible, theme-aware, no invented signal

Semantic HTML (real headings/lists, not divs styled to look like them), priority tiers distinguished by more than colour alone (colour *and* the existing rank number/label — never colour-only, for real accessibility, not just a nicety), light/dark via `prefers-color-scheme` so it reads correctly regardless of the viewer's OS/browser theme, responsive so a long `display_value` or provenance string doesn't force horizontal scrolling of the whole page. No chart, badge, or visual weight is introduced that isn't backed by a real field already in `Finding`/`Brief` — the same "never invented, only what's in the graph" discipline ADR-0005 already holds the markdown renderer to.

## Consequences

- **Positive:** directly closes the standing "hard to parse in a terminal" complaint with a real, shareable deliverable (a file a reader can open, skim, and forward) rather than terminal scrollback; costs nothing extra to *collect* since it's a pure second view over data already gathered.
- **Costs / accepted limits:** two renderers to keep from drifting apart (mitigated by D4's shared-input, no-new-facts constraint plus a consistency test); no interactive graph, no server, no live updates — all explicitly out of scope here, not gaps to feel bad about.

## Open questions

1. ~~Does the charter's "prioritised entity graph" (the actual "hairball problem" fix) get built later as ADR-0011, once real usage shows a flat list stops being enough?~~ **Resolved 2026-08-04:** yes, and real usage did show it. ADR-0011 became the web interface, and the relationship view (`glean_osint/graph.py`, served at `/scan/{id}/graph`) is the graph itself — built only once persisted edges existed to draw it from.
2. Should `glean eval`'s per-target output ever get an HTML form too? Out of scope for v1 — `eval` produces aggregate headline numbers across many targets, a different shape of output than one target's brief, already reasonably served by its current table.
3. ~~Should there eventually be a `glean serve` for live/interactive viewing?~~ **Resolved 2026-08-04:** yes, though not under that name — bare `glean` launches the web interface (ADR-0011 D2), localhost-only by default. The bar this question set was met: the static file genuinely stopped being enough once scans needed to be run, compared, triaged and traced back to source records.

## Validation

Implemented as `render_html()` in `brief.py`, wired into `scan --out <path>` via D2's extension rule. Automated: 5 new tests in `tests/test_brief.py` (self-contained document — no external requests/JS; D4's same-facts consistency check against `render_markdown`; full "Also found" list at 31 entries with no truncation; HTML-special-character escaping) plus a CLI test confirming `--out report.html` writes HTML while `--out report.md` still writes markdown, unchanged. 171/171 suite passes, ruff/mypy/wheel-build all clean.

Real-data validation: rendered `example.com` fixture data first, then a real live `--live --active` scan of `yulan.me` (528 findings, the same target whose 522-finding terminal dump originally motivated this whole thread) to a real `.html` file — 524 `<li>` entries inside a single collapsed `<details>`, valid `<!doctype html>...</html>` structure, no external `http(s)://` references. Extracted and published as a preview artifact for a human visual check (the actual generated file, unmodified, not a redesigned mock) rather than relying on structural assertions alone.
