# ADR-0011 — Interactive Web Interface

- **Status:** Accepted — Stage 1 (registry, server skeleton, scan form, results view) implemented and validated against real data 2026-07-27; Stage 2 (SSE progress) and Stage 3 (history browsing UI) not yet built, see Validation
- **Date:** 2026-07-27
- **Scope:** Glean v1 — a local, single-user web interface for configuring, running, watching, and browsing scans, in addition to (not instead of) the existing CLI
- **Depends on:** ADR-0002 (the `Adapter` protocol — `tool_id`/`default_method` are exactly what a tool registry needs, already present), ADR-0005 (Brief contract — rendered as-is, no new facts), ADR-0008 (the runner — the 3-stage pipeline this UI configures and watches, and D7's raw-archive location, amended here), ADR-0010 (the HTML report — reused directly as the results view)
- **Feeds:** charter §5 roadmap item "GUI... + readable report view" (the interactive half; ADR-0010 already closed the static-report half)

## Context

Real, explicit user request, not a speculative feature: a local interface to select/deselect tools before a scan, watch progress live, view/save/export results, and browse a persistent history of past scans across sessions — motivated specifically by "as we add more and more tools here," i.e. this should still make sense once Glean has 6, 8, 10 adapters, not just today's 4.

Two hard constraints given up front, both real engineering tradeoffs this ADR takes seriously rather than defaulting past: **fast and reliable on many machines with little effort** (ruling out anything that adds a second required toolchain), and **the interface itself must not become the bottleneck** — a scan's real latency is bounded by the tools/network (crt.sh, theHarvester), not by anything built here.

The project has been deliberately stdlib-only for HTTP/tooling so far (`urllib` for crt.sh and Ollama, no `requests`, no web framework) — `pyproject.toml`'s only runtime dependencies are `pyyaml` and `typer`. This ADR is the first real departure from that, and does so knowingly: hand-rolling HTTP routing, JSON handling, static file serving, and live-progress streaming in stdlib for a genuinely interactive multi-page app is a lot of reinvented, bug-prone wheel for something a small, extremely well-trodden dependency already solves well.

## Decision

### D1 — Backend: FastAPI + uvicorn; frontend: server-rendered HTML + htmx, no build step

FastAPI reuses every existing module directly (adapters, runner, brief, scoring, dedup) — no logic duplicated in a second language. It handles Server-Sent Events (D5) natively.

The frontend is server-rendered HTML (Jinja2) with htmx (one vendored local script file, no CDN — same self-contained discipline ADR-0010 already established) for the dynamic parts: live progress updates and partial page swaps, without a client-side framework re-implementing state management. Explicitly **not** React/Vue/Svelte with a build step: that requires Node.js + npm + a bundler as a second required ecosystem, which directly fights "runs on many machines without much effort" — and produces a `dist/` folder that would need embedding into the Python package at release time, a real packaging complication for no corresponding gain given this app's actual shape (forms, a progress view, a results table, export buttons — not something that needs a full SPA framework's capabilities).

This keeps the "don't add interface overhead" constraint structurally true: no client-side framework to parse/hydrate, no virtual-DOM diffing, nothing between the browser and the real data but plain HTML.

### D2 — Entry point: bare `glean` launches the server; the CLI is unchanged

`glean` with no subcommand starts the local server (default `http://127.0.0.1:<port>`, bound to localhost only — see D8) and opens/prints the URL. `glean scan ...` and `glean eval ...` keep working exactly as today, unaffected — this is additive, not a replacement. Mechanically: the existing `@app.callback()` gains a check on `ctx.invoked_subcommand is None` and dispatches to `serve()` in that case, rather than today's `no_args_is_help=True` behaviour.

### D3 — A real adapter registry, introduced here, not before

Today `cli.py`'s `scan()` hardcodes each tool's wiring by hand (`CrtshAdapter`, `TheHarvesterAdapter`, `DnsxAdapter`, `HttpxAdapter` each spelled out individually) — there is no central list to iterate. Introduce `ADAPTER_REGISTRY: dict[str, Adapter]` (keyed by `tool_id`, using the `Adapter` protocol's already-existing `tool_id`/`default_method` fields, ADR-0002) as the one place every tool is listed. Both the CLI's `scan()` and the new web API's tool-selection endpoint iterate this registry instead of hardcoding — a real refactor, but a small, clean one, and the direct enabler of "the tool list shows up in the UI automatically as adapters are added" (the user's own stated long-term motivation).

### D4 — Tool selection: free toggles + named presets, real dependency enforced, not papered over

The runner's existing 3-stage shape (ADR-0008 D1) already tolerates a subset of tools — if dnsx/httpx aren't selected, those stages simply don't run. This ADR does **not** introduce a generic pipeline dependency-graph system; the 3-stage shape stays explicit, hardcoded logic in the runner, exactly as ADR-0008 already decided. What's new is exposing tool inclusion as a real choice in the UI:

- Free per-tool toggles, plus a small set of named presets as shortcuts (e.g. "Passive only" = crt.sh + theHarvester + dnsx; "Full scan" = all four, active; "Certificate check" = crt.sh only; "Custom" = whatever's toggled). Presets are just pre-set toggle states, not separate backend logic — adding one later is a config entry, not new code.
- **One real structural constraint, enforced honestly rather than allowed to silently misbehave**: httpx is fed dnsx's *positively-confirmed* resolved hosts (ADR-0008 D1/D9's whole "never absence-as-evidence" discipline) — it cannot run meaningfully alone. The UI enforces this directly: selecting httpx auto-selects dnsx; deselecting dnsx disables httpx. dnsx alone is fine and useful on its own (with nothing upstream, `extract_candidates` already includes the apex target itself, so a dnsx-only run is a legitimate quick "is this domain alive" check).

### D5 — Progress: Server-Sent Events, not polling or WebSockets

A scan started from the UI runs server-side (a background thread/task); an SSE endpoint streams stage-by-stage status events to the browser — the same plain-language status strings the terminal `Spinner` (added earlier this session) already uses, reused rather than reinvented. One-directional is sufficient: the browser never needs to send anything back mid-scan, so the added complexity of a full-duplex WebSocket buys nothing here.

### D6 — Scan history: a fixed, cwd-independent location; unifies CLI and web scans into one history

Scan history lives at `~/.local/share/glean/scans/<slug>-<timestamp>/` (respecting `$XDG_DATA_HOME`), not the current working directory — explicit operator decision: history should be the same regardless of which folder `glean` happens to be launched from. Each scan directory gets a `manifest.json` (target, started_at, tools_run, authorisation, top_n, pointers to the rendered `brief.md`/`brief.html`) alongside the `raw/` archive ADR-0008 D7 already writes. File-based, no database — consistent with every other piece of state this project already keeps as files (raw archives, eval scans, ground truth), nothing to migrate as the schema evolves.

**Amends ADR-0008 D7**: the CLI's own default `--raw-dir` location changes from `./glean-output/<slug>-<timestamp>/raw/` (cwd-relative) to this same fixed XDG location, so a scan run from the terminal and a scan run from the web UI land in one shared, coherent history rather than two disconnected ones — directly serving "terminal action could also be allowed as is" as *one tool*, not two. `--raw-dir` remains fully overridable for anyone already scripting a custom location; only the default moves.

**Sequencing note**: only the *web-triggered* side of this is built in Stage 1 (the web app writes `manifest.json`/`brief.html`/raw archive to the fixed location for every scan it runs). The CLI's own `--raw-dir` default is deliberately left unchanged for now — amending real, already-tested CLI behaviour is sequenced into Stage 3 (history browsing), alongside the UI that actually makes "unified history" visible, rather than changed now for a payoff that doesn't exist yet.

### D7 — Results: view, save, export

A finished scan's results render using `render_html()` (ADR-0010) directly in the browser — no second results-rendering implementation. "Save"/"export" downloads the existing `.md`/`.html` file as-is. PDF: the browser's own native "Print to PDF" on the already-well-styled HTML report, zero new dependency — not a server-side renderer (Playwright bundles an actual browser, 300MB+; WeasyPrint needs native Pango/Cairo libs that can be fiddly across OSes) — both cut directly against "runs on many machines without much effort" for a feature the browser already does for free. Revisit only if that's genuinely insufficient in real use (see Open questions).

### D8 — Localhost-only, no authentication, single-user assumption made explicit

The server binds to `127.0.0.1` only, never `0.0.0.0` — this is a local single-operator tool, and an unauthenticated control plane that can trigger *active* recon (real requests at a real target) must never be reachable from the network by default. No login/auth system in v1: the OS-level boundary (only processes on this machine can reach `127.0.0.1`) is the actual security boundary, and adding a real auth system for a single local user would be complexity with no corresponding real threat addressed.

## Consequences

- **Positive:** directly closes every piece of the user's request (tool selection, live progress, results/export, persistent cross-session history) without adding a second toolchain; the adapter registry (D3) pays for itself immediately and makes future tools cheaper to add on both the CLI and web side; one unified history (D6) makes the CLI and web interface feel like one tool rather than two.
- **Costs / accepted limits:** first real runtime dependencies beyond stdlib+typer+pyyaml (FastAPI, uvicorn, jinja2 — all mature, widely-installed, but still a real departure worth naming plainly); `--raw-dir`'s default location changes (D6), a real behaviour change for existing CLI users, mitigated by remaining fully overridable; no multi-user/remote-access story, deliberately (D8).

## Open questions

1. Can two scans run concurrently from the UI, or is v1 one-at-a-time with a queue? Leaning one-at-a-time first — simpler to reason about and matches how the CLI is used today; revisit if it's a real friction point in practice.
2. Should the preset list (D4) itself become user-editable via the UI later? Not built now — the fixed starter set (Passive only / Full scan / Certificate check / Custom) covers the real usage seen so far.
3. Server-side PDF rendering (D7) — deferred until the browser-print path genuinely proves insufficient, not built speculatively.
4. Remote access / multi-user (D8) is out of scope entirely for v1, not just deferred — would need a real auth/threat-model decision this project hasn't needed to make yet.

## Validation

**Stage 1** (registry `registry.py`, shared pipeline `pipeline.py`, history `history.py`, FastAPI app `web/app.py`, bare-`glean` dispatch): 195/195 tests pass (new: `test_registry.py`, `test_pipeline.py`, `test_web_app.py` using FastAPI's `TestClient`, isolated from the real `~/.local/share/glean/` via `create_app(history_root=tmp_path)`), ruff/mypy clean, wheel build confirmed to actually package `web/templates/*.html` and `web/static/*`.

Real-data validation: started the server via bare `glean`, submitted real scans against `larnby.com` (owned target) through the actual HTTP form (crt.sh+theHarvester+dnsx, then a separate run adding httpx) — all four tools ran correctly, results rendered via the real `render_html()`, `manifest.json`/`brief.html`/raw archives landed under `~/.local/share/glean/scans/`. Confirmed the server binds to `127.0.0.1` only (`ss -ltnp` shows no `0.0.0.0`/wildcard bind), and that `glean scan ...` (the existing CLI) still works completely unchanged.

Two real bugs found and fixed during this validation, both worth recording:
1. **The web pipeline never read `$GLEAN_THEHARVESTER_BIN`/`$GLEAN_DNSX_BIN`/`$GLEAN_HTTPX_BIN` at all** — those env vars were only ever wired through Typer's CLI-option `envvar=` mechanism (added earlier this session), which the web app doesn't go through. A real scan through the web form hit the exact same binary-collision failures the CLI already solved once (theHarvester not on `PATH`, the wrong `httpx` on `PATH`). Fixed by having `pipeline.py` read these env vars directly via `os.environ.get(...)` (a `_tool_binary` helper, re-read fresh on every call rather than cached at import time, since the web app is a long-running process where a changed env var should take effect without a restart) — the same environment contract now works identically for both surfaces.
2. **A bound `from glean_osint.pipeline import run_scan` in `web/app.py`** would have silently defeated `monkeypatch.setattr(pipeline, "run_scan", ...)` in tests — the exact class of bug found and fixed in `fetch_crtsh_cached` earlier this session (ADR-0008 D9's correction note). Caught before it ever caused a real test-suite bug, by deliberately checking for the pattern this time: changed to `import glean_osint.pipeline as pipeline` / `pipeline.run_scan(...)` (module-qualified, resolved fresh per call).

**Stage 2** (SSE live progress) and **Stage 3** (history browsing UI, the CLI-side D6 amendment) are not yet built.
