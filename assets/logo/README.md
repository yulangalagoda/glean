# Glean — brand mark

**The Gather.** Six sources, ranked by weight, resolving into one judgment.

The concept is the word itself: *to glean* is to gather what is left in the
field, piece by piece. It is also, exactly, what the pipeline does — several
heterogeneous tools collapsing into a single prioritised brief. That is why
the mark animates by pulling inward rather than spinning: the motion is the
definition, and the loading state means something rather than merely passing
time.

Two decisions carry the design:

- **The ring is ranked.** Dot radii descend clockwise from the top
  (2.5 → 1.3). Without that, the static mark reads as a loading spinner
  someone paused. With it, hierarchy is visible even at rest — which is the
  whole product thesis.
- **The centre is the answer.** It is the only element in a fixed accent
  colour and the only one that never moves.

---

## Files

| File | Use |
|---|---|
| `glean-mark.svg` | Primary mark. Ring inherits `currentColor`; centre is fixed accent. |
| `glean-mark-mono.svg` | Single colour. Hierarchy by size and opacity only, never hue. |
| `glean-loader.svg` | Animated. Self-contained — animates even as `<img src>`. |
| `glean-favicon.svg` | Light-mode favicon. Optically corrected, **not** a scaled mark. |
| `glean-favicon-dark.svg` | Dark-mode favicon. |
| `glean-lockup.svg` | Mark + wordmark, horizontal. |

### Why the favicon is a different drawing

At 16px one viewBox unit is half a pixel, so the primary mark's smallest ring
dot would render about 1.3px across and vanish. The favicon equalises the ring
at `r=2.6`, pulls it in to radius 10.8, grows the centre to `r=6`, and raises
opacity — thin coverage reads lighter at small sizes than the same value does
at large ones. Scaling the primary mark down mechanically does not work; don't.

---

## Colour

| Token | Light | Dark |
|---|---|---|
| Accent (centre) | `#2a5adb` | `#7db8ff` |
| Ring | `currentColor` @ 50% | `currentColor` @ 50% |

These are already `--accent` in `src/glean_osint/web/static/style.css`, so the
mark is consistent with the interface by construction rather than by
coincidence. If the accent ever changes, change it there and the inline mark
follows.

---

## Clear space and minimum size

- **Clear space:** one full mark-height on every side.
- **Wordmark gap:** `0.3 ×` mark height.
- **Minimum size:** 16px using the favicon build; 24px using the primary mark.

Below 16px, drop to the centre dot alone rather than shrinking further.

---

## Wiring the loader into the web interface

The loader is designed to replace the indeterminate wait on the watch page
(`src/glean_osint/web/templates/watch.html`), where a scan can currently run
for 75 seconds against a static status line.

Because the interface forbids external requests, inline the SVG rather than
linking it. Add to `style.css`:

```css
.glean-loader { width: 1.15em; height: 1.15em; flex: none; vertical-align: -0.2em; }
.glean-loader .gl-dot {
  animation: gl-gather 1.9s cubic-bezier(.55,.1,.35,1) infinite;
  transform-box: fill-box;
  transform-origin: center;
}
@keyframes gl-gather {
  0%   { transform: translate(0, 0);                 opacity: 1; }
  55%  { transform: translate(var(--dx), var(--dy)); opacity: 0; }
  75%  { transform: translate(0, 0);                 opacity: 0; }
  100% { transform: translate(0, 0);                 opacity: 1; }
}
@media (prefers-reduced-motion: reduce) {
  .glean-loader .gl-dot { animation: none; opacity: 0.5; }
}
```

Then inline the `<svg>` body from `glean-loader.svg` (minus its own `<style>`,
which the stylesheet now provides) beside `#status-line`, and remove it when
the SSE `done` or `error` event fires.

Note the resting state is deliberately the *finished* state: at `0%` every dot
sits at home, fully placed. A paused frame, a reduced-motion render, or a
failed animation all degrade to the static mark rather than to a
half-collapsed shape.

### A third state worth building later

On the `done` event, the dots could travel inward **once** and stay, instead of
looping — the mark resolving as the scan resolves. That is a genuinely nice
completion beat and costs one extra keyframe set.

---

## Before you ship the wordmark

`glean-lockup.svg` uses live `<text>`, so it renders with whatever the system
resolves from the font stack and will differ between machines. Convert it to
outlines in Inkscape, Figma or Illustrator before using it anywhere final. It
is left as live text so you can still re-letterspace or change the typeface
first.

---

## Not packaged

This directory sits outside `src/`, so it is excluded from the built wheel by
`[tool.setuptools.packages.find] where = ["src"]`. If you want the favicon
actually served by the web interface, copy it into
`src/glean_osint/web/static/` — that path *is* packaged (see
`[tool.setuptools.package-data]`) and is already covered by the packaging
guard in CI.
