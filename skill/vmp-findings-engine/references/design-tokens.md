# VMP design tokens

Extracted from `prototype.html`. Match these when building the real UI. Full working CSS variables are in the prototype's `:root` block, including the dark-theme overrides.

## Palette (light)

| Token | Hex | Use |
|---|---|---|
| ink | #13161b | primary text |
| ink-2 | #3d434e | secondary text, factor rows |
| mute | #6b7280 | labels, meta |
| faint | #9aa1ab | de-emphasised |
| line | #e5e7eb | borders |
| bg | #f6f7f9 | page background |
| panel | #ffffff | cards, surfaces |
| accent | #1f5fb0 | selection, links, reasoning layer |

Severity colors carry a text + bg pair each: crit #b4232a/#fbeceb, high #c2560f/#fbeee3, med #8a6d0d/#f8f1d9, low #2f6f8f/#e8f1f5, ok #2c7a4b/#e7f3ec. Dark-theme equivalents are in the prototype.

This is a **blue-accented, muted, analyst-tool** palette — deliberately not the warm-cream/terracotta or near-black/acid-green looks that read as generated. Keep it quiet; the data is the hero.

## Type

System sans stack (`ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto`). One family. Weights do the work: 560–580 for titles, 620–680 for emphasis and numbers. Tabular numerals (`font-variant-numeric:tabular-nums`) on every score, count, and CVSS value. Monospace only inside evidence blocks and inline loci (`code`).

## Components

- **Radius** 10px on cards and blocks; 999px on filter chips; 5–6px on small tags/pills.
- **Selection** marked by accent border + `inset 3px 0 0 accent` shadow bar, not a fill.
- **Score** 46px, 700 weight, severity-colored, with a gradient meter + pin beneath.
- **Reasoning-layer insight banner** uses accent-bg with a translucent accent border and a small accent eyebrow — the one place accent is foregrounded.
- **Factor rows** use ↑ (crit color) / ↓ (ok color) markers.
- **FP band classes**: `low-likelihood` (crit), `needs-review` (high), `deterministic` (ok).
- **Evidence** in a collapsible `<details>` with a rotating chevron; gaps shown as `gap:` chips.

## Layout

Two-pane: left = actions/findings list, right = detail. Collapses to single-column under 920px. Progressive disclosure is the organising principle — actions → findings retired → evidence.

## Writing

Plain, active, analyst-facing. "Why this rating" and "Why these are one action" are full sentences that name the actual factors. No ALL-CAPS eyebrows except the single reasoning-layer label. No "→" appended to buttons. Errors and empty states give direction, not mood.
