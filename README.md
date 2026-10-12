# VMP Findings Assessment Engine

Standalone vulnerability findings assessment engine: ingests security scanner output, assesses each finding with an explainable multi-dimensional risk score, flags likely false positives, and clusters findings into ranked remediation actions.

## What's in this bundle

- **`BUILD_SPEC.md`** — the phase-1 architecture and build sequence. Start here.
- **`skill/vmp-findings-engine/`** — the skill carrying the durable rules and locked decisions. Claude Code reads this first and keeps it loaded.
  - `SKILL.md` — invariants, core model, four locked decisions, pipeline, differentiator.
  - `references/canonical-schema.md` — full canonical field model and design rationale.
  - `references/sample-findings.json` — worked examples of all three finding shapes.
  - `references/prototype.html` — the running reference UI. Open it in a browser.
  - `references/design-tokens.md` — palette, type, components.

## The idea in one paragraph

Scanners produce noisy, inconsistent, single-tool findings. This engine normalises them to one canonical model, deduplicates and correlates across tools, enriches from public threat intel (NVD/KEV/EPSS/OSV), computes a **deterministic, explainable** enterprise risk score, assesses false-positive likelihood with shape-appropriate logic, and — the differentiator — clusters findings into a ranked list of **remediation actions** so an analyst works fixes, not findings. Legacy scanners score findings in isolation and can't explain the number; this does both.

## The one rule that must not break

Agents gather and classify evidence; **deterministic code computes the score**; agents explain it. If the AI produces the number, reproducibility and auditability — the product's whole value — are gone. See the skill.

## Phase 1 scope

In: ingest → normalize → dedupe → correlate → enrich → score → assess-FP → cluster → explain → report, plus three screens and an own host-level asset inventory. Out: POA&M, owner routing, SSO/RBAC, ticketing. False-positive performance is measured on a constructed benchmark until customer scanner data with analyst dispositions is available.

## Development

Requires [uv](https://docs.astral.sh/uv/); it installs Python 3.12 and the locked dependencies.

```
uv sync                                       # create .venv from uv.lock
uv run pytest                                 # tests
uv run ruff check; uv run mypy src scripts    # lint + strict types
uv run python scripts/export_json_schema.py   # regenerate schema/json/ for the UI
```

Code lives in `src/vmp/<module>` following the module layout in `BUILD_SPEC.md`. The canonical model is `src/vmp/schema/`.

## Open items tracked outside this repo

- Masked Mirror JSON feed (the PDF shared so far is a rendered report, not ingestable data).
- IP arrangement: customer owns source + Ampcus integrates in phase 2 — needs reconciling.
- Which scanners the customer runs — determines connector priority after Trivy/Nessus/Qualys.
