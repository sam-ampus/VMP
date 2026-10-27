# VMP Findings Engine

Read these before working here:
- `skill/vmp-findings-engine/SKILL.md`: the invariants and locked decisions. Its rules win over everything else.
- `BUILD_SPEC.md`: the module layout and build order. Don't reorder it.
- `docs/design/00-overview.md`: Donna's ask, constraints, system map, status and open items.
- `docs/design/decisions.md`: every decision so far. Append new ones.
- `docs/design/NN-*.md`: one design note per build step.
- `docs/design/backlog.md`: everything deferred, known limitations and open questions. Read it at the start of every step.

## Working mode (Phase 1)
- Claude writes the code. Sam reviews; delivery to Donna comes first.
- After each step, stop for review. Write a `docs/design/NN-<step>.md` note covering:
  - the problem from first principles;
  - the system view;
  - choices and trade-offs;
  - the Applied AI tie-in;
  - a code tour;
  - three check-yourself questions.
- **No silent tech debt.** Fix small in-scope issues now. Anything deferred goes in `docs/design/backlog.md` with a trigger, never only in chat or a `TODO`; move items to *Resolved* when they're done.
- Commit only when Sam asks.

## Commands
```
uv run pytest
uv run ruff check; uv run mypy src scripts
uv run vmp ingest seed/demo --as-of 2026-10-22T00:00:00Z   # end-to-end demo run
```
