# VMP Findings Engine — Build Spec (Phase 1)

This is the what-to-build for the phase-1 internal checkpoint. The durable rules and invariants live in the `vmp-findings-engine` skill; this spec is the architecture and sequence for this repo. Where they ever disagree, the skill's invariants win.

---

## What this is

A standalone vulnerability findings assessment engine. Ingests scanner output, assesses each finding with an explainable risk score, flags likely false positives, and clusters findings into ranked remediation actions. Source is handed to a customer; a Mirror integration follows in phase 2. No GRACE/Wizard/Mirror code is reused.

## Non-negotiables (from the skill)

- Deterministic scoring engine with reproducible test vectors. Agents supply evidence and write explanations; **agents never compute the score.**
- Finding (immutable observation) vs Vulnerability (canonical record) are separate.
- Three finding shapes (host/package/endpoint) with shape-specific FP logic.
- The four locked decisions (CVSS selection, rescan/reopen, source severity, endpoint normalisation).
- Connector interface, not hardcoded parsers. Outbound events emitted from day one.

## Recommended module layout

```
/schema        canonical model (Finding, Vulnerability, RiskAssessment, Action) + validation
/connectors    connector interface + nessus, qualys, trivy (file-upload first); mirror later
/pipeline      normalize, dedupe, correlate, enrich, score, assess_fp, cluster, explain
/intel         NVD / KEV / EPSS / OSV clients, cached + versioned
/scoring       deterministic engine + weights config + TEST VECTORS (the long pole)
/assets        host-level asset inventory (the engine's own; AssetProvider interface + CSV stub)
/api           ingest endpoint, findings/actions query, outbound event emitter
/ui            the three screens — match references/prototype.html
/benchmark     constructed FP benchmark + metrics harness
```

## Build order (data-availability aware)

**Stage 1 — no customer data needed (start here):**
1. Canonical schema + validation, from `references/canonical-schema.md` and `sample-findings.json`.
2. Deterministic scoring engine **and its test vectors** — author ~30 fixture cases with expected scores/priorities first, then make the engine reproduce them. This is the long pole and needs no external data.
3. Threat-intel clients (NVD/KEV/EPSS/OSV — all public).
4. `AssetProvider` interface with a CSV-backed stub.
5. Connector interface + Trivy connector (cleanest: deterministic version FP logic).

**Stage 2 — using the DefectDojo corpus (MIT, already a reference):**
6. Nessus + Qualys connectors against real sample files.
7. Dedupe + correlation + endpoint normalisation.
8. FP triage layer (the three mechanisms) + the constructed FP benchmark and metrics.

**Stage 3 — the differentiator + UI:**
9. Remediation-action clustering (the reasoning layer).
10. The three screens, matching the prototype.
11. Outbound event emitter (phase-2 hook) + Mirror connector stub.

## The three screens

Match `references/prototype.html` behaviour and `references/design-tokens.md`:
- **Remediation actions** (landing) — ranked fixes, each with "why these are one action" + steps + findings retired.
- **All findings** — flat triage list, filterable by shape.
- **Finding detail** — risk factors up/down, computed score, FP assessment, CVSS with contested flag, correlation, "why this rating", evidence with gaps.

## Phase 1 explicitly excludes

POA&M, owner/control routing, SSO/RBAC, ticketing. FP measured on the constructed benchmark, not real customer data.

---

## Kicking off with Claude Code

1. Put the `vmp-findings-engine` skill where Claude Code loads skills, and the prototype + schema where the skill references point.
2. Open with: *"Read the vmp-findings-engine skill and BUILD_SPEC.md. Start Stage 1, step 1: implement the canonical schema with validation from the references, then stop so I can review before the scoring engine."*
3. Work one stage step at a time; review after each. The scoring engine (step 2) is where to be most careful — insist the test vectors are written before the engine, and that every score traces to named factors.
