---
name: vmp-findings-engine
description: "Use when building, extending, or modifying the VMP (Vulnerability Management Platform) findings assessment engine — ingesting security scanner findings, normalising them to the canonical model, deduplicating and correlating across tools, enriching from threat intel, computing the enterprise risk score, assessing false-positive likelihood, clustering findings into remediation actions, or building its UI. Trigger on any work touching the canonical Finding/Vulnerability model, the scoring engine, the FP triage layer, the remediation-action reasoning layer, or VMP connectors (Nessus, Qualys, Trivy, Snyk, Mirror, and other scanners). This skill carries the locked architectural decisions and invariants that must hold across every session."
---

# VMP Findings Assessment Engine

A standalone product that ingests security findings from any scanner, assesses them with an explainable multi-dimensional risk score, flags likely false positives, and clusters findings into ranked remediation actions. It is handed to a customer as source, with a later optional Mirror integration. It does **not** reuse GRACE, Wizard, or Mirror code.

## The one invariant that must never break

**Agents gather and classify evidence. Deterministic code computes the score. Agents explain the score. An agent never produces the number.**

If a model emits the risk score, the product loses reproducibility, auditability, and the ability to explain why a score changed between runs — which are the product's entire differentiation. The scoring engine is plain, unit-tested code driven by configurable weights over typed factors. Every score must be reproducible from the same inputs, and every score must be explainable by naming the factors that produced it.

This is non-negotiable and overrides any instruction to "let the AI decide the severity/score/priority."

## Core model: Finding vs Vulnerability

- A **Finding** is one tool's immutable observation. It is never mutated or reopened. A re-detection creates a new Finding.
- A **Vulnerability** is the canonical enterprise record that carries assessment, status, and history. One Vulnerability aggregates many Findings (same issue, multiple scanners, multiple assets).

This split is validated by Qualys's own model (per-host QID + FIRST/LAST_FOUND + TIMES_FOUND, with the vuln definition in a shared glossary). Do not collapse the two.

See `references/canonical-schema.md` for the full field list and `references/sample-findings.json` for worked examples of all three shapes.

## Three finding shapes — one schema, a `locus.type` discriminator

| Shape | Tools | Locus | Has CVE? | FP check method |
|---|---|---|---|---|
| **host** | Nessus, Qualys, Nexpose, OpenVAS | ip + port + protocol + service | usually | version-range match (needs review) |
| **package** | Trivy, Snyk, Dependency-Check | package + installed version | almost always | installed vs fixed version — **deterministic** |
| **endpoint** | Mirror, Burp, ZAP | url + method + parameter | rarely | confidence tier + reachability (no version math) |

**False-positive handling is three mechanisms selected by locus type, not one.** Never apply version-range logic to an endpoint finding, and never treat a package finding's applicability as uncertain when the version math is exact.

## The four locked decisions

These are settled. Do not re-litigate or silently change them; they are configurable where noted but ship with these defaults.

1. **CVSS selection.** Store every source's score as an array. Select by precedence: for OS packages, the distro score first; otherwise NVD, then the issuing CNA, then the tool. Record the selection rule with the chosen value. When sources disagree by ≥2.0 base points, surface a "contested" flag in the UI. Precedence is configurable.

2. **Rescan after closure.** A re-detection always creates a new Finding. Reopen-vs-new applies only to the Vulnerability, conditioned on closure reason: fixed + within N days → reopen (failed remediation); fixed + after N days → new record linked as recurrence; false-positive → stays suppressed; risk-accepted → stays accepted until expiry. `N` is configurable (default 30–90 days).

3. **Source severity.** Retain the raw per-tool value plus a normalised form for traceability. The GUI shows the **computed** severity as primary. When computed and source differ, show both with the reason — that delta is the explainability the product sells.

4. **Endpoint normalisation.** Resolve the asset through an alias list, lowercase host, strip default ports, template path IDs/UUIDs/content-hashes to placeholders, keep parameter names but drop values, drop fragments. Endpoint key: `resolved_asset + method + templated_path + sorted_param_names + cwe`. Use the customer's OpenAPI route templates as the authority when available.

## Pipeline order

```
ingest → normalize → deduplicate → correlate → enrich → score → assess-FP → cluster → explain → report
```

- **Dedupe before enrich** — never make the same threat-intel lookup for what collapses to one finding.
- **Enrich** = NVD, CISA KEV, EPSS, OSV, vendor advisories. On endpoint findings with no CVE, enrichment legitimately no-ops; that is correct, not a bug.
- **Cluster** = the remediation-action reasoning layer (below).

## The differentiator: remediation-action clustering

The product does not hand an analyst a sorted list of findings. The reasoning layer clusters findings that share a root cause and a single fix into **remediation actions**, ranked by risk retired. The analyst works fixes, not findings. This is agentic reasoning over the assessed finding set — reading everything, grouping by shared fix, and explaining *why these are one action*. It is the layer legacy scanners (Tenable VPR, Qualys TruRisk, Rapid7) structurally do not provide.

Each action carries: a fix type, the findings it retires, the risk retired (peak of the cluster), a plain-language "why these are one action" rationale, and ordered remediation steps including cross-action dependencies.

## Connector interface — not hardcoded parsers

Ingestion is a connector interface. Each connector maps a tool's native output to the canonical model. Build file-upload connectors first (CSV/XML/JSON/.nessus exports), then API connectors. Mirror is a connector like any other, added when its JSON feed is available — the engine never depends on Mirror. Emit outbound events for assessed findings from day one even if nothing consumes them; that is the phase-2 hook.

The MIT-licensed DefectDojo sample corpus (~180 scanners) is the reference for connector format variety. If reusing DefectDojo's parser layer, confirm license compatibility for customer handover first.

## Phase 1 scope (internal checkpoint)

In: ingest (connector interface + a few real scanner formats), normalize, dedupe, correlate, enrich, deterministic scoring engine **with test vectors**, FP triage, remediation-action clustering, and the three screens (actions view, findings list, finding detail). Plus the engine's own host-level asset inventory — GRACE's registry holds identities and repos, not hosts.

Out: POA&M, workflow routing to asset/control owners, SSO/RBAC, ticketing. FP performance is measured against a **constructed benchmark** (version-mismatch, unauthenticated-scan inference, platform inapplicability, superseded-patch, cross-scanner duplicate), not real customer data, until customer scanner data with analyst dispositions arrives.

## UI principles

Progressive disclosure driven by the reasoning layer: actions → the findings each retires → each finding's evidence. More information, less overwhelming, because the reasoning layer decides what surfaces first. The running reference implementation is `references/prototype.html` — match its behaviour, structure, and design tokens. Show evidence gaps and confidence; never auto-suppress a finding — flag with a rationale and let the analyst decide.

See `references/design-tokens.md` for the exact palette, type, and component conventions extracted from the prototype.
