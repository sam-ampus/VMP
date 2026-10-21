# Decision log

One line per decision: date, what was decided, why, and where it came from. Newest at the bottom. Later steps append here.

*"Kickoff" means the 2026-10-05 to 2026-10-12 sessions. "Skill" means `skill/vmp-findings-engine/SKILL.md`.*

| Date | Decision | Why | Source |
|---|---|---|---|
| 2026-10-05 | Agents never produce the score; deterministic code does | Reproducibility and auditability are the product | Skill invariant |
| 2026-10-05 | Locked decisions 1–4 (CVSS precedence, rescan after closure, source severity, endpoint normalisation) | Settled up front | Skill |
| 2026-10-05 | Skill rules win over conflicting reference files (sample CVSS rule, prototype "contested" flag, confidence tiers) | The skill is authoritative | Kickoff review |
| 2026-10-05 | Confidence enum = confirmed / likely / potential / untested / unvalidated | Reconciles the Mirror tiers in the schema notes with the prototype | Kickoff review |
| 2026-10-05 | Prototype scores are illustrative and are not test targets | The prototype says so | Kickoff review |
| 2026-10-07 | Python 3.12 engine + TypeScript UI | Cross-ecosystem version math, DefectDojo reference parsers, Pydantic unions | Sam |
| 2026-10-07 | Works offline; intel via live fetch **or** imported bundle, same snapshot format | Government network constraints | Sam |
| 2026-10-07 | AI provider is config and optional; a model decline is a normal outcome | Model availability depends on the ATO; no score depends on a model | Kickoff |
| 2026-10-07 | FIPS-only crypto, UBI 9 base, hash-pinned deps, config via env and mounted files | GovCloud authorisation | Kickoff |
| 2026-10-07 | Five agent roles; each output typed and checked by code | Defines the agentic component | Kickoff |
| 2026-10-07 | Plan for general Claude models (Opus for clustering, Sonnet/Haiku for bulk), not Mythos | Mythos access is restricted and not in GovCloud; it's a poor fit for these tasks | Kickoff |
| 2026-10-09 | FedRAMP **Moderate** (not High) | Corrected by Sam | Sam |
| 2026-10-09 | Add a report export (HTML/PDF + CSV/JSON) to Phase 1 | Covers "report on them" in Donna's ask | Oct 9 plan |
| 2026-10-09 | FP reduction = flagged and set aside, never auto-closed (*confirm with Donna*) | Analyst stays in control; measured on the benchmark | Oct 9 plan |
| 2026-10-09 | POA&M and owner routing out of every phase unless Donna asks | Donna's ask | Oct 9 plan |
| 2026-10-09 | Phase 1: Claude writes all code, with a short walkthrough after each step; Phase 2: co-write + interview drills | Delivery to Donna first; learning goal | Sam |
| 2026-10-09 | Findings frozen; tuples, Decimals; unknown fields rejected (Evidence excepted) | Immutability and exact reproducibility | Step 1 |
| 2026-10-09 | `vulnerability_id` assigned at correlation, not stored on Finding | Can't store a later fact on an immutable record | Step 1 |
| 2026-10-12 | Append-only `Sighting` rows instead of updating `times_detected` | Keeps Findings immutable; gives an audit trail | Sam |
| 2026-10-12 | Idempotency key unique only within a Vulnerability's open period | Lets a re-detection find the closed record and apply decision 2 | Sam |
| 2026-10-12 | Threat-intel enrichment is a separate record per CVE + snapshot id, never on a Finding | Dedupe before enrich: one lookup per CVE | Sam |
| 2026-10-12 | Additive scoring model, weights `w-0.1` as versioned data | Explainability; policy changes never rewrite past scores | Step 2 |
| 2026-10-12 | Unknown context = 0 points, listed in `missing_inputs` | Honest; gaps visible rather than guessed | Sam |
| 2026-10-12 | Fix availability never changes risk; ease of remediation shown separately and used as a ranking tie-break | Easier to fix ≠ less dangerous | Sam |
| 2026-10-12 | Don't reorder the BUILD_SPEC build order (no alpha-first detour) | Sam's call | Sam |
| 2026-10-12 | Demo data via `seed/demo/`: DefectDojo scans (MIT), Mirror PDF transcribed, mock `assets.csv`, intel bundle; canonical-JSON connector until native connectors exist | No customer data for the first viewing; mock data still goes through the real ingest path | Sam |
| 2026-10-12 | CVSS selection runs after enrichment, not at ingest | Live data showed the CNA score is 7.2, not Trivy's "ghsa 6.5" | Step 3 |
| 2026-10-12 | CVSS v3.1 preferred over v4.0 when both exist (configurable) | Weights calibrated on v3 | Step 3 |
| 2026-10-21 | Design notes live in `docs/design/`, one per step plus this log; `CLAUDE.md` points sessions here | The kickoff history was lost to a folder mismatch | Sam |
