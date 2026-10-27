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
| 2026-10-22 | `AssetProvider` Protocol + `AssetInventory` (in memory); CSV is only a parser | The asset data source is the most likely thing to change at the customer | Step 4 |
| 2026-10-22 | Ambiguous identifiers (shared alias, alias = another ref, duplicate ref) reject the whole inventory at load | Guessing would silently give a finding another asset's context | Step 4 |
| 2026-10-22 | Blank inventory fields stay `None` (unknown), never defaulted | Matches the "unknown = 0 points, listed as missing" scoring decision | Step 4 |
| 2026-10-22 | `RiskAssessment.asset_inventory_id`: content hash of the inventory a score used | Weights + intel + inventory versions together make every score replayable | Step 4 |
| 2026-10-22 | Identifier normalisation here = lowercase, trim, canonical IP; port and URL handling deferred to endpoint normalisation | Keep locked decision 4 in one place | Step 4 |
| 2026-10-22 | Mock `seed/demo/assets.csv` moved from step 4 to step 5 | It must match the DefectDojo scans, which are chosen in step 5 | Step 4 |
| 2026-10-22 | Connectors only translate (native → canonical dict); every connector's output goes through the one `validate_batch()` | A new connector can't weaken the schema rules | Step 5 |
| 2026-10-22 | Deterministic ids: `finding_id = sha256(scan_id, key)`; scan id from file content when not supplied; clock passed in | Re-ingesting a file is a no-op; runs are byte-identical | Step 5 |
| 2026-10-22 | Unknown assets ingest as `ast_unresolved_<name>` and score without context | Don't hide findings; don't guess context | Step 5 |
| 2026-10-22 | Intel beats the tool for KEV/EPSS; the tool's value is the fallback when intel is silent | CISA and FIRST are authoritative; the scanner's copy can be stale | Step 5 |
| 2026-10-22 | **Endpoint idempotency key now includes CWE** (`tool:scan:url:method:params:cwe`) | Different weaknesses on one endpoint were collapsing; matches locked decision 4's endpoint key | Step 5 (found by the slice) |
| 2026-10-22 | **Distro CVSS tier uses only the package's own distro** (`select_cvss(distro=…)`, from the purl namespace) | An Alpine package was taking Red Hat's score | Step 5 (found by the slice) |
| 2026-10-22 | `FixStatus` gains `under_investigation`; Trivy `fixed` with no version maps to `unknown` | Trivy's real vocabulary; don't claim a fix that names no version | Step 5 |
| 2026-10-22 | Trivy UNKNOWN severity maps to `info`, with the raw value kept | Schema has no "unknown" severity; the raw value stays traceable | Step 5 |
| 2026-10-22 | Mirror PDF transcribed by script: structured fields only, secrets redacted (refuses to write if any remain); `ALL`/`N/A`-method findings skipped | Report is confidential and contains live keys; never invent a method | Step 5 |
| 2026-10-22 | DefectDojo samples are BSD-3-Clause (not MIT as noted 2026-10-12); notice shipped alongside | Licence requires the notice | Step 5 |
| 2026-10-26 | Step 6 built against the team's real Qualys/Nessus samples, not DefectDojo's | Real data arrived; BUILD_SPEC already said "real sample files" | Sam |
| 2026-10-26 | Real client samples git-ignored (`sample-data-nessus-qualys/`, `data/private/`); committed tests use synthetic files; a local-only test runs the real ones | They are third-party client data; the repo is on GitHub | Step 6 |
| 2026-10-26 | One Qualys connector for EVA/ASV/IVA (same `scan-1.dtd` format); assessment kind kept as evidence | Same format; the profile differs, the translation doesn't | Step 6 |
| 2026-10-26 | Qualys VULN → `unvalidated` (scanner default); PRACTICE → `potential` (tool-asserted) | Qualys "confirmed" = detection matched, not Mirror's "exploited and verified"; same word, different claim | Step 6 |
| 2026-10-26 | Information-only items (Qualys INFO/SERVICE, Nessus severity 0) skipped and **counted** per tool and reason | About 95% of Nessus items; silent filtering hides recall loss | Sam (approved) |
| 2026-10-26 | `FindingBatch` gains `skipped` and `warnings`; warnings (e.g. Qualys "No host alive") never fail a run | An empty scan is a valid result, not a broken file | Step 6 |
| 2026-10-26 | Same QID, same port, plain + "over ssl" = one finding with both results | One weakness on one service | Step 6 |
| 2026-10-26 | Nessus scan type set per host from `Credentialed_Scan`; all CVSS versions, EPSS and exploit_available kept as tool values | Uncredentialed banner checks are an FP source; locked decision 1 still prefers NVD/CNA | Step 6 |
| 2026-10-26 | Uploaded XML parsed with `defusedxml` (DOCTYPE allowed, entities and external refs refused) | Upload input is untrusted; FedRAMP review expects it | Step 6 |
| 2026-10-26 | `Connector.extensions`: each connector names its file suffixes; drop folders ignore other files | XML and `.nessus` inputs; licence notices sit beside scans | Step 6 |
| 2026-10-26 | Verified: findings with no CVSS already score on source severity (`severity_fallback`); CVSS is listed as missing only when a CVE exists | The gap the samples raised was already handled; now tested end to end | Step 6 |
| 2026-10-27 | Confidence mapping (Qualys Confirmed → unvalidated, Mirror Confirmed → confirmed) approved | Same word, different claims | Sam |
| 2026-10-27 | `ValidationStatus.tool_label` keeps the tool's own word; `confidence_note()` gives a deterministic tooltip text with points read from the weights; the UI shows it on the confidence badge | A reader must see which "Confirmed" they're looking at and what it did to the score | Sam (asked for a tooltip) |
| 2026-10-27 | Mirror seed transcription (`seed/demo/scans/canonical/mirror-afd57ac3.json`) is committed to git | No secrets (redaction guard); the demo needs real endpoint findings | Sam |
| 2026-10-27 | Threat intel fetched for the real samples' CVEs (CVE ids only leave the machine; no IPs, hosts or client names) into git-ignored `data/private/real/intel/` | Real-sample findings need CVSS/KEV/EPSS to score fully | Sam |
