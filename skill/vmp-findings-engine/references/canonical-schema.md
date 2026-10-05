# VMP Canonical Finding Schema — v0.1 design notes

Derived from the DefectDojo sample corpus (Nessus, Qualys, Trivy, Snyk, Nexpose) correlated against the Mirror scan report `afd57ac3`.

Companion file: `canonical_findings_sample.json`

---

## The core idea

**A Finding is one tool's observation. A Vulnerability is the enterprise record.**

One vulnerability can produce many findings — the same CVE seen by two scanners on four hosts is one vulnerability and eight findings. Findings are immutable. Vulnerabilities carry assessment, status, and history.

This is not an invention. Qualys already models it this way: per-host it records `QID + FIRST_FOUND + LAST_FOUND + TIMES_FOUND`, while the vulnerability definition lives once in a `GLOSSARY` block. We are adopting a proven structure, not designing one.

---

## Three finding shapes, one schema

The corpus contains three fundamentally different kinds of finding. A schema that assumes "asset + port" breaks on two of them.

| Shape | Tools | Locus is | Has CVE? | Fix is |
|---|---|---|---|---|
| **host** | Nessus, Qualys, Nexpose, OpenVAS | IP + port + protocol + service | Usually | A patch |
| **package** | Trivy, Snyk, Dependency-Check | Package + installed version | Almost always | A version bump |
| **endpoint** | Mirror, Burp, ZAP | URL + method + parameter | Rarely | A code change |

Handled by a `locus` object with a `type` discriminator. Every other field is shared.

---

## Six design decisions worth challenging

### 1. CVSS is an array, not a number

Trivy returns a dictionary of scoring sources that disagree — on `CVE-2024-28248`, bitnami says 7.2 and ghsa says 6.5. Nessus supplies CVSS v2 where newer tools supply v3.1.

We store every score with its source, plus a `cvss_selected` object carrying the chosen value **and the rule that chose it**. Without the rule recorded, scores are not reproducible, and reproducibility is an explicit acceptance criterion.

*Open decision:* current default is `max_base_across_sources`. Alternatives are NVD-preferred, or vendor-preferred. This is a policy choice and should be configurable.

### 2. Validation confidence is first-class

Mirror is the only tool in the corpus that reports how far a finding was validated — Confirmed / Likely / Potential / Untested. On scan `afd57ac3`, that breakdown was 3 / 12 / 52 / 3.

Nothing else in the corpus has an equivalent, so scanners default to `unvalidated`. This field is what the triage layer operates on, and it is why a naive severity sort is misleading: a Confirmed medium is a fact, a Potential critical is a lead.

### 3. Inferred mappings are flagged

Mirror marks OWASP and CWE mappings as "(inferred)" — derived from the finding rather than asserted by the agent. On scan `afd57ac3`, CWE-1000 (the root node of the CWE tree, effectively *unclassified*) accounted for 29 of 70 findings.

Treating an inferred CWE-1000 as equivalent to an asserted CWE-89 would corrupt any control mapping built on top. `inferred_mappings` lists which fields were derived rather than asserted.

### 4. Evidence completeness is recorded, not assumed

The Mirror report disclosed that 12 findings had no captured request, 20 recorded headers without a body, and 60 had no proof-of-concept script.

A finding with no evidence and a finding with a full exploitation trace should not be presented identically. `evidence_completeness` plus `evidence_gaps` make the difference visible rather than something a reader must infer.

### 5. Exploit signals come from the tool where available

Nessus supplies `exploit_available` and `exploitability_ease` directly. That is real exploitability intelligence independent of EPSS or KEV, and it should feed the score rather than being discarded in favour of an external lookup.

### 6. Package findings make false-positive checking deterministic

For the package shape, `installed_version` + `fixed_version` + `fix_status` allows applicability to be computed in code. No model required, no ambiguity.

This is the highest-precision false-positive logic available and it is free. Host findings need version-range matching against the affected product, which is harder. Endpoint findings cannot be checked this way at all and depend on the confidence tier plus reachability reasoning.

**Implication:** false-positive handling is not one mechanism. It is at least three, selected by locus type.

---

## Deduplication

`idempotency_key` is deterministic per shape:

- host: `tool:native_id:ip:port:protocol`
- package: `tool:cve:purl`
- endpoint: `tool:scan_id:url:method:parameter`

Same key means the same observation seen again — update `last_detected` and `times_detected`, do not create a new finding.

Cross-tool correlation into a shared `vulnerability_id` is a separate step: CVE match plus asset match for host and package shapes, and CWE plus normalised endpoint for the endpoint shape. Near-misses are the only place judgement is required.

---

## Deliberately absent

- **Enrichment results.** EPSS and KEV populate after ingestion. Empty at ingest time is correct.
- **Assessed risk score, priority, rationale.** These belong to the Vulnerability record, not the Finding. Findings are immutable observations.
- **Asset business context.** `asset_ref` points at the asset inventory. Criticality, owner, and environment live there, not duplicated here.
- **POA&M and workflow fields.** Out of scope per agreed direction.

---

## Locked decisions

### 1. CVSS selection — follow industry standard, flag disagreement

Precedence: for OS packages, the distribution's own score first (distros backport fixes; NVD does not track that). For everything else, NVD first, then the issuing CNA's score, then the tool's score. CNA fallback matters because NVD has a scoring backlog from early 2024 onward, so many recent CVEs have no NVD score.

CVSS is an input, never the final priority — the enterprise risk score sits on top, which is where differentiation belongs. One cheap high-fidelity addition: when sources disagree by ≥2.0 base points, flag it in the UI so the analyst knows the severity itself is contested. The data is already stored per-source; this is display only.

### 2. Rescan after closure — window rule, conditioned on closure reason

A re-detection **always** creates a new immutable Finding. Reopen-vs-new applies only to the Vulnerability record:

- Closed as **fixed**, re-detected **within N days** → reopen the same vulnerability (failed remediation; preserves history and failure metrics).
- Closed as **fixed**, re-detected **after N days** → new vulnerability, linked to the prior one as a recurrence (likely regression).
- Closed as **false positive** → stays suppressed; do not reopen unless evidence materially changes.
- Closed as **risk accepted** → stays accepted until the acceptance expires.

`N` is configurable (default 30–90 days). A downstream ticket follows the vulnerability record: reopen reopens the ticket, new record opens a new linked ticket. Ticketing itself is out of scope for v1.

### 3. Source severity — retain raw, compute for display

Every tool uses a different scale (Nessus 0–4 + risk factor, Qualys 1–5, Trivy/Mirror LOW–CRITICAL). Store the raw value (`source_severity_raw`) plus a normalised form for traceability and reporting. The GUI shows the **computed** severity as primary. When computed and source differ, show both with the reason — that delta is the explainability the product sells.

### 4. Endpoint normalisation — path templating with asset alias resolution

Collapse loci by: resolving the asset through an alias list (so `192.168.100.10:8000` and `erp.fintec.solutions` are one application), lowercasing host, stripping default ports, templating path IDs/UUIDs/content-hashes to placeholders (so `/party/update_party/42/` = `/party/update_party/{id}/`, and `main.76a700c38298b5c8.js` = `main.{hash}.js`), keeping parameter names but dropping values, and dropping fragments. Use the customer's OpenAPI route templates as the authority when available.

Endpoint key: `resolved_asset + method + templated_path + sorted_param_names + cwe`.

Both problems are visible in the Mirror `afd57ac3` data: content-hashed bundle names, and the same app addressed two ways producing split endpoint counts.
