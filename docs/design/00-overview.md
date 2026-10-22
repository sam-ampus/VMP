# 00 — Overview: what we're building, why, and how it fits together

*Backfilled 2026-10-21 from the kickoff sessions (2026-10-05 to 2026-10-12), the approved Phase 1 plan (2026-10-09), and the code. Later notes add to this; the decision log is [`decisions.md`](decisions.md).*

## How this started

- **2026-10-05:** the project arrived as a pre-written bundle, now the first commit (`c3281db`):
  - `BUILD_SPEC.md`: architecture and build order.
  - The `vmp-findings-engine` skill: invariants and locked decisions.
  - `references/`: canonical schema, sample findings, `prototype.html`, design tokens.
- **First instruction:** read everything and confirm the invariant and the four locked decisions before writing any code.
- **That review found conflicts in the references.** Examples: the sample's CVSS rule contradicted locked decision 1; the prototype flagged a 0.7-point CVSS gap as "contested" when the threshold is 2.0; the confidence tiers were mixed up. The skill's rules win where they disagree.
- **2026-10-07, Donna's ask:**

> "An automated capability to assess vulnerability findings and report on them — with false-positive reduction, and without POA&M or owner/control-owner routing."

Every feature should trace back to that sentence:

| Her words | Where it lands |
|---|---|
| Automated | Pipeline runs unattended, ingest → ranked actions |
| Assess findings | Deterministic, explainable risk score |
| Report on them | Three screens **plus a report export** (HTML/PDF + CSV/JSON), added because screens alone are triage, not a report |
| False-positive reduction | Three FP mechanisms, one per finding shape. Likely FPs are **flagged and set aside, never auto-closed**. *Still to confirm with Donna* |
| No POA&M, no owner routing | Excluded from every phase unless she asks |

## Constraints that shaped the design

- **Deployment:** the agency's own AWS GovCloud at **FedRAMP Moderate** (corrected from High on 2026-10-09).
- **Network:** outbound internet is allowed, but everything must also work **offline from imported bundles**.
- **Supply chain:**
  - FIPS-approved crypto only (SHA-256, never MD5 or SHA-1).
  - Hardened base image (Red Hat UBI 9) and a hash-pinned lockfile.
  - Config only through environment variables and mounted files. No cloud SDKs in the core.
- **AI model:** a configuration setting (Bedrock in GovCloud once AWS permissions land), and optional. The engine runs with the model off. Only clustering and written explanations degrade.
- **Language and stack:** Python 3.12 (uv, Pydantic v2, FastAPI later) for the engine, TypeScript for the UI.
  - Python won for its cross-ecosystem version comparison (Debian/RPM/Go ordering is hard to hand-roll).
  - It also won because DefectDojo's reference parsers are Python, and Pydantic's discriminated unions fit the three finding shapes.

## The one invariant

**Agents gather and classify evidence. Deterministic code computes the score. Agents explain the score. An agent never produces the number.**

*First principles:* a security score is only useful if it is **reproducible** (same inputs, same number), **auditable** (you can show why) and **stable** (it changes only when inputs or versioned policy change). A model's output has none of those properties. So the number comes from code, and the model works around it.

## The four locked decisions

1. **CVSS selection.**
   - Store every source's score.
   - Choose by precedence: distro (OS packages only), then NVD, then CNA, then the tool.
   - Record the rule that chose it.
   - Flag "contested" when sources differ by ≥ 2.0.
2. **Rescan after closure.** A re-detection is always a new Finding. Only the Vulnerability reopens, depending on why it was closed:

   | Closed as | Re-detected | Outcome |
   |---|---|---|
   | Fixed | within N days | reopen (the fix failed) |
   | Fixed | after N days | new record, linked as a recurrence |
   | False positive | any time | stays suppressed |
   | Risk-accepted | any time | stays accepted until the acceptance expires |

3. **Source severity.** Keep the raw value and a normalised one. Show the **computed** severity first. When computed and source differ, show both with the reason.
4. **Endpoint normalisation.**
   - Resolve the asset alias, lowercase the host, strip default ports.
   - Template IDs, UUIDs and hashes in the path; keep parameter names and drop their values.
   - The key is `asset + method + templated_path + sorted_params + cwe`.

## System map

```
 scanner files ─► ingest ─► normalise ─► dedupe ─► correlate ─► enrich ─► score ─► assess-FP ─► cluster ─► explain ─► report
                  └──── connectors ────┘                        │         │                   │           │
                                                       threat intel   deterministic       AI proposes,   AI writes,
                                                      (NVD/KEV/EPSS/   engine + weights   code verifies   code checks
                                                       OSV snapshots)                     and ranks       against trace
 asset inventory ──────────────────────────────────────────────────────────►┘
```

| Stage | Status (2026-10-22) |
|---|---|
| Canonical schema + validation | **Built** (step 1), see [01-schema](01-schema.md) |
| Scoring engine + test vectors | **Built** (step 2), see [02-scoring](02-scoring.md) |
| Threat intel + CVSS selection | **Built** (step 3), see [03-intel](03-intel.md) |
| Asset inventory | **Built** (step 4), see [04-assets](04-assets.md) |
| Connectors (canonical JSON, Trivy) + seed data + glue | Next (step 5) |
| Nessus/Qualys, dedupe/correlate, FP triage | Stage 2 |
| Clustering, UI, report, events | Stage 3 |

**Gap to know about:** nothing yet builds a `ScoringInput` from a real Finding. The engine, intel and schema are each tested on their own but not yet wired together. Step 5 adds that glue.

## Where AI is and isn't allowed: five agent roles

Each agent returns typed, schema-validated output. Code checks it before using it.

| Agent | Does | Code then |
|---|---|---|
| Evidence | Reads raw scanner output, emits typed facts with citations | Validates, then scores with fixed weights |
| FP triage (host and endpoint only) | Extracts version and reachability facts | Maps facts to an FP band by rule; never suppresses |
| Correlation (near-misses only) | Proposes merge or no-merge with a reason | Shows the proposal; exact-key dedupe stays deterministic |
| Remediation clustering (the differentiator) | Groups findings by shared fix and explains why | Verifies the shared basis and computes the ranking |
| Explanation | Writes "why this rating" | Rejects any text naming a factor or number not in the trace |

Package findings need no FP agent: comparing installed and fixed versions is exact.

## Roadmap

- **Phase 1:** this build (Stages 1–3), delivery to Donna.
- **Phase 2:**
  - Mirror JSON connector.
  - Tenable/Qualys API connectors.
  - Real analyst data for FP accuracy.
  - GovCloud + Bedrock deployment.
  - Settle the IP arrangement.
- **Phase 3:** ticketing hand-off, SSO/RBAC.
- **Phase 4:** weights tuned from analyst feedback (versioned, re-validated against the vectors); SLA, recurrence and trend metrics.

## Open items

- A masked **Mirror JSON** feed. So far we only have a rendered PDF report.
- **Which scanners the customer runs.** This sets connector priority after Trivy and Nessus.
- **IP arrangement:** the customer owns the source, but Ampcus integrates in Phase 2. These need reconciling.
- Confirm with Donna that "FP reduction" means flagged and set aside, not removed.
- Elevated AWS permissions (pending since 2026-10-07).

## Check yourself

1. Why does turning the model off never change a score, and what *does* degrade?
2. Which part of Donna's sentence would be unmet if we shipped only the three screens?
3. Why is "offline bundles" a design constraint at step 3 rather than a deployment detail?
