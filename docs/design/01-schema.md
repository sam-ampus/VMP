# 01 — Canonical schema and validation (Stage 1, step 1)

*Built 2026-10-09 to 2026-10-12. Backfilled 2026-10-21 from that session's walkthrough and Q&A.*

## Problem from first principles

Scanners describe the same reality in incompatible ways. Nessus talks about hosts and plugins, Trivy about packages and versions, Mirror about URLs and parameters. Before anything can be compared, deduplicated or scored, it needs **one shape**. That shape has to make bad data impossible rather than merely unlikely, because every later layer trusts it.

What must be true:
- **A scanner's observation never changes after the fact.** It's evidence.
- **The enterprise view does change.** Status, closure and history move over time, so it needs a separate record.
- **Two sightings of the same thing must be recognisably the same.**

## System view

- **Sits at:** the front door. Everything after ingest reads only these types.
- **In:** dicts from connectors.
- **Out:** validated, frozen records, or a complete list of errors.
- **May not know:** scores, threat intel, policy thresholds. Those belong to later layers.

The main models:
- **`Finding`** (`src/vmp/schema/finding.py`): one tool's immutable observation. Its `locus` is a discriminated union on `locus.type`:

  | Shape | Locus class | Found by |
  |---|---|---|
  | host | `HostLocus` | Nessus, Qualys |
  | package | `PackageLocus` | Trivy, Snyk |
  | endpoint | `EndpointLocus` | Mirror, Burp |

- **`Vulnerability`** (`vulnerability.py`): the enterprise record. It aggregates Findings and carries status, closure, history, `RiskAssessment` (with named `Factor`s) and `FPAssessment`.
- **`Sighting`**: an append-only row each time a Finding's key is seen again.
- **`RemediationAction`** (`action.py`): a cluster of findings with a shared fix.
- **`keys.py`**: idempotency keys per shape. **`validation.py`**: `validate_batch()`.

## Choices and trade-offs

1. **Rules live in the types.** Some records can't be built at all:
   - a risk assessment with no factors;
   - computed and source severity differing with no reason given;
   - a package with `fix_status=fixed` and no fixed version.

   Explainability is enforced, not a convention.
2. **Unknown fields are rejected** (`extra="forbid"`). That's how three real errors in the original sample surfaced on their own. Raw `Evidence` is the one deliberately open record, because every tool emits different evidence fields. It's also the one place unvalidated data can get in.
3. **Frozen records, tuples instead of lists.** "Findings are never mutated" is enforced by code, nested values included.
4. **Decimals, not floats.** 0.1 + 0.2 ≠ 0.3 in floating point, and a score must be exactly reproducible.
5. **`validate_batch()` returns every error**, not the first. One bad record doesn't hide the others, and a full error list is what you'd hand an agent to repair its output.
6. **Policy stays out of the schema.** The schema says what a record *is*; policy decides what it *means*.
   - Step 1 had a `cvss_spread()` helper on the schema, with the 2.0 "contested" threshold kept out of it.
   - In step 3 the whole CVSS choice moved to `pipeline/cvss.py`, so the helper is gone.
7. **The idempotency key is stored and re-checked.** The validator rebuilds the key from the finding's own fields and rejects a mismatch. Computing it on the fly would make a mismatch impossible, but storing it lets us catch connector bugs and index on it.

**Decided with Sam (2026-10-12):**
- **Append-only sightings instead of updating `times_detected`.**
  - *Pros:* findings stay immutable, so scores stay reproducible. You get a full audit trail. Concurrent writes are safe. Metrics like time-open and flapping become possible.
  - *Cons:* one row per finding per scan, and reads must aggregate (a cached view fixes this).
- **The key is unique only within a Vulnerability's open period.** A re-detection after closure gets the *same* key. That's what makes locked decision 2 work: the key finds the closed record and its closure reason (reopen, recurrence, or stays-suppressed). Without it, analysts would re-triage the same false positives on every scan.
  - *Limit:* keys are per tool. The same issue reported by a different scanner is caught by correlation (CVE + asset), not by the key.
- **`vulnerability_id` moved off the Finding.** It's assigned at correlation, after ingest, so storing it on an immutable record would be a contradiction.

**Fixture corrections.** `references/` is untouched; `tests/fixtures/sample-findings.json` is a corrected copy:
- the endpoint parameters are split into names, with the original kept in `parameter_raw`;
- the stray `vulnerability_id` is removed.

The CVSS fix made here (choosing GHSA 6.5) later proved wrong and was undone in step 3; see [03-intel](03-intel.md).

## Applied AI tie-in

This schema is also **the contract agents must satisfy**. When an agent returns something invalid, the same validators reject it, and the full error list goes back for a retry. You make model output trustworthy by validating it against a contract, not by trusting the model.

## Code tour (read in this order)

1. `src/vmp/schema/types.py`: the base `Model` (frozen, forbids extra fields) and the constrained types (`CveId`, `CvssBase`, …).
2. `src/vmp/schema/enums.py`: the vocabulary.
3. `src/vmp/schema/finding.py`: the loci, `Finding`, `Sighting`. Watch for the `model_validator`s.
4. `src/vmp/schema/keys.py`: the key builders, written to take plain values so connectors can reuse them.
5. `src/vmp/schema/validation.py`: `validate_batch()`.
6. `tests/schema/test_finding.py`: one failing case per rule.

## Check yourself

1. Why would updating `last_detected` on a Finding break reproducibility of a past score?
2. A Mirror finding and a Burp finding describe the same SQL injection. Which mechanism links them, the key or correlation, and why?
3. What's the risk of `Evidence` allowing extra fields, and where would you put a guard?
