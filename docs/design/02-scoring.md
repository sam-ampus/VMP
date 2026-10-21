# 02 — Deterministic scoring engine and test vectors (Stage 1, step 2)

*Built 2026-10-12. Backfilled 2026-10-21 from that session's walkthroughs and Q&A.*

## Problem from first principles

A risk score has to answer three questions every time:
- **What is the number?**
- **Why that number?**
- **Would it be the same tomorrow on the same inputs?**

Scanner severities fail the last two, and model-produced scores fail all three. So the score is a pure function of typed inputs and versioned weights, and the expected answers were written down **before** the function existed.

## System view

- **Sits at:** after enrich and CVSS selection, before FP assessment and clustering.
- **In:** `ScoringInput` (`src/vmp/scoring/inputs.py`), the only thing the engine reads, plus a `Weights` version.
- **Out:** a `ScoreResult` holding:
  - a 0–100 score, a severity and a band;
  - **named factors** with their contributions;
  - **missing inputs**;
  - a reason whenever computed severity ≠ source severity.
- **May not know:** the clock, I/O, the model, or anything not in `ScoringInput`.

`assess()` scores a Vulnerability as its highest-scoring Finding and records which Finding that was.

## The model (weights `w-0.1`)

**score = sum of factor points, rounded half-up, clamped to 0–100.**

| Factor | Points |
|---|---|
| CVSS base | CVSS × 6 (so 0–60) |
| No CVSS | Source severity as base: critical 57, high 45, medium 33, low 18 |
| Known exploited (KEV) | +25 |
| Public exploit (tool-reported, not already in KEV) | +10 |
| EPSS ≥ 0.5 / ≥ 0.1 / < 0.01 | +15 / +8 / −5 |
| Internet-facing / known internal | +10 / −5 |
| Asset criticality critical / high / low | +8 / +4 / −4 |
| Non-production | −5 |
| Confidence confirmed / likely / untested | +15 / +8 / −8 |
| Evidence partial / none | −3 / −6 |

**Severity thresholds:** critical ≥ 75, high ≥ 50, medium ≥ 25, low ≥ 1, info = 0.

**Sample results** (the prototype's numbers were illustrative, not targets):

| Finding | Computed | Source severity | Prototype |
|---|---|---|---|
| SQL injection (Mirror) | 82 critical | critical | 94 |
| cilium (Trivy), with live intel | 33 medium | high | 61 |
| RDP MITM (Nessus) | 26 medium | medium | 48 |
| End-of-life host | 47 medium | critical | 64 |

The gaps between computed and source severity are the "here's why we differ" story the product sells.

## Choices and trade-offs

- **An additive model, for explainability.** Each factor adds points, so the engine can always say exactly why. A learned model might rank better but can't explain itself. That trade-off is the reason the number stays out of the agents' hands.
- **CVSS alone tops out at 60.** Reaching critical needs threat or exposure evidence on top.
- **Weights are versioned data** (`weights/w-0.1.json`), not code. Every assessment records the version, so a policy change never silently rewrites past scores. `load_weights()` rejects incomplete weights, for example a confidence tier with no value.
- **Pure functions.** The caller passes the assessment time, so the same inputs give an identical result.
- **Deterministic tie-break.** When findings tie, the lowest finding id wins, so input order never matters. A test checks both orders.
- **The severity-delta reason is built by code**, for example "Computed medium vs source high: epss (−5), internet facing (−5)". The explanation agent may rephrase it later, but its text is checked against these factors.

**Decided with Sam (2026-10-12):**
- **Unknown context is neutral (0 points) and listed in `missing_inputs`**, not worst case. It's honest, but it can under-score assets the inventory hasn't covered yet. The missing list makes that visible.
- **Fix availability never changes the risk score.** A fix makes remediation *easier*, not the vulnerability less dangerous. Ease is shown separately (fix available / workaround only / no fix) and breaks ties in action ranking. That gets built with the remediation actions.
- **Weights accepted as-is for now**, to revisit later.

## Applied AI tie-in

- **Vectors are a golden eval set.** They were hand-written before the system, each with a one-line "why".
  - `test_vectors_consistency.py` checks the vectors' own arithmetic (score = rounded factor sum) before any engine existed.
  - It can't catch a bad *policy* choice. Human review does that, just as labelling does for an LLM eval. This is the *oracle problem*.
- **Metamorphic and property tests.** "Adding KEV, an exploit, internet exposure or confirmation never lowers a score" is checked against every vector. When you can't hand-write every expected output, as with LLM systems, you test relationships between outputs instead.

## Code tour

1. `src/vmp/scoring/inputs.py`: `ScoringInput`, `FactorName`, `MissingInput`.
2. `src/vmp/scoring/weights/w-0.1.json`, then `weights.py`.
3. `tests/scoring/vectors/w-0.1.json`: read about ten cases; each has a `why`.
4. `src/vmp/scoring/engine.py`:
   - `score()` → `_base()` → `_modifiers()` → `_missing()` → `_delta_reason()`;
   - then `assess()`.
5. `tests/scoring/test_engine.py`: the property tests.

## Record notes

- On 2026-10-12 the session reported 44 vectors. The file now holds **43**.
- The record doesn't say which case was removed. It probably happened during the step-3 CVSS correction, which rewrote the cilium vector. Worth a look if it matters.

## Check yourself

1. Why does "CVSS × 6, capped at 60" force critical scores to carry threat or exposure evidence?
2. An asset is missing from the inventory. What does the score do, and how does the analyst find out?
3. You want to change KEV from +25 to +30. What has to change, and what happens to yesterday's scores?
