# 08: False-positive triage and the FP benchmark (Stage 2, step 8)

*Built 2026-10-28 to 2026-10-29.*

## Problem from first principles

A scanner finding is a claim: "this weakness is here." Some claims are wrong. The scanner read a version string that a distro had already patched behind, ran a Windows check against a Linux box, or never managed to log in and guessed. Analysts lose most of their time on these claims.

What must be true:
- **Never hide a real issue.** A missed false positive costs an analyst minutes; a real issue wrongly dismissed costs a breach. The costs are asymmetric, so the system must be built around the second one.
- **"Probably not real" is not "less dangerous".** A critical that's probably a false positive is still critical *if* it's real. So the FP judgement is a separate axis beside the score, never folded into it (Sam's decision, 2026-10-28).
- **Certainty only where it's earned.** Comparing an installed package version with a fixed version is exact, so say so. Inferring a host's software from a banner isn't, so never claim it is.
- **Measured, not asserted.** A constructed benchmark with a hard rule, until analysts' real verdicts exist.

## System view

```
Finding ─► assess_fp(finding, osv)           dispatch on locus type (the skill's rule)
             ├─ package  ► exact version math   dpkg / rpm / apk (ours) · PyPI (packaging)
             │             tool's fixed version → vendor fix status → OSV ranges → else review
             ├─ host     ► version-range rules  platform? → installed≥fixed? → potential?
             │                                  → banner without login? → else likely real
             └─ endpoint ► confidence + evidence  confirmed/likely+evidence → likely real
                                                  everything else → review (never "not real")
           ─► FPAssessment {band, rationale, facts}       one per finding
Correlated ─► combine()  ─► VulnerabilityFP {band, rationale, facts, findings[]}
                          disagree → review · "not real" needs all to agree
                          2 tools + one with a login → corroboration

score (unchanged) ──┐
FP band ────────────┴─► vmp ingest: "FP check" column + section; JSON fp_assessment
benchmark/cases/*.json ─► python -m benchmark ─► precision · recall · review rate · HARD RULE
```

**Connector change (B-017, now resolved):** Qualys's header says "Authentication ON" when a login was *configured*. Whether it *worked* is a per-host information item ("Unix Authentication Failed", QID 105053). The connector now reads it, records `host_auth` on each finding, treats that host's findings as unauthenticated, and warns. **On the real samples, 7 hosts had failed logins** that were previously treated as authenticated.

## Bands

| Band | Means | Who can give it |
|---|---|---|
| `confirmed_applicable` | Version math says it applies | package only |
| `confirmed_not_applicable` | Version math or the vendor says it doesn't | package only |
| `low_likelihood` | Low FP likelihood: likely real | all |
| `needs_review` | Can't tell by rule; a person should look | all |
| `likely_false_positive` | A fact contradicts the finding | host (package uses `confirmed_not_applicable`) |

The schema already enforced "endpoints can't be `confirmed_*`" and "the mechanism matches the shape" (step 1). Step 8 is the first code that produces these values.

## Choices and trade-offs

- **FP band beside the score, not inside it** (Sam). Same pattern as fix availability. The trace stays honest: a score can be explained without knowing whether a person has checked it yet.
- **Version comparison written in-house** (Sam): the dpkg, rpm and apk algorithms are ports of the reference implementations, tested against rpm's whole `rpmvercmp` suite and the dpkg/apk rules, with `packaging` for PEP 440. One dependency added instead of a multi-ecosystem library. npm and Maven wait (B-024): they get `needs_review` with that reason.
- **Package evidence order:** the vendor's fixed version (via Trivy) is the most specific statement, so it goes first; OSV ranges only fill gaps. Disagreement between the two isn't detected yet (B-053).
- **Fixes on several branches** (2.4.1 and 3.0.2, installed 2.9.0): the version string doesn't say which branch the install follows, so this is review, not a guess. It's in the benchmark as a known miss.
- **Host rules are ordered, and the first match wins.** A platform contradiction outranks everything, because a Windows KB check on a Linux host is wrong whatever else is true. "Installed ≥ fixed" in the scanner's *own* output comes next, because the scanner contradicts itself.
- **Backported banners go to review, not "likely FP".** OpenSSH 8.9p1 on Ubuntu may or may not carry the fix. Saying "likely FP" would be a guess that sometimes hides a real issue. The facts name the distro suffix so the analyst knows exactly what to check. Recall pays for this, by design.
- **Unknown login counts as no login.** The same rule as "unknown context = 0 points": no credit for what we can't show.
- **Corroboration needs independence.** Two tools both reading the same banner without a login agree for the same wrong reason. Agreement lifts `needs_review` only when at least one tool logged in.
- **Endpoints are never called "not real" yet.** Saying a web finding is false needs a fact against it (unreachable route, a response that contradicts it). Nothing provides that yet (B-052). An untested finding needs a person, not dismissal.

## Results

- **Benchmark** (`uv run python -m benchmark`): 44 cases.
  - **100% precision** on the "not real" call: 13 of 13 calls were correct.
  - **72% recall** (13 of 18 FPs caught); the 5 misses are deliberate known limits (backported banners, branch ambiguity, endpoints).
  - Review rate 25%.
  - **0 real issues called not real; 0 FPs called real.**
- **Demo seed:** 66 vulnerabilities. 9 confirmed applicable, 14 likely real, 42 review, and 1 vendor-marked "not affected" (a Trivy finding in the DefectDojo sample that was reported anyway). **Every score is identical to step 7.**
- **Real samples** (local only, counts): 898 vulnerabilities, 481 likely real and 417 review. Most of the review pile is Qualys "potential" (586 findings). 0 likely FPs: nothing in these files proves one, and the rules don't guess. The local-only test confirms that every finding the file itself proves is below the fix stays "real".

## Applied AI tie-in

- **The eval comes before the claim.** The benchmark is the contract: labelled cases, a precision/recall readout and a hard safety gate. Known limitations stay *in* the eval as expected misses, so the number shows them rather than hiding them. It's the same discipline as keeping hard cases in a model eval set instead of quietly dropping them.
- **Asymmetric error costs set the decision rule.** When false negatives (missing a real issue) cost far more than false positives, you trade recall on the "not real" class for near-perfect precision. Here that's a rule-level threshold; with a model it would be a calibrated confidence threshold, chosen the same way.
- **Abstention is a first-class output.** `needs_review` is the system saying "I don't know." A good classifier, rules or model, needs a calibrated way to abstain rather than being forced to pick.
- **Where the model will plug in:** the evidence agent will add *facts* (for example, the installed package list read over a credentialed session, or a reachability probe). `assess_fp` still picks the band from those facts, so the decision stays reproducible and the benchmark still applies.

## Known limitations

B-051 to B-057 in the backlog:
- the "version-inferred" text patterns (B-054);
- Cisco-style version strings (B-055);
- no FP-based queue ordering yet (B-056);
- real analyst dispositions to replace the constructed benchmark (B-057).

## Code tour

1. `src/vmp/pipeline/assess_fp/__init__.py`: the dispatch table in the docstring, then `combine`.
2. `versions/rpm.py` (`rpmvercmp`, line for line), `versions/dpkg.py`, `versions/apk.py` and `versions/__init__.py` (`BY_PURL_TYPE`, `dotted`).
3. `package.py`: `_against_fixes`, then `_against_osv` and `_in_range` (OSV's event walk).
4. `host.py`: the rule list in the docstring, then `assess_host` top to bottom.
5. `endpoint.py`: short by design.
6. `connectors/qualys.py`: `_auth_failures` and `host_auth`.
7. `benchmark/harness.py` (metrics and the hard rule), `benchmark/build.py` and `benchmark/cases/*.json`.
8. Tests:
   - `tests/pipeline/assess_fp/` (comparators, OSV ranges, combine);
   - `tests/benchmark/` (the gate actually fails; local-only real check);
   - `tests/pipeline/test_slice.py` (score unchanged by the band).

## Check yourself

1. A Nessus finding on an Ubuntu host says "OpenSSH < 9.6", the scan had no login, and the banner reads `8.9p1 Ubuntu-3ubuntu0.10`. Why does it get `needs_review` rather than `likely_false_positive`, and what single fact would move it either way?
2. Trivy reports a CVE in `openssh-server 1:8.9p1-3ubuntu0.10` with fixed version `1:8.9p1-3ubuntu0.6`. What does a plain string comparison conclude, what does dpkg conclude, and which band results?
3. The benchmark shows 100% precision and 72% recall. Why is that the right trade-off for this product, and what would you change, and measure, before letting a model propose "likely FP" on endpoints?
