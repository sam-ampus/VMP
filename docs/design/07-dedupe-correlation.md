# 07 — Dedupe, correlation and endpoint normalisation (Stage 2, step 7)

*Built 2026-10-27.*

## Problem from first principles

A **Finding** is one tool's observation at one moment. A **Vulnerability** is one thing to fix. Until now the pipeline scored findings, so the same weakness seen in two scans, by two tools or on two URLs counted twice. An analyst's queue has to be in Vulnerabilities, or they re-triage the same issue every week.

What must be true:
- **The same thing always lands in the same group,** whatever order the files arrive in.
- **A merge is never a guess.** Two findings join only when they share an exact, explainable key. Anything fuzzier is a proposal for a person.
- **Absence is not evidence of a fix** unless it's proven. A missed port, a failed login or a scan that didn't cover the host all look exactly like "fixed".

## System view

```
Findings ─► correlation_keys(finding)     one or more exact keys per finding
               │  host:     asset + CVE            (no CVE: asset + tool + id + port + proto)
               │  package:  asset + package + CVE  (no CVE: asset + tool + id + package)
               │  endpoint: asset + method + templated path + params + CWE   ◄── normalize.py
               ▼
         union-find: findings sharing any key are one Vulnerability
               ▼
         Correlated { vulnerability, keys (the shared basis), tools, scans, first/last seen,
                      not_seen[]  ◄── batch coverage: which assets each tool's scans looked at }
               ▼
         assess(): scored on its peak finding ──► vmp ingest: one row per vulnerability
```

**`lifecycle.redetect()`** is locked decision 2 as pure rules: reopen, recurrence, stays suppressed, stays accepted. Nothing calls it yet, because nothing is closed until storage exists. It's ready for the API.

## Choices and trade-offs

- **The CVE is the only cross-tool key.** Every tool names CVEs the same way. A Qualys QID and a Nessus plugin id aren't comparable, so findings without a CVE (TLS settings, headers) correlate only within one tool, across scans. Matching them across tools is the near-miss agent's job later: it proposes, a person decides.
- **Union-find over shared keys, not "same CVE set".** Tools list different subsets of CVEs for one advisory, so exact set-equality would almost never match across tools.
  - *Trade-off:* overlapping advisories chain together. On the real data, two Qualys Apache QIDs (< 2.4.60 and < 2.4.59) share CVEs and become one vulnerability. That's one fix (upgrade Apache), so it's arguably right, but the group can grow. The largest real group has 12 CVEs. Watch this, and revisit if groups get large.
- **One vulnerability per asset + CVE across ports.** The same Qualys QID on ports 443 and 8443 is one thing to fix, with each port kept as a finding.
- **Endpoint templating is conservative.**
  - Placeholders replace only integers, UUIDs, hex hashes (8+ characters, with both digits and letters) and long opaque tokens.
  - Words like `deadline`, `v2` and `cafe` stay as they are.
  - Over-templating merges different routes, which is worse than a missed merge: a missed merge shows up as a visible duplicate, while a wrong merge hides a finding.
  - The customer's OpenAPI routes win when supplied.
- **"Not seen in latest scan" is a flag, never a closure** (Sam's decision (a), 2026-10-27).
  - **Only the same tool's silence counts.** Qualys not reporting a Nessus finding says nothing.
  - **It needs coverage,** so batches now record every asset a scan looked at, including hosts with only information-level items. Without coverage, absence is ignored.
- **Vulnerability id comes from the group's smallest key.** It's stable while that key stays in the group. Once records are stored, ids are assigned once and kept.

## Results

- **Demo seed:** 67 findings become 66 vulnerabilities. The one merge is two Mirror reports of credentials sent in cleartext to `POST /auth/login/`, one reached by http and one by https, on the same asset via two aliases. The other two parameterless POSTs to that route have different CWEs and stay separate, as locked decision 4 requires.
- **Real samples** (local only):
  - 1,131 findings become **898 vulnerabilities**: 18 seen across two scans, and **15 flagged "not seen in a newer scan"**, all left open for review.
  - The two Nessus files that share 22 hosts are confirmed to be the same machines (22 of 22 hostnames, 21 of 22 operating systems, 85% plugin overlap, 44 days apart). They're a real rescan pair.
  - Cross-tool: 0, as expected. No client was scanned by both tools.

### Follow-up (2026-10-27): seeing groups that grow
Sam asked how anyone would know a group was chaining. Each `Correlated` now carries `review` flags:
- **`merged_checks`:** 3 or more different checks joined through shared CVEs. The flag names the joining CVEs.
- **`many_ports`:** 10 or more ports on one asset.

`vmp ingest` lists them in a "correlation review" section. On the real samples, 9 groups were flagged; all were correct, and now they're visible. Growth *across runs* needs storage (backlog B-030). The real notification channel is outbound events (B-070).

## Applied AI tie-in

- **Precision first, recall by proposal.** Exact keys give a deterministic, high-precision merge. The near-miss agent adds recall, but only as proposals a person reviews. It's the usual pattern for putting a model next to a rule: the rule owns the decision, the model widens the net.
- **The meaning of absence depends on coverage.** "No result" means something only when you know where you looked. Evaluating retrieval works the same way: a miss counts against recall only if the item was in the indexed corpus.
- **Entity resolution is the real problem.** IP addresses aren't identities: two clients can reuse the same private range. See the limitation below.

## Known limitations

- **IP collisions across networks.** Without an inventory, an asset is its IP (`ast_unresolved_10.0.0.5`). Two networks that reuse a private range would merge. The fix is the inventory (step 4), or scoping unresolved assets by scan target group. Revisit before a multi-network deployment.
- **No storage:** the folder is the history, so closures and `redetect()` aren't exercised end to end yet.
- **Coverage is per host, not per port.** A rescan that skipped a port still flags the port's finding as not seen. That's acceptable because it's only a flag.
- **The Mirror `CWE-1000` placeholder** still drives some endpoint merges, as in step 5.

## Code tour

1. `src/vmp/pipeline/normalize.py`: `template_segment` and then `endpoint_correlation_key`.
2. `src/vmp/pipeline/correlate.py`: the module docstring's key table, then `correlation_keys`, `_components` (union-find) and `_not_seen`.
3. `src/vmp/pipeline/lifecycle.py`: the table in the module docstring, one branch per row.
4. `src/vmp/pipeline/run.py`: correlate, then `assess` on the peak.
5. Tests: `tests/pipeline/test_normalize.py`, `test_correlate.py` (rescan, cross-tool, not-seen) and `test_lifecycle.py`.

## Check yourself

1. Nessus and Qualys both report the same TLS misconfiguration on one host, and neither gives a CVE. Why don't they merge, and what would have to be true for a deterministic merge to be safe?
2. A host's newest Nessus scan doesn't report a finding. Name three reasons that isn't proof of a fix, and say which one batch coverage rules out.
3. Why does union-find give the same groups whatever order findings arrive in, and why is the vulnerability id taken from the smallest key rather than the first finding?
