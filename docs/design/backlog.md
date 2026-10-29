# Backlog: deferred work, known limitations and open questions

One register for everything we've chosen **not** to do yet, so nothing lives only in a chat or a code comment. Started 2026-10-27 from every point raised in the sessions since 2026-10-05.

**Rules**
- **Small and in scope?** Fix it now, don't log it. This file is for what genuinely needs a later step, data we don't have yet, or someone else's decision.
- **Every item says when to act** (its trigger), not just what. "Someday" is not a trigger.
- **Done items move to *Resolved*** with the date and where the fix landed. Never delete them.
- **Check it at the start of every build step;** `CLAUDE.md` points here.
- **IDs are stable** (`B-001`…); design notes and decisions can cite them.

Status: **open** · **waiting** (on data or a person) · **planned** (assigned to a build step).

---

## Assets and identity

| ID | Item | Why it matters | Trigger / when | Source | Status |
|---|---|---|---|---|---|
| B-001 | **CMDB integration** (e.g. ServiceNow) as an `AssetProvider`, replacing the CSV stub | Exposure, criticality and owner come from the customer's system of record; the CSV is a demo stub | When Donna's environment's CMDB is known; Phase 2 | Sam, 2026-10-27 | waiting |
| B-002 | **IP collisions across networks:** without an inventory an asset *is* its IP, so two networks reusing a private range would merge | Wrong merges hide findings and mix two clients' hosts | Before any multi-network or multi-tenant deployment; or scope unresolved assets by scan target group | Step 7 | open |
| B-003 | **"Many ports" flag may mean several hosts behind one IP** (NAT, load balancer) | One asset record may really be several machines | When the CMDB lands (B-001), check the flagged groups against it | Step 7 (review flags) | open |

## Connectors and data

| ID | Item | Why it matters | Trigger / when | Source | Status |
|---|---|---|---|---|---|
| B-010 | **Mirror JSON connector** (web and network) | The live feed promised to Donna. It fixes the PDF transcription's limits: the `CWE-1000` placeholder merges, the 5 skipped `ALL`/`N/A`-method findings, and keying on Mirror's own finding id | When the team sends Mirror JSON samples (team ask #2) | Steps 5–6 | waiting |
| B-011 | **Nessus JSON** (Tenable.io / Tenable.sc export) | Only `.nessus` XML so far | If the team confirms they use it (team ask #4) | Step 6 | waiting |
| B-012 | **Tenable and Qualys API connectors** (live pull instead of file upload) | "Live feed of vulnerabilities" is Donna's stated need | Phase 2 | Roadmap | open |
| B-013 | **Approval to use the real client samples** for development; handling and retention rules | They are third-party client data | Team ask #1 | Step 6 | waiting |
| B-014 | **4 non-empty Qualys IVA scans** (3 of 4 received were "No host alive") | IVA is under-tested on real data | Team ask #3 | Step 6 | waiting |
| B-015 | **Same hosts scanned by Nessus and Qualys** | Cross-tool correlation is tested only on synthetic data; real cross-tool matches = 0 | Team ask #5; re-run step 7 checks when it arrives | Steps 6–7 | waiting |
| B-016 | **More rescan pairs** (same scope, two dates) | Only one real pair so far (two Nessus files, 22 hosts) | Team ask #6 | Step 7 | waiting |
| B-018 | **Qualys severity 1 → `info`** (DefectDojo's mapping) is arguable | Affects the severity fallback for no-CVE findings | Revisit with analyst feedback | Step 6 | open |
| B-019 | **Nessus severity attribute vs `risk_factor` disagree** on some items; the attribute is used | Analysts may expect the `risk_factor` | Show both in the UI (Stage 3) | Step 6 | planned |
| B-020 | **The Mirror PDF transcription script** uses `pypdf` via `uv run --with`, outside the locked dependencies | Not hash-pinned; one-off tool | Retire when B-010 lands | Step 5 | open |
| B-021 | **The committed Mirror seed names the target's hosts and weaknesses** | Committed by decision; confidential report | Before sharing the repo outside the team | Sam, 2026-10-27 | open |
| B-022 | **Seed `osv.json` is 2.2 MB** (mostly Debian binutils advisories) | Repo size | If repo size matters; prune to in-scope packages | Step 5 | open |
| B-023 | **BUILD_SPEC calls the DefectDojo corpus "MIT"**; it's BSD-3-Clause | The spec text is wrong (the notice ships correctly) | Next time BUILD_SPEC is edited with Sam's okay | Step 5 | open |
| B-024 | **npm (semver) and Maven version comparators** for package FP triage; step 8 covers dpkg, rpm, apk and PyPI | Packages from other ecosystems get `needs_review` instead of a definite answer | When a scan contains those ecosystems | Sam, 2026-10-28 | open |

## Correlation and lifecycle

| ID | Item | Why it matters | Trigger / when | Source | Status |
|---|---|---|---|---|---|
| B-030 | **Group growth over time.** Review flags catch large groups in a run, but not a group that keeps growing across runs | A slowly chaining group is the failure the flags are meant to catch | When storage exists: compare each group's size with its last stored version and flag growth | Sam, 2026-10-27 | planned (storage) |
| B-031 | **Review thresholds** (3+ merged checks, 10+ ports) set from one sample set | May be too noisy or too quiet at scale | Re-tune with more data (B-015, B-016) and analyst feedback | Step 7 | open |
| B-032 | **Near-miss correlation agent** for no-CVE findings across tools (e.g. the same TLS issue from Nessus and Qualys) | Exact keys can't match QIDs to plugin ids | After FP triage; agent proposes, analyst decides | Step 7 | open |
| B-033 | **Permanent vulnerability ids.** Today the id is a hash of the group's smallest key | Ids must survive groups changing shape | With storage (Stage 3 API) | Step 7 | planned (storage) |
| B-034 | **Wire `redetect()` (locked decision 2) end to end.** Built and tested, but nothing is closed in a stateless run | Reopen and recurrence never happen in practice yet | With storage and analyst close actions | Step 7 | planned (storage) |
| B-035 | **N (reopen window) defaults to 30 days**; the skill allows 30–90 | Policy choice for Donna's team | Confirm with Donna | Step 7 | waiting |
| B-036 | **Coverage is per host, not per port.** A rescan that skipped a port still flags "not seen" | False "not seen" flags (flag only, nothing closes) | If flags prove noisy; Nessus records scanned ports | Step 7 | open |
| B-037 | **Mirror `CWE-1000` placeholder** joins different issues on one endpoint | Some wrong endpoint merges | Fixed by B-010 (key on Mirror's finding id) | Steps 5, 7 | waiting |

## Scoring and intel

| ID | Item | Why it matters | Trigger / when | Source | Status |
|---|---|---|---|---|---|
| B-040 | **Weights `w-0.1` tuned from analyst feedback** (versioned, re-validated against the vectors) | Today's weights are a reasoned first cut | Phase 4 | Roadmap | open |
| B-041 | **Intel freshness:** snapshots are dated, but nothing warns when one is old | A stale snapshot is the same failure as Trivy's stale NVD copy | With scheduled intel refresh (API stage) | Step 5 lesson | open |
| B-042 | **CVSS v4.0 is ranked below v3.x** because the weights are calibrated on v3 | As NVD moves to v4, more scores will be v4-only | When v4-only CVEs become common in the data; recalibrate | Step 3 | open |
| B-043 | **5 real CVEs have no CVSS from any source** (NVD backlog); 202 used the CNA score | Scored on severity; shown as missing | Monitor; nothing to build | Intel run, 2026-10-27 | open |

## False-positive triage (step 8)

| ID | Item | Why it matters | Trigger / when | Source | Status |
|---|---|---|---|---|---|
| B-051 | **Confirm with Donna that FP reduction means "flagged and set aside", never removed** | Scope of her ask | Next Donna meeting | Oct 9 plan | waiting |
| B-052 | **Endpoint "likely FP" needs a fact against the finding** (unreachable route, response contradicts the claim). Step 8 never calls a web finding not real | Endpoint recall on FPs is 0% in the benchmark | With Mirror JSON (B-010) or the evidence agent: reachability facts | Step 8 | open |
| B-053 | **OSV vs vendor disagreement isn't detected.** OSV is consulted only when the tool's fix data can't decide | Two authoritative sources disagreeing should go to a person | When OSV is checked for every package finding; flag disagreement as review | Step 8 | open |
| B-054 | **"Inferred from a version" is recognised by fixed text patterns** (Nessus "self-reported version", Qualys "Vulnerable … detected", titles with "< x.y") | A check worded differently is treated as directly observed (likely real) | Re-check against analyst dispositions; add patterns from more sample data | Step 8 | open |
| B-055 | **Host version comparison is plain dotted numbers only** (plus dpkg/rpm package pairs). Cisco "Installed release 9.8(4)" style (40 real items) isn't compared | Those findings get no version fact | If Cisco/network-device findings matter to Donna's team | Step 8 | open |
| B-056 | **FP band in queue ordering.** It's shown beside the score; ordering is still by score only | "Usable for ordering" (2026-10-28) isn't built | Stage 3 UI: a sort/filter by band | Step 8 | planned |
| B-057 | **Benchmark on real dispositions.** 44 constructed cases today; real analyst verdicts replace them as the measure | Constructed cases measure the rules we thought of | When analysts disposition real findings (Stage 3+) | Skill | waiting |

## UI and report (Stage 3)

| ID | Item | Why it matters | Trigger / when | Source | Status |
|---|---|---|---|---|---|
| B-060 | **Confidence tooltip** shows `confidence_note` on the badge | Qualys "Confirmed" ≠ Mirror "Confirmed" | Stage 3 UI | Sam, 2026-10-27 | planned |
| B-061 | **Show "contested CVSS", "not seen in latest scan" and "review grouping" flags**, each with its reason | They exist in the data; the analyst must see them | Stage 3 UI | Steps 3, 7 | planned |
| B-062 | **Explanation in one place, not many tooltips.** Use a per-vulnerability "why" panel built from the trace (confidence note, CVSS rule, merge basis, missing inputs) | Too many tooltips overwhelm; progressive disclosure per the skill | Stage 3 UI design | Sam, 2026-10-27 | planned |
| B-063 | **Report export** (HTML/PDF plus CSV/JSON) | "Report on them" in Donna's ask | Stage 3 | Oct 9 plan | planned |

## Platform, deployment and compliance

| ID | Item | Why it matters | Trigger / when | Source | Status |
|---|---|---|---|---|---|
| B-070 | **Outbound events for assessed findings.** The skill says to emit them "from day one"; none are emitted yet | The Phase 2 hook (ticketing, notifications), and the real home for "notify me when a group grows" (B-030) | With the API (Stage 3); flagged now as a gap against the skill | Skill | planned |
| B-071 | **Storage and API** (FastAPI) | B-030, B-033, B-034 and B-070 all depend on it | Stage 3 | BUILD_SPEC | planned |
| B-072 | **GovCloud and Bedrock deployment;** elevated AWS permissions pending since 2026-10-07 | Can't deploy or use the model in GovCloud without them | When the permissions land | Kickoff | waiting |
| B-073 | **Supply chain:** UBI 9 base image, hash-pinned install from `uv.lock`, FIPS-only crypto review | FedRAMP Moderate authorisation | Before the first deployable build | Kickoff | open |
| B-074 | **Dependency review** of `defusedxml` (added in step 6) and `packaging` (step 8) alongside B-073 | Every dependency needs a reason and a review | With B-073 | Steps 6, 8 | open |
| B-075 | **IP arrangement:** the customer owns the source, but Ampcus integrates in Phase 2 | Contractual | Before Phase 2 starts | Kickoff | waiting |

## Working practice

| ID | Item | Why it matters | Trigger / when | Source | Status |
|---|---|---|---|---|---|
| B-080 | **Phase 2 working mode:** co-writing and interview drills | Sam's learning goal | After Phase 1 delivery to Donna | Oct 9 | planned |

---

## Resolved

| ID | Item | Resolved | Where |
|---|---|---|---|
| R-001 | CVSS factor was labelled "tool" even when NVD or the CNA supplied it (an engine `TODO`) | 2026-10-27 | `scoring/engine.py`, `ScoringInput.cvss_from_intel`; test in `test_slice.py` |
| R-002 | No way to see correlation groups that chained or grew large | 2026-10-27, partly; growth over time is B-030 | `correlate.ReviewFlag`; "correlation review" section in `vmp ingest` |
| R-003 | CLI header used `·`, garbled on Windows consoles | 2026-10-27 | `cli.py` uses ASCII separators |
| R-004 | No-CVSS scoring gap raised by the Qualys samples | 2026-10-26 (already handled by `severity_fallback`; now tested) | `test_host_scanners.py` |
| R-005 | Real client samples were one `git add` away from GitHub | 2026-10-26 | `.gitignore` |
| R-006 | B-017: Qualys "Authentication ON" didn't prove a per-host login | 2026-10-29 | `connectors/qualys.py` reads per-host "Authentication Failed" items; `host_auth` evidence; run warning |
| R-007 | B-050: Qualys "potential" and Nessus `Credentialed_Scan=false` unused as FP signals | 2026-10-29 | `pipeline/assess_fp/host.py` rules 3–4 |
