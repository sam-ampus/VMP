# 03 — Threat intel and CVSS selection (Stage 1, step 3)

*Built 2026-10-12. Backfilled 2026-10-21 from that session's walkthrough.*

## Problem from first principles

A scanner's view of a CVE is partial and goes stale. Public sources answer the questions a score needs:
- **Is it exploited in the wild?** CISA KEV.
- **How likely is exploitation?** FIRST EPSS.
- **What's the authoritative severity?** NVD, plus the issuing CNA.
- **Which package versions are affected?** OSV.

Two constraints follow from the deployment and the invariant:
- The engine must work **with or without internet access**.
- A score must be reproducible **against the exact intel it used**, even months later.

## System view

- **Sits at:** enrich. It runs after dedupe, so each CVE is looked up once, not once per finding.
- **In:** the set of CVEs and packages present in findings.
- **Out:** an immutable **snapshot** (content-addressed), and per-CVE `Enrichment` records carrying that snapshot's id.
- **Never written onto a Finding.** EPSS and KEV values on a Finding are only what the tool itself reported.

There are two ways in, and both use the same parsers:

```
live:     fetch_* (HttpClient) ─┐
                                ├─► parse_* (pure) ─► SnapshotData ─► write_snapshot (sha256 id)
offline:  bundle files ─────────┘                                         │
                                                                 IntelReader ─► enrich_all
```

## Choices and trade-offs

- **Pure parsers; the network sits behind a `HttpClient` Protocol.** All network tests use a fake client, so the suite runs fully offline, which matters in GovCloud. Live fetching only asks for CVEs and packages that are actually present, and respects NVD's rate limit.
- **Content addressing.**
  - The snapshot id is a SHA-256 of the normalised content. The same data gets the same id regardless of input order or source path.
  - A test proves the live path and the bundle path produce **identical ids**.
  - Normalisation is what makes this work: EPSS `0.006200000` from the API and `0.0062` from the CSV are one value.
  - Snapshots are written atomically, and tampering is detected on load.
- **"Unknown" is never "no".**
  - A KEV source missing from the snapshot gives `None`, not `False`.
  - A package the bundle never answered is unknown, not clean.
  - The whole KEV catalogue is stored so that "not listed" is a real answer.

  Systems that blur unknown and negative fail quietly.
- **CVSS selection moved after enrichment** (`src/vmp/pipeline/cvss.py`, `select_cvss`). This is locked decision 1:
  - Precedence: distro (OS packages only) → NVD → CNA → tool.
  - Within a tier: preferred version → highest base → source name.
  - It records the rule that chose the score.
  - Spread is measured on the chosen version only, because v2 and v3 scales aren't comparable. It flags "contested" at ≥ 2.0.
- **CVSS v3.1 is preferred over v4.0** when both exist, because the weights are calibrated on v3. This is configurable.

## The correction live data caught

- **The step-1 assumption.** In step 1 the fixture had cilium (CVE-2024-28248) select **GHSA 6.5** as the CNA score.
- **What one live call showed.** One live call to each real feed revealed that GitHub, the CNA, publishes **7.2**, and NVD also says **7.2**. Trivy's "ghsa 6.5" is not the CNA's score.
- **The root cause.** The deeper bug was selecting a CVSS **at ingest**, before NVD and CNA scores are known.
- **The fix.** Findings now keep only what the tool reported, and selection runs after enrichment.
- **The result.** cilium now selects NVD 7.2, with a spread of 0.7, so it is not contested. It scores 33, medium, with EPSS 0.62%.

*Lesson:* parsers written only from documentation would have shipped the wrong assumption. Test against real data early, even just once.

## Applied AI tie-in

- **Snapshots plus versioned weights make every score a pure function of recorded inputs.** That's the same property you want from an eval run: pin the data, pin the policy, and the result is replayable.
- **"Unknown ≠ no" is the classic quiet failure in AI pipelines.** A retrieval step that returns nothing is not evidence of absence.

## Code tour

1. `src/vmp/intel/records.py`: the normalised record types.
2. `src/vmp/intel/sources.py`: `parse_kev`, `parse_epss_*`, `parse_nvd`, `parse_osv`, then the matching `fetch_*`.
3. `src/vmp/intel/http.py`: the `HttpClient` Protocol and `UrllibClient`.
4. `src/vmp/intel/snapshot.py`: `SnapshotData`, `write_snapshot`, `IntelReader`.
5. `src/vmp/intel/build.py`: `build_live_snapshot`, `import_bundle`.
6. `src/vmp/intel/enrich.py`, then `src/vmp/pipeline/cvss.py`.
7. `tests/intel/bundle/`: what an offline bundle looks like.

## Check yourself

1. Why must dedupe happen before enrich, in cost terms and in correctness terms?
2. Two snapshots were built from the same data, one live and one from a bundle. Why must their ids match, and what would break if they didn't?
3. An OS package has a Red Hat score of 5.0 and an NVD score of 7.5. Which wins, why, and is it contested?
