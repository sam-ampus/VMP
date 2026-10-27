# 06 — Qualys and Nessus connectors, on real samples (Stage 2, step 6)

*Built 2026-10-26.*

## Problem from first principles

Step 5 proved the chain works on one package scanner (Trivy). Host scanners are the bulk of what a security team actually runs, and they're the feed Donna needs. Two questions had to be answered before writing any code:
1. **What do the files really contain?** That means the real exports, not documentation or DefectDojo's samples.
2. **What in each file is a finding, and what is noise?**

The team sent real samples on 2026-10-26: Qualys XML for EVA, ASV and IVA scans, and Nessus `.nessus` files. So step 6 was built against them, as BUILD_SPEC already said ("against real sample files"). The plan's guess was DefectDojo samples, made when we had nothing better.

**The data was profiled before any code was written.** That meant counting element paths, attribute shapes and value distributions, without printing any client content. The profile changed the design in four places (below).

## What the profile found

| Fact | Design consequence |
|---|---|
| All three Qualys scan types use one format (`scan-1.dtd` "Scan Results") | **One** connector; the assessment kind (EVA/ASV/IVA) is evidence, not a code path |
| Qualys has **no CVSS** at all; severity is 1–5 | CVSS comes from intel by CVE. About 2/3 of EVA findings have no CVE and score on severity (the engine already had `severity_fallback`) |
| Qualys separates VULN (confirmed), PRACTICE (potential), INFO/SERVICE (information gathered) | Findings = VULN + PRACTICE; INFO/SERVICE skipped and counted |
| 90 Qualys "duplicates": one QID on one port, reported plain **and** "over ssl" | One observation; merged, keeping each transport's result |
| 3 of the 4 Qualys IVA files are `No host alive` (error 3509) | Empty batch **plus a warning**, not a connector error |
| About 95% of Nessus items are severity 0 (4,456 of 4,717) | Skipped and counted, or the queue is 95% noise |
| Nessus has CVSS v2/v3/v4, EPSS (0–1), exploit availability, CWE, and a per-host `Credentialed_Scan` | All kept; scan type is set **per host**, not per file |
| The Nessus severity attribute disagrees with `risk_factor` on some items | Attribute used (it's what Nessus displays); `risk_factor` kept as evidence |

## System view

```
scans/qualys/*.xml  ──QualysConnector──┐
scans/nessus/*.nessus ─NessusConnector─┤  load_xml() (defusedxml)  →  canonical dict
scans/trivy/*.json  ──TrivyConnector───┤        + skipped{reason: n} + warnings[]
                                        ▼
                               validate_batch()   (unchanged: the one gate)
                                        ▼
               RunResult.skipped / .warnings  →  vmp ingest prints them; they never fail a run
```

**Changed contracts**
- `Connector.extensions`: each connector names its own file suffixes. The drop folder no longer assumes `.json`, and stray READMEs are ignored.
- `FindingBatch` gains `skipped` and `warnings`. Both describe the translation, not a record, so they live on the envelope.

## Choices and trade-offs

- **Qualys "confirmed" gets no validation weight. "Potential" is kept as `potential`.**
  - The schema reference already says scanners default to `unvalidated`. Mirror's "confirmed" means *exploited and verified*. Qualys's means *the detection signature matched*. The same word for two different claims would have given every Qualys finding +15 points.
  - "Potential" is Qualys admitting it couldn't verify. It's worth 0 points either way, but FP triage will read it.
- **Silence is unknown.**
  - Qualys lists exploit sources when it knows of any, so no list means `None`, not `False`.
  - Nessus says `exploit_available=false` outright, and that's kept as `False`.
- **Information-only items are skipped, not dropped silently.** The count per tool and reason shows up in every run. A reviewer can always ask "what did you leave out?" and get a number.
  - *Trade-off:* a few Qualys INFO items carry real signal (for example, a TLS version list). That signal belongs to FP triage and asset context later, not to the findings queue.
- **Untrusted XML goes through `defusedxml`.** Uploaded files are attacker-reachable input in a FedRAMP system. Entity expansion and external entities are refused; the plain DOCTYPE that Qualys writes is allowed. There's a test with an entity bomb.
  - *Trade-off:* one new dependency, small and pure-Python, with no transitive dependencies.
- **Real data is never in the repo.**
  - `sample-data-nessus-qualys/` is git-ignored.
  - Committed tests use synthetic files (RFC 5737 IPs, `example.com`).
  - `test_real_samples.py` runs all 19 real files when they're present and skips itself otherwise.

## Result on the real samples (local only)

- **19 files → 1,131 findings scored, 0 validation errors, 0 ingest problems.**
- **9,048 information-only items skipped and counted.**
- **3 warnings**, all `No host alive`.
- **The duplicate EVA file** produced identical finding ids and collapsed, 1,136 → 1,131. That's the step 5 idempotency design working on real data.
- **No intel or assets yet**, so every host is `ast_unresolved_*` and Qualys CVE findings list `cvss` as missing. That's honest, and it's the next gap to close.

### Follow-up (2026-10-27): making the mapping visible
Sam approved the mapping and asked how a reader would know. The answer has two parts:
- **`ValidationStatus.tool_label`** keeps the tool's own word ("Confirmed", "Potential").
- **`pipeline/confidence_note.py`** turns tool + label + confidence into one plain sentence: what the tool's word means, then what it did to the score. The points are read from the weights the score used, so the note can't contradict the trace.

`vmp ingest --json` carries it per finding as `confidence_note`. The Stage 3 UI shows it as the tooltip on the confidence badge. It's deterministic text, not model output: an explanation of a number follows the same rules as the number.

## Applied AI tie-in

- **Profile before you build.** It's the data-first habit behind good evals: look at the real distribution before writing the logic, or you design for the documentation.
- **Same word, different meaning.** "Confirmed" from two tools is a labelling-schema problem. It's the same trap as merging two annotators' labels without checking that their guidelines agree.
- **Report what you filtered.** Silent filtering is how pipelines, and RAG retrievers, lose recall without anyone noticing. Counting skips makes that loss measurable.

## Known limitations

- **No cross-tool overlap in the samples.** Every file is a different client, so step 7's Nessus↔Qualys correlation needs a same-hosts pair (requested from the team).
- **Only one real rescan pair** (two Nessus files sharing 22 hosts).
- **Qualys severity 1 maps to `info`,** as DefectDojo does. That's arguable; the raw value is kept.
- **The Qualys scan type comes from the `OPTIONS` header** ("… Authentication ON"). It doesn't prove a login succeeded per host. Nessus's per-host flag is stronger.
- **Mirror JSON** and **Nessus JSON**: no samples yet.

## Code tour

1. `src/vmp/connectors/base.py`: `load_xml()`, `text()`, and `envelope(skipped=, warnings=)`.
2. `src/vmp/connectors/qualys.py`: the module docstring maps each Qualys section to the canonical model.
3. `src/vmp/connectors/nessus.py`: `_host_findings` (per-host context), then `_finding`, then `_cvss`.
4. `src/vmp/pipeline/run.py`: `ingest_folder` routes files by `connector.extensions`.
5. Tests:
   - `tests/connectors/test_qualys.py` and `test_nessus.py` (synthetic);
   - `tests/pipeline/test_host_scanners.py` (scoring with and without CVSS);
   - `tests/connectors/test_real_samples.py` (local only).

## Check yourself

1. Why does Qualys "confirmed" map to `unvalidated` while "potential" maps to `potential`? What would the score distribution look like if we'd mapped confirmed → `confirmed`?
2. A Qualys finding has a CVE but no intel bundle was loaded. What does the engine use as its base, and what does it list as missing? Why is that better than reading Qualys's severity as if it were a CVSS?
3. Why are `skipped` and `warnings` on the batch envelope rather than on findings, and why don't warnings change the CLI exit code?
