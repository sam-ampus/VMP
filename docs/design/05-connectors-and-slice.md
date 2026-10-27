# 05 — Connectors, demo seed, and the first end-to-end slice (Stage 1, step 5)

*Built 2026-10-22.*

## Problem from first principles

Steps 1–4 built four parts that had never been connected: a schema, a scoring engine, threat intel and an inventory. Each was tested on its own, so each was "correct". But a system is the parts **plus the connections between them**, and the connections are where the assumptions hide. This step does two jobs:
1. **Translate real scanner output** into the canonical model. These are the connectors.
2. **Run the whole chain once, on real files,** and see what breaks. This is the walking skeleton.

What must be true:
- **A connector only translates.** If each connector validated in its own way, every new scanner would be a new chance to weaken the rules.
- **The same file always produces the same findings** with the same ids, so re-uploading is a no-op.
- **Mock data goes through the real path.** Otherwise the demo proves nothing.

## System view

```
seed/demo/scans/<connector>/*.json
        │  connector.to_batch()        translate only (trivy, canonical)
        ▼
  canonical dict ──► validate_batch()  ONE validation path for every connector
        │
        ▼  Findings ──► CVEs + purls ──► import_bundle(seed/demo/intel) ──► snapshot ──► enrich_all
        │                                                                                │
        ▼                                                                                ▼
  build_scoring_input(finding, enrichment, asset)  ◄── AssetInventory(seed/demo/assets.csv)
        │      tool's view + intel's view + inventory's view, one rule per overlap
        ▼
  score() ──► RunResult (weights version + intel snapshot id + inventory id)  ──► vmp ingest
```

## What was built

| File | Holds |
|---|---|
| `src/vmp/connectors/base.py` | `Connector` Protocol, `ScanContext`, `ingest()`; deterministic `finding_id()` and `scan_id_for()`; `resolve_asset_ref()` |
| `src/vmp/connectors/canonical.py` | Pass-through for our own format, used for the seed and as the reference output |
| `src/vmp/connectors/trivy.py` | Trivy JSON, schema 2 and legacy, to package findings |
| `src/vmp/pipeline/assemble.py` | `build_scoring_input()`: the missing glue |
| `src/vmp/pipeline/run.py` | `run_folder()`: drop folder → scored findings |
| `src/vmp/cli.py` | `vmp ingest <folder> [--as-of] [--json]` |
| `scripts/transcribe_mirror_report.py` | Mirror PDF → canonical JSON, structured fields only, secrets redacted |
| `scripts/build_seed_intel.py` | Fetches a real offline bundle for exactly the seed's CVEs and packages |
| `seed/demo/` | assets, scans, intel; see its README for where each file came from |

**The result:** 5 files, 67 findings scored, 0 ingest problems, byte-identical on rerun.

## Choices and trade-offs

- **Translate, then validate in one shared place.** Connectors return plain dicts; `validate_batch()` turns them into Findings or a list of errors. A connector bug becomes a per-record error, not a silently wrong Finding.
  - *Trade-off:* a connector can't use the type checker on its own output. The shared validation is the guard instead.
- **Deterministic ids.**
  - `finding_id = sha256(scan_id, key)`.
  - The scan id comes from the file's content when the upload doesn't supply one.
  - The clock is passed in (`--as-of`).
- **Unknown assets still ingest.** They get `ast_unresolved_<name>`, score with no context, and the CLI lists them with a `(?)`. Refusing them would hide findings; guessing their context would corrupt scores.
- **Within-scan duplicates are collapsed by the connector.**
  - **Trivy:** the same CVE in the same package at two paths is one finding, with all paths recorded.
  - **Mirror:** the same endpoint, method, parameters and CWE is one finding, with the extra titles recorded.
  - Cross-scan and cross-tool dedupe is still step 7.
- **Each overlap in `build_scoring_input` has one stated rule:**
  - Intel beats the tool for KEV and EPSS, because CISA and FIRST are the authorities.
  - The tool's own report is the fallback when intel is silent, never an override.
  - Asset context comes only from the inventory.
- **The Mirror PDF is transcribed by a script, not by hand.** It's reproducible and reviewable. It refuses to write if anything key-shaped survives, and it skips what it can't represent rather than inventing values.

## What the slice exposed

Each of these would have stayed hidden with the layers tested only on their own. That is the point of a walking skeleton.

1. **The endpoint dedupe key ignored the CWE.**
   - The step 1 key was `tool:scan:url:method:params`, so seven different weaknesses in one JavaScript bundle collapsed into one finding.
   - Locked decision 4's endpoint key already includes the CWE. The idempotency key now does too (`…:params:cwe`), and the fixture is updated.
2. **The distro tier accepted any distro.**
   - An **Alpine** package selected **Red Hat's** 8.6 as its "distro" score.
   - The reason distro scores come first is that *your own* distro backports fixes. Red Hat's rating says nothing about Alpine.
   - `select_cvss(distro=…)` now takes the package's own distro, read from its purl.
3. **The scanner's copy of NVD was stale.**
   - Trivy's database recorded NVD 6.5 for CVE-2020-15999. NVD today says 9.6, and the CVE is in CISA KEV.
   - The pipeline correctly took the snapshot's value, and freetype went from "medium" at the source to **93 critical**.
   - This is the product's pitch, shown on real data: the tool's severity is a historical opinion, and the enterprise score uses current intel.
4. **Trivy says `fixed` without a fixed version.** That's now mapped to `unknown`, and `FixStatus` gained Trivy's `under_investigation`.
5. **The DefectDojo licence is BSD-3-Clause, not MIT.** That's fine to use, but the notice has to ship with the files: `scans/trivy/LICENSE-DefectDojo.md`.

## Systems-thinking angle

- **The defects were at the interfaces.** All 446 earlier tests passed while three of the bugs above existed. Unit tests check parts against their own assumptions; only integration checks the assumptions against each other.
- **Cross-layer consistency is now tested.** `test_pipeline_reproduces_the_hand_computed_cilium_vector` runs real files through every layer and must land on the step 2 vector's 33 medium. If any layer drifts, it fails.
- **Every output names its three input versions** (weights, intel snapshot, inventory). "Why did this score change?" always has an answer.

## Applied AI tie-in

- **Connectors are the deterministic version of what the evidence agent will do** for messy, unstructured inputs. The contract is the same, `validate_batch()`. An agent's output will be checked by exactly the code that checks Trivy's.
- **"Translate, don't judge."** The connector never decides applicability or severity. That separation is what will let an agent be added later without being able to move a number.
- **The stale-NVD finding is a retrieval lesson.** A model or tool carrying a frozen copy of the world answers confidently and wrongly. Pin a dated snapshot, and prefer it over embedded knowledge.

## Known limitations

- **Mirror:** `CWE-1000` ("unclassified") makes some merges join different issues. 5 findings with method `ALL` or `N/A` are skipped. The JSON feed connector (Phase 2) should key on Mirror's finding id.
- **Seed size:** `osv.json` is about 2.2 MB, mostly Debian binutils advisories. It's fine for a demo; prune it if repo size matters.
- **No storage yet:** `vmp ingest` reports and writes JSON. Persistence comes with the API and UI.

## Code tour

1. `src/vmp/connectors/base.py`, then `canonical.py` (the reference), then `trivy.py` (`to_batch` → `_finding`).
2. `src/vmp/pipeline/assemble.py`: read the comment on each rule.
3. `src/vmp/pipeline/run.py`: the pipeline order in one function.
4. `src/vmp/cli.py`. Run `uv run vmp ingest seed/demo --as-of 2026-10-22T00:00:00Z`.
5. `tests/pipeline/test_slice.py`: the cross-layer tests.

## Check yourself

1. Why does every connector go through `validate_batch()` instead of building `Finding` objects itself? What would go wrong in a year with 10 connectors?
2. The tool reports KEV=false and the intel snapshot has no KEV data. What does the engine see, and why is that the right fallback?
3. Three of today's bugs passed every unit test. Name the interface each one lived on, and the test that now guards it.
