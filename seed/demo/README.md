# Demo seed

A drop folder that stands in for what a customer would provide, so the platform can be shown before any customer data arrives. It goes through **the real ingest path**: nothing here is pre-scored.

```
uv run vmp ingest seed/demo --as-of 2026-10-22T00:00:00Z     # fixed clock: identical reruns
```

| Path | What it is | Where it came from |
|---|---|---|
| `assets.csv` | Mock asset inventory | **Invented** for the demo. Hosts and images match the scans below; criticality, exposure and owners are illustrative. |
| `scans/trivy/defectdojo-*.json` | Native Trivy reports | DefectDojo's unit-test samples, unmodified (BSD-3-Clause, see `LICENSE-DefectDojo.md`) |
| `scans/canonical/kickoff-nessus-trivy.json` | One Nessus host finding and one Trivy package finding, already canonical | The kickoff fixture, traced from real scanner output |
| `scans/canonical/mirror-afd57ac3.json` | 50 Mirror endpoint findings | Transcribed from the Mirror PDF report by `scripts/transcribe_mirror_report.py` (see below) |
| `intel/` | Offline threat-intel bundle: KEV, EPSS, NVD, OSV | Fetched live on 2026-10-22 by `scripts/build_seed_intel.py`, for exactly the CVEs and packages above |

## The Mirror transcription

The PDF is a rendered report, not the Mirror JSON feed (a Phase 2 connector). The script keeps structured fields only:
- title, endpoint, method, parameter names;
- CVSS, confidence, CWE/OWASP;
- evidence gaps and remediation text.

**What it deliberately leaves out**
- It does not copy raw requests, responses, payloads or PoC scripts.
- It redacts anything key-shaped, and refuses to write output if any remains.

**What it can't represent**
- 70 findings in the report become 50:
  - **5 skipped:** their method is `ALL` or `N/A`, which the endpoint shape can't express.
  - **15 merged:** same endpoint, method, parameters and CWE in the same scan. Each merge is recorded under `evidence.also_reported_as`.
- Mirror uses `CWE-1000` ("unclassified") as a placeholder, so a few merges join different issues on the same endpoint. The JSON feed connector should key on Mirror's own finding id instead.

**Committed by decision (2026-10-27):** the Mirror report is marked confidential. This file contains no secrets, but it does name the target's hosts and its weaknesses. Keep that in mind before sharing the repo outside the team.

To regenerate:

```
uv run --with pypdf python scripts/transcribe_mirror_report.py <report.pdf> \
    --assets seed/demo/assets.csv --out seed/demo/scans/canonical/mirror-afd57ac3.json
uv run python scripts/build_seed_intel.py seed/demo
```
