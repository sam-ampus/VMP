"""Fetch an offline intel bundle for exactly the CVEs and packages in a drop folder.

Writes the sources' own published formats (the layout vmp.intel.build.import_bundle reads):
    <folder>/intel/kev.json       CISA KEV catalogue, filtered to in-scope CVEs
    <folder>/intel/epss.csv       FIRST EPSS, bulk-CSV format
    <folder>/intel/nvd/<cve>.json NVD API 2.0 responses
    <folder>/intel/osv.json       {"<purl>": <OSV /v1/query response>}

Run once with outbound access; the folder then scores fully offline:
    uv run python scripts/build_seed_intel.py seed/demo
"""

import argparse
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vmp.assets import load_asset_csv
from vmp.intel import UrllibClient
from vmp.intel import sources as src
from vmp.pipeline.run import ingest_folder
from vmp.schema.finding import PackageLocus


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("folder", type=Path)
    p.add_argument("--nvd-api-key", default=None)
    args = p.parse_args()

    assets = args.folder / "assets.csv"
    inventory = load_asset_csv(assets) if assets.exists() else None
    ingested = ingest_folder(args.folder / "scans", datetime.now(UTC), inventory)
    findings, problems = ingested.findings, ingested.problems
    if problems:
        print(f"note: {len(problems)} ingest problems (run `vmp ingest` to see them)")
    cves = sorted({c for f in findings for c in f.classification.cve})
    purls = sorted({f.locus.purl for f in findings if isinstance(f.locus, PackageLocus)})
    print(f"in scope: {len(cves)} CVEs, {len(purls)} purls")

    out = args.folder / "intel"
    (out / "nvd").mkdir(parents=True, exist_ok=True)
    http = UrllibClient()

    kev: dict[str, Any] = http.get_json(src.KEV_URL)
    wanted = set(cves)
    kev["vulnerabilities"] = [v for v in kev["vulnerabilities"] if v["cveID"] in wanted]
    kev["count"] = len(kev["vulnerabilities"])
    _write(out / "kev.json", kev)

    rows, score_date, model = [], None, None
    for i in range(0, len(cves), src.EPSS_BATCH):
        batch = cves[i:i + src.EPSS_BATCH]
        payload = http.get_json(src.EPSS_URL, {"cve": ",".join(batch), "limit": str(len(batch))})
        model = model or payload.get("model_version")
        for d in payload.get("data", []):
            score_date = score_date or d.get("date")
            rows.append(f"{d['cve']},{d['epss']},{d['percentile']}")
    header = f"#model_version:{model or 'unknown'},score_date:{score_date}T00:00:00Z"
    (out / "epss.csv").write_text("\n".join([header, "cve,epss,percentile", *sorted(rows)])
                                  + "\n", "utf-8")

    headers = {"apiKey": args.nvd_api_key} if args.nvd_api_key else None
    delay = src.NVD_DELAY_WITH_KEY if args.nvd_api_key else src.NVD_DELAY_NO_KEY
    for i, cve in enumerate(cves):
        if i:
            time.sleep(delay)
        _write(out / "nvd" / f"{cve}.json", http.get_json(src.NVD_URL, {"cveId": cve}, headers))
        print(f"  nvd {i + 1}/{len(cves)} {cve}")

    _write(out / "osv.json",
           {purl: http.post_json(src.OSV_URL, {"package": {"purl": purl}}) for purl in purls})
    print(f"wrote {out}")
    return 0


def _write(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", "utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
