"""Command line: `vmp ingest <folder>` runs the pipeline over a drop folder and reports.

    vmp ingest seed/demo                      # table of scored findings
    vmp ingest seed/demo --json out.json      # plus the full machine-readable result
    vmp ingest seed/demo --as-of 2026-10-22T00:00:00Z   # fixed clock: byte-identical reruns
"""

import argparse
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vmp.pipeline.confidence_note import confidence_note
from vmp.pipeline.run import RunResult, Scored, run_folder
from vmp.scoring.weights import Weights, load_weights


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vmp", description="VMP findings assessment engine")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("ingest", help="ingest, enrich and score a drop folder")
    p.add_argument("folder", type=Path)
    p.add_argument("--as-of", type=datetime.fromisoformat, default=None,
                   help="the run's timestamp (default: now). Fix it to make runs reproducible.")
    p.add_argument("--snapshots", type=Path, default=Path(".vmp/snapshots"),
                   help="where intel snapshots are written (default: .vmp/snapshots)")
    p.add_argument("--json", type=Path, default=None, help="write the full result here")
    args = parser.parse_args(argv)

    if not (args.folder / "scans").is_dir():
        parser.error(f"{args.folder}: no scans/ sub-folder")
    now = args.as_of or datetime.now(UTC)
    if now.tzinfo is None:
        parser.error("--as-of needs a timezone, e.g. 2026-10-22T00:00:00Z")

    result = run_folder(args.folder, now=now, snapshot_root=args.snapshots)
    sys.stdout.write(render_table(result))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(to_json(result, now), indent=2) + "\n", "utf-8")
        sys.stdout.write(f"\nwrote {args.json}\n")
    return 1 if result.problems else 0


def render_table(r: RunResult) -> str:
    lines = [
        f"files: {len(r.files)}   findings scored: {len(r.scored)}   "
        f"ingest problems: {len(r.problems)}",
        f"weights {r.weights_version} · intel {_short(r.intel_snapshot_id)} · "
        f"assets {_short(r.asset_inventory_id)}",
        "",
        f"{'score':>5}  {'computed':<8}  {'source':<8}  {'tool':<9}  {'asset':<28}  title",
        f"{'-' * 5}  {'-' * 8}  {'-' * 8}  {'-' * 9}  {'-' * 28}  {'-' * 40}",
    ]
    for s in r.scored:
        f = s.finding
        asset = f.locus.asset_ref + ("" if s.assembled.asset_known else " (?)")
        flag = " [contested CVSS]" if s.assembled.cvss and s.assembled.cvss.contested else ""
        lines.append(
            f"{s.result.score:>5}  {s.result.severity:<8}  "
            f"{f.classification.source_severity:<8}  {f.source.tool:<9}  {asset[:28]:<28}  "
            f"{f.classification.title[:70]}{flag}"
        )
    sev = Counter(str(s.result.severity) for s in r.scored)
    lines += ["", "computed severity: " + ", ".join(
        f"{k} {sev[k]}" for k in ("critical", "high", "medium", "low", "info") if sev[k])]
    unknown = sorted({s.finding.locus.asset_ref for s in r.scored if not s.assembled.asset_known})
    if unknown:
        lines.append("assets not in inventory (scored without context, marked ?): "
                     + ", ".join(unknown))
    if r.skipped:
        lines.append("skipped (not findings): "
                     + ", ".join(f"{k} {v}" for k, v in r.skipped.items()))
    for w in r.warnings:
        lines.append(f"WARNING {w.file}: " + "; ".join(w.messages))
    for p in r.problems:
        who = f" {p.finding_id}" if p.finding_id else ""
        lines.append(f"PROBLEM {p.file}{who}: " + "; ".join(p.messages))
    return "\n".join(lines) + "\n"


def to_json(r: RunResult, now: datetime) -> dict[str, Any]:
    weights = load_weights(r.weights_version)
    return {
        "run_at": now.isoformat(),
        "weights_version": r.weights_version,
        "intel_snapshot_id": r.intel_snapshot_id,
        "asset_inventory_id": r.asset_inventory_id,
        "files": list(r.files),
        "problems": [{"file": p.file, "finding_id": p.finding_id, "messages": list(p.messages)}
                     for p in r.problems],
        "warnings": [{"file": w.file, "messages": list(w.messages)} for w in r.warnings],
        "skipped": r.skipped,
        "scored": [_scored_json(s, weights) for s in r.scored],
    }


def _scored_json(s: Scored, weights: Weights) -> dict[str, Any]:
    return {
        "finding": s.finding.model_dump(mode="json"),
        "confidence_note": confidence_note(s.finding, weights),  # the UI's tooltip text
        "scoring_input": s.assembled.scoring_input.model_dump(mode="json"),
        "cvss_selection": s.assembled.cvss.model_dump(mode="json") if s.assembled.cvss else None,
        "asset_known": s.assembled.asset_known,
        "result": s.result.model_dump(mode="json"),
    }


def _short(value: str | None) -> str:
    return value[:12] if value else "none"


if __name__ == "__main__":
    raise SystemExit(main())
