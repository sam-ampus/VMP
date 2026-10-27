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
    """One row per vulnerability (what an analyst works), shown by its peak finding."""
    by_id = {s.finding.finding_id: s for s in r.scored}
    lines = [
        f"files: {len(r.files)}   findings scored: {len(r.scored)}   "
        f"vulnerabilities: {len(r.vulnerabilities)}   ingest problems: {len(r.problems)}",
        f"weights {r.weights_version} | intel {_short(r.intel_snapshot_id)} | "
        f"assets {_short(r.asset_inventory_id)}",
        "",
        f"{'score':>5}  {'computed':<8}  {'source':<8}  {'seen by':<16}  {'asset':<28}  title",
        f"{'-' * 5}  {'-' * 8}  {'-' * 8}  {'-' * 16}  {'-' * 28}  {'-' * 40}",
    ]
    for v in r.vulnerabilities:
        a, c = v.assessment, v.correlated
        peak = by_id[a.peak_finding_id]
        asset = c.asset_ref + ("" if peak.assembled.asset_known else " (?)")
        n = len(c.vulnerability.finding_ids)
        seen = ",".join(c.tools) + (f" ({n})" if n > 1 else "")
        flags = " [contested CVSS]" if peak.assembled.cvss and peak.assembled.cvss.contested else ""
        if c.review:
            flags += " [review grouping]"
        if c.not_seen:
            flags += " [not seen in latest " + ",".join(x.tool for x in c.not_seen) + " scan]"
        lines.append(
            f"{a.score:>5}  {a.computed_severity:<8}  {a.source_severity or '-':<8}  "
            f"{seen[:16]:<16}  {asset[:28]:<28}  {peak.finding.classification.title[:70]}{flags}"
        )
    sev = Counter(str(v.assessment.computed_severity) for v in r.vulnerabilities)
    lines += ["", "computed severity (vulnerabilities): " + ", ".join(
        f"{k} {sev[k]}" for k in ("critical", "high", "medium", "low", "info") if sev[k])]
    multi = sum(1 for v in r.vulnerabilities if len(v.correlated.tools) > 1)
    not_seen = sum(1 for v in r.vulnerabilities if v.correlated.not_seen)
    lines.append(f"seen by more than one tool: {multi}   "
                 f"not seen in a newer scan (open, for review): {not_seen}")
    review = [v for v in r.vulnerabilities if v.correlated.review]
    if review:
        lines += ["", f"correlation review ({len(review)}): groups to confirm, nothing changed"]
        for v in review:
            for flag in v.correlated.review:
                lines.append(f"  REVIEW {v.correlated.vulnerability.vulnerability_id} "
                             f"{v.correlated.asset_ref}: {flag.detail}")
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
        "vulnerabilities": [{
            **v.correlated.model_dump(mode="json"),
            "assessment": v.assessment.model_dump(mode="json"),
        } for v in r.vulnerabilities],
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
