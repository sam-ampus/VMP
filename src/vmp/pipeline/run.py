"""Run the pipeline end to end over a drop folder: ingest -> enrich -> score.

Drop-folder layout (what a customer, or the demo seed, provides):

    <folder>/assets.csv                  asset inventory          (optional)
    <folder>/intel/                      offline intel bundle     (optional; see intel/build.py)
    <folder>/scans/<connector>/*         scanner output, one sub-folder per connector name;
                                         each connector reads its own suffixes

Each Finding is scored, then findings are correlated into Vulnerabilities, each assessed on
its peak finding. The folder is the history for now: every scan in it is one point in time.
FP triage and clustering (Stage 2-3) slot in after scoring; the shape of this function is
the pipeline order from the skill.
"""

import hashlib
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from pydantic import AwareDatetime

from vmp.assets import AssetInventory, load_asset_csv
from vmp.connectors import CONNECTORS, ConnectorError, ScanContext, ingest, scan_id_for
from vmp.intel import IntelReader, enrich_all, import_bundle
from vmp.pipeline.assemble import AssembledInput, build_scoring_input
from vmp.pipeline.correlate import Correlated, correlate
from vmp.schema.enrichment import Enrichment
from vmp.schema.finding import Finding, PackageLocus
from vmp.schema.validation import ScanCoverage
from vmp.schema.vulnerability import RiskAssessment
from vmp.scoring.engine import ScoreResult, assess, score
from vmp.scoring.weights import load_weights


@dataclass(frozen=True)
class Scored:
    finding: Finding
    assembled: AssembledInput
    result: ScoreResult


@dataclass(frozen=True)
class AssessedVulnerability:
    correlated: Correlated
    assessment: RiskAssessment


@dataclass(frozen=True)
class IngestProblem:
    file: str
    finding_id: str | None
    messages: tuple[str, ...]


@dataclass(frozen=True)
class RunResult:
    """Everything needed to replay this run: the three input versions plus what came out."""

    weights_version: str
    intel_snapshot_id: str | None
    asset_inventory_id: str | None
    files: tuple[str, ...]
    scored: tuple[Scored, ...]
    problems: tuple[IngestProblem, ...]
    enrichments: dict[str, Enrichment]
    skipped: dict[str, int]  # "<tool>:<reason>" -> count, e.g. "nessus:information_only"
    warnings: tuple[IngestProblem, ...]  # worth reading, not errors (e.g. "no host alive")
    vulnerabilities: tuple[AssessedVulnerability, ...]  # what an analyst works, peak score first


def run_folder(folder: Path, *, now: AwareDatetime, snapshot_root: Path,
               weights_version: str = "w-0.1") -> RunResult:
    inventory = _inventory(folder / "assets.csv")
    ingested = ingest_folder(folder / "scans", now, inventory)
    findings, files, problems = ingested.findings, ingested.files, ingested.problems

    cves = {c for f in findings for c in f.classification.cve}
    purls = {f.locus.purl for f in findings if isinstance(f.locus, PackageLocus)}
    snapshot_id: str | None = None
    enrichments: dict[str, Enrichment] = {}
    if (bundle := folder / "intel").is_dir():
        manifest = import_bundle(bundle, snapshot_root, cves=cves, purls=purls,
                                 imported_at=now)
        snapshot_id = manifest.snapshot_id
        enrichments = enrich_all(cves, IntelReader.load(snapshot_root, snapshot_id))

    weights = load_weights(weights_version)
    scored = []
    for f in sorted(findings, key=lambda f: f.finding_id):
        assembled = build_scoring_input(f, enrichments, inventory)
        scored.append(Scored(f, assembled, score(assembled.scoring_input, weights)))
    scored.sort(key=lambda s: (-s.result.score, s.finding.finding_id))

    inventory_id = inventory.inventory_id if inventory else None
    inputs = {s.finding.finding_id: s.assembled.scoring_input for s in scored}
    vulnerabilities = sorted(
        (AssessedVulnerability(c, assess(
            c.vulnerability.vulnerability_id,
            [(fid, inputs[fid]) for fid in c.vulnerability.finding_ids], weights,
            assessed_at=now, intel_snapshot_id=snapshot_id, asset_inventory_id=inventory_id))
         for c in correlate(findings, ingested.coverage)),
        key=lambda v: (-v.assessment.score, v.correlated.vulnerability.vulnerability_id))

    return RunResult(
        weights_version=weights.version, intel_snapshot_id=snapshot_id,
        asset_inventory_id=inventory_id,
        files=tuple(files), scored=tuple(scored), problems=tuple(problems),
        enrichments=enrichments, skipped=ingested.skipped, warnings=ingested.warnings,
        vulnerabilities=tuple(vulnerabilities),
    )


def _inventory(path: Path) -> AssetInventory | None:
    return load_asset_csv(path) if path.exists() else None


@dataclass(frozen=True)
class Ingested:
    findings: list[Finding]
    files: list[str]
    problems: list[IngestProblem]
    skipped: dict[str, int]
    warnings: tuple[IngestProblem, ...]
    coverage: dict[str, list[ScanCoverage]]  # tool -> assets its scans covered


def ingest_folder(scans: Path, now: AwareDatetime, inventory: AssetInventory | None
                  ) -> Ingested:
    findings: list[Finding] = []
    files: list[str] = []
    problems: list[IngestProblem] = []
    warnings: list[IngestProblem] = []
    skipped: Counter[str] = Counter()
    coverage: dict[str, list[ScanCoverage]] = {}
    for folder in sorted(p for p in scans.iterdir() if p.is_dir()):
        connector = CONNECTORS.get(folder.name)
        if connector is None:
            known = ", ".join(sorted(CONNECTORS))
            problems.append(IngestProblem(folder.name + "/", None,
                                          (f"no connector named {folder.name!r} ({known})",)))
            continue
        # Only the connector's own formats: licence notices and READMEs sit alongside scans.
        for path in sorted(p for p in folder.iterdir() if p.suffix.lower() in connector.extensions):
            rel = path.relative_to(scans).as_posix()
            raw = path.read_bytes()
            ctx = ScanContext(scan_id=scan_id_for(raw, connector.name),
                              batch_id="ing_" + hashlib.sha256(raw).hexdigest()[:12],
                              received_at=now, assets=inventory)
            try:
                report = ingest(connector, raw, ctx)
            except ConnectorError as exc:
                problems.append(IngestProblem(rel, None, (str(exc),)))
                continue
            files.append(rel)
            findings.extend(report.findings)
            problems.extend(IngestProblem(rel, e.finding_id, e.messages) for e in report.errors)
            warnings.extend(IngestProblem(rel, None, (w,)) for w in report.warnings)
            skipped.update({f"{connector.name}:{k}": v for k, v in report.skipped.items()})
            # Canonical batches name their tool in the envelope, not the folder.
            tool = report.batch.source_tool if report.batch else connector.name
            coverage.setdefault(tool, []).extend(report.coverage)
    return Ingested(_unique(findings, problems), files, problems, dict(sorted(skipped.items())),
                    tuple(warnings), coverage)


def _unique(findings: Sequence[Finding], problems: list[IngestProblem]) -> list[Finding]:
    """The same file dropped twice yields the same finding ids; keep one copy."""
    seen: dict[str, Finding] = {}
    for f in findings:
        if f.finding_id in seen and seen[f.finding_id] != f:
            problems.append(IngestProblem("*", f.finding_id,
                                          ("two different findings share this finding_id",)))
        seen.setdefault(f.finding_id, f)
    return list(seen.values())
