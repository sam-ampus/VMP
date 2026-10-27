"""Assemble a ScoringInput from the three things that know about a finding.

    Finding (what the tool saw) + Enrichment (what threat intel says about its CVEs)
                                + Asset (what the inventory says about where it is)
                                ─────────────────────────────────────────► ScoringInput

This is the only place those three meet before scoring. Each rule below says which source
wins when they overlap, and an input no source knows stays None (unknown), which the
engine scores as neutral and lists as missing.
"""

from collections.abc import Iterable, Mapping
from decimal import Decimal

from vmp.assets import AssetProvider
from vmp.pipeline.cvss import distro_of, select_cvss
from vmp.schema.enrichment import CvssSelection, Enrichment
from vmp.schema.finding import Finding, PackageLocus
from vmp.schema.types import Model
from vmp.scoring.inputs import ScoringInput


class AssembledInput(Model):
    finding_id: str
    scoring_input: ScoringInput
    cvss: CvssSelection | None  # carries the rule and the contested flag for the UI
    asset_ref: str
    asset_known: bool


def build_scoring_input(
    finding: Finding, enrichments: Mapping[str, Enrichment], assets: AssetProvider | None
) -> AssembledInput:
    intel = [enrichments[c] for c in finding.classification.cve if c in enrichments]
    purl = finding.locus.purl if isinstance(finding.locus, PackageLocus) else None
    cvss = select_cvss(
        finding.scores.cvss, [s for e in intel for s in e.cvss], distro=distro_of(purl)
    )
    asset = assets.resolve(finding.locus.asset_ref) if assets is not None else None

    kev = _kev(e.kev for e in intel)
    epss = _epss(e.epss for e in intel)
    inp = ScoringInput(
        cvss_base=cvss.base if cvss else None,
        source_severity=finding.classification.source_severity,
        has_cve=bool(finding.classification.cve),
        # Intel wins when it knows; the tool's own report is the fallback, never the override.
        kev=kev if kev is not None else finding.scores.kev,
        epss=epss if epss is not None else finding.scores.epss,
        exploit_available=finding.exploit_signals.exploit_available,
        internet_facing=asset.internet_facing if asset else None,
        asset_criticality=asset.criticality if asset else None,
        environment=asset.environment if asset else None,
        confidence=finding.validation.confidence,
        evidence_completeness=finding.validation.evidence_completeness,
    )
    return AssembledInput(finding_id=finding.finding_id, scoring_input=inp, cvss=cvss,
                          asset_ref=finding.locus.asset_ref, asset_known=asset is not None)


def _kev(values: Iterable[bool | None]) -> bool | None:
    """Intel wins over the tool: KEV is CISA's catalogue, not the scanner's opinion.
    Any CVE listed -> True; all known and unlisted -> False; otherwise unknown."""
    vals = list(values)
    if any(v is True for v in vals):
        return True
    return False if vals and all(v is False for v in vals) else None


def _epss(values: Iterable[Decimal | None]) -> Decimal | None:
    """The most likely-to-be-exploited CVE drives the finding (conservative)."""
    known = [v for v in values if v is not None]
    return max(known) if known else None
