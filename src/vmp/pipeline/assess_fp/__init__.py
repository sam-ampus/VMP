"""False-positive triage: three mechanisms, chosen by the finding's shape (skill rule).

    host      version_range            assess_host      can be "likely FP", never certain
    package   deterministic_version    assess_package   certain whenever the math is exact
    endpoint  confidence_reachability  assess_endpoint  never version math, never certain

Flags only. The band never changes the risk score and never hides or closes a finding
(decisions 2026-10-09 and 2026-10-28): "probably not real" and "dangerous if real" are
different questions, so each keeps its own axis and the analyst sees both.

This is the agent seam. A later evidence agent may add facts (for example the package list it
read from a host); these functions still pick the band, so the outcome stays reproducible.
"""

from collections.abc import Sequence

from vmp.intel.records import OsvPackage
from vmp.pipeline.assess_fp.endpoint import assess_endpoint
from vmp.pipeline.assess_fp.host import assess_host, logged_in
from vmp.pipeline.assess_fp.package import assess_package
from vmp.schema.enums import FPBand
from vmp.schema.finding import EndpointLocus, Finding, HostLocus, PackageLocus
from vmp.schema.types import Model, NonEmptyStr
from vmp.schema.vulnerability import FPAssessment

# Which way each band points: evidence the finding is real, against it, or neither.
REAL = (FPBand.CONFIRMED_APPLICABLE, FPBand.LOW_LIKELIHOOD)
NOT_REAL = (FPBand.CONFIRMED_NOT_APPLICABLE, FPBand.LIKELY_FALSE_POSITIVE)
# Strongest first, within each side.
_STRENGTH = [FPBand.CONFIRMED_APPLICABLE, FPBand.CONFIRMED_NOT_APPLICABLE,
             FPBand.LIKELY_FALSE_POSITIVE, FPBand.LOW_LIKELIHOOD, FPBand.NEEDS_REVIEW]


def assess_fp(finding: Finding, osv: OsvPackage | None = None) -> FPAssessment:
    match finding.locus:
        case HostLocus():
            return assess_host(finding)
        case PackageLocus():
            return assess_package(finding, osv)
        case EndpointLocus():
            return assess_endpoint(finding)


class VulnerabilityFP(Model):
    """The FP view of one Vulnerability: one band, and every finding's own assessment."""

    vulnerability_id: NonEmptyStr
    band: FPBand
    rationale: NonEmptyStr
    facts: tuple[NonEmptyStr, ...] = ()
    findings: tuple[FPAssessment, ...]


def combine(vulnerability_id: str, findings: Sequence[Finding],
            assessments: Sequence[FPAssessment]) -> VulnerabilityFP:
    """One band for a vulnerability from its findings' bands.

    - Findings that point opposite ways (real vs not real) -> needs_review: a person decides.
    - Evidence that it's real beats an open question; "not real" needs every finding to agree.
    - Two tools reporting it, at least one with a working login, lifts needs_review to
      low_likelihood. Two unauthenticated tools can both be reading the same banner, so
      they don't count as independent.
    """
    by_id = {a.finding_id: a for a in assessments}
    ordered = tuple(by_id[f.finding_id] for f in findings)
    bands = {a.band for a in ordered}
    facts: list[str] = []

    if bands & set(REAL) and bands & set(NOT_REAL):
        band = FPBand.NEEDS_REVIEW
        rationale = "Its findings disagree: some point to a real issue, others to a false positive."
    elif bands <= set(NOT_REAL):
        band = min(bands, key=_STRENGTH.index)
        rationale = next(a.rationale for a in ordered if a.band is band)
    elif bands & set(REAL):
        band = min(bands & set(REAL), key=_STRENGTH.index)
        rationale = next(a.rationale for a in ordered if a.band is band)
    else:
        band = FPBand.NEEDS_REVIEW
        rationale = ordered[0].rationale

    tools = sorted({f.source.tool for f in findings})
    if len(tools) > 1:
        facts.append(f"reported by {len(tools)} tools ({', '.join(tools)})")
        any_login = any(isinstance(f.locus, HostLocus) and logged_in(f) for f in findings)
        if band is FPBand.NEEDS_REVIEW and any_login and not bands & set(NOT_REAL):
            band = FPBand.LOW_LIKELIHOOD
            rationale = ("Reported independently by more than one tool, at least one of them "
                         "with a working login.")
    for a in ordered:
        facts.extend(a.facts)
    return VulnerabilityFP(vulnerability_id=vulnerability_id, band=band, rationale=rationale,
                           facts=tuple(dict.fromkeys(facts)), findings=ordered)


__all__ = ["NOT_REAL", "REAL", "VulnerabilityFP", "assess_fp", "combine"]
