from collections.abc import Iterable

from vmp.schema.enums import FPBand
from vmp.schema.finding import Finding
from vmp.schema.vulnerability import MECHANISM_FOR_LOCUS, FPAssessment


def fp(finding: Finding, band: FPBand, rationale: str, facts: Iterable[str]) -> FPAssessment:
    """One FP assessment, with the mechanism always the one the finding's shape requires."""
    locus_type = finding.locus.type
    return FPAssessment(
        finding_id=finding.finding_id, locus_type=locus_type,  # type: ignore[arg-type]
        mechanism=MECHANISM_FOR_LOCUS[locus_type],  # type: ignore[index]
        band=band, rationale=rationale, facts=tuple(dict.fromkeys(facts)))
