"""Endpoint findings (Mirror, DAST): confidence tier plus evidence, never version math.

A web finding has no installed version to compare. What it has is how far the tool got:
exploited (confirmed), strong signs (likely), a lead (potential), or not tried (untested), and
whether it kept the request and response that show it.

Never 'likely_false_positive' in step 8: saying a web finding isn't real takes a fact against
it, such as the endpoint being unreachable or the response not matching the claim. No input
carries those facts yet (backlog B-052). A finding nobody tested needs review, not dismissal.
"""

from vmp.pipeline.assess_fp.common import fp
from vmp.schema.enums import Confidence, EvidenceCompleteness, FPBand
from vmp.schema.finding import Finding
from vmp.schema.vulnerability import FPAssessment


def assess_endpoint(finding: Finding) -> FPAssessment:
    v = finding.validation
    said = v.tool_label or str(v.confidence)
    facts = [f"{finding.source.tool} confidence: {said}",
             f"evidence: {v.evidence_completeness}",
             *(f"evidence gap: {g}" for g in v.evidence_gaps)]
    if v.confidence is Confidence.CONFIRMED or v.reproduced:
        return fp(finding, FPBand.LOW_LIKELIHOOD,
                  "The tool exploited or reproduced this during the test.", facts)
    if v.confidence is Confidence.LIKELY and v.evidence_completeness is not \
            EvidenceCompleteness.NONE:
        return fp(finding, FPBand.LOW_LIKELIHOOD,
                  "The tool saw strong signs it works and kept evidence of them.", facts)
    if v.confidence is Confidence.LIKELY:
        return fp(finding, FPBand.NEEDS_REVIEW,
                  "Rated likely, but no evidence was kept to check that against.", facts)
    return fp(finding, FPBand.NEEDS_REVIEW,
              f"Not verified by the tool ({said}); a person should try it before it is "
              "trusted or dismissed.", facts)
