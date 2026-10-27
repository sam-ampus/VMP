"""The plain-language note behind a finding's confidence: the text for the UI tooltip.

Tools use the same words for different claims. Qualys "Confirmed" means its detection check
matched; Mirror "Confirmed" means the issue was exploited during the test. A reader who sees
"Confirmed" next to a score needs to know which claim it is and what it did to the score.

Deterministic, like every explanation of a number: the text is chosen by rule from the
finding's fields, and the points are read from the weights the score actually used, so the
note can never disagree with the score trace. No model writes or rewrites this text.
"""

from decimal import Decimal

from vmp.schema.enums import Confidence, ConfidenceSource
from vmp.schema.finding import Finding
from vmp.scoring.weights import Weights

# (tool, the tool's own label) -> what the tool's word means. Keyed on the label, not on our
# confidence value, because that is exactly where tools disagree.
_TOOL_MEANING = {
    ("qualys", "confirmed"): (
        "Qualys reports this as Confirmed: its detection check matched on the host (for example "
        "a version or configuration check). Nobody exploited it, so VMP treats it like any other "
        "scanner result: unvalidated."),
    ("qualys", "potential"): (
        "Qualys reports this as Potential: its check points to the weakness but could not verify "
        "it. VMP keeps it as potential, which makes it a candidate for false-positive review."),
}
_MIRROR_MEANING = {
    Confidence.CONFIRMED: ("Mirror confirmed this by exploiting it during the test; the "
                           "request and response are the proof."),
    Confidence.LIKELY: ("Mirror rates this Likely: the attack showed strong signs of working "
                        "(for example, the payload was delivered) but was not fully proven."),
    Confidence.POTENTIAL: "Mirror rates this Potential: a lead that was not tested to a result.",
    Confidence.UNTESTED: "Mirror lists this as Untested: it found the issue but did not try it.",
}


def confidence_note(finding: Finding, weights: Weights) -> str:
    v, tool = finding.validation, finding.source.tool
    label = (v.tool_label or "").lower()
    if v.confidence_source is ConfidenceSource.ANALYST:
        meaning = f"An analyst set this finding's confidence to {v.confidence}."
    elif (tool, label) in _TOOL_MEANING:
        meaning = _TOOL_MEANING[(tool, label)]
    elif tool == "mirror" and v.confidence in _MIRROR_MEANING:
        meaning = _MIRROR_MEANING[v.confidence]
    elif v.confidence_source is ConfidenceSource.DEFAULT_FOR_TOOL_CLASS:
        meaning = (f"{tool.capitalize()} does not report whether its findings were verified, "
                   "so VMP treats this as unvalidated.")
    else:
        said = v.tool_label or str(v.confidence)
        meaning = f"{tool.capitalize()} rated this finding's confidence as {said}."
    return f"{meaning} {_effect(weights.validation.confidence[v.confidence], v.confidence)}"


def _effect(points: Decimal, confidence: Confidence) -> str:
    if points > 0:
        return f"Confidence '{confidence}' adds {points} points to the score."
    if points < 0:
        return f"Confidence '{confidence}' takes {-points} points off the score."
    return f"Confidence '{confidence}' neither adds nor removes points."
