"""Engine properties beyond the vectors: determinism, monotonicity, explanation, aggregation."""

from datetime import UTC, datetime
from typing import Any

import pytest
from vector_cases import CASES, IDS, WEIGHTS_VERSION, merged_input

from vmp.scoring import ScoringInput, load_weights
from vmp.scoring.engine import assess, score

WEIGHTS = load_weights(WEIGHTS_VERSION)
INPUTS = [ScoringInput.model_validate(merged_input(c)) for c in CASES]
AT = datetime(2026, 10, 12, tzinfo=UTC)


@pytest.mark.parametrize("inp", INPUTS, ids=IDS)
def test_deterministic(inp: ScoringInput) -> None:
    assert score(inp, WEIGHTS) == score(inp, WEIGHTS)


@pytest.mark.parametrize("inp", INPUTS, ids=IDS)
@pytest.mark.parametrize("change", [
    {"kev": True}, {"exploit_available": True}, {"internet_facing": True},
    {"confidence": "confirmed"},
], ids=lambda c: next(iter(c)))
def test_more_threat_or_exposure_never_lowers_the_score(
    inp: ScoringInput, change: dict[str, Any]
) -> None:
    worse = ScoringInput.model_validate(inp.model_dump() | change)
    assert score(worse, WEIGHTS).score >= score(inp, WEIGHTS).score


@pytest.mark.parametrize("inp", INPUTS, ids=IDS)
def test_delta_reason_iff_severities_differ(inp: ScoringInput) -> None:
    r = score(inp, WEIGHTS)
    if r.severity == inp.source_severity:
        assert r.severity_delta_reason is None
    else:
        assert r.severity_delta_reason is not None
        assert f"Computed {r.severity} vs source {inp.source_severity}" in (
            r.severity_delta_reason
        )


def test_delta_reason_names_the_biggest_drivers() -> None:
    cilium = INPUTS[IDS.index("sample_cilium")]
    assert score(cilium, WEIGHTS).severity_delta_reason == (
        "Computed medium vs source high: epss (-5), internet facing (-5)."
    )


def test_assessment_takes_the_peak_finding_regardless_of_order() -> None:
    internal = INPUTS[IDS.index("not_internet_facing")]  # 40
    exposed = INPUTS[IDS.index("internet_facing")]  # 55
    pairs = [("fnd_a", internal), ("fnd_b", exposed)]
    forward = assess("vln_x", pairs, WEIGHTS, assessed_at=AT)
    backward = assess("vln_x", pairs[::-1], WEIGHTS, assessed_at=AT)
    assert forward == backward
    assert (forward.peak_finding_id, forward.score) == ("fnd_b", 55)
    assert forward.weights_version == WEIGHTS_VERSION


def test_ties_go_to_the_lowest_finding_id() -> None:
    inp = INPUTS[0]
    result = assess("vln_x", [("fnd_z", inp), ("fnd_a", inp)], WEIGHTS, assessed_at=AT)
    assert result.peak_finding_id == "fnd_a"


def test_assessing_nothing_is_an_error() -> None:
    with pytest.raises(ValueError, match="at least one finding"):
        assess("vln_x", [], WEIGHTS, assessed_at=AT)
