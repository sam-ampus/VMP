"""Check the hand-computed vectors are internally consistent, before any engine exists.

This catches arithmetic slips in the vectors. It cannot catch a wrong policy choice;
that is what human review of the vectors is for.
"""

from decimal import ROUND_HALF_UP, Decimal
from typing import Any

import pytest
from vector_cases import CASES, IDS, WEIGHTS_VERSION, merged_input

from vmp.scoring import FactorName, MissingInput, ScoringInput, load_weights

WEIGHTS = load_weights(WEIGHTS_VERSION)
BASE_FACTORS = {FactorName.CVSS_BASE, FactorName.SEVERITY_FALLBACK}


def test_enough_unique_cases() -> None:
    assert len(CASES) >= 30
    assert len(set(IDS)) == len(IDS)


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_vector_is_consistent(case: dict[str, Any]) -> None:
    inp = ScoringInput.model_validate(merged_input(case))
    exp = case["expected"]
    factors = {FactorName(k): Decimal(v) for k, v in exp["factors"].items()}

    # Exactly one base factor, and it is the right one for the input.
    (base,) = BASE_FACTORS & factors.keys()
    if inp.cvss_base is not None:
        assert base is FactorName.CVSS_BASE
        assert factors[base] == inp.cvss_base * WEIGHTS.base.cvss_multiplier
    else:
        assert base is FactorName.SEVERITY_FALLBACK
        assert factors[base] == WEIGHTS.base.severity_fallback[inp.source_severity]

    # Non-base factors are listed only when they move the score.
    assert all(v != 0 for k, v in factors.items() if k not in BASE_FACTORS)

    # The score is fully explained by the factors.
    raw = sum(factors.values(), Decimal(0))
    rounded = int(raw.quantize(Decimal(1), rounding=ROUND_HALF_UP))
    assert exp["score"] == max(0, min(100, rounded))

    tier = WEIGHTS.classify(exp["score"])
    assert (exp["severity"], exp["band"]) == (tier.severity, tier.band)

    missing = exp["missing_inputs"]
    assert missing == sorted(missing)
    assert all(MissingInput(m) for m in missing)
