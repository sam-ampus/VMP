"""The engine must reproduce every hand-computed vector exactly.

Skipped until vmp.scoring.engine exists: the vectors are written and reviewed first.
"""

from decimal import Decimal
from typing import Any

import pytest
from vector_cases import CASES, IDS, WEIGHTS_VERSION, merged_input

from vmp.scoring import ScoringInput, load_weights

engine = pytest.importorskip(
    "vmp.scoring.engine", reason="engine not written yet: vectors come first"
)

WEIGHTS = load_weights(WEIGHTS_VERSION)


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_engine_reproduces_vector(case: dict[str, Any]) -> None:
    result = engine.score(ScoringInput.model_validate(merged_input(case)), WEIGHTS)
    exp = case["expected"]
    assert result.score == exp["score"]
    assert (result.severity, result.band) == (exp["severity"], exp["band"])
    assert {f.name: f.contribution for f in result.factors} == {
        k: Decimal(v) for k, v in exp["factors"].items()
    }
    assert list(result.missing_inputs) == exp["missing_inputs"]
