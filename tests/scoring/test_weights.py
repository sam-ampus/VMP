import pytest
from pydantic import ValidationError

from vmp.scoring import DEFAULT_VERSION, Weights, load_weights


def test_default_weights_load_and_declare_their_version() -> None:
    assert load_weights().version == DEFAULT_VERSION


def test_every_enum_value_needs_a_weight() -> None:
    raw = load_weights().model_dump(mode="json")
    del raw["validation"]["confidence"]["potential"]
    with pytest.raises(ValidationError, match="no weight for"):
        Weights.model_validate(raw)


def test_thresholds_must_reach_zero() -> None:
    raw = load_weights().model_dump(mode="json")
    raw["severity_thresholds"] = raw["severity_thresholds"][:-1]
    with pytest.raises(ValidationError, match="end at min_score 0"):
        Weights.model_validate(raw)


def test_epss_bands_must_be_descending() -> None:
    raw = load_weights().model_dump(mode="json")
    raw["threat"]["epss_bands"].reverse()
    with pytest.raises(ValidationError, match="highest first"):
        Weights.model_validate(raw)
