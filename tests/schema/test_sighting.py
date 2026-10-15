import pytest
from pydantic import ValidationError

from vmp.schema import Sighting

RAW = {"finding_id": "fnd_7c2a91", "scan_id": "scan_nessus_20130708",
       "ingest_batch_id": "ing_02", "detected_at": "2013-07-08T09:00:00Z"}


def test_sighting_parses_and_is_frozen() -> None:
    s = Sighting.model_validate(RAW)
    with pytest.raises(ValidationError):
        s.scan_id = "other"  # type: ignore[misc]


def test_sighting_needs_a_timezone() -> None:
    with pytest.raises(ValidationError, match="timezone"):
        Sighting.model_validate(RAW | {"detected_at": "2013-07-08T09:00:00"})
