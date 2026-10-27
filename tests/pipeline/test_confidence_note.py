"""The confidence tooltip: same word, different claims, explained; points match the weights."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from vmp.connectors import QualysConnector, ScanContext, ingest
from vmp.pipeline.confidence_note import confidence_note
from vmp.schema.finding import Finding
from vmp.scoring.weights import load_weights

REPO = Path(__file__).resolve().parents[2]
W = load_weights("w-0.1")
AT = datetime(2026, 10, 26, tzinfo=UTC)


def qualys() -> dict[str, Finding]:
    raw = (REPO / "tests/connectors/samples/qualys-iva.xml").read_bytes()
    report = ingest(QualysConnector(), raw, ScanContext("scan_q", "ing_q", AT))
    return {f.source.native_id: f for f in report.findings}


def with_validation(f: Finding, **kw: object) -> Finding:
    data = f.model_dump(mode="json")
    data["validation"].update(kw)
    return Finding.model_validate(data)


def test_qualys_confirmed_explains_it_is_a_detection_not_an_exploit() -> None:
    note = confidence_note(qualys()["38173"], W)
    assert note.startswith("Qualys reports this as Confirmed: its detection check matched")
    assert note.endswith("Confidence 'unvalidated' neither adds nor removes points.")


def test_qualys_potential_is_explained() -> None:
    assert "could not verify" in confidence_note(qualys()["38913"], W)


@pytest.mark.parametrize(("confidence", "phrase", "effect"), [
    ("confirmed", "exploiting it during the test", "adds 15 points"),
    ("likely", "strong signs of working", "adds 8 points"),
    ("untested", "did not try it", "takes 8 points off"),
])
def test_mirror_labels_and_their_effect_come_from_the_weights(
        confidence: str, phrase: str, effect: str) -> None:
    data = qualys()["38173"].model_dump(mode="json")
    data["source"]["tool"] = "mirror"
    data["idempotency_key"] = data["idempotency_key"].replace("qualys:", "mirror:", 1)
    data["validation"].update(confidence=confidence, confidence_source="tool_asserted",
                              tool_label=None)
    note = confidence_note(Finding.model_validate(data), W)
    assert phrase in note
    assert effect in note
    assert str(W.validation.confidence[confidence]).lstrip("-") in note  # type: ignore[index]


def test_scanner_default_and_analyst_overrides() -> None:
    f = qualys()["38173"]
    assert "does not report whether its findings were verified" in confidence_note(
        with_validation(f, tool_label=None), W)
    assert confidence_note(with_validation(f, confidence="confirmed",
                                           confidence_source="analyst"), W).startswith(
        "An analyst set this finding's confidence to confirmed.")
