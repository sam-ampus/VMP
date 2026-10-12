from typing import Any

from vmp.schema import validate_batch


def test_corrected_fixture_is_valid(batch: dict[str, Any]) -> None:
    report = validate_batch(batch)
    assert report.ok, report.errors
    assert [f.locus.type for f in report.findings] == ["host", "package", "endpoint"]


def test_one_bad_record_does_not_hide_the_others(batch: dict[str, Any]) -> None:
    batch["findings"][1]["locus"]["fixed_version"] = []
    batch["findings"][2]["validation"]["evidence_gaps"] = []
    report = validate_batch(batch)
    assert len(report.findings) == 1
    assert [(e.index, e.finding_id) for e in report.errors] == [
        (1, "fnd_a41f03"),
        (2, "fnd_e90bb7"),
    ]


def test_duplicate_finding_ids_are_reported(batch: dict[str, Any]) -> None:
    batch["findings"].append(batch["findings"][0])
    report = validate_batch(batch)
    assert not report.ok
    assert "duplicate finding_id" in report.errors[0].messages[0]


def test_bad_envelope_is_reported_without_parsing_findings(batch: dict[str, Any]) -> None:
    batch["schema_version"] = "9.9"
    report = validate_batch(batch)
    assert report.batch is None
    assert report.errors[0].index is None


def test_original_reference_fixture_is_rejected(reference_batch: dict[str, Any]) -> None:
    """The reference sample predates the locked decisions; every finding conflicts with them."""
    report = validate_batch(reference_batch)
    assert not report.findings
    assert len(report.errors) == 3
