"""The constructed FP benchmark: it passes, it covers the skill's five categories, and its
hard rule actually fails a run when a real issue is called not real."""

import json
from pathlib import Path

import pytest

from benchmark import harness
from benchmark.harness import CASES, main, run
from vmp.schema.enums import FPBand
from vmp.schema.vulnerability import FPAssessment

SKILL_CATEGORIES = {"version-mismatch", "unauthenticated-scan-inference",
                    "platform-inapplicability", "superseded-patch", "cross-scanner-duplicate"}


def test_benchmark_passes_with_no_real_issue_called_not_real() -> None:
    report = run()
    m = report.metrics()
    assert report.ok, harness.render(report)
    assert m["violations"] == []
    assert m["fp_called_real"] == 0
    assert m["precision"] == 1.0


def test_every_skill_category_is_covered_with_both_truths() -> None:
    report = run()
    assert {o.category for o in report.outcomes} >= SKILL_CATEGORIES
    for category in SKILL_CATEGORIES - {"cross-scanner-duplicate"}:
        truths = {o.truth for o in report.outcomes if o.category == category}
        assert truths == {"real", "false_positive"}, category


def test_known_limitations_show_up_as_missed_recall_not_as_wrong_calls() -> None:
    m = run().metrics()
    assert m["recall"] is not None and m["recall"] < 1.0  # the limitation is visible
    assert m["fp_called_real"] == 0  # and never turns into "it's real"


def test_hard_rule_fails_the_run(monkeypatch: pytest.MonkeyPatch,
                                 capsys: pytest.CaptureFixture[str]) -> None:
    """Break the rules on purpose: every finding called a likely FP."""
    def always_fp(finding: object, osv: object = None) -> FPAssessment:
        a = original(finding, osv)  # type: ignore[arg-type]
        band = (FPBand.NEEDS_REVIEW if a.locus_type == "endpoint"
                else FPBand.LIKELY_FALSE_POSITIVE)
        return a.model_copy(update={"band": band})

    original = harness.assess_fp
    monkeypatch.setattr(harness, "assess_fp", always_fp)
    assert main([]) == 1
    out = capsys.readouterr().out
    assert "HARD RULE BROKEN" in out and out.rstrip().endswith("FAIL")


def test_a_band_change_shows_as_a_mismatch(tmp_path: Path) -> None:
    case = json.loads((CASES / "superseded_patch.json").read_text("utf-8"))
    case["cases"] = case["cases"][:1]
    case["cases"][0]["expect"] = "needs_review"
    (tmp_path / "one.json").write_text(json.dumps(case), "utf-8")
    report = run(tmp_path)
    assert not report.ok
    assert [o.case_id for o in report.mismatches] == ["sp-nessus-equal-versions"]
