"""Qualys and Nessus through the whole pipeline: folder routing, skipped counts, warnings,
and how host findings with and without CVSS score.
"""

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vmp.cli import main
from vmp.pipeline.run import RunResult, run_folder
from vmp.scoring.inputs import FactorName, MissingInput

SAMPLES = Path(__file__).resolve().parents[1] / "connectors" / "samples"
AT = datetime(2026, 10, 26, tzinfo=UTC)


@pytest.fixture
def drop(tmp_path: Path) -> Path:
    (tmp_path / "scans" / "qualys").mkdir(parents=True)
    (tmp_path / "scans" / "nessus").mkdir()
    for name in ("qualys-iva.xml", "qualys-no-host-alive.xml"):
        shutil.copy(SAMPLES / name, tmp_path / "scans" / "qualys" / name)
    shutil.copy(SAMPLES / "nessus-iva.nessus", tmp_path / "scans" / "nessus" / "iva.nessus")
    # Sits beside the scans in real drops; must be ignored, not reported as a bad scan.
    (tmp_path / "scans" / "nessus" / "README.md").write_text("notes", "utf-8")
    return tmp_path


def run(drop: Path, tmp_path: Path) -> RunResult:
    return run_folder(drop, now=AT, snapshot_root=tmp_path / "snaps")


def scored(r: RunResult, tool: str, native_id: str) -> object:
    return next(s for s in r.scored
                if (s.finding.source.tool, s.finding.source.native_id) == (tool, native_id))


def test_each_connector_reads_only_its_own_files(drop: Path, tmp_path: Path) -> None:
    r = run(drop, tmp_path)
    assert r.problems == ()
    assert r.files == ("nessus/iva.nessus", "qualys/qualys-iva.xml",
                       "qualys/qualys-no-host-alive.xml")
    assert {s.finding.source.tool for s in r.scored} == {"nessus", "qualys"}


def test_skipped_and_warnings_are_reported_per_tool(drop: Path, tmp_path: Path) -> None:
    r = run(drop, tmp_path)
    assert r.skipped == {"nessus:information_only": 2, "qualys:information_gathered": 3}
    assert [(w.file, w.messages) for w in r.warnings] == [
        ("qualys/qualys-no-host-alive.xml", ("Qualys reported error 3509: No host alive",))]


def test_no_cve_finding_scores_on_source_severity_and_is_not_missing_cvss(
        drop: Path, tmp_path: Path) -> None:
    s = scored(run(drop, tmp_path), "qualys", "150004")
    assert s.result.factors[0].name == FactorName.SEVERITY_FALLBACK  # type: ignore[attr-defined]
    assert MissingInput.CVSS not in s.result.missing_inputs  # type: ignore[attr-defined]


def test_cve_finding_without_any_cvss_says_so(drop: Path, tmp_path: Path) -> None:
    """Qualys carries no CVSS; with no intel bundle the gap must be visible, not guessed."""
    s = scored(run(drop, tmp_path), "qualys", "38173")
    assert s.result.factors[0].name == FactorName.SEVERITY_FALLBACK  # type: ignore[attr-defined]
    assert MissingInput.CVSS in s.result.missing_inputs  # type: ignore[attr-defined]


def test_nessus_cvss_is_used_as_the_tool_tier(drop: Path, tmp_path: Path) -> None:
    s = scored(run(drop, tmp_path), "nessus", "200001")
    cvss = s.assembled.cvss  # type: ignore[attr-defined]
    assert (cvss.rule, cvss.version, str(cvss.base)) == ("tool", "3.0", "7.5")


def test_warnings_do_not_fail_the_run(drop: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["ingest", str(drop), "--as-of", "2026-10-26T00:00:00Z",
                 "--snapshots", str(drop / ".snaps")])
    out = capsys.readouterr().out
    assert code == 0
    assert "skipped (not findings): nessus:information_only 2" in out
    assert "WARNING qualys/qualys-no-host-alive.xml" in out
