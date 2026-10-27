"""The end-to-end slice: drop folder -> connectors -> intel -> assets -> score.

The point is not any one number but that the layers agree: the full pipeline reproduces
a hand-computed scoring vector, and the same inputs give the same output.
"""

import json
import shutil
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from vmp.assets import AssetInventory, load_asset_csv
from vmp.cli import main, to_json
from vmp.connectors import CanonicalConnector, ScanContext, ingest
from vmp.pipeline.assemble import build_scoring_input
from vmp.pipeline.run import RunResult, run_folder
from vmp.schema.enrichment import Enrichment

REPO = Path(__file__).resolve().parents[2]
SEED = REPO / "seed" / "demo"
AT = datetime(2026, 10, 22, tzinfo=UTC)


@pytest.fixture(scope="module")
def result(tmp_path_factory: pytest.TempPathFactory) -> RunResult:
    return run_folder(SEED, now=AT, snapshot_root=tmp_path_factory.mktemp("snaps"))


def by_title(r: RunResult, prefix: str) -> list[object]:
    return [s for s in r.scored if s.finding.classification.title.startswith(prefix)]


def test_seed_ingests_cleanly(result: RunResult) -> None:
    assert result.problems == ()
    assert len(result.files) == 5
    assert {s.finding.source.tool for s in result.scored} == {"mirror", "nessus", "trivy"}


def test_pipeline_reproduces_the_hand_computed_cilium_vector(result: RunResult) -> None:
    """Step 2's vector 'sample_cilium' = 33 medium, from NVD 7.2, EPSS, internal production."""
    vectors = json.loads((REPO / "tests/scoring/vectors/w-0.1.json").read_text("utf-8"))
    expected = next(c for c in vectors["cases"] if c["id"] == "sample_cilium")["expected"]
    (cilium,) = by_title(result, "Intermittent HTTP policy bypass")
    assert cilium.result.score == expected["score"]  # type: ignore[attr-defined]
    assert cilium.result.severity == expected["severity"]  # type: ignore[attr-defined]


def test_kev_listing_lifts_a_medium_finding_to_critical(result: RunResult) -> None:
    (freetype,) = by_title(result, "freetype")
    names = {f.name for f in freetype.result.factors}  # type: ignore[attr-defined]
    assert "known_exploited" in names
    assert freetype.result.severity == "critical"  # type: ignore[attr-defined]
    assert freetype.finding.classification.source_severity == "medium"  # type: ignore[attr-defined]
    # Alpine package: Red Hat's 8.6 must not win the distro tier. NVD wins, with NVD's
    # *current* score from the snapshot (9.6), not the 6.5 Trivy's database held at scan time.
    sel = freetype.assembled.cvss  # type: ignore[attr-defined]
    assert (sel.rule, sel.source) == ("nvd", "nvd@nist.gov")
    tool_nvd = {c.base for c in freetype.finding.scores.cvss  # type: ignore[attr-defined]
                if c.source == "nvd" and c.version == "3.1"}
    assert tool_nvd == {Decimal("6.5")} and sel.base != Decimal("6.5")


def test_unknown_asset_scores_without_context_and_says_so(result: RunResult) -> None:
    unknown = [s for s in result.scored if not s.assembled.asset_known]
    assert unknown and all(s.finding.locus.asset_ref.startswith("ast_unresolved_")
                           for s in unknown)
    for s in unknown:
        assert {"internet_facing", "asset_criticality", "environment"} <= set(
            s.result.missing_inputs)


def test_every_score_is_traceable_to_its_three_input_versions(result: RunResult) -> None:
    assert result.weights_version == "w-0.1"
    assert result.intel_snapshot_id and result.asset_inventory_id
    assert all(s.result.factors for s in result.scored)


def test_rerun_is_byte_identical(result: RunResult, tmp_path: Path) -> None:
    again = run_folder(SEED, now=AT, snapshot_root=tmp_path)
    assert json.dumps(to_json(again, AT)) == json.dumps(to_json(result, AT))


def test_scan_folder_order_does_not_matter(result: RunResult, tmp_path: Path) -> None:
    """Copy the seed with files renamed so they sort in reverse; the result must not move."""
    copy = tmp_path / "seed"
    shutil.copytree(SEED, copy)
    for path in sorted((copy / "scans").glob("*/*.json")):
        path.rename(path.with_name("z" * (10 - len(path.stem) % 10) + path.name))
    again = run_folder(copy, now=AT, snapshot_root=tmp_path / "snaps")
    ids = [s.finding.finding_id for s in again.scored]
    assert ids == [s.finding.finding_id for s in result.scored]


def test_intel_beats_the_tools_own_kev_and_epss(batch: dict[str, object]) -> None:
    raw = json.dumps(batch).encode()
    report = ingest(CanonicalConnector(), raw,
                    ScanContext(scan_id="s", batch_id="b", received_at=AT))
    cilium = next(f for f in report.findings if f.locus.type == "package")
    assert cilium.scores.epss == Decimal("0.0042")  # what Trivy reported
    intel = {"CVE-2024-28248": Enrichment(cve="CVE-2024-28248", snapshot_id="x", kev=False,
                                          epss=Decimal("0.0062"))}
    assert build_scoring_input(cilium, intel, None).scoring_input.epss == Decimal("0.0062")
    # Intel silent -> fall back to the tool's report, never invent.
    unknown = {"CVE-2024-28248": Enrichment(cve="CVE-2024-28248", snapshot_id="x")}
    inp = build_scoring_input(cilium, unknown, None).scoring_input
    assert (inp.epss, inp.kev) == (Decimal("0.0042"), False)


def test_asset_context_comes_from_the_inventory(batch: dict[str, object]) -> None:
    report = ingest(CanonicalConnector(), json.dumps(batch).encode(),
                    ScanContext(scan_id="s", batch_id="b", received_at=AT))
    inventory: AssetInventory = load_asset_csv(SEED / "assets.csv")
    host = next(f for f in report.findings if f.locus.type == "host")
    inp = build_scoring_input(host, {}, inventory).scoring_input
    assert (inp.internet_facing, inp.asset_criticality, inp.environment) == (
        False, "medium", "non_production")


def test_cli_exit_code_and_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "run.json"
    code = main(["ingest", str(SEED), "--as-of", "2026-10-22T00:00:00+00:00",
                 "--snapshots", str(tmp_path / "s"), "--json", str(out)])
    assert code == 0
    assert "findings scored: 67" in capsys.readouterr().out
    assert len(json.loads(out.read_text("utf-8"))["scored"]) == 67
