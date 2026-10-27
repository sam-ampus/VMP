"""Trivy connector: mapping, statuses, CVSS, purls, determinism, foreign input.

Fixtures are DefectDojo's Trivy samples (BSD-3-Clause, see seed/demo/scans/trivy/).
"""

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from vmp.assets import load_asset_csv
from vmp.connectors import ConnectorError, ScanContext, TrivyConnector, ingest
from vmp.connectors.trivy import _purl
from vmp.pipeline.cvss import _DISTRO_SOURCE, DISTRO_SOURCES
from vmp.schema.enums import FixStatus

REPO = Path(__file__).resolve().parents[2]
SAMPLES = REPO / "seed" / "demo" / "scans" / "trivy"
AT = datetime(2026, 10, 22, tzinfo=UTC)


def ctx(**kw: Any) -> ScanContext:
    return ScanContext(scan_id="scan_t1", batch_id="ing_t1", received_at=AT, **kw)


def run(name: str, **kw: Any) -> Any:
    report = ingest(TrivyConnector(), (SAMPLES / name).read_bytes(), ctx(**kw))
    assert report.ok, report.errors
    return report


def test_schema_2_report_maps_os_and_language_packages() -> None:
    report = run("defectdojo-teamdojo.json")
    by_purl = {f.locus.purl: f for f in report.findings}
    freetype = by_purl["pkg:apk/alpine/freetype@2.9.1-r2"]
    assert freetype.locus.installed_version == "2.9.1-r2"
    assert freetype.locus.fixed_version == ("2.9.1-r3",)
    assert freetype.locus.fix_status is FixStatus.FIXED
    assert freetype.classification.cve == ("CVE-2020-15999",)
    assert freetype.classification.cwe == ("CWE-787",)
    assert freetype.classification.source_severity_raw == "MEDIUM"
    assert freetype.source.scan_type == "container_image"
    assert "pkg:maven/org.apache.commons/commons-compress@1.14" in by_purl


def test_every_cvss_source_and_version_is_kept_as_reported() -> None:
    freetype = next(f for f in run("defectdojo-teamdojo.json").findings
                    if f.locus.package_name == "freetype")
    got = {(c.source, c.version, c.base) for c in freetype.scores.cvss}
    assert got == {("nvd", "2.0", Decimal("4.3")), ("nvd", "3.1", Decimal("6.5")),
                   ("redhat", "3.1", Decimal("8.6"))}


def test_all_trivy_statuses_map_to_fix_status() -> None:
    findings = run("defectdojo-example-app.json").findings
    assert {f.locus.fix_status for f in findings} == {
        FixStatus.UNKNOWN, FixStatus.NOT_AFFECTED, FixStatus.AFFECTED,
        FixStatus.UNDER_INVESTIGATION, FixStatus.WILL_NOT_FIX, FixStatus.FIX_DEFERRED,
        FixStatus.END_OF_LIFE}
    # The sample's one 'fixed' entry names no fixed version, so it can't claim 'fixed'.
    raw = json.loads((SAMPLES / "defectdojo-example-app.json").read_bytes())
    vulns = [v for r in raw["Results"] for v in r["Vulnerabilities"]]
    (claimed,) = [v for v in vulns if v["Status"] == "fixed"]
    assert not claimed.get("FixedVersion")
    (mapped,) = [f for f in findings if f.source.native_id == claimed["VulnerabilityID"]
                 and f.locus.package_name == claimed["PkgName"]]
    assert mapped.locus.fix_status is FixStatus.UNKNOWN


def test_trivys_own_purl_wins_when_present() -> None:
    purls = {f.locus.purl for f in run("defectdojo-sbom.json").findings}
    assert "pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.14?arch=amd64&distro=ubuntu-22.04" in purls


def test_asset_resolves_through_the_inventory_or_stays_unresolved() -> None:
    inventory = load_asset_csv(REPO / "seed" / "demo" / "assets.csv")
    known = run("defectdojo-teamdojo.json", assets=inventory)
    assert {f.locus.asset_ref for f in known.findings} == {"ast_teamdojo-image"}
    # ArtifactName is empty in this report: the first Target names the image.
    app = run("defectdojo-example-app.json", assets=inventory)
    assert {f.locus.asset_ref for f in app.findings} == {"ast_example-app-image"}
    unknown = run("defectdojo-teamdojo.json")
    assert {f.locus.asset_ref for f in unknown.findings} == {"ast_unresolved_teamdojo-latest"}


def test_same_file_same_context_gives_identical_output() -> None:
    raw = (SAMPLES / "defectdojo-teamdojo.json").read_bytes()
    assert TrivyConnector().to_batch(raw, ctx()) == TrivyConnector().to_batch(raw, ctx())


def test_result_order_does_not_change_the_findings() -> None:
    report = json.loads((SAMPLES / "defectdojo-teamdojo.json").read_bytes())
    flipped = {**report, "Results": report["Results"][::-1]}
    a = TrivyConnector().to_batch(json.dumps(report).encode(), ctx())
    b = TrivyConnector().to_batch(json.dumps(flipped).encode(), ctx())
    assert a == b


def test_same_cve_and_package_at_two_paths_is_one_finding() -> None:
    report = json.loads((SAMPLES / "defectdojo-teamdojo.json").read_bytes())
    vuln = report["Results"][0]["Vulnerabilities"][0]
    again = {**vuln, "PkgPath": "other/path/freetype"}
    report["Results"][0]["Vulnerabilities"].append(again)
    batch = TrivyConnector().to_batch(json.dumps(report).encode(), ctx())
    hits = [f for f in batch["findings"] if f["source"]["native_id"] == vuln["VulnerabilityID"]]
    assert len(hits) == 1
    assert hits[0]["evidence"]["pkg_paths"] == ["app/libs/freetype-2.9.1-r2", "other/path/freetype"]


def test_status_fixed_without_a_version_is_downgraded_to_unknown() -> None:
    report = {"Results": [{"Type": "alpine", "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2024-0001", "PkgName": "x", "InstalledVersion": "1",
        "Status": "fixed", "Severity": "HIGH"}]}]}
    batch = ingest(TrivyConnector(), json.dumps(report).encode(), ctx())
    assert batch.ok and batch.findings[0].locus.fix_status is FixStatus.UNKNOWN


def test_empty_report_and_legacy_list_are_accepted() -> None:
    assert run("defectdojo-teamdojo.json").findings
    legacy = [{"Target": "img (alpine 3.9)", "Type": "alpine", "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2024-0002", "PkgName": "y", "InstalledVersion": "1",
        "FixedVersion": "2", "Severity": "LOW"}]}]
    report = ingest(TrivyConnector(), json.dumps(legacy).encode(), ctx())
    assert report.ok and report.findings[0].locus.fix_status is FixStatus.FIXED
    empty = ingest(TrivyConnector(), b'{"Results": []}', ctx())
    assert empty.ok and not empty.findings


@pytest.mark.parametrize("raw", [b"not json", b'{"foo": 1}', b"\xff\xfe"])
def test_foreign_input_is_a_connector_error(raw: bytes) -> None:
    with pytest.raises(ConnectorError):
        TrivyConnector().to_batch(raw, ctx())


@pytest.mark.parametrize(("rtype", "name", "version", "purl"), [
    ("debian", "libc6", "2.28-10", "pkg:deb/debian/libc6@2.28-10"),
    ("jar", "org.apache:commons", "1.0", "pkg:maven/org.apache/commons@1.0"),
    ("npm", "@angular/core", "17.0.0", "pkg:npm/%40angular/core@17.0.0"),
    ("gomod", "github.com/a/b", "v1.2.3", "pkg:golang/github.com/a/b@v1.2.3"),
    ("pip", "requests", "2.31.0", "pkg:pypi/requests@2.31.0"),
    ("something-new", "thing", "1", "pkg:generic/thing@1"),
])
def test_purl_built_from_result_type(rtype: str, name: str, version: str, purl: str) -> None:
    assert _purl(rtype, name, version) == purl


def test_distro_mapping_uses_trivys_vendor_names() -> None:
    assert set(_DISTRO_SOURCE.values()) <= DISTRO_SOURCES
