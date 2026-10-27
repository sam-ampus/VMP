"""Correlation: same-tool rescans, cross-tool CVE matches, no-CVE isolation, not-seen flags."""

from datetime import UTC, datetime
from pathlib import Path

from vmp.connectors import NessusConnector, QualysConnector, ScanContext, ingest, scan_id_for
from vmp.pipeline.correlate import Correlated, ReviewThresholds, correlate, correlation_keys
from vmp.schema.finding import Finding
from vmp.schema.validation import BatchReport, ScanCoverage

SAMPLES = Path(__file__).resolve().parents[1] / "connectors" / "samples"
AT = datetime(2026, 10, 27, tzinfo=UTC)
NESSUS = (SAMPLES / "nessus-iva.nessus").read_bytes()
QUALYS = (SAMPLES / "qualys-iva.xml").read_bytes()
LATER = 1782000000  # a rescan ~11 days after the sample's HOST_END_TIMESTAMP


def load(connector: NessusConnector | QualysConnector, raw: bytes) -> BatchReport:
    report = ingest(connector, raw, ScanContext(scan_id_for(raw, connector.name), "b", AT))
    assert report.ok, report.errors
    return report


def run(*reports: tuple[str, BatchReport]) -> list[Correlated]:
    findings = [f for _, r in reports for f in r.findings]
    coverage: dict[str, list[ScanCoverage]] = {}
    for tool, r in reports:
        coverage.setdefault(tool, []).extend(r.coverage)
    return correlate(findings, coverage)


def find(groups: list[Correlated], native_id: str, findings: list[Finding]) -> Correlated:
    ids = {f.finding_id for f in findings if f.source.native_id == native_id}
    (group,) = [g for g in groups if ids & set(g.vulnerability.finding_ids)]
    return group


def rescan(raw: bytes, *, drop_plugin: str | None = None) -> bytes:
    out = raw.replace(b"1781000000", str(LATER).encode()).replace(
        b"1781000500", str(LATER + 500).encode())
    if drop_plugin:
        start = out.index(f'pluginID="{drop_plugin}"'.encode())
        start = out.rindex(b"<ReportItem", 0, start)
        out = out[:start] + out[out.index(b"</ReportItem>", start) + len(b"</ReportItem>"):]
    return out


def test_a_rescan_adds_sightings_to_the_same_vulnerabilities() -> None:
    first, second = load(NessusConnector(), NESSUS), load(NessusConnector(), rescan(NESSUS))
    groups = run(("nessus", first), ("nessus", second))
    assert len(groups) == 3  # three plugins, each seen twice
    assert all(len(g.vulnerability.finding_ids) == 2 and len(g.scans) == 2 for g in groups)
    assert all(g.not_seen == () for g in groups)
    assert {g.last_seen for g in groups} == {datetime.fromtimestamp(LATER, UTC),
                                            datetime.fromtimestamp(LATER + 500, UTC)}


def test_missing_from_the_newer_scan_is_flagged_and_stays_open() -> None:
    first = load(NessusConnector(), NESSUS)
    second = load(NessusConnector(), rescan(NESSUS, drop_plugin="10114"))
    groups = run(("nessus", first), ("nessus", second))
    icmp = find(groups, "10114", list(first.findings))
    assert icmp.vulnerability.status == "open"
    assert [(n.tool, n.latest_scan) for n in icmp.not_seen] == [
        ("nessus", datetime.fromtimestamp(LATER, UTC))]
    web = find(groups, "200001", list(first.findings))
    assert web.not_seen == ()


def test_only_the_same_tools_silence_counts() -> None:
    """Qualys scanning the host later and not reporting a Nessus finding says nothing."""
    nessus = load(NessusConnector(), NESSUS)
    qualys = load(QualysConnector(), QUALYS.replace(b"192.0.2.10", b"192.0.2.20").replace(
        b"2026-10-14T07:56:07Z", b"2026-12-01T00:00:00Z"))
    groups = run(("nessus", nessus), ("qualys", qualys))
    assert find(groups, "10114", list(nessus.findings)).not_seen == ()


def test_same_cve_on_the_same_asset_correlates_across_tools() -> None:
    nessus = load(NessusConnector(), NESSUS.replace(b"192.0.2.20", b"192.0.2.10").replace(
        b"CVE-2023-43622", b"CVE-2016-2183"))
    qualys = load(QualysConnector(), QUALYS)
    groups = run(("nessus", nessus), ("qualys", qualys))
    both = find(groups, "38173", list(qualys.findings))
    assert both.tools == ("nessus", "qualys")
    assert "host|ast_unresolved_192.0.2.10|CVE-2016-2183" in both.keys


def test_same_cve_on_a_different_asset_does_not() -> None:
    nessus = load(NessusConnector(), NESSUS.replace(b"CVE-2023-43622", b"CVE-2016-2183"))
    groups = run(("nessus", nessus), ("qualys", load(QualysConnector(), QUALYS)))
    assert all(len(g.tools) == 1 for g in groups)


def test_findings_without_a_cve_never_correlate_across_tools() -> None:
    qualys = load(QualysConnector(), QUALYS)
    urgent = next(f for f in qualys.findings if f.source.native_id == "150004")
    assert correlation_keys(urgent) == (
        "host|ast_unresolved_192.0.2.11|qualys|150004|80|tcp",)


def test_result_does_not_depend_on_input_order() -> None:
    a = load(NessusConnector(), NESSUS)
    b = load(NessusConnector(), rescan(NESSUS, drop_plugin="10114"))
    assert run(("nessus", a), ("nessus", b)) == run(("nessus", b), ("nessus", a))


def _merged_three_checks() -> list[Correlated]:
    """Three Nessus plugins on one host, each sharing a CVE with the next: one chained group."""
    raw = NESSUS.replace(b"CVE-2023-43622", b"CVE-1999-0524")  # 200001 <-> 10114
    raw = raw.replace(b"192.0.2.21", b"192.0.2.20").replace(
        b"<cvss4_base_score>", b"<cve>CVE-2023-45802</cve><cvss4_base_score>")  # 200002 <-> 200001
    return run(("nessus", load(NessusConnector(), raw)))


def test_a_group_that_merged_several_checks_is_flagged_for_review() -> None:
    (group,) = _merged_three_checks()
    (flag,) = group.review
    assert flag.reason == "merged_checks"
    assert flag.detail == ("3 different checks merged through 2 shared CVEs "
                           "(CVE-1999-0524, CVE-2023-45802); confirm they are one fix")


def test_thresholds_are_configurable_and_flags_never_change_the_grouping() -> None:
    (flagged,) = _merged_three_checks()
    findings = [f for _, r in [("nessus", load(NessusConnector(), NESSUS))] for f in r.findings]
    lenient = correlate(findings, {}, thresholds=ReviewThresholds(merged_checks=4))
    assert all(g.review == () for g in lenient)
    strict = correlate(findings, {}, thresholds=ReviewThresholds(merged_checks=1))
    assert all(g.review for g in strict)
    assert [g.vulnerability for g in lenient] == [g.vulnerability for g in strict]
    assert len(flagged.vulnerability.finding_ids) == 3


def test_many_ports_is_flagged() -> None:
    items = b"".join(
        f'<ReportItem port="{p}" svc_name="ssh" protocol="tcp" severity="2" pluginID="300001" '
        f'pluginName="SSH weak" pluginFamily="Misc."><cve>CVE-2023-48795</cve></ReportItem>'
        .encode() for p in range(2200, 2210))
    raw = NESSUS.replace(b"</ReportHost>", items + b"</ReportHost>", 1)
    groups = run(("nessus", load(NessusConnector(), raw)))
    ssh = next(g for g in groups if "host|ast_unresolved_192.0.2.20|CVE-2023-48795" in g.keys)
    assert [f.reason for f in ssh.review] == ["many_ports"]
