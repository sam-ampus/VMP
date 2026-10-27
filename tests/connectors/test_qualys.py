"""Qualys connector: confirmed vs potential, information skipped, merges, empty scans, safety.

Fixtures are synthetic (see samples/README.md); the real samples are exercised by
test_real_samples.py when present.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from vmp.assets import AssetInventory, parse_asset_csv
from vmp.connectors import ConnectorError, QualysConnector, ScanContext, ingest
from vmp.schema.enums import Confidence, ConfidenceSource, ScanType
from vmp.schema.finding import Finding, HostLocus

SAMPLES = Path(__file__).parent / "samples"
AT = datetime(2026, 10, 26, tzinfo=UTC)
RAW = (SAMPLES / "qualys-iva.xml").read_bytes()


def ctx(**kw: Any) -> ScanContext:
    return ScanContext(scan_id="scan_q1", batch_id="ing_q1", received_at=AT, **kw)


def run(raw: bytes = RAW, **kw: Any) -> Any:
    report = ingest(QualysConnector(), raw, ctx(**kw))
    assert report.ok, report.errors
    return report


def by_qid(report: Any) -> dict[str, Finding]:
    return {f.source.native_id: f for f in report.findings}


def host(f: Finding) -> HostLocus:
    assert isinstance(f.locus, HostLocus)
    return f.locus


def test_vulns_and_practices_become_findings_information_is_counted_not_kept() -> None:
    report = run()
    assert sorted(by_qid(report)) == ["105489", "150004", "150079", "38173", "38913"]
    assert report.skipped == {"information_gathered": 3}  # 2 INFO + 1 SERVICE
    assert report.warnings == ()


def test_potential_is_kept_as_qualys_said_and_confirmed_stays_at_scanner_default() -> None:
    q = by_qid(run())
    terrapin, cert = q["38913"], q["38173"]
    assert terrapin.validation.confidence is Confidence.POTENTIAL
    assert terrapin.validation.confidence_source is ConfidenceSource.TOOL_ASSERTED
    # Qualys "confirmed" = its detection matched, not a proven exploit: no validation weight.
    assert cert.validation.confidence is Confidence.UNVALIDATED
    assert cert.evidence.model_extra is not None
    assert cert.evidence.model_extra["qualys_type"] == "confirmed"


def test_severity_scale_and_raw_value() -> None:
    q = by_qid(run())
    assert {qid: (str(f.classification.source_severity), f.classification.source_severity_raw)
            for qid, f in q.items()} == {
        "150079": ("info", "1"), "105489": ("low", "2"), "38173": ("medium", "3"),
        "38913": ("high", "4"), "150004": ("critical", "5")}


def test_cves_are_the_union_of_attribute_and_list() -> None:
    assert by_qid(run())["38173"].classification.cve == ("CVE-2016-2183", "CVE-2016-6329")


def test_plain_and_over_ssl_reports_of_one_qid_merge_into_one_finding() -> None:
    cert = by_qid(run())["38173"]
    assert cert.evidence.model_extra is not None
    assert [o["transport"] for o in cert.evidence.model_extra["observations"]] == [
        "over ssl", "plain"]
    assert sum(f.source.native_id == "38173" for f in run().findings) == 1


def test_host_locus_fields() -> None:
    q = by_qid(run())
    cert, local, urgent = host(q["38173"]), host(q["105489"]), host(q["150004"])
    assert (str(cert.ip), cert.hostname, cert.port, cert.protocol, cert.os) == (
        "192.0.2.10", "web01.example.com", 443, "tcp", "Ubuntu / Linux 22.04")
    assert (local.port, local.protocol) == (None, None)  # host-level finding
    assert urgent.hostname is None  # "No registered hostname" is not a hostname


def test_scan_type_assessment_and_detection_time() -> None:
    cert = by_qid(run())["38173"]
    assert cert.source.scan_type is ScanType.AUTHENTICATED_NETWORK
    assert cert.source.first_detected == datetime(2026, 10, 14, 7, 56, 7, tzinfo=UTC)
    assert cert.evidence.model_extra is not None
    assert cert.evidence.model_extra["assessment"] == "iva"
    asv = RAW.replace(b"Authenticated Scan : Full Scan : 2025",
                      b"Payment Card Industry (PCI) Options").replace(
                      b"Windows Authentication ON, Unix Authentication ON", b"")
    asv_cert = by_qid(run(asv))["38173"]
    assert asv_cert.source.scan_type is ScanType.UNAUTHENTICATED_NETWORK
    assert asv_cert.evidence.model_extra is not None
    assert asv_cert.evidence.model_extra["assessment"] == "asv"


def test_exploit_sources_mean_true_and_silence_means_unknown() -> None:
    q = by_qid(run())
    assert q["38173"].exploit_signals.exploit_available is True
    assert q["38913"].exploit_signals.exploit_available is None


def test_no_host_alive_is_an_empty_scan_with_a_warning_not_an_error() -> None:
    report = run((SAMPLES / "qualys-no-host-alive.xml").read_bytes())
    assert report.findings == ()
    assert report.warnings == ("Qualys reported error 3509: No host alive",)


def test_inventory_resolves_by_ip_or_hostname() -> None:
    inv = AssetInventory(parse_asset_csv(
        "asset_ref,name,aliases,internet_facing,criticality,environment,owner\n"
        "ast_web01,Web 01,web01.example.com,true,high,production,Web team\n"))
    q = by_qid(run(assets=inv))
    assert q["38173"].locus.asset_ref == "ast_web01"
    assert q["150004"].locus.asset_ref == "ast_unresolved_192.0.2.11"


def test_same_file_gives_identical_output() -> None:
    a = QualysConnector().to_batch(RAW, ctx())
    assert a == QualysConnector().to_batch(RAW, ctx())


@pytest.mark.parametrize("raw", [b"{}", b"<NessusClientData_v2/>", b"not xml"])
def test_foreign_input_is_rejected(raw: bytes) -> None:
    with pytest.raises(ConnectorError):
        QualysConnector().to_batch(raw, ctx())


def test_entity_expansion_is_refused() -> None:
    """Uploaded XML is untrusted: a billion-laughs style entity must not be expanded."""
    bomb = (b'<?xml version="1.0"?><!DOCTYPE SCAN [<!ENTITY a "aaaaaaaaaa">'
            b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><SCAN>&b;</SCAN>')
    with pytest.raises(ConnectorError):
        QualysConnector().to_batch(bomb, ctx())
