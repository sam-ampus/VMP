"""Nessus connector: info-only skipped, every CVSS version, EPSS, exploit signals, credentials.

Fixture is synthetic (see samples/README.md).
"""

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from vmp.connectors import ConnectorError, NessusConnector, ScanContext, ingest
from vmp.schema.enums import Confidence, ScanType
from vmp.schema.finding import Finding, HostLocus

SAMPLES = Path(__file__).parent / "samples"
AT = datetime(2026, 10, 26, tzinfo=UTC)
RAW = (SAMPLES / "nessus-iva.nessus").read_bytes()


def ctx() -> ScanContext:
    return ScanContext(scan_id="scan_n1", batch_id="ing_n1", received_at=AT)


def findings() -> dict[str, Finding]:
    report = ingest(NessusConnector(), RAW, ctx())
    assert report.ok, report.errors
    return {f.source.native_id: f for f in report.findings}


def host(f: Finding) -> HostLocus:
    assert isinstance(f.locus, HostLocus)
    return f.locus


def test_information_only_items_are_skipped_and_counted() -> None:
    report = ingest(NessusConnector(), RAW, ctx())
    assert sorted(f.source.native_id for f in report.findings) == ["10114", "200001", "200002"]
    assert report.skipped == {"information_only": 2}


def test_severity_and_raw_value_and_risk_factor_kept() -> None:
    f = findings()
    assert (str(f["200002"].classification.source_severity),
            f["200002"].classification.source_severity_raw) == ("critical", "4")
    # The attribute and risk_factor can disagree; both are kept, the attribute is used.
    assert f["200002"].evidence.model_extra is not None
    assert f["200002"].evidence.model_extra["risk_factor"] == "Medium"
    assert str(f["10114"].classification.source_severity) == "low"


def test_every_cvss_version_is_kept_with_clean_vectors() -> None:
    f = findings()
    assert {(c.version, c.base, c.vector) for c in f["200001"].scores.cvss} == {
        ("2.0", Decimal("5.0"), "AV:N/AC:L/Au:N/C:N/I:N/A:P"),
        ("3.0", Decimal("7.5"), "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")}
    assert {c.version for c in f["200002"].scores.cvss} == {"3.1", "4.0"}
    assert {c.source for c in f["200001"].scores.cvss} == {"nessus"}


def test_classification_cves_cwes_and_epss() -> None:
    web = findings()["200001"]
    assert web.classification.cve == ("CVE-2023-43622", "CVE-2023-45802")
    assert web.classification.cwe == ("CWE-400",)
    assert web.scores.epss == Decimal("0.0123")
    assert web.validation.confidence is Confidence.UNVALIDATED


def test_exploit_available_true_false_and_unknown() -> None:
    f = findings()
    assert f["200001"].exploit_signals.exploit_available is True
    assert f["200001"].exploit_signals.exploitability_ease == "Exploits are available"
    assert f["10114"].exploit_signals.exploit_available is False
    assert f["200002"].exploit_signals.exploit_available is None  # not stated = unknown


def test_host_fields_port_zero_and_detection_time() -> None:
    f = findings()
    web, icmp = host(f["200001"]), host(f["10114"])
    assert (str(web.ip), web.hostname, web.port, web.protocol, web.service, web.os) == (
        "192.0.2.20", "app01.example.com", 443, "tcp", "www", "Microsoft Windows Server 2019")
    assert (icmp.port, icmp.protocol, icmp.service) == (None, "icmp", None)
    assert f["200001"].source.first_detected == datetime.fromtimestamp(1781000000, UTC)


def test_scan_type_follows_each_hosts_credentialed_flag() -> None:
    f = findings()
    assert f["200001"].source.scan_type is ScanType.AUTHENTICATED_NETWORK
    assert f["200002"].source.scan_type is ScanType.UNAUTHENTICATED_NETWORK
    assert f["200002"].evidence.model_extra is not None
    assert f["200002"].evidence.model_extra["credentialed"] is False


def test_repeated_plugin_on_one_port_is_one_finding() -> None:
    web = findings()["200001"]
    assert web.evidence.model_extra is not None
    assert web.evidence.model_extra["times_reported"] == 2


def test_na_solution_is_not_remediation_text() -> None:
    f = findings()
    assert f["200001"].remediation_source.text == "Upgrade to version 2.4.58 or later."
    assert f["200002"].remediation_source.text is None


def test_same_file_gives_identical_output() -> None:
    assert NessusConnector().to_batch(RAW, ctx()) == NessusConnector().to_batch(RAW, ctx())


@pytest.mark.parametrize("raw", [b"{}", b"<SCAN/>", b"\x00\x01"])
def test_foreign_input_is_rejected(raw: bytes) -> None:
    with pytest.raises(ConnectorError):
        NessusConnector().to_batch(raw, ctx())
