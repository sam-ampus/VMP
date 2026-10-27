"""Qualys "Scan Results" XML (scan-1.dtd; Scans > Download > XML) -> canonical host findings.

EVA, ASV and IVA scans all use this one format; only the option profile differs. The kind of
assessment is recorded as evidence, never used to change a value.

What Qualys reports, and where it lands:
- VULNS     confirmed vulnerabilities    -> findings (confidence left at the scanner default)
- PRACTICES potential vulnerabilities    -> findings (confidence 'potential', as Qualys says)
- INFOS, SERVICES  information gathered  -> skipped and counted; they are not vulnerabilities

Qualys's "confirmed" means its detection logic matched, not that anyone exploited it, so it
does not earn the validation weight Mirror's 'confirmed' does. 'Potential' is Qualys telling
us it could not verify; that is kept, and FP triage (Stage 2) reads it.

This format carries no CVSS. CVSS comes from intel for findings with CVEs; findings without
one (TLS configuration, headers) score on the source severity, which the engine handles.
"""

import re
from collections.abc import Iterator
from datetime import datetime
from typing import Any
from xml.etree.ElementTree import Element

from vmp.connectors.base import (
    ScanContext,
    envelope,
    finding_id,
    load_xml,
    resolve_asset_ref,
    text,
)
from vmp.schema import keys

TOOL = "qualys"

# Qualys 1 (minimal) .. 5 (urgent). Severity 1 is information an attacker could use, not a
# weakness on its own: 'info', with the raw value kept.
_SEVERITY = {"1": "info", "2": "low", "3": "medium", "4": "high", "5": "critical"}
_FINDINGS = (("VULNS", "VULN", "confirmed"), ("PRACTICES", "PRACTICE", "potential"))
_INFORMATION = (("INFOS", "INFO"), ("SERVICES", "SERVICE"))
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_ASSESSMENT = re.compile(r"(?<![A-Za-z])(EVA|ASV|IVA)(?![A-Za-z])")
_AUTH_ON = re.compile(r"\b\w+ Authentication ON\b")
_NO_HOSTNAME = "No registered hostname"


class QualysConnector:
    name = TOOL
    extensions: tuple[str, ...] = (".xml",)

    def to_batch(self, raw: bytes, ctx: ScanContext) -> dict[str, Any]:
        scan = load_xml(raw, root_tag="SCAN", what="Qualys scan results")
        header = {k.get("value"): (k.text or "").strip() for k in scan.iterfind("HEADER/KEY")}
        profile = text(scan, "HEADER/OPTION_PROFILE/OPTION_PROFILE_TITLE")
        detected = _timestamp(header.get("DATE")) or ctx.received_at.isoformat()
        common = {
            "detected": detected,
            "scan_type": ("authenticated_network" if _AUTH_ON.search(header.get("OPTIONS", ""))
                          else "unauthenticated_network"),
            "tool_version": header.get("SCAN_HOST") or None,
            "scan_evidence": {
                "assessment": _assessment(profile, header.get("TITLE")),
                "option_profile": profile,
                "qualys_scan_ref": scan.get("value"),
            },
        }

        # A scan that found no live host is a valid, empty result, not a broken file.
        warnings = [f"Qualys reported error {e.get('number')}: {(e.text or '').strip()}"
                    for e in scan.iterfind("ERROR")]
        skipped = {"information_gathered": 0}
        by_key: dict[str, dict[str, Any]] = {}
        coverage: dict[str, str] = {}
        for host in scan.iterfind("IP"):
            coverage[_asset_ref(host, ctx)] = detected
            skipped["information_gathered"] += sum(
                1 for section, tag in _INFORMATION for _ in host.iterfind(f"{section}/CAT/{tag}"))
            for f in _host_findings(host, ctx, common):
                if (seen := by_key.get(f["idempotency_key"])) is None:
                    by_key[f["idempotency_key"]] = f
                else:
                    # Same QID on the same port, tested once plain and once over SSL: one
                    # observation of one weakness. Keep every transport's result.
                    seen["evidence"]["observations"] = sorted(
                        [*seen["evidence"]["observations"], *f["evidence"]["observations"]],
                        key=lambda o: (o["transport"], o["result"] or ""))
        findings = sorted(by_key.values(), key=lambda f: f["finding_id"])
        return envelope(TOOL, ctx, findings, skipped=skipped, warnings=warnings,
                        coverage=coverage)


def _host_findings(host: Element, ctx: ScanContext, common: dict[str, Any]
                   ) -> Iterator[dict[str, Any]]:
    ip = host.get("value") or ""
    hostname = _hostname(host)
    asset_ref = _asset_ref(host, ctx)
    for section, tag, qualys_type in _FINDINGS:
        for cat in host.iterfind(f"{section}/CAT"):
            for item in cat.iterfind(tag):
                yield _finding(item, cat, ctx, common, ip=ip, hostname=hostname,
                               os=text(host, "OS"), asset_ref=asset_ref, qualys_type=qualys_type)


def _hostname(host: Element) -> str | None:
    name = host.get("name")
    return name if name and name != _NO_HOSTNAME else None


def _asset_ref(host: Element, ctx: ScanContext) -> str:
    return resolve_asset_ref(ctx.assets, host.get("value"), _hostname(host))


def _finding(item: Element, cat: Element, ctx: ScanContext, common: dict[str, Any], *, ip: str,
             hostname: str | None, os: str | None, asset_ref: str, qualys_type: str
             ) -> dict[str, Any]:
    qid = item.get("number") or ""
    port = int(p) if (p := cat.get("port")) else None
    protocol = (cat.get("protocol") or "").lower() or None
    key = keys.host_key(TOOL, qid, ip, port, protocol)
    raw_sev = item.get("severity") or ""
    potential = qualys_type == "potential"

    return {
        "finding_id": finding_id(ctx.scan_id, key),
        "idempotency_key": key,
        "source": {
            "tool": TOOL, "tool_version": common["tool_version"], "native_id": qid,
            "native_family": cat.get("value"), "scan_id": ctx.scan_id,
            "scan_type": common["scan_type"],
            "first_detected": common["detected"], "last_detected": common["detected"],
        },
        "locus": {
            "type": "host", "asset_ref": asset_ref, "ip": ip, "hostname": hostname,
            "port": port, "protocol": protocol, "os": os,
        },
        "classification": {
            "title": text(item, "TITLE") or f"Qualys QID {qid}",
            "cve": _cves(item),
            "source_severity": _SEVERITY.get(raw_sev, "info"),
            "source_severity_raw": raw_sev or "unknown",
        },
        "validation": {
            "confidence": "potential" if potential else "unvalidated",
            "confidence_source": "tool_asserted" if potential else "default_for_tool_class",
            "tool_label": qualys_type.capitalize(),
            "evidence_completeness": "full",
        },
        # Qualys lists exploit sources when it knows of any. Silence is unknown, not "none".
        "exploit_signals": (
            {"exploit_available": True, "signal_source": TOOL}
            if item.find("CORRELATION/EXPLOITABILITY/EXPLT_SRC") is not None else {}),
        "remediation_source": (
            {"text": solution, "provided_by": TOOL}
            if (solution := text(item, "SOLUTION")) else {}),
        "evidence": {
            "references": sorted({u.text.strip() for u in item.iter("URL")
                                  if u.text and u.text.strip()}),
            **common["scan_evidence"],
            "qualys_type": qualys_type,
            "pci_flag": text(item, "PCI_FLAG") == "1",
            "diagnosis": text(item, "DIAGNOSIS"),
            "consequence": text(item, "CONSEQUENCE"),
            "observations": [{"transport": cat.get("misc") or "plain",
                              "result": text(item, "RESULT")}],
            "last_update": text(item, "LAST_UPDATE"),
        },
    }


def _cves(item: Element) -> list[str]:
    """The cveid attribute and CVE_ID_LIST can each be incomplete; take their union."""
    listed = (text(c, "ID") or "" for c in item.iterfind("CVE_ID_LIST/CVE_ID"))
    return sorted({m for s in (item.get("cveid") or "", *listed) for m in _CVE.findall(s)})


def _assessment(profile: str | None, title: str | None) -> str | None:
    """'asv' / 'eva' / 'iva' from the PCI profile or the scan title; None when neither says."""
    if profile and "Payment Card Industry" in profile:
        return "asv"
    m = _ASSESSMENT.search(title or "")
    return m.group(1).lower() if m else None


def _timestamp(value: str | None) -> str | None:
    return datetime.fromisoformat(value).isoformat() if value else None
