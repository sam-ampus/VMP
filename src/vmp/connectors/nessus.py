"""Nessus `.nessus` (NessusClientData_v2) -> canonical host findings.

One ReportItem per plugin per port per host. Severity 0 items are information-only plugins
(OS detection, open ports, traceroute): about 95% of a typical file. They are skipped and
counted, never turned into findings.

Nessus carries more than any other host scanner: CVSS v2/v3/v4, EPSS, exploit availability,
CWE, and whether the scan logged in to the host. Everything is copied as reported:
- CVSS goes in as tool scores. Selection still prefers NVD and the CNA (locked decision 1).
- `Credentialed_Scan` sets the scan type per host. An uncredentialed scan reads versions from
  service banners, which is a classic false-positive source that FP triage (Stage 2) will weigh.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
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

TOOL = "nessus"

# Nessus 0 (info) .. 4 (critical). The attribute can disagree with risk_factor (it may be
# derived from CVSS v3 while risk_factor follows v2); the attribute is what Nessus displays.
_SEVERITY = {"1": "low", "2": "medium", "3": "high", "4": "critical"}
_SCAN_TYPE = {"true": "authenticated_network", "false": "unauthenticated_network"}
_CVSS = (("cvss_base_score", "cvss_vector"), ("cvss3_base_score", "cvss3_vector"),
         ("cvss4_base_score", "cvss4_vector"))


class NessusConnector:
    name = TOOL
    extensions: tuple[str, ...] = (".nessus",)

    def to_batch(self, raw: bytes, ctx: ScanContext) -> dict[str, Any]:
        root = load_xml(raw, root_tag="NessusClientData_v2", what="Nessus (.nessus v2)")
        skipped = {"information_only": 0}
        by_key: dict[str, dict[str, Any]] = {}
        coverage: dict[str, str] = {}
        for host in root.iterfind("Report/ReportHost"):
            h = _host_info(host, ctx)
            coverage[h["asset_ref"]] = max(h["detected"], coverage.get(h["asset_ref"], ""))
            for f in _host_findings(host, ctx, h):
                if f is None:
                    skipped["information_only"] += 1
                elif (seen := by_key.get(f["idempotency_key"])) is None:
                    by_key[f["idempotency_key"]] = f
                else:
                    # The same plugin reported twice for one host and port: one observation.
                    seen["evidence"]["times_reported"] += 1
        findings = sorted(by_key.values(), key=lambda f: f["finding_id"])
        return envelope(TOOL, ctx, findings, skipped=skipped, coverage=coverage)


def _host_info(host: Element, ctx: ScanContext) -> dict[str, Any]:
    props = {t.get("name"): (t.text or "").strip() for t in host.iterfind("HostProperties/tag")}
    ip = props.get("host-ip") or host.get("name") or ""
    hostname = props.get("host-fqdn") or props.get("netbios-name") or None
    asset_ref = resolve_asset_ref(ctx.assets, ip, hostname, props.get("netbios-name"))
    detected = (_epoch(props.get("HOST_END_TIMESTAMP")) or _epoch(props.get("HOST_START_TIMESTAMP"))
                or ctx.received_at.isoformat())
    credentialed = props.get("Credentialed_Scan")
    return {
        "ip": ip, "hostname": hostname, "os": props.get("operating-system") or None,
        "asset_ref": asset_ref, "detected": detected,
        "scan_type": _SCAN_TYPE.get(credentialed or "", "unknown"),
        "credentialed": {"true": True, "false": False}.get(credentialed or ""),
    }


def _host_findings(host: Element, ctx: ScanContext, h: dict[str, Any]
                   ) -> Iterator[dict[str, Any] | None]:
    """One canonical finding per ReportItem; None for an information-only item."""
    for item in host.iterfind("ReportItem"):
        yield _finding(item, ctx, h) if item.get("severity") in _SEVERITY else None


def _finding(item: Element, ctx: ScanContext, h: dict[str, Any]) -> dict[str, Any]:
    plugin = item.get("pluginID") or ""
    port = int(item.get("port") or 0) or None  # port 0 = a host-level finding
    protocol = (item.get("protocol") or "").lower() or None
    key = keys.host_key(TOOL, plugin, h["ip"], port, protocol)
    raw_sev = item.get("severity") or ""
    exploit = {"true": True, "false": False}.get(text(item, "exploit_available") or "")
    see_also = (text(item, "see_also") or "").split()
    solution = text(item, "solution")

    return {
        "finding_id": finding_id(ctx.scan_id, key),
        "idempotency_key": key,
        "source": {
            "tool": TOOL, "native_id": plugin, "native_family": item.get("pluginFamily"),
            "scan_id": ctx.scan_id, "scan_type": h["scan_type"],
            "first_detected": h["detected"], "last_detected": h["detected"],
        },
        "locus": {
            "type": "host", "asset_ref": h["asset_ref"], "ip": h["ip"],
            "hostname": h["hostname"], "port": port, "protocol": protocol,
            "service": item.get("svc_name") if port else None, "os": h["os"],
            "cpe": sorted({c for c in (text(item, "cpe") or "").split() if c}),
        },
        "classification": {
            "title": item.get("pluginName") or text(item, "plugin_name") or f"Nessus {plugin}",
            "cve": sorted({c.text.strip() for c in item.iterfind("cve") if c.text}),
            "cwe": sorted({f"CWE-{c.text.strip()}" for c in item.iterfind("cwe")
                           if c.text and c.text.strip().isdigit()}),
            "source_severity": _SEVERITY[raw_sev],
            "source_severity_raw": raw_sev,
        },
        "scores": {"cvss": list(_cvss(item)), "epss": _decimal(text(item, "epss_score"))},
        "validation": {
            "confidence": "unvalidated", "confidence_source": "default_for_tool_class",
            "evidence_completeness": "full",
        },
        # Nessus states exploit availability outright when it knows: real exploit intel,
        # independent of KEV and EPSS. Absent means unknown, not "no exploit".
        "exploit_signals": (
            {"exploit_available": exploit, "exploitability_ease": text(item, "exploitability_ease"),
             "signal_source": TOOL} if exploit is not None else {}),
        "remediation_source": (
            {"text": solution, "provided_by": TOOL}
            if solution and solution.lower() != "n/a" else {}),
        "evidence": {
            "references": sorted({u for u in see_also if u.startswith(("http://", "https://"))}),
            "credentialed": h["credentialed"],
            "risk_factor": text(item, "risk_factor"),
            "vpr_score": text(item, "vpr_score"),
            "synopsis": text(item, "synopsis"),
            "description": text(item, "description"),
            "plugin_output": text(item, "plugin_output"),
            "plugin_type": text(item, "plugin_type"),
            "plugin_modification_date": text(item, "plugin_modification_date"),
            "xref": sorted({x.text.strip() for x in item.iterfind("xref") if x.text}),
            "times_reported": 1,
        },
    }


def _cvss(item: Element) -> Iterator[dict[str, Any]]:
    for score_field, vector_field in _CVSS:
        base = _decimal(text(item, score_field))
        if base is None:
            continue
        vector = text(item, vector_field)
        if score_field == "cvss_base_score":
            version, vector = "2.0", vector.removeprefix("CVSS2#") if vector else None
        elif score_field == "cvss4_base_score":
            version = "4.0"
        else:
            version = "3.0" if vector and vector.startswith("CVSS:3.0/") else "3.1"
        yield {"source": TOOL, "version": version, "base": str(base.quantize(Decimal("0.1"))),
               "vector": vector}


def _decimal(value: str | None) -> Decimal | None:
    try:
        return Decimal(value) if value else None
    except InvalidOperation:
        return None


def _epoch(value: str | None) -> str | None:
    if not value or not value.isdigit():
        return None
    return datetime.fromtimestamp(int(value), UTC).isoformat()
