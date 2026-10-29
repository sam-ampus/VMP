"""Turn a compact benchmark case into real, schema-validated Findings.

A case describes only what matters to FP triage (versions, OS, scan login, the tool's text).
Everything else is filled with neutral values, and the result goes through the same Finding
model every connector's output does, so a case can't describe something the schema forbids.
"""

from typing import Any

from vmp.connectors.base import finding_id
from vmp.schema import keys
from vmp.schema.finding import Finding

DETECTED = "2026-10-20T00:00:00+00:00"


def findings(case: dict[str, Any]) -> list[Finding]:
    return [_build(case["id"], i, spec) for i, spec in enumerate(case["findings"])]


def _build(case_id: str, i: int, spec: dict[str, Any]) -> Finding:
    shape = spec["shape"]
    tool = spec.get("tool") or {"host": "nessus", "package": "trivy", "endpoint": "mirror"}[shape]
    scan_id = f"bench_{case_id}_{i}"
    builder = {"host": _host, "package": _package, "endpoint": _endpoint}[shape]
    data = builder(spec, tool, scan_id)
    data["source"] = {"tool": tool, "native_id": data.pop("native_id"),
                      "native_family": spec.get("family"), "scan_id": scan_id,
                      "scan_type": spec.get("scan_type", data.pop("default_scan_type")),
                      "first_detected": DETECTED, "last_detected": DETECTED}
    data["finding_id"] = finding_id(scan_id, data["idempotency_key"])
    data.setdefault("validation", {"confidence": "unvalidated",
                                   "confidence_source": "default_for_tool_class",
                                   "evidence_completeness": "full"})
    data["classification"] = {"title": spec.get("title", f"Benchmark case {case_id}"),
                              "cve": spec.get("cve", []), "cwe": spec.get("cwe", []),
                              "source_severity": "high", "source_severity_raw": "high"}
    return Finding.model_validate(data)


def _host(spec: dict[str, Any], tool: str, scan_id: str) -> dict[str, Any]:
    native = spec.get("native_id", "100001")
    ip, port = spec.get("ip", "192.0.2.50"), spec.get("port", 443)
    evidence: dict[str, Any] = {"description": spec.get("description")}
    validation = None
    if tool == "qualys":
        qtype = spec.get("qualys_type", "confirmed")
        evidence |= {"qualys_type": qtype, "host_auth": spec.get("host_auth"),
                     "observations": [{"transport": "plain", "result": spec.get("result")}]}
        potential = qtype == "potential"
        validation = {"confidence": "potential" if potential else "unvalidated",
                      "confidence_source": "tool_asserted" if potential
                      else "default_for_tool_class",
                      "tool_label": qtype.capitalize(), "evidence_completeness": "full"}
    else:
        evidence |= {"plugin_output": spec.get("plugin_output"),
                     "credentialed": spec.get("scan_type") == "authenticated_network"}
    data: dict[str, Any] = {
        "native_id": native, "default_scan_type": "unauthenticated_network",
        "idempotency_key": keys.host_key(tool, native, ip, port, "tcp"),
        "locus": {"type": "host", "asset_ref": f"ast_unresolved_{ip}", "ip": ip, "port": port,
                  "protocol": "tcp", "os": spec.get("os")},
        "evidence": evidence,
    }
    if validation:
        data["validation"] = validation
    return data


def _package(spec: dict[str, Any], tool: str, scan_id: str) -> dict[str, Any]:
    purl = spec["purl"]
    name = purl.split("@", 1)[0].rsplit("/", 1)[1]
    native = spec.get("cve", ["GHSA-bench"])[0] if spec.get("cve") else "GHSA-bench"
    fixed = spec.get("fixed", [])
    return {
        "native_id": native, "default_scan_type": "sca",
        "idempotency_key": keys.package_key(tool, spec.get("cve", []), native, purl),
        "locus": {"type": "package", "asset_ref": "ast_bench_image", "package_name": name,
                  "purl": purl, "installed_version": spec["installed"], "fixed_version": fixed,
                  "fix_status": spec.get("fix_status", "fixed" if fixed else "affected")},
    }


def _endpoint(spec: dict[str, Any], tool: str, scan_id: str) -> dict[str, Any]:
    url, method = spec.get("url", "https://app.example.com/login"), spec.get("method", "POST")
    native = spec.get("native_id", "MIR-1")
    completeness = spec.get("evidence", "full")
    return {
        "native_id": native, "default_scan_type": "dast_agentic",
        "idempotency_key": keys.endpoint_key(tool, scan_id, url, method, (), spec.get("cwe", [])),
        "locus": {"type": "endpoint", "asset_ref": "ast_bench_app", "url": url,
                  "method": method},
        "validation": {"confidence": spec.get("confidence", "unvalidated"),
                       "confidence_source": "tool_asserted",
                       "tool_label": spec.get("confidence", "unvalidated").capitalize(),
                       "reproduced": spec.get("reproduced", False),
                       "evidence_completeness": completeness,
                       "evidence_gaps": spec.get("gaps", [] if completeness == "full"
                                                 else ["request/response not captured"])},
    }
