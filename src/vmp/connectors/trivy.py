"""Trivy JSON (`trivy image|fs|sbom --format json`) -> canonical package findings.

Handles report schema 2 ({"Results": [...]}) and the legacy bare list of results.
Only `Vulnerabilities` are read; misconfigurations, secrets and licenses are out of scope
for phase 1.

Every value is copied from what Trivy reported. Nothing here selects a CVSS (that needs
enrichment, see pipeline/cvss.py) or judges applicability (that is FP triage, Stage 2).
"""

import json
import re
from collections.abc import Iterator, Mapping
from datetime import datetime
from decimal import Decimal
from typing import Any
from urllib.parse import quote

from vmp.connectors.base import (
    ConnectorError,
    ScanContext,
    envelope,
    finding_id,
    resolve_asset_ref,
)
from vmp.schema import keys

TOOL = "trivy"

# Trivy's Result.Type -> purl type (and namespace for OS packages).
_OS_PURL = {
    "alpine": ("apk", "alpine"), "wolfi": ("apk", "wolfi"), "chainguard": ("apk", "chainguard"),
    "debian": ("deb", "debian"), "ubuntu": ("deb", "ubuntu"),
    "redhat": ("rpm", "redhat"), "centos": ("rpm", "centos"), "rocky": ("rpm", "rocky"),
    "alma": ("rpm", "almalinux"), "amazon": ("rpm", "amazon"), "oracle": ("rpm", "oracle"),
    "fedora": ("rpm", "fedora"), "photon": ("rpm", "photon"), "cbl-mariner": ("rpm", "mariner"),
    "suse linux enterprise server": ("rpm", "suse"), "opensuse.leap": ("rpm", "opensuse"),
}
_LANG_PURL = {
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "node-pkg": "npm",
    "pip": "pypi", "pipenv": "pypi", "poetry": "pypi", "python-pkg": "pypi", "uv": "pypi",
    "jar": "maven", "pom": "maven", "gradle": "maven", "sbt": "maven",
    "gomod": "golang", "gobinary": "golang",
    "cargo": "cargo", "rust-binary": "cargo",
    "composer": "composer", "nuget": "nuget", "dotnet-core": "nuget", "packages-props": "nuget",
    "bundler": "gem", "gemspec": "gem", "conan": "conan", "cocoapods": "cocoapods",
    "swift": "swift", "pub": "pub", "hex": "hex", "conda-pkg": "conda",
}
_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low",
             "UNKNOWN": "info"}  # Trivy UNKNOWN: no rating anywhere; raw value is kept
_STATUSES = {"fixed", "affected", "will_not_fix", "fix_deferred", "end_of_life",
             "not_affected", "under_investigation", "unknown"}
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CWE = re.compile(r"^CWE-\d+$")
_CVSS_FIELDS = (("V2Score", "V2Vector"), ("V3Score", "V3Vector"), ("V40Score", "V40Vector"))


class TrivyConnector:
    name = TOOL
    extensions: tuple[str, ...] = (".json",)

    def to_batch(self, raw: bytes, ctx: ScanContext) -> dict[str, Any]:
        report = _load(raw)
        results, meta = (report, {}) if isinstance(report, list) else (
            report.get("Results") or [], report)
        # Older reports can leave ArtifactName empty; the first Target then names the image,
        # e.g. "registry/app:1.2 (debian 10.13)".
        artifact = meta.get("ArtifactName") or next(
            (r["Target"].split(" (", 1)[0] for r in results if r.get("Target")), None)
        identifiers = [artifact, *(meta.get("Metadata") or {}).get("RepoTags", []),
                       _untagged(artifact)]
        asset_ref = resolve_asset_ref(ctx.assets, *identifiers, "trivy-scan")
        detected = _timestamp(meta.get("CreatedAt")) or ctx.received_at.isoformat()
        scan_type = "container_image" if meta.get("ArtifactType") == "container_image" else "sca"
        tool_version = (meta.get("Trivy") or {}).get("Version")

        by_key: dict[str, dict[str, Any]] = {}
        for result in results:
            for vuln in result.get("Vulnerabilities") or []:
                f = _finding(vuln, result, ctx, asset_ref=asset_ref, detected=detected,
                             scan_type=scan_type, tool_version=tool_version)
                if (seen := by_key.get(f["idempotency_key"])) is None:
                    by_key[f["idempotency_key"]] = f
                else:
                    # Same CVE, same package, same scan, found at another path: one
                    # observation. Keep the first and record every location.
                    paths = seen["evidence"]["pkg_paths"]
                    seen["evidence"]["pkg_paths"] = sorted({*paths, *f["evidence"]["pkg_paths"]})
        findings = sorted(by_key.values(), key=lambda f: f["finding_id"])
        return envelope(TOOL, ctx, findings, coverage={asset_ref: detected})


def _load(raw: bytes) -> Any:
    try:
        report = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectorError(f"not JSON: {exc}") from exc
    if isinstance(report, list) or (isinstance(report, dict) and "Results" in report):
        return report
    raise ConnectorError("not a Trivy JSON report (no 'Results')")


def _finding(v: Mapping[str, Any], result: Mapping[str, Any], ctx: ScanContext, *,
             asset_ref: str, detected: str, scan_type: str, tool_version: str | None
             ) -> dict[str, Any]:
    vid = v.get("VulnerabilityID") or ""
    name, installed = v.get("PkgName") or "", v.get("InstalledVersion") or ""
    purl = (v.get("PkgIdentifier") or {}).get("PURL") or _purl(result.get("Type"), name,
                                                                 installed)
    cves = [vid] if _CVE.match(vid) else []
    fixed = tuple(s.strip() for s in (v.get("FixedVersion") or "").split(",") if s.strip())
    status = _fix_status(v.get("Status"), fixed)
    key = keys.package_key(TOOL, cves, vid, purl)
    raw_sev = (v.get("Severity") or "UNKNOWN").upper()
    data_source = v.get("DataSource") or {}

    return {
        "finding_id": finding_id(ctx.scan_id, key),
        "idempotency_key": key,
        "source": {
            "tool": TOOL, "tool_version": tool_version, "native_id": vid,
            "native_family": data_source.get("ID") or v.get("SeveritySource"),
            "scan_id": ctx.scan_id, "scan_type": scan_type,
            "first_detected": detected, "last_detected": detected,
        },
        "locus": {
            "type": "package", "asset_ref": asset_ref, "package_name": name,
            "package_id": v.get("PkgID") or f"{name}@{installed}", "purl": purl,
            "installed_version": installed, "fixed_version": list(fixed), "fix_status": status,
        },
        "classification": {
            "title": v.get("Title") or f"{vid} in {name}",
            "cve": cves,
            "cwe": sorted({c for c in v.get("CweIDs") or [] if _CWE.match(c)}),
            "source_severity": _SEVERITY.get(raw_sev, "info"),
            "source_severity_raw": raw_sev,
        },
        "scores": {"cvss": list(_cvss(v.get("CVSS") or {}))},
        "validation": {
            "confidence": "unvalidated", "confidence_source": "default_for_tool_class",
            "evidence_completeness": "full",
        },
        "remediation_source": (
            {"text": f"Upgrade {name} to {' or '.join(fixed)} or later.",
             "provided_by": "derived_from_fixed_version"} if fixed else {}),
        "evidence": {
            "references": sorted({*(v.get("References") or []),
                                  *([v["PrimaryURL"]] if v.get("PrimaryURL") else [])}),
            "target": result.get("Target"),
            "data_source": data_source.get("Name"),
            "pkg_paths": [v["PkgPath"]] if v.get("PkgPath") else [],
            "layer_diff_id": (v.get("Layer") or {}).get("DiffID"),
        },
    }


def _fix_status(status: str | None, fixed: tuple[str, ...]) -> str:
    if status:
        s = status.strip().lower()
        if s not in _STATUSES:
            return "unknown"
        # Trivy has been seen to say 'fixed' with no version; keep the claim honest.
        return "unknown" if s == "fixed" and not fixed else s
    # Legacy reports carry no Status: a listed vuln affects the installed version, and a
    # FixedVersion means a fix exists.
    return "fixed" if fixed else "affected"


def _cvss(by_source: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
    for source in sorted(by_source):
        entry = by_source[source] or {}
        for score_field, vector_field in _CVSS_FIELDS:
            if entry.get(score_field) is None:
                continue
            vector = entry.get(vector_field)
            yield {"source": source.lower(), "version": _version(score_field, vector),
                   "base": str(Decimal(str(entry[score_field])).quantize(Decimal("0.1"))),
                   "vector": vector}


def _version(score_field: str, vector: str | None) -> str:
    if score_field == "V2Score":
        return "2.0"
    if score_field == "V40Score":
        return "4.0"
    return "3.0" if vector and vector.startswith("CVSS:3.0/") else "3.1"


def _purl(result_type: str | None, name: str, version: str) -> str:
    t = (result_type or "").lower()
    v = quote(version, safe=".-_~+")
    if t in _OS_PURL:
        ptype, namespace = _OS_PURL[t]
        return f"pkg:{ptype}/{namespace}/{quote(name, safe='.-_~+')}@{v}"
    ptype = _LANG_PURL.get(t, "generic")
    if ptype == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        return f"pkg:maven/{quote(group, safe='.-_~')}/{quote(artifact, safe='.-_~')}@{v}"
    if ptype == "npm" and name.startswith("@"):
        scope, _, pkg = name.partition("/")
        return f"pkg:npm/{quote(scope)}/{quote(pkg, safe='.-_~')}@{v}"
    return f"pkg:{ptype}/{quote(name, safe='/.-_~+')}@{v}"


def _untagged(artifact: str | None) -> str | None:
    """'registry.local/k-client:1.2' -> 'registry.local/k-client' (inventories rarely pin tags)."""
    if not artifact or "@" in artifact:
        return artifact.split("@", 1)[0] if artifact else None
    head, sep, tag = artifact.rpartition(":")
    return head if sep and "/" not in tag else artifact


def _timestamp(value: str | None) -> str | None:
    if not value:
        return None
    # Trivy writes nanoseconds; keep it as given but make sure it parses.
    return datetime.fromisoformat(value).isoformat()
