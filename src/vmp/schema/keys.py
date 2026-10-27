"""Deterministic idempotency keys, one format per finding shape.

Same key means the same observation. These builders take primitives only, so they
can be reused by connectors and dedupe without importing the models.
"""

from collections.abc import Iterable

MISSING = "-"


def _part(value: object | None) -> str:
    return MISSING if value is None else str(value)


def host_key(
    tool: str, native_id: str, ip: str, port: int | None, protocol: str | None
) -> str:
    """tool:native_id:ip:port:protocol. Host-level findings (e.g. EOL OS) have no port."""
    return ":".join([tool, native_id, ip, _part(port), _part(protocol)])


def package_key(tool: str, cves: Iterable[str], native_id: str, purl: str) -> str:
    """tool:cve:purl. Falls back to the tool's native id when there is no CVE."""
    cve_part = ",".join(sorted(set(cves))) or native_id
    return ":".join([tool, cve_part, purl])


def endpoint_key(
    tool: str, scan_id: str, url: str, method: str, parameters: Iterable[str],
    cwes: Iterable[str] = (),
) -> str:
    """tool:scan_id:url:method:parameters:cwe. Names and CWEs are sorted so order is irrelevant.

    The CWE is part of the key (as in locked decision 4's endpoint key): one endpoint can
    carry several different weaknesses, and without it they would collapse into one finding.
    """
    params = ",".join(sorted(set(parameters))) or MISSING
    cwe = ",".join(sorted(set(cwes))) or MISSING
    return ":".join([tool, scan_id, url, method, params, cwe])
