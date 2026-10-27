"""Transcribe a rendered Mirror pentest report (PDF) into a canonical FindingBatch.

A stop-gap for the demo seed: the Mirror JSON feed is a Phase 2 connector. Only structured
fields are kept (title, endpoint, method, parameter names, CVSS, confidence, CWE/OWASP,
evidence gaps, remediation text). Raw requests, responses, payloads, PoC scripts and any
secrets in them are deliberately NOT copied: the report is confidential and contains live
keys.

    uv run --with pypdf python scripts/transcribe_mirror_report.py REPORT.pdf \
        --assets seed/demo/assets.csv --out seed/demo/scans/canonical/mirror-<scan>.json

Findings the canonical endpoint shape cannot represent (no real HTTP method, no URL) are
skipped and listed, never guessed.
"""

import argparse
import json
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from vmp.assets import AssetInventory, load_asset_csv
from vmp.connectors import ScanContext, finding_id, resolve_asset_ref
from vmp.connectors.base import envelope
from vmp.schema import keys, validate_batch
from vmp.schema.enums import HttpMethod

TOOL = "mirror"
_METHODS = {m.value for m in HttpMethod}
_CONFIDENCE = {"CONFIRMED": "confirmed", "LIKELY": "likely", "POTENTIAL": "potential",
               "UNTESTED": "untested"}
_PARAM_LOCATION = {"json body": "body", "body": "body", "form body": "body", "query": "query",
                   "header": "header", "cookie": "cookie", "path": "path"}
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_PARAM_NAME = re.compile(r"^(?!N/A$)[A-Za-z_][A-Za-z0-9_.\-\[\]]*$")
# Anything that looks like a key, token or JWT: 20+ chars mixing letters and digits.
_SECRET = re.compile(r"\b(?=[A-Za-z0-9+/_\-.]*\d)(?=[A-Za-z0-9+/_\-.]*[A-Za-z])"
                     r"[A-Za-z0-9+/_\-.]{20,}={0,2}")
_ALLOWED = re.compile(r"^(CVSS:|https?://|CWE-|[a-z0-9.-]+\.(js|json|py|html|xlsx)$)")


def redact(text: str) -> str:
    """Mirror's prose quotes the live secrets it found; never carry them into the seed."""
    return _SECRET.sub(lambda m: m.group(0) if _ALLOWED.match(m.group(0)) else "[REDACTED]",
                       text)
_FIELD = re.compile(r"^(Severity|Endpoint|Method|CVSS|Confidence|Parameter|OWASP|CWE|Agent): (.*)$")
_CURL_URL = re.compile(r"curl -i(?: -X [A-Z]+)? '(https?://[^']+)'")
_NOISE = re.compile(r"^(Mirror · Ampcus Cyber · Confidential Page \d+ of \d+|=====PAGE=====|\d+)$")
_GAPS = {
    "Only response headers were captured": "response body not captured",
    "No proof-of-concept script was captured": "no proof-of-concept script",
    "No raw request was captured": "raw request not captured",
    "reconstructed from the recorded method": "request reconstructed, not captured",
}


@dataclass
class Block:
    number: int
    title: str
    fields: dict[str, str] = field(default_factory=dict)
    lines: list[str] = field(default_factory=list)


def pdf_text(path: Path) -> str:
    try:
        import pypdf  # type: ignore[import-not-found, unused-ignore]
    except ImportError:
        sys.exit("pypdf is needed only for this script: uv run --with pypdf python ...")
    reader = pypdf.PdfReader(str(path))
    return "\n=====PAGE=====\n".join(p.extract_text() or "" for p in reader.pages)


def header(text: str) -> dict[str, str]:
    scan = re.search(r"Scan ID: (\w+)", text)
    target = re.search(r"Target: (https?://\S+)", text)
    started = re.search(r"Started (\d{4}-\d{2}-\d{2} \d{2}:\d{2}) UTC", text)
    if not (scan and target and started):
        sys.exit("not a Mirror report: scan id, target or start time not found")
    return {"scan": scan.group(1), "target": target.group(1).rstrip("/"),
            "started": started.group(1).replace(" ", "T") + ":00+00:00"}


def blocks(text: str) -> Iterator[Block]:
    """A finding starts at '<title>' / '<SEVERITY>' / 'Severity: <SEVERITY>'."""
    lines = [ln.strip() for ln in text.splitlines()]
    starts = [i for i in range(2, len(lines))
              if lines[i].startswith("Severity: ") and lines[i - 1] in _SEVERITIES]
    for n, (i, end) in enumerate(zip(starts, [*starts[1:], len(lines)], strict=True), start=1):
        title = lines[i - 2]
        block = Block(n, title)
        for ln in lines[i:end - 2]:
            if (m := _FIELD.match(ln)) and m.group(1) not in block.fields:
                block.fields[m.group(1)] = m.group(2).strip()
            elif not _NOISE.match(ln):
                block.lines.append(ln)
        yield block


def to_finding(b: Block, meta: dict[str, str], assets: AssetInventory | None
               ) -> tuple[dict[str, Any] | None, str | None]:
    method = b.fields.get("Method", "").upper()
    if method not in _METHODS:
        return None, f"#{b.number} {b.title!r}: method {b.fields.get('Method')!r} is not HTTP"
    url = _url(b, meta["target"])
    if url is None:
        return None, f"#{b.number} {b.title!r}: no URL in {b.fields.get('Endpoint')!r}"

    names, location, raw_param = _parameters(b.fields.get("Parameter"))
    scan_id = f"scan_mirror_{meta['scan']}"
    cwe, cwe_inferred = _tagged(b.fields.get("CWE"))
    cwe = cwe if cwe and re.fullmatch(r"CWE-\d+", cwe) else None
    key = keys.endpoint_key(TOOL, scan_id, url, method, names, [cwe] if cwe else [])
    gaps = sorted({gap for phrase, gap in _GAPS.items() if any(phrase in ln for ln in b.lines)})
    owasp, owasp_inferred = _tagged(b.fields.get("OWASP"))
    severity = b.fields["Severity"].lower()
    confidence = _CONFIDENCE.get(b.fields.get("Confidence", "").split(" ")[0], "unvalidated")
    title = redact(b.title) if b.title.upper() not in _SEVERITIES else (
        f"Untitled Mirror finding on {method} {urlsplit(url).path or '/'}")

    return {
        "finding_id": finding_id(scan_id, key),
        "idempotency_key": key,
        "source": {"tool": TOOL, "native_id": f"{meta['scan']}-{b.number:02d}",
                   "native_family": b.fields.get("Agent"), "scan_id": scan_id,
                   "scan_type": "dast_agentic", "first_detected": meta["started"],
                   "last_detected": meta["started"]},
        "locus": {"type": "endpoint",
                  "asset_ref": resolve_asset_ref(assets, urlsplit(url).netloc,
                                                 urlsplit(url).hostname),
                  "url": url, "method": method, "parameters": names,
                  "parameter_location": location, "parameter_raw": raw_param},
        "classification": {
            "title": title,
            "cwe": [cwe] if cwe else [],
            "owasp": owasp,
            "source_severity": severity, "source_severity_raw": b.fields["Severity"],
            "inferred_mappings": [m for m, flag, val in (("cwe", cwe_inferred, cwe),
                                                         ("owasp", owasp_inferred, owasp))
                                  if flag and val],
        },
        "scores": {"cvss": _cvss(b.fields.get("CVSS"))},
        "validation": {"confidence": confidence, "confidence_source": "tool_asserted",
                       "reproduced": confidence == "confirmed",
                       "evidence_completeness": "partial" if gaps else "full",
                       "evidence_gaps": gaps},
        "remediation_source": {"text": _remediation(b.lines), "provided_by": "mirror"},
        "evidence": {"references": [], "mirror_agent": b.fields.get("Agent"),
                     "report_finding": b.number, "endpoint_as_reported": b.fields.get("Endpoint")},
    }, None


def _url(b: Block, target: str) -> str | None:
    endpoint = b.fields.get("Endpoint", "")
    token = endpoint.split(" ")[0] if endpoint else ""
    curl = next((m.group(1) for ln in b.lines if (m := _CURL_URL.search(ln))), None)
    if token.startswith(("http://", "https://")):
        parts = urlsplit(token)
    elif token.startswith("/"):
        base = urlsplit(curl or target)
        parts = urlsplit(f"{base.scheme}://{base.netloc}{token}")
    elif curl:
        parts = urlsplit(curl)
    else:
        return None
    # Query values and fragments are dropped (locked decision 4); names live in parameters.
    return f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"


def _parameters(raw: str | None) -> tuple[list[str], str | None, str | None]:
    if not raw:
        return [], None, None
    names_part, _, loc = raw.partition("(")
    location = _PARAM_LOCATION.get(loc.rstrip(") ").strip().lower())
    # Only identifier-like names count. Prose such as "Authorization token" or "N/A" is a
    # description, not a parameter; it stays in parameter_raw and does not enter the key.
    names = sorted({n.strip() for n in names_part.split(",") if _PARAM_NAME.match(n.strip())})
    return names, location if names else None, raw


def _tagged(raw: str | None) -> tuple[str | None, bool]:
    if not raw or raw in ("—", "-"):
        return None, False
    inferred = raw.endswith("(inferred)")
    return raw.removesuffix("(inferred)").strip(), inferred


def _cvss(raw: str | None) -> list[dict[str, Any]]:
    m = re.match(r"([\d.]+) — (CVSS:(\d\.\d)/\S+)", raw or "")
    if not m:
        return []
    return [{"source": TOOL, "version": m.group(3), "base": m.group(1), "vector": m.group(2)}]


def _remediation(lines: list[str]) -> str | None:
    try:
        start = lines.index("Remediation:") + 1
    except ValueError:
        return None
    out = []
    for ln in lines[start:]:
        if ln.startswith("References:"):
            break
        out.append(ln)
    text = " ".join(out).strip()
    if not text or text.startswith("No remediation guidance"):
        return None
    return redact(text)[:1000]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("report", type=Path)
    p.add_argument("--assets", type=Path)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()

    text = pdf_text(args.report)
    meta = header(text)
    assets = load_asset_csv(args.assets) if args.assets else None
    by_key: dict[str, dict[str, Any]] = {}
    skipped: list[str] = []
    merged = 0
    for b in blocks(text):
        f, why = to_finding(b, meta, assets)
        if f is None:
            skipped.append(why or "")
            continue
        if (seen := by_key.get(f["idempotency_key"])) is None:
            by_key[f["idempotency_key"]] = f
        else:
            # Same scan, endpoint, method and parameters: one observation reported twice.
            merged += 1
            seen["evidence"].setdefault("also_reported_as", []).append(
                {"report_finding": b.number, "title": f["classification"]["title"]})

    received = datetime.fromisoformat(meta["started"]).astimezone(UTC)
    ctx = ScanContext(scan_id=f"scan_mirror_{meta['scan']}", batch_id=f"ing_mirror_{meta['scan']}",
                      received_at=received)
    batch = envelope(TOOL, ctx, sorted(by_key.values(), key=lambda f: f["source"]["native_id"]))
    report = validate_batch(batch)
    if not report.ok:
        for e in report.errors:
            print("INVALID", e, file=sys.stderr)
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(batch, indent=2, ensure_ascii=False) + "\n", "utf-8")
    print(f"{len(report.findings)} findings written to {args.out} "
          f"({merged} duplicates merged, {len(skipped)} skipped)")
    for s in skipped:
        print("  skipped", s)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
