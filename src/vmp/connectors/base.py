"""The connector contract: translate one tool's native output into the canonical batch format.

A connector only *translates*. It never validates, scores, enriches, or deduplicates across
scans. Validation is shared: every connector's output goes through the same validate_batch(),
so a new connector cannot weaken the schema's rules, and a translation bug surfaces as a
per-record error instead of a silently wrong Finding.

    native bytes ──connector.to_batch()──► canonical dict ──validate_batch()──► BatchReport
"""

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from xml.etree.ElementTree import Element, ParseError

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring
from pydantic import AwareDatetime

from vmp.assets import AssetProvider
from vmp.schema.validation import SCHEMA_VERSION, BatchReport, validate_batch


class ConnectorError(ValueError):
    """The input is not this connector's format at all (as opposed to one bad record)."""


@dataclass(frozen=True)
class ScanContext:
    """What the caller knows about an upload that the file itself may not say.

    scan_id and received_at come from the caller, never from the clock inside a connector,
    so translating the same file twice gives byte-identical output.
    """

    scan_id: str
    batch_id: str
    received_at: AwareDatetime
    assets: AssetProvider | None = None


class Connector(Protocol):
    name: str  # registry key and Source.tool, e.g. "trivy"
    extensions: tuple[str, ...]  # file suffixes this connector reads, e.g. (".json",)

    def to_batch(self, raw: bytes, ctx: ScanContext) -> dict[str, Any]:
        """Native bytes -> a FindingBatch payload. Raises ConnectorError on a foreign format."""
        ...


def ingest(connector: Connector, raw: bytes, ctx: ScanContext) -> BatchReport:
    return validate_batch(connector.to_batch(raw, ctx))


def envelope(source_tool: str, ctx: ScanContext, findings: Iterable[Mapping[str, Any]], *,
             skipped: Mapping[str, int] | None = None, warnings: Iterable[str] = ()
             ) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "ingest_batch": {"batch_id": ctx.batch_id, "source_tool": source_tool,
                         "received_at": ctx.received_at.isoformat()},
        "findings": [dict(f) for f in findings],
        "skipped": {k: v for k, v in sorted((skipped or {}).items()) if v},
        "warnings": list(warnings),
    }


def load_xml(raw: bytes, *, root_tag: str, what: str) -> Element:
    """Parse an uploaded XML export safely, and check it is the format we expect.

    Scanner exports are untrusted input. defusedxml refuses entity expansion and external
    references (billion-laughs, XXE); a plain DOCTYPE, which Qualys always writes, is allowed.
    """
    try:
        root = fromstring(raw, forbid_dtd=False)
    except (ParseError, DefusedXmlException) as exc:
        raise ConnectorError(f"not a readable {what} XML file: {exc}") from exc
    if root.tag != root_tag:
        raise ConnectorError(f"not a {what} file (root element <{root.tag}>, "
                             f"expected <{root_tag}>)")
    return root


def text(el: Element | None, path: str) -> str | None:
    """Stripped text of a child element; None when absent or blank (unknown, not empty)."""
    if el is None:
        return None
    value = el.findtext(path)
    return value.strip() or None if value is not None else None


def finding_id(scan_id: str, idempotency_key: str) -> str:
    """Deterministic: the same observation in the same scan always gets the same id,
    so re-ingesting a file is a no-op rather than a pile of duplicates."""
    digest = hashlib.sha256(f"{scan_id}\0{idempotency_key}".encode()).hexdigest()
    return f"fnd_{digest[:16]}"


def scan_id_for(raw: bytes, tool: str) -> str:
    """A content-derived scan id for uploads that carry none: same file, same id."""
    return f"scan_{tool}_{hashlib.sha256(raw).hexdigest()[:12]}"


_SLUG = re.compile(r"[^A-Za-z0-9_.-]+")


def resolve_asset_ref(assets: AssetProvider | None, *identifiers: str | None) -> str:
    """The inventory's asset_ref for the first identifier it knows.

    Unknown assets still get a stable ref ('ast_unresolved_<first identifier>') so their
    findings ingest and score; they simply carry no business context, which scoring
    reports as missing input rather than guessing.
    """
    candidates = [i for i in identifiers if i]
    if not candidates:
        raise ConnectorError("finding has no asset identifier")
    if assets is not None:
        for ident in candidates:
            if (asset := assets.resolve(ident)) is not None:
                return asset.asset_ref
    return "ast_unresolved_" + _SLUG.sub("-", candidates[0].strip().lower()).strip("-")
