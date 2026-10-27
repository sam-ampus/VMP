"""Connectors: one per scanner format, each translating native output to the canonical batch.

Phase 1 is file upload. API connectors (Tenable, Qualys) are Phase 2; the Mirror JSON feed
connector is built when its samples arrive.
"""

from vmp.connectors.base import (
    Connector,
    ConnectorError,
    ScanContext,
    finding_id,
    ingest,
    resolve_asset_ref,
    scan_id_for,
)
from vmp.connectors.canonical import CanonicalConnector
from vmp.connectors.nessus import NessusConnector
from vmp.connectors.qualys import QualysConnector
from vmp.connectors.trivy import TrivyConnector

CONNECTORS: dict[str, Connector] = {
    c.name: c for c in (CanonicalConnector(), NessusConnector(), QualysConnector(),
                        TrivyConnector())
}

__all__ = [
    "CONNECTORS",
    "CanonicalConnector",
    "Connector",
    "ConnectorError",
    "NessusConnector",
    "QualysConnector",
    "ScanContext",
    "TrivyConnector",
    "finding_id",
    "ingest",
    "resolve_asset_ref",
    "scan_id_for",
]
