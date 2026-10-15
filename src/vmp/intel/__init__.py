"""Threat intel (CISA KEV, FIRST EPSS, NVD, OSV): fetched live or imported from offline
bundles, stored as immutable content-addressed snapshots, read back for enrichment."""

from vmp.intel.build import build_live_snapshot, import_bundle
from vmp.intel.enrich import enrich, enrich_all
from vmp.intel.http import HttpClient, UrllibClient
from vmp.intel.snapshot import (
    IntelReader,
    Manifest,
    SnapshotData,
    SnapshotIntegrityError,
    SourceInfo,
    write_snapshot,
)

__all__ = [
    "HttpClient",
    "IntelReader",
    "Manifest",
    "SnapshotData",
    "SnapshotIntegrityError",
    "SourceInfo",
    "UrllibClient",
    "build_live_snapshot",
    "enrich",
    "enrich_all",
    "import_bundle",
    "write_snapshot",
]
