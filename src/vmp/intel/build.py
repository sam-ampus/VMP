"""Build an intel snapshot from live feeds or from an offline bundle. Both produce the same format.

Offline bundle layout (every file optional; files are the sources' own published formats):
    kev.json              CISA KEV catalogue
    epss.csv[.gz]         FIRST EPSS bulk scores
    nvd/*.json            NVD API 2.0 responses or NVD JSON 2.0 feed files
    osv.json              {"<purl>": <OSV /v1/query response for that purl>, ...}
"""

import gzip
import json
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from pydantic import AwareDatetime

from vmp.intel import sources as src
from vmp.intel.http import HttpClient
from vmp.intel.records import EpssEntry, KevEntry, NvdEntry, OsvPackage
from vmp.intel.snapshot import Manifest, SnapshotData, SourceInfo, write_snapshot

ALL_SOURCES = ("kev", "epss", "nvd", "osv")


def build_live_snapshot(
    http: HttpClient, root: Path, *, cves: Iterable[str], purls: Iterable[str],
    now: AwareDatetime, nvd_api_key: str | None = None,
    sleep: Callable[[float], None] = time.sleep, include: Iterable[str] = ALL_SOURCES,
) -> Manifest:
    """Fetch only what is in scope: the CVEs and purls present in the deduplicated findings."""
    cve_list, purl_list, wanted = sorted(set(cves)), sorted(set(purls)), set(include)
    sources: dict[str, SourceInfo] = {}
    kev: tuple[KevEntry, ...] | None = None
    epss: tuple[EpssEntry, ...] | None = None
    nvd: tuple[NvdEntry, ...] | None = None
    osv: tuple[OsvPackage, ...] | None = None

    if "kev" in wanted:
        version, kev = src.fetch_kev(http)
        sources["kev"] = SourceInfo(origin=src.KEV_URL, retrieved_at=now, version=version,
                                    count=len(kev))
    if "epss" in wanted:
        as_of, epss = src.fetch_epss(http, cve_list)
        sources["epss"] = SourceInfo(origin=src.EPSS_URL, retrieved_at=now, as_of=as_of,
                                     count=len(epss))
    if "nvd" in wanted:
        nvd = src.fetch_nvd(http, cve_list, nvd_api_key, sleep)
        sources["nvd"] = SourceInfo(origin=src.NVD_URL, retrieved_at=now, count=len(nvd))
    if "osv" in wanted:
        osv = src.fetch_osv(http, purl_list)
        sources["osv"] = SourceInfo(origin=src.OSV_URL, retrieved_at=now, count=len(osv))

    scope_purls = tuple(purl_list) if osv is not None else ()
    data = SnapshotData(scope_cves=tuple(cve_list), scope_purls=scope_purls,
                        kev=kev, epss=epss, nvd=nvd, osv=osv)
    return write_snapshot(root, data, sources, "live", now)


def import_bundle(
    bundle: Path, root: Path, *, cves: Iterable[str], purls: Iterable[str],
    imported_at: AwareDatetime,
) -> Manifest:
    """Import an offline bundle, keeping only in-scope records (KEV is kept whole)."""
    wanted_cves, wanted_purls = set(cves), set(purls)
    sources: dict[str, SourceInfo] = {}
    kev: tuple[KevEntry, ...] | None = None
    epss: tuple[EpssEntry, ...] | None = None
    nvd: tuple[NvdEntry, ...] | None = None
    osv: tuple[OsvPackage, ...] | None = None

    def info(name: str, count: int, version: str | None = None,
             as_of: str | None = None) -> SourceInfo:
        return SourceInfo(origin=f"bundle:{name}", retrieved_at=imported_at,
                          version=version, as_of=as_of, count=count)

    if (path := bundle / "kev.json").exists():
        version, kev = src.parse_kev(_read_json(path))
        sources["kev"] = info(path.name, len(kev), version=version)

    if epss_path := next((p for p in (bundle / "epss.csv.gz", bundle / "epss.csv")
                          if p.exists()), None):
        model, as_of, epss = src.parse_epss_csv(_read_text(epss_path), wanted_cves)
        sources["epss"] = info(epss_path.name, len(epss), version=model, as_of=as_of)

    if nvd_files := sorted((bundle / "nvd").glob("*.json")):
        nvd = tuple(e for f in nvd_files for e in src.parse_nvd(_read_json(f))
                    if e.cve in wanted_cves)
        sources["nvd"] = info("nvd/", len(nvd))

    scope_purls: set[str] = set()
    if (path := bundle / "osv.json").exists():
        responses: dict[str, Any] = _read_json(path)
        # Only purls the bundle actually answered are in scope; others stay unknown.
        scope_purls = wanted_purls & responses.keys()
        osv = tuple(src.parse_osv(p, responses[p]) for p in sorted(scope_purls))
        sources["osv"] = info(path.name, len(osv))

    data = SnapshotData(scope_cves=tuple(wanted_cves), scope_purls=tuple(scope_purls),
                        kev=kev, epss=epss, nvd=nvd, osv=osv)
    return write_snapshot(root, data, sources, "bundle", imported_at)


def _read_text(path: Path) -> str:
    raw = path.read_bytes()
    return (gzip.decompress(raw) if path.suffix == ".gz" else raw).decode("utf-8")


def _read_json(path: Path) -> Any:
    return json.loads(_read_text(path))
