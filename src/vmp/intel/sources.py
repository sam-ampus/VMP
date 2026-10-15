"""Parsers and live fetchers for CISA KEV, FIRST EPSS, NVD and OSV.

Parsers are pure: official format in, normalised records out. Live fetching and offline
bundles both go through them, so the two paths cannot drift apart.
Fetchers only request what is in scope (the CVEs and purls actually present in findings).
"""

import csv
import io
import re
import time
from collections.abc import Callable, Iterable, Sequence
from decimal import Decimal
from typing import Any

from vmp.intel.http import HttpClient
from vmp.intel.records import (
    EpssEntry,
    KevEntry,
    NvdEntry,
    OsvAdvisory,
    OsvAffected,
    OsvEvent,
    OsvPackage,
    OsvRange,
)
from vmp.schema.enrichment import SourcedCvss
from vmp.schema.enums import CvssSourceKind

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_URL = "https://api.osv.dev/v1/query"

NVD_SOURCE = "nvd@nist.gov"
NVD_DELAY_NO_KEY = 6.0  # NVD public limit: 5 requests / 30 s without an API key
NVD_DELAY_WITH_KEY = 0.6  # 50 requests / 30 s with one
EPSS_BATCH = 100
_CWE = re.compile(r"^CWE-\d+$")
_NVD_METRICS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


# --- CISA KEV --------------------------------------------------------------------


def parse_kev(payload: dict[str, Any]) -> tuple[str | None, tuple[KevEntry, ...]]:
    """Returns (catalogVersion, entries). The full catalogue is kept: it is small, and
    keeping all of it makes 'not listed' authoritative for any CVE."""
    entries = tuple(
        KevEntry(
            cve=v["cveID"],
            date_added=v["dateAdded"],
            due_date=v.get("dueDate") or None,
            vendor=v.get("vendorProject", ""),
            product=v.get("product", ""),
            # CISA uses "Known" / "Unknown": unknown is not the same as no.
            ransomware=True if v.get("knownRansomwareCampaignUse") == "Known" else None,
        )
        for v in payload["vulnerabilities"]
    )
    return payload.get("catalogVersion"), entries


def fetch_kev(http: HttpClient) -> tuple[str | None, tuple[KevEntry, ...]]:
    return parse_kev(http.get_json(KEV_URL))


# --- FIRST EPSS ------------------------------------------------------------------


def parse_epss_api(payload: dict[str, Any]) -> tuple[str | None, tuple[EpssEntry, ...]]:
    """API response -> (score date, entries)."""
    data = payload.get("data", [])
    entries = tuple(
        EpssEntry(cve=d["cve"], epss=d["epss"], percentile=d["percentile"]) for d in data
    )
    return (data[0].get("date") if data else None), entries


def parse_epss_csv(
    text: str, cves: Iterable[str]
) -> tuple[str | None, str | None, tuple[EpssEntry, ...]]:
    """Bulk CSV (epss_scores-YYYY-MM-DD.csv) -> (model_version, score_date, in-scope entries).

    The first line is a comment: '#model_version:v2025.03.14,score_date:2026-10-11T00:00:00Z'.
    """
    first, _, body = text.partition("\n")
    meta = dict(
        part.split(":", 1) for part in first.lstrip("#").strip().split(",") if ":" in part
    )
    wanted = set(cves)
    entries = tuple(
        EpssEntry(cve=row["cve"], epss=Decimal(row["epss"]),
                  percentile=Decimal(row["percentile"]))
        for row in csv.DictReader(io.StringIO(body))
        if row["cve"] in wanted
    )
    return meta.get("model_version"), meta.get("score_date"), entries


def fetch_epss(
    http: HttpClient, cves: Sequence[str]
) -> tuple[str | None, tuple[EpssEntry, ...]]:
    score_date: str | None = None
    entries: list[EpssEntry] = []
    for i in range(0, len(cves), EPSS_BATCH):
        batch = cves[i : i + EPSS_BATCH]
        payload = http.get_json(EPSS_URL, {"cve": ",".join(batch), "limit": str(len(batch))})
        date, found = parse_epss_api(payload)
        score_date = score_date or date
        entries.extend(found)
    return score_date, tuple(entries)


# --- NVD -------------------------------------------------------------------------


def parse_nvd(payload: dict[str, Any]) -> tuple[NvdEntry, ...]:
    """NVD API 2.0 response (or a feed file in the same format) -> entries."""
    return tuple(_nvd_entry(item["cve"]) for item in payload.get("vulnerabilities", []))


def _nvd_entry(cve: dict[str, Any]) -> NvdEntry:
    cna = cve.get("sourceIdentifier")
    scores = []
    for key in _NVD_METRICS:
        for m in cve.get("metrics", {}).get(key, []):
            source, data = m["source"], m["cvssData"]
            kind = (
                CvssSourceKind.NVD if source == NVD_SOURCE
                else CvssSourceKind.CNA if source == cna
                else CvssSourceKind.OTHER
            )
            scores.append(SourcedCvss(kind=kind, source=source, version=data["version"],
                                      base=data["baseScore"], vector=data["vectorString"]))
    cwes = sorted({
        d["value"]
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if _CWE.match(d.get("value", ""))  # drops NVD-CWE-Other / NVD-CWE-noinfo
    })
    return NvdEntry(cve=cve["id"], cna=cna, status=cve.get("vulnStatus"),
                    published=cve.get("published"), last_modified=cve.get("lastModified"),
                    cvss=tuple(scores), cwes=tuple(cwes))


def fetch_nvd(
    http: HttpClient, cves: Sequence[str], api_key: str | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[NvdEntry, ...]:
    headers = {"apiKey": api_key} if api_key else None
    delay = NVD_DELAY_WITH_KEY if api_key else NVD_DELAY_NO_KEY
    entries: list[NvdEntry] = []
    for i, cve in enumerate(cves):
        if i:
            sleep(delay)
        entries.extend(parse_nvd(http.get_json(NVD_URL, {"cveId": cve}, headers)))
    return tuple(entries)


# --- OSV -------------------------------------------------------------------------


def parse_osv(purl: str, payload: dict[str, Any]) -> OsvPackage:
    """OSV /v1/query response for one purl -> its advisories."""
    advisories = tuple(_osv_advisory(v) for v in payload.get("vulns", []))
    return OsvPackage(purl=purl, advisories=advisories)


def _osv_advisory(v: dict[str, Any]) -> OsvAdvisory:
    affected = tuple(
        OsvAffected(
            ecosystem=a.get("package", {}).get("ecosystem", ""),
            name=a.get("package", {}).get("name", ""),
            purl=a.get("package", {}).get("purl"),
            ranges=tuple(
                OsvRange(type=r["type"], events=tuple(
                    OsvEvent(kind=kind, version=version)
                    for e in r.get("events", []) for kind, version in e.items()
                ))
                for r in a.get("ranges", [])
            ),
        )
        for a in v.get("affected", [])
    )
    return OsvAdvisory(id=v["id"], aliases=tuple(v.get("aliases", [])),
                       modified=v.get("modified"), affected=affected)


def fetch_osv(http: HttpClient, purls: Sequence[str]) -> tuple[OsvPackage, ...]:
    return tuple(parse_osv(p, http.post_json(OSV_URL, {"package": {"purl": p}})) for p in purls)
