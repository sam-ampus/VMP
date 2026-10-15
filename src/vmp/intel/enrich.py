"""Turn snapshot lookups into Enrichment records, one per distinct CVE."""

from collections.abc import Iterable

from vmp.intel.snapshot import IntelReader
from vmp.schema.enrichment import Enrichment


def enrich(cve: str, reader: IntelReader) -> Enrichment:
    kev, epss, nvd = reader.kev(cve), reader.epss(cve), reader.nvd(cve)
    return Enrichment(
        cve=cve,
        snapshot_id=reader.snapshot_id,
        kev=reader.kev_listed(cve),
        kev_date_added=kev.date_added if kev else None,
        kev_ransomware=kev.ransomware if kev else None,
        epss=epss.epss if epss else None,
        epss_percentile=epss.percentile if epss else None,
        cna=nvd.cna if nvd else None,
        nvd_status=nvd.status if nvd else None,
        cvss=nvd.cvss if nvd else (),
    )


def enrich_all(cves: Iterable[str], reader: IntelReader) -> dict[str, Enrichment]:
    """Dedupe before enrich: each CVE is looked up once, however many findings share it."""
    return {cve: enrich(cve, reader) for cve in sorted(set(cves))}
