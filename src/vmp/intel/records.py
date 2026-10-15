"""Normalised threat-intel records, one model per source.

Parsers turn each source's official format into these; snapshots store only these.
"""

from datetime import date
from decimal import Decimal

from pydantic import field_validator

from vmp.schema.enrichment import SourcedCvss
from vmp.schema.types import CveId, CweId, Model, NonEmptyStr, Probability


class KevEntry(Model):
    cve: CveId
    date_added: date
    due_date: date | None = None
    vendor: str = ""
    product: str = ""
    ransomware: bool | None = None  # CISA: "Known" / "Unknown"


class EpssEntry(Model):
    cve: CveId
    epss: Probability
    percentile: Probability

    @field_validator("epss", "percentile")
    @classmethod
    def _canonical(cls, v: Decimal) -> Decimal:
        """The API sends '0.006200000', the bulk CSV '0.0062'. Same value, so the same
        representation; otherwise identical data would hash to different snapshot ids."""
        return Decimal(format(v.normalize(), "f"))


class NvdEntry(Model):
    cve: CveId
    cna: str | None  # sourceIdentifier: the organisation that issued the CVE
    status: str | None
    published: str | None  # NVD timestamps carry no timezone; kept verbatim
    last_modified: str | None
    cvss: tuple[SourcedCvss, ...] = ()
    cwes: tuple[CweId, ...] = ()


class OsvEvent(Model):
    kind: str  # introduced | fixed | last_affected | limit
    version: str


class OsvRange(Model):
    type: str  # SEMVER | ECOSYSTEM | GIT
    events: tuple[OsvEvent, ...]


class OsvAffected(Model):
    ecosystem: str
    name: str
    purl: str | None = None
    ranges: tuple[OsvRange, ...] = ()


class OsvAdvisory(Model):
    id: NonEmptyStr
    aliases: tuple[str, ...] = ()
    modified: str | None = None
    affected: tuple[OsvAffected, ...] = ()


class OsvPackage(Model):
    """OSV advisories for one package version, as returned by an OSV query for its purl."""

    purl: NonEmptyStr
    advisories: tuple[OsvAdvisory, ...] = ()
