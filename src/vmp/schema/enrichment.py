"""Enrichment: what threat intel says about a CVE, as of one intel snapshot.

Kept apart from Findings on purpose. Findings are per tool and per asset; intel is per CVE.
One lookup serves every finding that shares the CVE (dedupe before enrich), and the
snapshot id makes every enriched score reproducible.
"""

from datetime import date
from decimal import Decimal

from vmp.schema.enums import CvssSelectionRule, CvssSourceKind, CvssVersion
from vmp.schema.types import CveId, CvssBase, Model, NonEmptyStr, Probability


class SourcedCvss(Model):
    kind: CvssSourceKind
    source: NonEmptyStr  # NVD's source identifier, e.g. "nvd@nist.gov"
    version: CvssVersion
    base: CvssBase
    vector: str


class CvssSelection(Model):
    """The chosen CVSS and the rule that chose it (locked decision 1). Without the rule,
    the score is not reproducible."""

    source: NonEmptyStr
    version: CvssVersion
    base: CvssBase
    rule: CvssSelectionRule
    spread: Decimal | None = None  # max - min base across sources on the chosen version
    contested: bool = False  # spread >= the contested threshold (default 2.0)


class Enrichment(Model):
    """None means the snapshot cannot say (source not included, or CVE out of scope)."""

    cve: CveId
    snapshot_id: NonEmptyStr
    kev: bool | None = None
    kev_date_added: date | None = None
    kev_ransomware: bool | None = None
    epss: Probability | None = None
    epss_percentile: Probability | None = None
    cna: str | None = None  # the organisation that issued the CVE
    nvd_status: str | None = None
    cvss: tuple[SourcedCvss, ...] = ()
