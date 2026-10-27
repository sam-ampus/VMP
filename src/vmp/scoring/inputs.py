"""What the scoring engine reads, and the names of what it can produce.

ScoringInput is the boundary between evidence-gathering (connectors, enrichment, inventory,
agents) and scoring. Everything upstream fills these typed fields; the engine reads nothing else.
"""

from enum import StrEnum
from typing import Any

from pydantic import field_validator

from vmp.schema.enums import (
    AssetCriticality,
    Confidence,
    Environment,
    EvidenceCompleteness,
    NormalisedSeverity,
)
from vmp.schema.types import CvssBase, Model, Probability


class FactorName(StrEnum):
    CVSS_BASE = "cvss_base"
    SEVERITY_FALLBACK = "severity_fallback"  # no CVSS: posture findings, many endpoint findings
    KNOWN_EXPLOITED = "known_exploited"
    PUBLIC_EXPLOIT = "public_exploit"
    EPSS = "epss"
    INTERNET_FACING = "internet_facing"
    ASSET_CRITICALITY = "asset_criticality"
    ENVIRONMENT = "environment"
    VALIDATION_CONFIDENCE = "validation_confidence"
    EVIDENCE_COMPLETENESS = "evidence_completeness"


class MissingInput(StrEnum):
    """Context the engine expected but did not get. Reported, never guessed."""

    CVSS = "cvss"
    KEV = "kev"
    EPSS = "epss"
    INTERNET_FACING = "internet_facing"
    ASSET_CRITICALITY = "asset_criticality"
    ENVIRONMENT = "environment"


class ScoringInput(Model):
    """None means unknown. Unknown contributes nothing and is listed as a missing input."""

    cvss_base: CvssBase | None = None
    cvss_from_intel: bool = False  # chosen from NVD/CNA (intel) rather than the tool's report
    source_severity: NormalisedSeverity
    has_cve: bool
    kev: bool | None = None
    epss: Probability | None = None
    exploit_available: bool | None = None
    internet_facing: bool | None = None
    asset_criticality: AssetCriticality | None = None
    environment: Environment | None = None
    confidence: Confidence = Confidence.UNVALIDATED
    evidence_completeness: EvidenceCompleteness = EvidenceCompleteness.FULL

    @field_validator("source_severity", mode="before")
    @classmethod
    def _lower_severity(cls, v: Any) -> Any:
        return v.lower() if isinstance(v, str) else v
