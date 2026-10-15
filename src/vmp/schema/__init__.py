"""Canonical model: Finding, Vulnerability, RiskAssessment, FPAssessment, RemediationAction."""

from vmp.schema.action import RemediationAction, SharedBasis
from vmp.schema.enrichment import CvssSelection, Enrichment, SourcedCvss
from vmp.schema.finding import (
    Classification,
    CvssScore,
    EndpointLocus,
    Evidence,
    ExploitSignals,
    Finding,
    HostLocus,
    Locus,
    PackageLocus,
    RemediationSource,
    Scores,
    Sighting,
    Source,
    ValidationStatus,
)
from vmp.schema.validation import (
    BatchReport,
    FindingBatch,
    IngestBatch,
    RecordError,
    validate_batch,
)
from vmp.schema.vulnerability import (
    Closure,
    Factor,
    FPAssessment,
    HistoryEvent,
    RiskAssessment,
    Vulnerability,
)

__all__ = [
    "BatchReport",
    "Classification",
    "Closure",
    "CvssScore",
    "CvssSelection",
    "EndpointLocus",
    "Enrichment",
    "Evidence",
    "ExploitSignals",
    "FPAssessment",
    "Factor",
    "Finding",
    "FindingBatch",
    "HistoryEvent",
    "HostLocus",
    "IngestBatch",
    "Locus",
    "PackageLocus",
    "RecordError",
    "RemediationAction",
    "RemediationSource",
    "RiskAssessment",
    "Scores",
    "SharedBasis",
    "Sighting",
    "Source",
    "SourcedCvss",
    "ValidationStatus",
    "Vulnerability",
    "validate_batch",
]
