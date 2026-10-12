"""Canonical model: Finding, Vulnerability, RiskAssessment, FPAssessment, RemediationAction."""

from vmp.schema.action import RemediationAction, SharedBasis
from vmp.schema.finding import (
    Classification,
    CvssScore,
    CvssSelected,
    EndpointLocus,
    Evidence,
    ExploitSignals,
    Finding,
    HostLocus,
    Locus,
    PackageLocus,
    RemediationSource,
    Scores,
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
    "CvssSelected",
    "EndpointLocus",
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
    "Source",
    "ValidationStatus",
    "Vulnerability",
    "validate_batch",
]
