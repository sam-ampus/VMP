"""Finding: one tool's immutable observation.

A Finding never carries assessment, status, or its Vulnerability link. Those live on
the Vulnerability record, so a Finding can stay exactly as the tool reported it.
"""

from typing import Annotated, Any, Literal, Self
from urllib.parse import urlsplit

from pydantic import (
    AwareDatetime,
    ConfigDict,
    Field,
    IPvAnyAddress,
    PositiveInt,
    StringConstraints,
    field_validator,
    model_validator,
)

from vmp.schema import keys
from vmp.schema.enums import (
    Confidence,
    ConfidenceSource,
    CvssVersion,
    EvidenceCompleteness,
    FixStatus,
    HttpMethod,
    NormalisedSeverity,
    ParameterLocation,
    Protocol,
    ScanType,
)
from vmp.schema.types import (
    CveId,
    CvssBase,
    CweId,
    FindingId,
    Model,
    NonEmptyStr,
    Probability,
    SourceName,
)

Port = Annotated[int, Field(ge=0, le=65535)]
Purl = Annotated[str, StringConstraints(pattern=r"^pkg:[a-z0-9.+-]+/.+")]


class Source(Model):
    """Which tool saw it, in which scan, and the detection window as the tool reported it."""

    tool: SourceName
    tool_version: str | None = None
    native_id: NonEmptyStr
    native_family: str | None = None
    scan_id: NonEmptyStr
    scan_type: ScanType
    first_detected: AwareDatetime
    last_detected: AwareDatetime
    times_detected: PositiveInt = 1

    @model_validator(mode="after")
    def _detection_window(self) -> Self:
        if self.first_detected > self.last_detected:
            raise ValueError("first_detected is after last_detected")
        return self


# --- Locus: three shapes, one discriminator --------------------------------------


class HostLocus(Model):
    type: Literal["host"]
    asset_ref: NonEmptyStr
    ip: IPvAnyAddress
    hostname: str | None = None
    port: Port | None = None
    protocol: Protocol | None = None
    service: str | None = None
    os: str | None = None
    cpe: tuple[str, ...] = ()


class PackageLocus(Model):
    type: Literal["package"]
    asset_ref: NonEmptyStr
    package_name: NonEmptyStr
    package_id: str | None = None
    purl: Purl
    installed_version: NonEmptyStr
    fixed_version: tuple[NonEmptyStr, ...] = ()
    fix_status: FixStatus

    @model_validator(mode="after")
    def _fixed_needs_version(self) -> Self:
        if self.fix_status is FixStatus.FIXED and not self.fixed_version:
            raise ValueError("fix_status is 'fixed' but fixed_version is empty")
        return self


class EndpointLocus(Model):
    type: Literal["endpoint"]
    asset_ref: NonEmptyStr
    url: NonEmptyStr
    method: HttpMethod
    parameters: tuple[NonEmptyStr, ...] = ()
    parameter_location: ParameterLocation | None = None
    parameter_raw: str | None = None  # the tool's original wording, kept for traceability

    @field_validator("url")
    @classmethod
    def _absolute_http_url(cls, v: str) -> str:
        parts = urlsplit(v)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError("url must be an absolute http(s) URL")
        return v

    @field_validator("method", mode="before")
    @classmethod
    def _upper_method(cls, v: Any) -> Any:
        return v.upper() if isinstance(v, str) else v


Locus = Annotated[HostLocus | PackageLocus | EndpointLocus, Field(discriminator="type")]


# --- What it is ----------------------------------------------------------------


class Classification(Model):
    title: NonEmptyStr
    cve: tuple[CveId, ...] = ()
    cwe: tuple[CweId, ...] = ()
    owasp: str | None = None
    source_severity: NormalisedSeverity
    source_severity_raw: NonEmptyStr  # e.g. Nessus "2", Qualys "4", Trivy "HIGH"
    inferred_mappings: tuple[Literal["cve", "cwe", "owasp"], ...] = ()

    @field_validator("source_severity", mode="before")
    @classmethod
    def _lower_severity(cls, v: Any) -> Any:
        return v.lower() if isinstance(v, str) else v

    @model_validator(mode="after")
    def _inferred_fields_present(self) -> Self:
        empty = [m for m in self.inferred_mappings if not getattr(self, m)]
        if empty:
            raise ValueError(f"inferred_mappings lists {empty} but those fields are empty")
        return self


class CvssScore(Model):
    source: SourceName
    version: CvssVersion
    base: CvssBase
    vector: str | None = None


class Scores(Model):
    """Scores exactly as the tool reported them.

    No CVSS is selected here: locked decision 1's precedence (NVD, then CNA) needs
    enrichment, which happens after ingest. See vmp.pipeline.cvss.
    """

    cvss: tuple[CvssScore, ...] = ()
    epss: Probability | None = None
    kev: bool | None = None


# --- How sure, and what supports it ---------------------------------------------


class ValidationStatus(Model):
    confidence: Confidence = Confidence.UNVALIDATED
    confidence_source: ConfidenceSource
    # The tool's own word, e.g. Qualys "Confirmed". Kept because the same word can mean
    # different things across tools; the UI explains the mapping (pipeline/confidence_note.py).
    tool_label: NonEmptyStr | None = None
    reproduced: bool = False
    evidence_completeness: EvidenceCompleteness
    evidence_gaps: tuple[NonEmptyStr, ...] = ()

    @model_validator(mode="after")
    def _gaps_match_completeness(self) -> Self:
        full = self.evidence_completeness is EvidenceCompleteness.FULL
        if full and self.evidence_gaps:
            raise ValueError("evidence_completeness is 'full' but evidence_gaps is not empty")
        if not full and not self.evidence_gaps:
            raise ValueError(
                f"evidence_completeness is '{self.evidence_completeness}' "
                "but evidence_gaps does not say what is missing"
            )
        return self


class ExploitSignals(Model):
    exploit_available: bool | None = None
    exploitability_ease: str | None = None
    signal_source: SourceName | None = None


class RemediationSource(Model):
    text: str | None = None
    provided_by: str | None = None


class Evidence(Model):
    """Raw evidence. The one open record: each tool emits different evidence fields."""

    model_config = ConfigDict(frozen=True, extra="allow")

    references: tuple[str, ...] = ()


# --- The Finding and its sightings -------------------------------------------------


class Sighting(Model):
    """A later scan observing the same Finding (same idempotency key, Vulnerability still open).

    Append-only: re-sightings are recorded here instead of updating the Finding, so the
    Finding stays exactly as first reported. 'Last seen' is the latest sighting.
    """

    finding_id: FindingId
    scan_id: NonEmptyStr
    ingest_batch_id: NonEmptyStr
    detected_at: AwareDatetime


class Finding(Model):
    finding_id: FindingId
    idempotency_key: NonEmptyStr
    source: Source
    locus: Locus
    classification: Classification
    scores: Scores = Scores()
    validation: ValidationStatus
    exploit_signals: ExploitSignals = ExploitSignals()
    remediation_source: RemediationSource = RemediationSource()
    evidence: Evidence = Evidence()

    def expected_idempotency_key(self) -> str:
        s, loc = self.source, self.locus
        match loc:
            case HostLocus():
                return keys.host_key(s.tool, s.native_id, str(loc.ip), loc.port, loc.protocol)
            case PackageLocus():
                return keys.package_key(s.tool, self.classification.cve, s.native_id, loc.purl)
            case EndpointLocus():
                return keys.endpoint_key(s.tool, s.scan_id, loc.url, loc.method, loc.parameters,
                                         self.classification.cwe)

    @model_validator(mode="after")
    def _key_matches_fields(self) -> Self:
        expected = self.expected_idempotency_key()
        if self.idempotency_key != expected:
            raise ValueError(
                f"idempotency_key {self.idempotency_key!r} does not match the key "
                f"rebuilt from the finding's fields {expected!r}"
            )
        return self
