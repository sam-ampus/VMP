"""Batch validation: check every record and report every error, not just the first."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import AwareDatetime, Field, NonNegativeInt, ValidationError

from vmp.schema.finding import Finding
from vmp.schema.types import Model, NonEmptyStr, duplicates

SCHEMA_VERSION = "0.1"


class IngestBatch(Model):
    batch_id: NonEmptyStr
    source_tool: NonEmptyStr
    received_at: AwareDatetime


class FindingBatch(Model):
    """The ingest envelope. Findings are parsed one by one so one bad record can't hide others."""

    schema_version: Literal["0.1"]
    ingest_batch: IngestBatch
    findings: tuple[dict[str, Any], ...]
    # What the connector deliberately left out, by reason (e.g. information-only items), and
    # scan-level conditions worth telling the analyst (e.g. "no host alive"). Neither is an
    # error: dropping noise and reporting empty scans are both correct translations.
    skipped: dict[NonEmptyStr, NonNegativeInt] = Field(default_factory=dict)
    warnings: tuple[NonEmptyStr, ...] = ()


@dataclass(frozen=True)
class RecordError:
    index: int | None  # None for envelope- or batch-level errors
    finding_id: str | None
    messages: tuple[str, ...]


@dataclass(frozen=True)
class BatchReport:
    batch: IngestBatch | None
    findings: tuple[Finding, ...]
    errors: tuple[RecordError, ...]
    skipped: Mapping[str, int] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.errors


def _messages(exc: ValidationError) -> tuple[str, ...]:
    out = []
    for e in exc.errors(include_url=False):
        loc = ".".join(str(p) for p in e["loc"])
        out.append(f"{loc}: {e['msg']}" if loc else e["msg"])
    return tuple(out)


def validate_batch(payload: Mapping[str, Any]) -> BatchReport:
    try:
        envelope = FindingBatch.model_validate(payload)
    except ValidationError as exc:
        return BatchReport(None, (), (RecordError(None, None, _messages(exc)),))

    valid: list[Finding] = []
    errors: list[RecordError] = []
    for i, raw in enumerate(envelope.findings):
        try:
            valid.append(Finding.model_validate(raw))
        except ValidationError as exc:
            fid = raw.get("finding_id")
            errors.append(RecordError(i, fid if isinstance(fid, str) else None, _messages(exc)))

    if dupes := duplicates(f.finding_id for f in valid):
        errors.append(RecordError(None, None, (f"duplicate finding_id in batch: {dupes}",)))

    return BatchReport(envelope.ingest_batch, tuple(valid), tuple(errors),
                       dict(envelope.skipped), envelope.warnings)
