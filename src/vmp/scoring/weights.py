"""Versioned scoring weights.

Weights are data, not code: a new policy is a new versioned file, and every RiskAssessment
records the version it was computed with. Changing a weight never silently changes history.
"""

import json
from decimal import Decimal
from enum import StrEnum
from importlib import resources
from typing import Annotated, Self

from pydantic import Field, model_validator

from vmp.schema.enums import (
    AssetCriticality,
    Confidence,
    Environment,
    EvidenceCompleteness,
    NormalisedSeverity,
    ScoreBand,
)
from vmp.schema.types import Model, NonEmptyStr, Probability

DEFAULT_VERSION = "w-0.1"


def _require_all_keys[E: StrEnum](mapping: dict[E, Decimal], enum: type[E], name: str) -> None:
    if missing := sorted(set(enum) - set(mapping)):
        raise ValueError(f"{name} has no weight for {missing}")


class BaseWeights(Model):
    cvss_multiplier: Decimal  # CVSS 0-10 -> 0-60 points with the default of 6
    severity_fallback: dict[NormalisedSeverity, Decimal]

    @model_validator(mode="after")
    def _complete(self) -> Self:
        _require_all_keys(self.severity_fallback, NormalisedSeverity, "severity_fallback")
        return self


class EpssBand(Model):
    min: Probability
    points: Decimal


class ThreatWeights(Model):
    known_exploited: Decimal
    public_exploit: Decimal  # applied only when not already known-exploited
    epss_bands: tuple[EpssBand, ...]  # highest 'min' first; first match wins
    epss_low_below: Probability
    epss_low_points: Decimal

    @model_validator(mode="after")
    def _bands_descending(self) -> Self:
        mins = [b.min for b in self.epss_bands]
        if mins != sorted(mins, reverse=True):
            raise ValueError("epss_bands must be ordered by min, highest first")
        if mins and self.epss_low_below > mins[-1]:
            raise ValueError("epss_low_below overlaps the lowest positive EPSS band")
        return self


class ExposureWeights(Model):
    internet_facing: Decimal
    not_internet_facing: Decimal
    asset_criticality: dict[AssetCriticality, Decimal]
    environment: dict[Environment, Decimal]

    @model_validator(mode="after")
    def _complete(self) -> Self:
        _require_all_keys(self.asset_criticality, AssetCriticality, "asset_criticality")
        _require_all_keys(self.environment, Environment, "environment")
        return self


class ValidationWeights(Model):
    confidence: dict[Confidence, Decimal]
    evidence_completeness: dict[EvidenceCompleteness, Decimal]

    @model_validator(mode="after")
    def _complete(self) -> Self:
        _require_all_keys(self.confidence, Confidence, "confidence")
        _require_all_keys(self.evidence_completeness, EvidenceCompleteness, "evidence_completeness")
        return self


class SeverityThreshold(Model):
    min_score: Annotated[int, Field(ge=0, le=100)]
    severity: NormalisedSeverity
    band: ScoreBand


class Weights(Model):
    version: NonEmptyStr
    base: BaseWeights
    threat: ThreatWeights
    exposure: ExposureWeights
    validation: ValidationWeights
    severity_thresholds: tuple[SeverityThreshold, ...]  # highest min_score first

    @model_validator(mode="after")
    def _thresholds_cover_range(self) -> Self:
        mins = [t.min_score for t in self.severity_thresholds]
        if mins != sorted(mins, reverse=True) or len(set(mins)) != len(mins):
            raise ValueError("severity_thresholds must be strictly descending by min_score")
        if not mins or mins[-1] != 0:
            raise ValueError("severity_thresholds must end at min_score 0")
        return self

    def classify(self, score: int) -> SeverityThreshold:
        return next(t for t in self.severity_thresholds if score >= t.min_score)


def load_weights(version: str = DEFAULT_VERSION) -> Weights:
    text = resources.files("vmp.scoring").joinpath("weights", f"{version}.json").read_text(
        encoding="utf-8"
    )
    weights = Weights.model_validate(json.loads(text))
    if weights.version != version:
        raise ValueError(f"weights file {version}.json declares version {weights.version!r}")
    return weights
