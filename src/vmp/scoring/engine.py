"""The deterministic scoring engine.

score = clamp(0..100, round_half_up(sum of factor contributions))

Pure functions only: no clock, no I/O, no randomness, no model. The same ScoringInput and
Weights always produce the same result, and every point in the score is a named Factor.
"""

from collections.abc import Sequence
from decimal import ROUND_HALF_UP, Decimal

from pydantic import AwareDatetime

from vmp import __version__
from vmp.schema.enums import FactorDirection, FactorSource, NormalisedSeverity, ScoreBand
from vmp.schema.types import Model
from vmp.schema.vulnerability import Factor, RiskAssessment
from vmp.scoring.inputs import FactorName, MissingInput, ScoringInput
from vmp.scoring.weights import Weights

ENGINE_VERSION = __version__


class ScoreResult(Model):
    score: int
    severity: NormalisedSeverity
    band: ScoreBand
    factors: tuple[Factor, ...]
    raw_total: Decimal  # before rounding and clamping, for audit
    missing_inputs: tuple[MissingInput, ...]
    severity_delta_reason: str | None
    weights_version: str


def score(inp: ScoringInput, weights: Weights) -> ScoreResult:
    factors = [_base(inp, weights)]
    factors += [f for f in _modifiers(inp, weights) if f is not None]

    raw = sum((f.contribution for f in factors), Decimal(0))
    value = max(0, min(100, int(raw.quantize(Decimal(1), rounding=ROUND_HALF_UP))))
    tier = weights.classify(value)

    return ScoreResult(
        score=value,
        severity=tier.severity,
        band=tier.band,
        factors=tuple(factors),
        raw_total=raw,
        missing_inputs=_missing(inp),
        severity_delta_reason=_delta_reason(inp.source_severity, tier.severity, factors),
        weights_version=weights.version,
    )


def assess(
    vulnerability_id: str,
    findings: Sequence[tuple[str, ScoringInput]],
    weights: Weights,
    *,
    assessed_at: AwareDatetime,
    intel_snapshot_id: str | None = None,
    asset_inventory_id: str | None = None,
) -> RiskAssessment:
    """Score each finding; the vulnerability's assessment is its peak finding's score.

    Ties go to the lowest finding_id, so the result never depends on input order.
    The caller supplies assessed_at: the engine never reads the clock.
    """
    if not findings:
        raise ValueError("a vulnerability needs at least one finding to assess")
    scored = [(fid, inp, score(inp, weights)) for fid, inp in findings]
    peak_id, peak_inp, peak = min(scored, key=lambda s: (-s[2].score, s[0]))
    return RiskAssessment(
        vulnerability_id=vulnerability_id,
        peak_finding_id=peak_id,
        score=peak.score,
        band=peak.band,
        computed_severity=peak.severity,
        source_severity=peak_inp.source_severity,
        severity_delta_reason=peak.severity_delta_reason,
        factors=peak.factors,
        missing_inputs=tuple(str(m) for m in peak.missing_inputs),
        weights_version=weights.version,
        intel_snapshot_id=intel_snapshot_id,
        asset_inventory_id=asset_inventory_id,
        engine_version=ENGINE_VERSION,
        assessed_at=assessed_at,
    )


# --- Factors ---------------------------------------------------------------------


def _factor(
    name: FactorName, points: Decimal, observed: object, source: FactorSource,
    weight: Decimal | None = None,
) -> Factor:
    return Factor(
        name=name,
        direction=FactorDirection.DOWN if points < 0 else FactorDirection.UP,
        observed=str(observed),
        weight=points if weight is None else weight,
        contribution=points,
        source=source,
    )


def _nonzero(
    name: FactorName, points: Decimal, observed: object, source: FactorSource
) -> Factor | None:
    """Only factors that move the score are listed; zero-point values are known, not shown."""
    return _factor(name, points, observed, source) if points != 0 else None


def _base(inp: ScoringInput, w: Weights) -> Factor:
    """The anchor factor, always present so every score has at least one explanation."""
    if inp.cvss_base is not None:
        m = w.base.cvss_multiplier
        source = FactorSource.INTEL if inp.cvss_from_intel else FactorSource.TOOL
        return _factor(FactorName.CVSS_BASE, inp.cvss_base * m, inp.cvss_base, source, weight=m)
    points = w.base.severity_fallback[inp.source_severity]
    return _factor(FactorName.SEVERITY_FALLBACK, points, inp.source_severity, FactorSource.TOOL)


def _modifiers(inp: ScoringInput, w: Weights) -> list[Factor | None]:
    t, e, v = w.threat, w.exposure, w.validation
    out: list[Factor | None] = []

    if inp.kev:
        out.append(_nonzero(FactorName.KNOWN_EXPLOITED, t.known_exploited, "kev",
                            FactorSource.INTEL))
    elif inp.exploit_available:  # KEV already implies an exploit: never double-count
        out.append(_nonzero(FactorName.PUBLIC_EXPLOIT, t.public_exploit, "exploit_available",
                            FactorSource.TOOL))

    if inp.epss is not None:
        out.append(_nonzero(FactorName.EPSS, _epss_points(inp.epss, w), inp.epss,
                            FactorSource.INTEL))

    if inp.internet_facing is not None:
        points = e.internet_facing if inp.internet_facing else e.not_internet_facing
        observed = "internet_facing" if inp.internet_facing else "internal"
        out.append(_nonzero(FactorName.INTERNET_FACING, points, observed, FactorSource.INVENTORY))
    if inp.asset_criticality is not None:
        out.append(_nonzero(FactorName.ASSET_CRITICALITY,
                            e.asset_criticality[inp.asset_criticality],
                            inp.asset_criticality, FactorSource.INVENTORY))
    if inp.environment is not None:
        out.append(_nonzero(FactorName.ENVIRONMENT, e.environment[inp.environment],
                            inp.environment, FactorSource.INVENTORY))

    out.append(_nonzero(FactorName.VALIDATION_CONFIDENCE, v.confidence[inp.confidence],
                        inp.confidence, FactorSource.TOOL))
    out.append(_nonzero(FactorName.EVIDENCE_COMPLETENESS,
                        v.evidence_completeness[inp.evidence_completeness],
                        inp.evidence_completeness, FactorSource.TOOL))
    return out


def _epss_points(epss: Decimal, w: Weights) -> Decimal:
    for band in w.threat.epss_bands:
        if epss >= band.min:
            return band.points
    return w.threat.epss_low_points if epss < w.threat.epss_low_below else Decimal(0)


def _missing(inp: ScoringInput) -> tuple[MissingInput, ...]:
    """Expected-but-absent context. KEV/EPSS/CVSS are only expected when there is a CVE."""
    checks = {
        MissingInput.CVSS: inp.has_cve and inp.cvss_base is None,
        MissingInput.KEV: inp.has_cve and inp.kev is None,
        MissingInput.EPSS: inp.has_cve and inp.epss is None,
        MissingInput.INTERNET_FACING: inp.internet_facing is None,
        MissingInput.ASSET_CRITICALITY: inp.asset_criticality is None,
        MissingInput.ENVIRONMENT: inp.environment is None,
    }
    return tuple(sorted(m for m, is_missing in checks.items() if is_missing))


def _delta_reason(
    source: NormalisedSeverity, computed: NormalisedSeverity, factors: list[Factor]
) -> str | None:
    """A deterministic, factor-based reason. Agents may rephrase it; they never change it."""
    if source == computed:
        return None
    base, *modifiers = factors
    if modifiers:
        top = sorted(modifiers, key=lambda f: (-abs(f.contribution), f.name))[:3]
        drivers = ", ".join(f"{f.name.replace('_', ' ')} ({f.contribution:+})" for f in top)
    else:
        drivers = f"{base.name.replace('_', ' ')} alone ({base.contribution:+})"
    return f"Computed {computed} vs source {source}: {drivers}."
