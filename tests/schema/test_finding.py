"""Finding parsing: the three shapes, immutability, and every cross-field rule."""

import re
from collections.abc import Callable
from decimal import Decimal
from typing import Any

import pytest
from pydantic import ValidationError

from vmp.schema import EndpointLocus, Finding, HostLocus, PackageLocus
from vmp.schema.enums import CvssSelectionRule, NormalisedSeverity


def test_three_shapes_route_to_their_locus_type(
    host: dict[str, Any], package: dict[str, Any], endpoint: dict[str, Any]
) -> None:
    assert isinstance(Finding.model_validate(host).locus, HostLocus)
    assert isinstance(Finding.model_validate(package).locus, PackageLocus)
    assert isinstance(Finding.model_validate(endpoint).locus, EndpointLocus)


def test_findings_are_immutable(host: dict[str, Any]) -> None:
    f = Finding.model_validate(host)
    with pytest.raises(ValidationError):
        f.finding_id = "fnd_other"  # type: ignore[misc]
    # Collections are tuples, so nested values can't be edited in place either.
    assert isinstance(f.classification.cve, tuple)


def test_values_are_normalised_but_raw_is_kept(package: dict[str, Any]) -> None:
    f = Finding.model_validate(package)
    assert f.classification.source_severity is NormalisedSeverity.HIGH
    assert f.classification.source_severity_raw == "HIGH"


def test_cvss_is_decimal_and_selection_records_its_rule(package: dict[str, Any]) -> None:
    scores = Finding.model_validate(package).scores
    assert scores.cvss_selected is not None
    assert scores.cvss_selected.base == Decimal("6.5")
    assert scores.cvss_selected.rule is CvssSelectionRule.CNA
    assert scores.cvss_spread() == Decimal("0.7")  # below the 2.0 'contested' threshold


def test_spread_ignores_other_cvss_versions(host: dict[str, Any]) -> None:
    host["scores"]["cvss"].append({"source": "nvd", "version": "3.1", "base": 9.0})
    assert Finding.model_validate(host).scores.cvss_spread() is None


def test_endpoint_method_is_uppercased(endpoint: dict[str, Any]) -> None:
    endpoint["locus"]["method"] = "post"
    assert Finding.model_validate(endpoint).locus.method == "POST"  # type: ignore[union-attr]


def test_tool_specific_evidence_fields_are_kept(endpoint: dict[str, Any]) -> None:
    evidence = Finding.model_validate(endpoint).evidence
    assert evidence.model_extra is not None
    assert "payload" in evidence.model_extra


# --- Each rule gets one failing case -----------------------------------------------

Mutation = Callable[[dict[str, Any]], None]


def _walk(d: Any, path: str) -> tuple[Any, str | int]:
    """Follow a dotted path ('scores.cvss.0.base'); return the parent and the last key."""
    *parents, leaf = [int(p) if p.isdigit() else p for p in path.split(".")]
    for p in parents:
        d = d[p]
    return d, leaf


def _set(path: str, value: Any) -> Mutation:
    def apply(d: dict[str, Any]) -> None:
        parent, leaf = _walk(d, path)
        parent[leaf] = value

    return apply


def _drop(path: str) -> Mutation:
    def apply(d: dict[str, Any]) -> None:
        parent, leaf = _walk(d, path)
        del parent[leaf]

    return apply


RULES: list[tuple[str, str, Mutation, str]] = [
    ("detection window", "host",
     _set("source.first_detected", "2014-01-01T00:00:00Z"), "first_detected is after"),
    ("times_detected >= 1", "host", _set("source.times_detected", 0), "greater than 0"),
    ("timezone required", "host",
     _set("source.last_detected", "2013-07-01T11:40:48"), "timezone"),
    ("fixed needs fixed_version", "package",
     _set("locus.fixed_version", []), "fixed_version is empty"),
    ("selected must be stored", "package",
     _set("scores.cvss_selected.base", 7.0), "does not match any entry"),
    ("partial evidence names its gaps", "endpoint",
     _set("validation.evidence_gaps", []), "does not say what is missing"),
    ("full evidence has no gaps", "host",
     _set("validation.evidence_gaps", ["x"]), "is not empty"),
    ("CVE format", "host", _set("classification.cve", ["CVE-05-1"]), "pattern"),
    ("CWE format", "package", _set("classification.cwe", ["693"]), "pattern"),
    ("inferred field must exist", "endpoint",
     _set("classification.owasp", None), "inferred_mappings"),
    ("key rebuilt from fields", "host",
     _set("idempotency_key", "nessus:18405:10.31.112.29:3389:udp"), "does not match the key"),
    ("unknown locus type", "host", _set("locus.type", "container"), "tag"),
    ("endpoint url is absolute http(s)", "endpoint",
     _set("locus.url", "/auth/login/"), "absolute http(s) URL"),
    ("unknown fields rejected", "host", _set("vulnerability_id", "vln_x"), "Extra inputs"),
    ("validation is required", "package", _drop("validation"), "Field required"),
    ("cvss base range", "package", _set("scores.cvss.0.base", 11), "less than or equal"),
]


@pytest.mark.parametrize(("shape", "mutate", "expected"),
                         [r[1:] for r in RULES], ids=[r[0] for r in RULES])
def test_rule_rejects_bad_finding(
    request: pytest.FixtureRequest, shape: str, mutate: Mutation, expected: str
) -> None:
    raw: dict[str, Any] = request.getfixturevalue(shape)
    Finding.model_validate(raw)  # the unmutated fixture is valid, so the mutation is the cause
    mutate(raw)
    with pytest.raises(ValidationError, match=re.escape(expected)):
        Finding.model_validate(raw)
