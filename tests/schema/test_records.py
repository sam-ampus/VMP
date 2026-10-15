"""Vulnerability, RiskAssessment, FPAssessment and RemediationAction invariants."""

import re
from typing import Any

import pytest
from pydantic import ValidationError

from vmp.schema import FPAssessment, RemediationAction, RiskAssessment, Vulnerability

NOW = "2026-10-09T12:00:00Z"


def vuln(**over: Any) -> dict[str, Any]:
    return {"vulnerability_id": "vln_cve-2005-1794", "finding_ids": ["fnd_7c2a91"],
            "status": "open"} | over


def assessment(**over: Any) -> dict[str, Any]:
    factor = {"name": "exploit_available", "direction": "up", "observed": "true",
              "weight": "8", "contribution": "8", "source": "tool"}
    return {"vulnerability_id": "vln_cve-2005-1794", "peak_finding_id": "fnd_7c2a91",
            "score": 48, "band": "moderate",
            "computed_severity": "medium", "source_severity": "medium", "factors": [factor],
            "weights_version": "w-0.1", "engine_version": "0.1.0", "assessed_at": NOW} | over


def fp(**over: Any) -> dict[str, Any]:
    return {"finding_id": "fnd_a41f03", "locus_type": "package",
            "mechanism": "deterministic_version", "band": "confirmed_applicable",
            "rationale": "installed 1.14.5 < fixed 1.14.8"} | over


def action(**over: Any) -> dict[str, Any]:
    return {"action_id": "act_a3", "title": "Upgrade the k-client image dependencies",
            "fix_types": ["version_bump", "rebuild"], "finding_ids": ["fnd_a41f03"],
            "shared_basis": [{"kind": "image", "value": "ast_k-client-image"}],
            "risk_retired": 61, "rationale": "Same image; one rebuild retires both.",
            "steps": ["Bump cilium to 1.14.8.", "Rebuild and rescan."]} | over


def test_valid_records_parse() -> None:
    Vulnerability.model_validate(vuln())
    RiskAssessment.model_validate(assessment())
    FPAssessment.model_validate(fp())
    RemediationAction.model_validate(action())


CASES: list[tuple[str, type[Any], dict[str, Any], str]] = [
    ("closed needs closure", Vulnerability, vuln(status="closed"), "if and only if"),
    ("open has no closure", Vulnerability,
     vuln(closure={"reason": "fixed", "closed_at": NOW}), "if and only if"),
    ("risk acceptance expires", Vulnerability,
     vuln(status="closed", closure={"reason": "risk_accepted", "closed_at": NOW}),
     "requires accepted_until"),
    ("no self recurrence", Vulnerability, vuln(recurrence_of="vln_cve-2005-1794"), "itself"),
    ("no duplicate findings", Vulnerability,
     vuln(finding_ids=["fnd_a", "fnd_a"]), "duplicates"),
    ("score needs factors", RiskAssessment, assessment(factors=[]), "at least 1"),
    ("score range", RiskAssessment, assessment(score=101), "less than or equal"),
    ("severity delta explained", RiskAssessment,
     assessment(source_severity="critical"), "severity_delta_reason is required"),
    ("FP mechanism fits shape", FPAssessment,
     fp(mechanism="version_range"), "use the 'deterministic_version' mechanism"),
    ("endpoint has no version math", FPAssessment,
     fp(finding_id="fnd_e90bb7", locus_type="endpoint",
        mechanism="confidence_reachability"), "cannot be 'confirmed_"),
    ("FP needs a rationale", FPAssessment, fp(rationale="  "), "at least 1 character"),
    ("action not self-dependent", RemediationAction, action(depends_on=["act_a3"]), "itself"),
    ("action has a shared basis", RemediationAction, action(shared_basis=[]), "at least 1"),
    ("action has steps", RemediationAction, action(steps=[]), "at least 1"),
]


@pytest.mark.parametrize(("model", "raw", "expected"),
                         [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_invariant(model: type[Any], raw: dict[str, Any], expected: str) -> None:
    with pytest.raises(ValidationError, match=re.escape(expected)):
        model.model_validate(raw)
