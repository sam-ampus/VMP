"""Write JSON Schemas for the canonical models to schema/json/.

The TypeScript UI generates its types from these, so Python stays the single source of truth.
Run: uv run python scripts/export_json_schema.py
"""

import json
from pathlib import Path

from pydantic import BaseModel

from vmp.schema import (
    FindingBatch,
    FPAssessment,
    RemediationAction,
    RiskAssessment,
    Vulnerability,
)
from vmp.schema.finding import Finding

OUT = Path(__file__).resolve().parents[1] / "schema" / "json"

MODELS: dict[str, type[BaseModel]] = {
    "finding": Finding,
    "finding_batch": FindingBatch,
    "vulnerability": Vulnerability,
    "risk_assessment": RiskAssessment,
    "fp_assessment": FPAssessment,
    "remediation_action": RemediationAction,
}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, model in MODELS.items():
        path = OUT / f"{name}.json"
        schema = model.model_json_schema(mode="validation")
        path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {path.relative_to(OUT.parents[1])}")


if __name__ == "__main__":
    main()
