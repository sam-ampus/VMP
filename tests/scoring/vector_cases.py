"""Loads the hand-computed scoring vectors for the test modules in this directory."""

import json
from pathlib import Path
from typing import Any

VECTORS = Path(__file__).parent / "vectors" / "w-0.1.json"

_data: dict[str, Any] = json.loads(VECTORS.read_text(encoding="utf-8"))

WEIGHTS_VERSION: str = _data["weights_version"]
CASES: list[dict[str, Any]] = _data["cases"]
IDS: list[str] = [c["id"] for c in CASES]


def merged_input(case: dict[str, Any]) -> dict[str, Any]:
    return _data["defaults"] | case["input"]
