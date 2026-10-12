import copy
import json
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tests" / "fixtures" / "sample-findings.json"
REFERENCE = REPO / "skill" / "vmp-findings-engine" / "references" / "sample-findings.json"


def load(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    data.pop("_corrections", None)
    return data


@pytest.fixture
def batch() -> dict[str, Any]:
    """A fresh deep copy of the corrected fixture, safe to mutate in a test."""
    return load(FIXTURE)


@pytest.fixture
def reference_batch() -> dict[str, Any]:
    """The original sample from the skill's references, as shipped."""
    return load(REFERENCE)


@pytest.fixture
def host(batch: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(batch["findings"][0])


@pytest.fixture
def package(batch: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(batch["findings"][1])


@pytest.fixture
def endpoint(batch: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(batch["findings"][2])
