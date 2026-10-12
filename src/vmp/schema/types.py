"""Shared base model and constrained types for the canonical schema."""

from collections import Counter
from collections.abc import Iterable
from decimal import Decimal
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


class Model(BaseModel):
    """Base for every canonical record.

    frozen: records are values. A change is a new record, never an in-place edit.
    extra="forbid": an unknown field is an error, so connector bugs and schema drift
    surface at ingest instead of being silently dropped.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")


NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]

# Lowercase identifier for a tool or score source: "nessus", "trivy", "ghsa", "nvd".
SourceName = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_.-]*$")]

CveId = Annotated[str, StringConstraints(pattern=r"^CVE-\d{4}-\d{4,}$")]
CweId = Annotated[str, StringConstraints(pattern=r"^CWE-\d+$")]

FindingId = Annotated[str, StringConstraints(pattern=r"^fnd_[A-Za-z0-9]+$")]
VulnerabilityId = Annotated[str, StringConstraints(pattern=r"^vln_[A-Za-z0-9_.-]+$")]
ActionId = Annotated[str, StringConstraints(pattern=r"^act_[A-Za-z0-9_-]+$")]

# Decimal, not float: scores must be reproducible bit-for-bit. 0.1 + 0.2 != 0.3 in float.
CvssBase = Annotated[Decimal, Field(ge=0, le=10, max_digits=3, decimal_places=1)]
Probability = Annotated[Decimal, Field(ge=0, le=1)]


def duplicates(items: Iterable[str]) -> list[str]:
    """Values that appear more than once, sorted for stable error messages."""
    return sorted(item for item, n in Counter(items).items() if n > 1)
