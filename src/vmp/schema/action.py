"""RemediationAction: findings that share a root cause and a single fix."""

from typing import Annotated, Self

from pydantic import Field, model_validator

from vmp.schema.enums import FixType, SharedBasisKind
from vmp.schema.types import ActionId, FindingId, Model, NonEmptyStr, duplicates


class SharedBasis(Model):
    """A checkable claim about what the findings share, e.g. kind=host, value=qa3app09."""

    kind: SharedBasisKind
    value: NonEmptyStr


class RemediationAction(Model):
    action_id: ActionId
    title: NonEmptyStr
    fix_types: Annotated[tuple[FixType, ...], Field(min_length=1)]
    finding_ids: Annotated[tuple[FindingId, ...], Field(min_length=1)]
    shared_basis: Annotated[tuple[SharedBasis, ...], Field(min_length=1)]
    risk_retired: Annotated[int, Field(ge=0, le=100)]  # computed by code: peak of the cluster
    rationale: NonEmptyStr  # "why these are one action"
    steps: Annotated[tuple[NonEmptyStr, ...], Field(min_length=1)]
    depends_on: tuple[ActionId, ...] = ()

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if dupes := duplicates(self.finding_ids):
            raise ValueError(f"finding_ids contains duplicates: {dupes}")
        if self.action_id in self.depends_on:
            raise ValueError("an action cannot depend on itself")
        return self
