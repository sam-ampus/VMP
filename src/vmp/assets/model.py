"""The engine's own asset record: business context the scanners don't carry."""

import ipaddress
from typing import Annotated, Any

from pydantic import StringConstraints, field_validator

from vmp.schema.enums import AssetCriticality, Environment
from vmp.schema.types import Model, NonEmptyStr

AssetRef = Annotated[str, StringConstraints(pattern=r"^ast_[A-Za-z0-9_.-]+$")]


def normalise_identifier(value: str) -> str:
    """One spelling per identifier, so lookups don't depend on how a scanner wrote it.

    Lowercase and trimmed; a bare IP address in its canonical form (IPv6 compressed).
    Port stripping and URL handling belong to endpoint normalisation, not here.
    """
    v = value.strip().lower()
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return v


class Asset(Model):
    """None means unknown: the engine scores unknown context as neutral and reports it missing.

    An inventory row can be partial. Leaving a field blank is honest; guessing is not.
    """

    asset_ref: AssetRef
    name: NonEmptyStr
    aliases: tuple[NonEmptyStr, ...] = ()  # IPs, hostnames, FQDNs, host:port, image names
    internet_facing: bool | None = None
    criticality: AssetCriticality | None = None
    environment: Environment | None = None
    owner: str | None = None  # context only; owner routing is out of scope

    @field_validator("aliases", mode="before")
    @classmethod
    def _normalise_aliases(cls, v: Any) -> Any:
        if isinstance(v, list | tuple):
            return tuple(sorted({normalise_identifier(a) for a in v if isinstance(a, str)}))
        return v
