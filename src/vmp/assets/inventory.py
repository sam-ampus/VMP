"""AssetProvider: how the pipeline asks "what is this asset?". AssetInventory: the in-memory one.

The provider is a Protocol so a customer CMDB, ServiceNow, or a cloud inventory can replace
the CSV later without touching the pipeline. Where the rows came from is the parser's
business (see csv_source.py); the inventory only answers lookups.
"""

import hashlib
import json
from collections.abc import Iterable
from typing import Protocol

from vmp.assets.model import Asset, normalise_identifier
from vmp.schema.types import duplicates


class AssetInventoryError(ValueError):
    """Every problem found in an inventory, reported together."""

    def __init__(self, errors: Iterable[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("asset inventory is invalid:\n  " + "\n  ".join(self.errors))


class AssetProvider(Protocol):
    @property
    def inventory_id(self) -> str:
        """Content hash of the inventory, recorded so a score's asset context is replayable."""
        ...

    def resolve(self, identifier: str) -> Asset | None:
        """Look up by asset_ref or any alias. None means the asset is unknown, not 'safe'."""
        ...


class AssetInventory:
    """Read-only lookups over a validated set of assets.

    Ambiguity is an error at load, not a guess at lookup: an identifier that could mean two
    assets would silently give one finding the other asset's exposure and criticality.
    """

    def __init__(self, assets: Iterable[Asset]) -> None:
        self._assets = tuple(sorted(assets, key=lambda a: a.asset_ref))
        errors = [f"duplicate asset_ref {r}" for r in duplicates(a.asset_ref for a in self._assets)]

        index: dict[str, str] = {}
        for asset in self._assets:
            for key in {normalise_identifier(asset.asset_ref), *asset.aliases}:
                owner = index.setdefault(key, asset.asset_ref)
                if owner != asset.asset_ref:
                    errors.append(f"identifier {key!r} maps to both {owner} and {asset.asset_ref}")
        if errors:
            raise AssetInventoryError(sorted(set(errors)))

        self._by_ref = {a.asset_ref: a for a in self._assets}
        self._index = index
        # Sorted assets + sorted keys: the same inventory always gets the same id,
        # whatever order its rows arrived in.
        payload = json.dumps([a.model_dump(mode="json") for a in self._assets], sort_keys=True)
        self._inventory_id = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @property
    def inventory_id(self) -> str:
        return self._inventory_id

    @property
    def assets(self) -> tuple[Asset, ...]:
        return self._assets

    def resolve(self, identifier: str) -> Asset | None:
        ref = self._index.get(normalise_identifier(identifier))
        return None if ref is None else self._by_ref[ref]

    def __len__(self) -> int:
        return len(self._assets)
