"""The engine's own asset inventory: exposure, criticality and environment for scoring.

Scanners say *what* is wrong; the inventory says *how much it matters here*.
"""

from vmp.assets.csv_source import load_asset_csv, parse_asset_csv
from vmp.assets.inventory import AssetInventory, AssetInventoryError, AssetProvider
from vmp.assets.model import Asset, normalise_identifier

__all__ = [
    "Asset",
    "AssetInventory",
    "AssetInventoryError",
    "AssetProvider",
    "load_asset_csv",
    "normalise_identifier",
    "parse_asset_csv",
]
