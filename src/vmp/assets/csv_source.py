"""CSV asset inventory: the phase-1 stub a customer (or the demo seed) drops in.

Format, one asset per row, header required:

    asset_ref,name,aliases,internet_facing,criticality,environment,owner

- aliases: separated by ';' (IPs, hostnames, FQDNs, host:port, image names)
- internet_facing: true / false; blank = unknown
- criticality: low / medium / high / critical; blank = unknown
- environment: production / non_production; blank = unknown

Pure parse (text in, assets out) plus a thin file loader, the same split as the intel
parsers. Every bad row is reported, with its line number, not just the first.
"""

import csv
import io
from pathlib import Path

from pydantic import ValidationError

from vmp.assets.inventory import AssetInventory, AssetInventoryError
from vmp.assets.model import Asset

COLUMNS = ("asset_ref", "name", "aliases", "internet_facing", "criticality", "environment",
           "owner")
_BOOLS = {"true": True, "false": False}


def parse_asset_csv(text: str) -> tuple[Asset, ...]:
    reader = csv.DictReader(io.StringIO(text.lstrip("﻿")))  # tolerate an Excel BOM
    header = tuple(h.strip() for h in reader.fieldnames or ())
    if set(header) != set(COLUMNS):
        missing = sorted(set(COLUMNS) - set(header))
        unknown = sorted(set(header) - set(COLUMNS))
        raise AssetInventoryError([f"header: missing {missing}, unknown {unknown}"])

    assets: list[Asset] = []
    errors: list[str] = []
    for line, raw in enumerate(reader, start=2):  # line 1 is the header
        row = {k.strip(): (v or "").strip() for k, v in raw.items() if k is not None}
        if None in raw:
            errors.append(f"line {line}: more values than columns")
            continue
        if not any(row.values()):
            continue  # blank line
        facing = row["internet_facing"].lower()
        if facing and facing not in _BOOLS:
            errors.append(f"line {line}: internet_facing must be true, false or blank")
            continue
        try:
            assets.append(Asset.model_validate({
                "asset_ref": row["asset_ref"],
                "name": row["name"],
                "aliases": [a for a in row["aliases"].split(";") if a.strip()],
                "internet_facing": _BOOLS.get(facing),
                "criticality": row["criticality"].lower() or None,
                "environment": row["environment"].lower() or None,
                "owner": row["owner"] or None,
            }))
        except ValidationError as e:
            errors += [f"line {line}: {'.'.join(map(str, err['loc']))}: {err['msg']}"
                       for err in e.errors()]
    if errors:
        raise AssetInventoryError(errors)
    return tuple(assets)


def load_asset_csv(path: Path) -> AssetInventory:
    return AssetInventory(parse_asset_csv(path.read_text(encoding="utf-8")))
