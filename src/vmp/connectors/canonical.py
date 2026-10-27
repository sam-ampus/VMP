"""Canonical-JSON connector: input already in our own FindingBatch format.

Used for the demo seed until native connectors exist, and kept afterwards for any source
that can export in our format. It does no translation, so it is also the reference for
what every other connector must produce.
"""

import json
from typing import Any

from vmp.connectors.base import ConnectorError, ScanContext


class CanonicalConnector:
    name = "canonical"
    extensions: tuple[str, ...] = (".json",)

    def to_batch(self, raw: bytes, ctx: ScanContext) -> dict[str, Any]:
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConnectorError(f"not JSON: {exc}") from exc
        if not isinstance(payload, dict) or "findings" not in payload:
            raise ConnectorError("not a canonical FindingBatch (no 'findings')")
        # The file's own envelope wins: it was produced by a tool that knew the scan.
        return payload
