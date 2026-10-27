"""The team's real Qualys and Nessus exports, when they are on this machine.

They are client data, git-ignored and never committed, so this module skips itself when the
folder is absent (CI, other laptops). Assertions are about the translation, never the content:
every file is recognised, every record validates, and output is deterministic.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from vmp.connectors import CONNECTORS, ScanContext, ingest, scan_id_for

REAL = Path(__file__).resolve().parents[2] / "sample-data-nessus-qualys"
pytestmark = pytest.mark.skipif(not REAL.is_dir(), reason="real samples not on this machine")

FOLDERS = {"EVA XML": "qualys", "ASV XML": "qualys", "IVA XML": "qualys",
           "Nessus XML": "nessus"}
AT = datetime(2026, 10, 26, tzinfo=UTC)


def files() -> list[tuple[str, Path]]:
    if not REAL.is_dir():
        return []
    return [(tool, p) for sub, tool in FOLDERS.items() if (REAL / sub).is_dir()
            for p in sorted((REAL / sub).iterdir())
            if p.suffix.lower() in CONNECTORS[tool].extensions]


@pytest.mark.parametrize(("tool", "path"), files(), ids=lambda v: getattr(v, "name", v))
def test_every_real_file_translates_and_validates(tool: str, path: Path) -> None:
    raw = path.read_bytes()
    ctx = ScanContext(scan_id=scan_id_for(raw, tool), batch_id="ing_real", received_at=AT)
    report = ingest(CONNECTORS[tool], raw, ctx)
    assert report.errors == ()
    # A file either has findings or says why it has none.
    assert report.findings or report.warnings or report.skipped
    assert CONNECTORS[tool].to_batch(raw, ctx) == CONNECTORS[tool].to_batch(raw, ctx)
