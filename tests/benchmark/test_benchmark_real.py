"""Local only: FP triage on the real client samples, where the answer is provable from the file.

When Nessus's own output says the installed version is below the fixed version, the file
itself proves the finding applies to that version string. The hard rule then says the
triage must never call it not real. Skipped when the git-ignored samples are absent.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from vmp.pipeline.assess_fp import NOT_REAL, assess_fp
from vmp.pipeline.assess_fp.host import version_facts
from vmp.pipeline.run import ingest_folder
from vmp.schema.finding import HostLocus

REAL = Path(__file__).resolve().parents[2] / "data" / "private" / "real" / "scans"
pytestmark = pytest.mark.skipif(not REAL.is_dir(), reason="real samples are local only")


def test_findings_the_file_proves_below_the_fix_are_never_called_not_real() -> None:
    ingested = ingest_folder(REAL, datetime(2026, 10, 28, tzinfo=UTC), None)
    proven = []
    for f in ingested.findings:
        if not isinstance(f.locus, HostLocus):
            continue
        extra = f.evidence.model_extra or {}
        text = extra.get("plugin_output") or ""
        if version_facts([text], f.locus.os, []) == "below_fix":
            proven.append(f)
    assert proven, "expected some real findings with an installed and a fixed version"
    called = [f.finding_id for f in proven if assess_fp(f).band in NOT_REAL]
    assert called == []


def test_every_real_finding_gets_a_band_and_a_reason() -> None:
    ingested = ingest_folder(REAL, datetime(2026, 10, 28, tzinfo=UTC), None)
    for f in ingested.findings:
        a = assess_fp(f)
        assert a.rationale and a.mechanism
