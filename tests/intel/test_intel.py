"""Intel: parsers, offline bundles, live fetching (faked), snapshots, enrichment."""

import csv
import json
import shutil
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from vmp.intel import (
    IntelReader,
    SnapshotData,
    SnapshotIntegrityError,
    build_live_snapshot,
    enrich_all,
    import_bundle,
    write_snapshot,
)
from vmp.intel import sources as src
from vmp.intel.records import EpssEntry
from vmp.schema.enums import CvssSourceKind

BUNDLE = Path(__file__).parent / "bundle"
CVES = ["CVE-2024-28248", "CVE-2021-44228", "CVE-2099-0001"]  # last: unknown to every source
CILIUM = "pkg:golang/github.com/cilium/cilium@1.14.5"
UNANSWERED = "pkg:npm/left-pad@1.0.0"  # in scope, but the bundle has no answer for it
AT = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)


def load(path: str) -> Any:
    return json.loads((BUNDLE / path).read_text(encoding="utf-8"))


# --- Parsers -------------------------------------------------------------------------


def test_kev_keeps_version_and_treats_unknown_ransomware_as_unknown() -> None:
    version, entries = src.parse_kev(load("kev.json"))
    by_cve = {e.cve: e for e in entries}
    assert version == "2026.10.08"
    assert by_cve["CVE-2021-44228"].ransomware is True
    assert by_cve["CVE-2023-0001"].ransomware is None


def test_epss_csv_reads_model_header_and_keeps_only_scope() -> None:
    text = (BUNDLE / "epss.csv").read_text(encoding="utf-8")
    model, as_of, entries = src.parse_epss_csv(text, CVES)
    assert (model, as_of) == ("v2025.03.14", "2026-10-12T12:55:00Z")
    assert {e.cve for e in entries} == {"CVE-2024-28248", "CVE-2021-44228"}


def test_nvd_classifies_who_scored_it() -> None:
    (log4j,) = src.parse_nvd(load("nvd/CVE-2021-44228.json"))
    assert log4j.cna == "security@apache.org"
    assert [(c.kind, c.version, c.base) for c in log4j.cvss] == [
        (CvssSourceKind.NVD, "3.1", Decimal("10.0")),
        (CvssSourceKind.OTHER, "3.1", Decimal("10.0")),  # CISA ADP
        (CvssSourceKind.NVD, "2.0", Decimal("9.3")),
    ]
    (cilium,) = src.parse_nvd(load("nvd/CVE-2024-28248.json"))
    assert {c.kind for c in cilium.cvss} == {CvssSourceKind.NVD, CvssSourceKind.CNA}
    assert cilium.cwes == ("CWE-693",)  # NVD-CWE-Other dropped


def test_osv_keeps_fix_events() -> None:
    pkg = src.parse_osv(CILIUM, load("osv.json")[CILIUM])
    fixed = [e.version for r in pkg.advisories[0].affected[0].ranges
             for e in r.events if e.kind == "fixed"]
    assert fixed == ["1.13.13", "1.14.8", "1.15.2"]


def test_epss_precision_is_canonical() -> None:
    assert EpssEntry(cve="CVE-2024-28248", epss=Decimal("0.006200000"),
                     percentile=Decimal("0.69")).epss == Decimal("0.0062")


# --- Bundle -> snapshot -> enrichment ----------------------------------------------------


@pytest.fixture
def reader(tmp_path: Path) -> IntelReader:
    m = import_bundle(BUNDLE, tmp_path, cves=CVES, purls=[CILIUM, UNANSWERED], imported_at=AT)
    return IntelReader.load(tmp_path, m.snapshot_id)


def test_enrichment_from_bundle(reader: IntelReader) -> None:
    e = enrich_all(CVES, reader)
    assert e["CVE-2021-44228"].kev is True
    assert e["CVE-2024-28248"].kev is False  # full catalogue: absence means not listed
    assert e["CVE-2024-28248"].epss == Decimal("0.0062")
    assert e["CVE-2024-28248"].cna == "security-advisories@github.com"
    assert e["CVE-2099-0001"].epss is None and e["CVE-2099-0001"].cvss == ()
    assert all(x.snapshot_id == reader.snapshot_id for x in e.values())


def test_osv_scope_distinguishes_unknown_from_none_found(reader: IntelReader) -> None:
    cilium = reader.osv(CILIUM)
    assert cilium is not None and len(cilium.advisories) == 1
    assert reader.osv(UNANSWERED) is None  # the bundle never answered: unknown, not "clean"


def test_missing_source_is_unknown_not_negative(tmp_path: Path) -> None:
    partial = tmp_path / "bundle"
    shutil.copytree(BUNDLE, partial)
    (partial / "kev.json").unlink()
    m = import_bundle(partial, tmp_path / "snaps", cves=CVES, purls=[], imported_at=AT)
    r = IntelReader.load(tmp_path / "snaps", m.snapshot_id)
    assert r.kev_listed("CVE-2021-44228") is None
    assert "kev" not in m.sources


# --- Snapshot properties -----------------------------------------------------------------


def test_snapshot_id_ignores_input_order(tmp_path: Path) -> None:
    a = import_bundle(BUNDLE, tmp_path / "a", cves=CVES, purls=[CILIUM], imported_at=AT)
    b = import_bundle(BUNDLE, tmp_path / "b", cves=CVES[::-1], purls=[CILIUM], imported_at=AT)
    assert a.snapshot_id == b.snapshot_id


def test_rewriting_identical_data_is_a_no_op(tmp_path: Path) -> None:
    first = import_bundle(BUNDLE, tmp_path, cves=CVES, purls=[], imported_at=AT)
    later = datetime(2026, 11, 1, tzinfo=UTC)
    again = import_bundle(BUNDLE, tmp_path, cves=CVES, purls=[], imported_at=later)
    assert again == first  # same id, original provenance kept


def test_tampered_data_is_detected(tmp_path: Path) -> None:
    m = import_bundle(BUNDLE, tmp_path, cves=CVES, purls=[], imported_at=AT)
    data = tmp_path / m.snapshot_id / "data.json"
    data.write_bytes(data.read_bytes().replace(b"0.0062", b"0.9062"))
    with pytest.raises(SnapshotIntegrityError, match="does not match"):
        IntelReader.load(tmp_path, m.snapshot_id)


def test_existing_id_with_other_content_is_refused(tmp_path: Path) -> None:
    m = write_snapshot(tmp_path, SnapshotData(scope_cves=("CVE-2024-28248",)), {}, "bundle", AT)
    manifest = tmp_path / m.snapshot_id / "manifest.json"
    manifest.write_text(manifest.read_text().replace(m.data_sha256, "0" * 64))
    with pytest.raises(SnapshotIntegrityError, match="different content"):
        write_snapshot(tmp_path, SnapshotData(scope_cves=("CVE-2024-28248",)), {}, "bundle", AT)


# --- Live fetching (faked network) ---------------------------------------------------------


class FakeHttp:
    """Serves the bundle's files the way the real APIs would."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, str] | None, Mapping[str, str] | None]] = []
        with (BUNDLE / "epss.csv").open(encoding="utf-8") as f:
            next(f)
            self.epss = {r["cve"]: r for r in csv.DictReader(f)}

    def get_json(self, url: str, params: Mapping[str, str] | None = None,
                 headers: Mapping[str, str] | None = None) -> Any:
        self.calls.append((url, params, headers))
        assert params is not None or url == src.KEV_URL
        if url == src.KEV_URL:
            return load("kev.json")
        if url == src.EPSS_URL:
            assert params is not None
            rows = [self.epss[c] for c in params["cve"].split(",") if c in self.epss]
            # The API pads to 9 decimals; the snapshot must not care.
            return {"status": "OK", "data": [
                {"cve": r["cve"], "epss": f"{Decimal(r['epss']):.9f}",
                 "percentile": f"{Decimal(r['percentile']):.9f}", "date": "2026-10-12"}
                for r in rows]}
        if url == src.NVD_URL:
            assert params is not None
            path = BUNDLE / "nvd" / f"{params['cveId']}.json"
            return load(f"nvd/{path.name}") if path.exists() else {"vulnerabilities": []}
        raise AssertionError(url)

    def post_json(self, url: str, body: Any) -> Any:
        assert url == src.OSV_URL
        return load("osv.json").get(body["package"]["purl"], {"vulns": []})


def test_live_and_bundle_paths_produce_the_same_snapshot(tmp_path: Path) -> None:
    sleeps: list[float] = []
    live = build_live_snapshot(FakeHttp(), tmp_path / "live", cves=CVES, purls=[CILIUM],
                               now=AT, sleep=sleeps.append)
    bundle = import_bundle(BUNDLE, tmp_path / "bundle", cves=CVES, purls=[CILIUM],
                           imported_at=AT)
    assert live.snapshot_id == bundle.snapshot_id
    assert sleeps == [src.NVD_DELAY_NO_KEY] * (len(CVES) - 1)  # NVD rate limit respected


def test_live_fetch_requests_only_scope_and_sends_nvd_key(tmp_path: Path) -> None:
    http = FakeHttp()
    build_live_snapshot(http, tmp_path, cves=CVES, purls=[], now=AT, nvd_api_key="k",
                        sleep=lambda _: None, include=("epss", "nvd"))
    epss_calls = [p for u, p, _ in http.calls if u == src.EPSS_URL]
    assert epss_calls == [{"cve": ",".join(sorted(CVES)), "limit": "3"}]
    assert all(h == {"apiKey": "k"} for u, _, h in http.calls if u == src.NVD_URL)
