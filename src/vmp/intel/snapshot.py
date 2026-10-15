"""Immutable, content-addressed intel snapshots.

A snapshot is a directory:  <root>/<snapshot_id>/data.json + manifest.json
- data.json holds normalised records only, in canonical form (sorted, compact).
- snapshot_id = "intel-" + first 16 hex of sha256(data.json). Same data, same id.
- manifest.json records provenance: where each source came from, when, and which version.

Scoring reads snapshots, never live feeds, so a score can be reproduced offline years later.
"""

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Literal

from pydantic import AwareDatetime, NonNegativeInt

from vmp.intel.records import EpssEntry, KevEntry, NvdEntry, OsvPackage
from vmp.schema.types import CveId, Model, NonEmptyStr

DATA_FILE = "data.json"
MANIFEST_FILE = "manifest.json"


class SourceInfo(Model):
    origin: NonEmptyStr  # URL, or "bundle:<file>"
    retrieved_at: AwareDatetime
    version: str | None = None  # KEV catalogVersion, EPSS model_version
    as_of: str | None = None  # EPSS score date
    count: NonNegativeInt


def _by_cve[T: KevEntry | EpssEntry | NvdEntry](xs: tuple[T, ...] | None) -> tuple[T, ...] | None:
    if xs is None:
        return None
    return tuple(sorted({x.cve: x for x in xs}.values(), key=lambda x: x.cve))


class SnapshotData(Model):
    """None for a source means 'not included', which is different from 'nothing found'."""

    scope_cves: tuple[CveId, ...] = ()
    scope_purls: tuple[str, ...] = ()
    kev: tuple[KevEntry, ...] | None = None
    epss: tuple[EpssEntry, ...] | None = None
    nvd: tuple[NvdEntry, ...] | None = None
    osv: tuple[OsvPackage, ...] | None = None

    def canonical(self) -> "SnapshotData":
        """Sorted and de-duplicated, so input order can never change the snapshot id."""
        return SnapshotData(
            scope_cves=tuple(sorted(set(self.scope_cves))),
            scope_purls=tuple(sorted(set(self.scope_purls))),
            kev=_by_cve(self.kev),
            epss=_by_cve(self.epss),
            nvd=_by_cve(self.nvd),
            osv=None if self.osv is None else tuple(
                sorted({p.purl: p for p in self.osv}.values(), key=lambda p: p.purl)
            ),
        )

    def to_bytes(self) -> bytes:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True,
                          separators=(",", ":")).encode()


class Manifest(Model):
    snapshot_id: NonEmptyStr
    created_at: AwareDatetime
    origin: Literal["live", "bundle"]
    data_sha256: NonEmptyStr
    sources: dict[str, SourceInfo]


class SnapshotIntegrityError(Exception):
    pass


def write_snapshot(
    root: Path, data: SnapshotData, sources: dict[str, SourceInfo],
    origin: Literal["live", "bundle"], created_at: AwareDatetime,
) -> Manifest:
    blob = data.canonical().to_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    sid = f"intel-{digest[:16]}"
    target = root / sid
    if target.exists():  # immutable: identical data is a no-op, different data is a bug
        existing = load_manifest(target)
        if existing.data_sha256 != digest:
            raise SnapshotIntegrityError(f"{sid} exists with different content")
        return existing

    manifest = Manifest(snapshot_id=sid, created_at=created_at, origin=origin,
                        data_sha256=digest, sources=sources)
    tmp = root / f".{sid}.tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    (tmp / DATA_FILE).write_bytes(blob)
    (tmp / MANIFEST_FILE).write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    os.replace(tmp, target)  # atomic: readers never see a half-written snapshot
    return manifest


def load_manifest(snapshot_dir: Path) -> Manifest:
    return Manifest.model_validate_json((snapshot_dir / MANIFEST_FILE).read_text("utf-8"))


class IntelReader:
    """Read-only lookups against one verified snapshot."""

    def __init__(self, manifest: Manifest, data: SnapshotData) -> None:
        self.manifest = manifest
        self._scope = set(data.scope_cves)
        self._scope_purls = set(data.scope_purls)
        self._kev = None if data.kev is None else {e.cve: e for e in data.kev}
        self._epss = None if data.epss is None else {e.cve: e for e in data.epss}
        self._nvd = None if data.nvd is None else {e.cve: e for e in data.nvd}
        self._osv = None if data.osv is None else {p.purl: p for p in data.osv}

    @classmethod
    def load(cls, root: Path, snapshot_id: str) -> "IntelReader":
        target = root / snapshot_id
        manifest = load_manifest(target)
        blob = (target / DATA_FILE).read_bytes()
        if hashlib.sha256(blob).hexdigest() != manifest.data_sha256:
            raise SnapshotIntegrityError(f"{snapshot_id}: data does not match its manifest")
        return cls(manifest, SnapshotData.model_validate_json(blob))

    @property
    def snapshot_id(self) -> str:
        return self.manifest.snapshot_id

    def kev(self, cve: str) -> KevEntry | None:
        return None if self._kev is None else self._kev.get(cve)

    def kev_listed(self, cve: str) -> bool | None:
        """The full KEV catalogue is stored, so absence means 'not listed' for any CVE."""
        return None if self._kev is None else cve in self._kev

    def epss(self, cve: str) -> EpssEntry | None:
        return None if self._epss is None else self._epss.get(cve)

    def nvd(self, cve: str) -> NvdEntry | None:
        return None if self._nvd is None else self._nvd.get(cve)

    def osv(self, purl: str) -> OsvPackage | None:
        """None if OSV was not included or the purl was out of scope."""
        if self._osv is None or purl not in self._scope_purls:
            return None
        return self._osv.get(purl, OsvPackage(purl=purl))

    def in_scope(self, cve: str) -> bool:
        return cve in self._scope
