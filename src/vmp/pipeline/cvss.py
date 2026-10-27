"""CVSS selection, locked decision 1. Runs after enrichment, when every source is known.

Precedence: OS packages take *their own* distro's score first (distros backport fixes; NVD
does not track that). Another distro's score is just another tool-reported score: Red Hat's
rating says nothing about an Alpine package. Everything else: NVD, then the issuing CNA, then
the tool. Within a tier the preferred CVSS version wins, then the highest base (conservative),
then source name.
"""

from collections.abc import Sequence
from decimal import Decimal
from typing import NamedTuple

from vmp.schema.enrichment import CvssSelection, SourcedCvss
from vmp.schema.enums import CvssSelectionRule, CvssSourceKind, CvssVersion
from vmp.schema.finding import CvssScore

# Tool-reported sources that are a distribution's own advisory (Trivy's vendor names).
DISTRO_SOURCES = frozenset({
    "redhat", "ubuntu", "debian", "alma", "rocky", "amazon", "oracle-oval",
    "suse-cvrf", "photon", "alpine", "azure", "cbl-mariner",
})
OS_PACKAGE_PURL_TYPES = frozenset({"deb", "rpm", "apk"})
# purl namespace (the distro) -> the vendor source name Trivy reports for that distro.
_DISTRO_SOURCE = {
    "debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine", "redhat": "redhat",
    "centos": "redhat", "rocky": "rocky", "almalinux": "alma", "alma": "alma",
    "amazon": "amazon", "oracle": "oracle-oval", "photon": "photon", "mariner": "cbl-mariner",
    "suse": "suse-cvrf", "opensuse": "suse-cvrf", "azurelinux": "azure",
}

# The weights are calibrated on the v3.x scale, so v3 is preferred over v4.0 when both exist.
DEFAULT_VERSION_PREFERENCE = (CvssVersion.V3_1, CvssVersion.V3_0, CvssVersion.V4_0,
                              CvssVersion.V2_0)
CONTESTED_SPREAD = Decimal("2.0")


class _Candidate(NamedTuple):
    source: str
    version: CvssVersion
    base: Decimal


def is_os_package(purl: str | None) -> bool:
    return purl is not None and purl.removeprefix("pkg:").split("/", 1)[0] in OS_PACKAGE_PURL_TYPES


def distro_of(purl: str | None) -> str | None:
    """'pkg:apk/alpine/freetype@2.9.1-r2' -> 'alpine'. None for non-OS or unknown distros."""
    if not is_os_package(purl):
        return None
    assert purl is not None
    parts = purl.removeprefix("pkg:").split("@", 1)[0].split("/")
    return _DISTRO_SOURCE.get(parts[1].lower()) if len(parts) > 2 else None


def select_cvss(
    tool: Sequence[CvssScore], intel: Sequence[SourcedCvss], *, distro: str | None,
    version_preference: Sequence[CvssVersion] = DEFAULT_VERSION_PREFERENCE,
    contested_spread: Decimal = CONTESTED_SPREAD,
) -> CvssSelection | None:
    tool_c = [_Candidate(c.source, c.version, c.base) for c in tool]
    intel_c = [(c.kind, _Candidate(c.source, c.version, c.base)) for c in intel]
    intel_by_kind = {kind: [c for k, c in intel_c if k is kind] for kind in CvssSourceKind}

    tiers: list[tuple[CvssSelectionRule, list[_Candidate]]] = []
    if distro is not None:
        tiers.append((CvssSelectionRule.DISTRO, [c for c in tool_c if c.source == distro]))
    tiers += [
        (CvssSelectionRule.NVD, intel_by_kind[CvssSourceKind.NVD]),
        (CvssSelectionRule.CNA, intel_by_kind[CvssSourceKind.CNA]),
        (CvssSelectionRule.TOOL, tool_c),
    ]

    first = next(((rule, cands) for rule, cands in tiers if cands), None)
    if first is None:
        return None
    rule, candidates = first
    chosen = _pick(candidates, version_preference)

    # Disagreement is measured across every source, on the chosen version only:
    # v2 and v3 scales are not comparable.
    every = tool_c + [c for _, c in intel_c]
    same_version = [c.base for c in every if c.version == chosen.version]
    spread = max(same_version) - min(same_version) if len(same_version) > 1 else None
    return CvssSelection(
        source=chosen.source, version=chosen.version, base=chosen.base, rule=rule,
        spread=spread, contested=spread is not None and spread >= contested_spread,
    )


def _pick(candidates: list[_Candidate], preference: Sequence[CvssVersion]) -> _Candidate:
    def rank(c: _Candidate) -> tuple[int, Decimal, str]:
        version_rank = preference.index(c.version) if c.version in preference else len(preference)
        return version_rank, -c.base, c.source

    return min(candidates, key=rank)
