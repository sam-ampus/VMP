"""CVSS selection: locked decision 1 precedence, version preference, contested flag."""

from decimal import Decimal

from vmp.pipeline.cvss import distro_of, is_os_package, select_cvss
from vmp.schema.enrichment import SourcedCvss
from vmp.schema.enums import CvssSelectionRule
from vmp.schema.finding import CvssScore


def tool(source: str, base: str, version: str = "3.1") -> CvssScore:
    return CvssScore(source=source, version=version, base=Decimal(base))


def intel(kind: str, base: str, version: str = "3.1", source: str = "") -> SourcedCvss:
    return SourcedCvss(kind=kind, source=source or f"{kind}@example", version=version,
                       base=Decimal(base), vector="v")


def test_cilium_sample_selects_nvd_over_tool_scores() -> None:
    sel = select_cvss([tool("bitnami", "7.2"), tool("ghsa", "6.5")],
                      [intel("cna", "7.2"), intel("nvd", "7.2")], distro=None)
    assert sel is not None
    assert (sel.rule, sel.base) == (CvssSelectionRule.NVD, Decimal("7.2"))
    assert (sel.spread, sel.contested) == (Decimal("0.7"), False)


def test_cna_when_nvd_has_not_scored_it() -> None:  # the NVD backlog case
    sel = select_cvss([tool("trivy", "9.0")], [intel("cna", "8.1")], distro=None)
    assert sel is not None and (sel.rule, sel.base) == (CvssSelectionRule.CNA, Decimal("8.1"))


def test_tool_last_highest_base_wins() -> None:
    sel = select_cvss([tool("ghsa", "6.5"), tool("bitnami", "7.2")], [], distro=None)
    assert sel is not None and (sel.rule, sel.source) == (CvssSelectionRule.TOOL, "bitnami")


def test_os_package_prefers_distro_even_over_nvd() -> None:
    sel = select_cvss([tool("redhat", "5.9")], [intel("nvd", "9.8")], distro="redhat")
    assert sel is not None and (sel.rule, sel.source) == (CvssSelectionRule.DISTRO, "redhat")
    assert sel.contested  # 9.8 vs 5.9: the distro disagrees with NVD, so show it


def test_distro_tier_only_applies_to_os_packages() -> None:
    sel = select_cvss([tool("redhat", "5.9")], [intel("nvd", "9.8")], distro=None)
    assert sel is not None and sel.rule is CvssSelectionRule.NVD


def test_v3_preferred_over_v4_and_v2() -> None:
    scores = [intel("nvd", "9.3", "4.0"), intel("nvd", "9.8", "3.1"), intel("nvd", "10.0", "2.0")]
    sel = select_cvss([], scores, distro=None)
    assert sel is not None and sel.version == "3.1"


def test_contested_at_exactly_two_points_and_only_same_version() -> None:
    sel = select_cvss([tool("t", "5.5"), tool("t2", "1.0", "2.0")], [intel("nvd", "7.5")],
                      distro=None)
    assert sel is not None
    assert (sel.spread, sel.contested) == (Decimal("2.0"), True)


def test_nothing_to_select() -> None:
    assert select_cvss([], [], distro=None) is None


def test_os_package_detection() -> None:
    assert is_os_package("pkg:deb/debian/openssl@3.0.11")
    assert is_os_package("pkg:rpm/redhat/openssl@3.0.7")
    assert not is_os_package("pkg:golang/github.com/cilium/cilium@1.14.5")
    assert not is_os_package(None)


def test_another_distros_score_is_not_the_distro_tier() -> None:
    """Red Hat's rating says nothing about an Alpine package (found on the demo seed)."""
    sel = select_cvss([tool("redhat", "8.6"), tool("nvd", "6.5")], [intel("nvd", "6.5")],
                      distro="alpine")
    assert sel is not None and (sel.rule, sel.base) == (CvssSelectionRule.NVD, Decimal("6.5"))


def test_distro_is_read_from_the_purl_namespace() -> None:
    assert distro_of("pkg:apk/alpine/freetype@2.9.1-r2") == "alpine"
    assert distro_of("pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.14?arch=amd64") == "ubuntu"
    assert distro_of("pkg:rpm/almalinux/openssl@3.0.7") == "alma"
    assert distro_of("pkg:rpm/unknownlinux/openssl@3.0.7") is None
    assert distro_of("pkg:golang/github.com/cilium/cilium@1.14.5") is None
