"""FP triage: the three mechanisms, OSV ranges, and combining findings into one band.

Most rule-by-rule coverage lives in the benchmark (benchmark/cases); these tests cover what
the benchmark can't express: OSV data, schema guarantees and the combine rules' edges.
"""

from typing import Any

import pytest

from benchmark.build import findings
from vmp.intel.records import OsvAdvisory, OsvAffected, OsvEvent, OsvPackage, OsvRange
from vmp.pipeline.assess_fp import assess_fp, combine
from vmp.schema.enums import FPBand, FPMechanism
from vmp.schema.finding import Finding


def one(**spec: Any) -> Finding:
    (f,) = findings({"id": "t", "findings": [spec]})
    return f


def pkg(installed: str, *, fixed: tuple[str, ...] = (), status: str | None = None,
        ptype: str = "pypi", name: str = "libx") -> Finding:
    spec: dict[str, Any] = {"shape": "package", "purl": f"pkg:{ptype}/{name}@{installed}",
                            "installed": installed, "fixed": list(fixed), "cve": ["CVE-2024-0001"]}
    if status:
        spec["fix_status"] = status
    return one(**spec)


def osv(*events: tuple[str, str], name: str = "libx", alias: str = "CVE-2024-0001"
        ) -> OsvPackage:
    rng = OsvRange(type="ECOSYSTEM",
                   events=tuple(OsvEvent(kind=k, version=v) for k, v in events))
    affected = OsvAffected(ecosystem="PyPI", name=name, ranges=(rng,))
    advisory = OsvAdvisory(id="GHSA-xxxx", aliases=(alias,), affected=(affected,))
    return OsvPackage(purl="pkg:pypi/libx", advisories=(advisory,))


# --- package ----------------------------------------------------------------------


@pytest.mark.parametrize(("installed", "events", "band"), [
    ("1.5", [("introduced", "0"), ("fixed", "2.0")], FPBand.CONFIRMED_APPLICABLE),
    ("2.0", [("introduced", "0"), ("fixed", "2.0")], FPBand.CONFIRMED_NOT_APPLICABLE),
    ("0.9", [("introduced", "1.0"), ("fixed", "2.0")], FPBand.CONFIRMED_NOT_APPLICABLE),
    ("1.4", [("introduced", "1.0"), ("last_affected", "1.4")], FPBand.CONFIRMED_APPLICABLE),
    ("1.5", [("introduced", "1.0"), ("last_affected", "1.4")], FPBand.CONFIRMED_NOT_APPLICABLE),
    # Two affected windows in one range; events listed out of order on purpose.
    ("3.1", [("fixed", "3.2"), ("introduced", "3.0"), ("fixed", "2.0"), ("introduced", "0")],
     FPBand.CONFIRMED_APPLICABLE),
    ("2.5", [("fixed", "3.2"), ("introduced", "3.0"), ("fixed", "2.0"), ("introduced", "0")],
     FPBand.CONFIRMED_NOT_APPLICABLE),
])
def test_osv_ranges_decide_when_the_tool_has_no_fix_version(
        installed: str, events: list[tuple[str, str]], band: FPBand) -> None:
    a = assess_fp(pkg(installed, status="unknown"), osv(*events))
    assert a.band is band
    assert any(f.startswith("OSV GHSA-xxxx") for f in a.facts)


def test_osv_that_does_not_name_the_package_or_cve_decides_nothing() -> None:
    f = pkg("1.5", status="unknown")
    other_pkg = osv(("introduced", "0"), ("fixed", "2.0"), name="liby")
    other_cve = osv(("introduced", "0"), ("fixed", "2.0"), alias="CVE-2024-9999")
    for data in (other_pkg, other_cve, None):
        assert assess_fp(f, data).band is FPBand.NEEDS_REVIEW


def test_the_vendors_fixed_version_is_used_before_osv() -> None:
    # The tool says fixed in 1.2; OSV (wrongly, here) says everything below 9 is affected.
    a = assess_fp(pkg("1.5", fixed=("1.2",)), osv(("introduced", "0"), ("fixed", "9.0")))
    assert a.band is FPBand.CONFIRMED_NOT_APPLICABLE


def test_an_unparseable_version_is_review_never_a_guess() -> None:
    a = assess_fp(pkg("not.a.version!", fixed=("2.0",)))
    assert a.band is FPBand.NEEDS_REVIEW
    assert "could not be parsed" in a.rationale


def test_package_mechanism_is_always_deterministic_version() -> None:
    assert assess_fp(pkg("1.0", fixed=("2.0",))).mechanism is FPMechanism.DETERMINISTIC_VERSION


# --- host -------------------------------------------------------------------------


def host(**spec: Any) -> Finding:
    return one(shape="host", **spec)


def test_host_findings_are_never_certain() -> None:
    f = host(scan_type="authenticated_network", title="X < 2.0",
             plugin_output="Installed version : 1.0\nFixed version : 2.0")
    a = assess_fp(f)
    assert a.mechanism is FPMechanism.VERSION_RANGE
    assert a.band is FPBand.LOW_LIKELIHOOD  # credentialed and below the fix: still not "certain"


def test_unknown_login_counts_as_no_login() -> None:
    f = host(scan_type="unknown", title="Nginx < 1.20.1",
             description="According to its self-reported version, nginx is prior to 1.20.1.")
    a = assess_fp(f)
    assert a.band is FPBand.NEEDS_REVIEW
    assert "whether the scan logged in is unknown" in a.facts


def test_a_backported_banner_is_named_as_the_reason() -> None:
    f = host(tool="qualys", title="OpenSSH Multiple Vulnerabilities",
             result="Vulnerable SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10 detected on port 22")
    a = assess_fp(f)
    assert a.band is FPBand.NEEDS_REVIEW
    assert any("distro package suffix" in x for x in a.facts)


def test_platform_conflict_beats_everything_else() -> None:
    f = host(os="Ubuntu 22.04", family="Windows : Microsoft Bulletins",
             scan_type="authenticated_network", title="KB5034441: Windows Security Update",
             plugin_output="Installed version : 1.0\nFixed version : 2.0")
    a = assess_fp(f)
    assert a.band is FPBand.LIKELY_FALSE_POSITIVE
    assert a.facts == ("check platform: windows", "host OS: Ubuntu 22.04")


# --- endpoint ---------------------------------------------------------------------


def test_endpoints_never_get_a_not_real_band_or_version_math() -> None:
    for confidence in ("confirmed", "likely", "potential", "untested", "unvalidated"):
        for evidence in ("full", "partial", "none"):
            a = assess_fp(one(shape="endpoint", confidence=confidence, evidence=evidence,
                              cwe=["CWE-89"]))
            assert a.mechanism is FPMechanism.CONFIDENCE_REACHABILITY
            assert a.band in (FPBand.LOW_LIKELIHOOD, FPBand.NEEDS_REVIEW)


# --- combine ----------------------------------------------------------------------


def combined(*specs: dict[str, Any]) -> Any:
    fs = findings({"id": "c", "findings": list(specs)})
    return combine("vln_x", fs, [assess_fp(f) for f in fs])


UNAUTH_BANNER = {"shape": "host", "title": "Nginx < 1.20.1", "cve": ["CVE-2021-23017"],
                 "description": "According to its self-reported version, nginx is old."}


def test_two_tools_without_a_login_are_not_corroboration() -> None:
    v = combined(UNAUTH_BANNER, {**UNAUTH_BANNER, "tool": "qualys"})
    assert v.band is FPBand.NEEDS_REVIEW
    assert "reported by 2 tools (nessus, qualys)" in v.facts


def test_not_real_needs_every_finding_to_agree() -> None:
    windows_on_linux = {"shape": "host", "os": "Ubuntu 22.04", "family": "Windows",
                        "title": "Windows thing", "cve": ["CVE-2021-23017"]}
    v = combined(windows_on_linux, {**UNAUTH_BANNER, "tool": "qualys"})
    assert v.band is FPBand.NEEDS_REVIEW  # one says "not real", one is an open question
    both = combined(windows_on_linux, {**windows_on_linux, "tool": "qualys"})
    assert both.band is FPBand.LIKELY_FALSE_POSITIVE


def test_every_findings_assessment_is_kept() -> None:
    v = combined(UNAUTH_BANNER, {**UNAUTH_BANNER, "port": 8443})
    assert len(v.findings) == 2
    assert {a.finding_id for a in v.findings} == {f.finding_id for f in findings(
        {"id": "c", "findings": [UNAUTH_BANNER, {**UNAUTH_BANNER, "port": 8443}]})}
