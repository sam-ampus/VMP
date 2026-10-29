"""Version comparators against each ecosystem's own published reference cases.

dpkg: deb-version(7) and dpkg's t-version tests. rpm: rpm's rpmvercmp test suite
(tests/rpmvercmp.at). apk: apk-tools' version ordering rules. PyPI: PEP 440 examples.
"""

import pytest

from vmp.pipeline.assess_fp.versions import VersionError, apk, dotted, dpkg, pypi, rpm


@pytest.mark.parametrize(("a", "b", "expected"), [
    ("1.0", "1.0", 0),
    ("1.0", "1.1", -1),
    ("1:0.1", "2.0", 1),  # epoch wins
    ("0:1.0", "1.0", 0),  # epoch 0 is the default
    ("1.0~rc1", "1.0", -1),  # tilde sorts before the release
    ("1.0~~", "1.0~", -1),
    ("1.0-1", "1.0-2", -1),
    ("1.0", "1.0-0", 0),  # no revision == revision 0
    ("1.0+b1", "1.0", 1),
    ("2.30-1", "2.30-1ubuntu1", -1),  # Ubuntu's change sorts after Debian's
    ("8.9p1-3ubuntu0.10", "8.9p1-3ubuntu0.6", 1),  # numbers compare as numbers
    ("1.1.1n-0+deb11u3", "1.1.1n-0+deb11u4", -1),
    ("1.0a", "1.0+", -1),  # letters sort before other symbols
    ("1.001", "1.1", 0),  # leading zeros don't count
])
def test_dpkg(a: str, b: str, expected: int) -> None:
    assert dpkg.compare(a, b) == expected
    assert dpkg.compare(b, a) == -expected


@pytest.mark.parametrize("bad", ["x:1.0", "abc", ":1.0"])
def test_dpkg_refuses_what_it_cannot_parse(bad: str) -> None:
    with pytest.raises(VersionError):
        dpkg.compare(bad, "1.0")


# rpm's own rpmvercmp cases (a, b, expected).
RPMVERCMP = [
    ("1.0", "1.0", 0), ("1.0", "2.0", -1), ("2.0", "1.0", 1),
    ("2.0.1", "2.0.1", 0), ("2.0", "2.0.1", -1), ("2.0.1", "2.0", 1),
    ("2.0.1a", "2.0.1a", 0), ("2.0.1a", "2.0.1", 1), ("2.0.1", "2.0.1a", -1),
    ("5.5p1", "5.5p1", 0), ("5.5p1", "5.5p2", -1), ("5.5p2", "5.5p1", 1),
    ("5.5p10", "5.5p10", 0), ("5.5p1", "5.5p10", -1), ("5.5p10", "5.5p1", 1),
    ("10xyz", "10.1xyz", -1), ("10.1xyz", "10xyz", 1),
    ("xyz10", "xyz10", 0), ("xyz10", "xyz10.1", -1), ("xyz10.1", "xyz10", 1),
    ("xyz.4", "xyz.4", 0), ("xyz.4", "8", -1), ("8", "xyz.4", 1), ("xyz.4", "2", -1),
    ("2", "xyz.4", 1),
    ("5.5p2", "5.6p1", -1), ("5.6p1", "5.5p2", 1),
    ("5.6p1", "6.5p1", -1), ("6.5p1", "5.6p1", 1),
    ("6.0.rc1", "6.0", 1), ("6.0", "6.0.rc1", -1),
    ("10b2", "10a1", 1), ("10a2", "10b2", -1),
    ("1.0aa", "1.0aa", 0), ("1.0a", "1.0aa", -1), ("1.0aa", "1.0a", 1),
    ("10.0001", "10.0001", 0), ("10.0001", "10.1", 0), ("10.1", "10.0001", 0),
    ("10.0001", "10.0039", -1), ("10.0039", "10.0001", 1),
    ("4.999.9", "5.0", -1), ("5.0", "4.999.9", 1),
    ("20101121", "20101121", 0), ("20101121", "20101122", -1), ("20101122", "20101121", 1),
    ("2_0", "2_0", 0), ("2.0", "2_0", 0), ("2_0", "2.0", 0),
    ("a", "a", 0), ("a+", "a+", 0), ("a+", "a_", 0), ("a_", "a+", 0),
    ("+a", "+a", 0), ("+a", "_a", 0), ("_a", "+a", 0), ("+_", "+_", 0), ("_+", "+_", 0),
    ("_+", "_+", 0), ("+", "_", 0), ("_", "+", 0),
    ("1.0~rc1", "1.0~rc1", 0), ("1.0~rc1", "1.0", -1), ("1.0", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc2", -1), ("1.0~rc2", "1.0~rc1", 1),
    ("1.0~rc1~git123", "1.0~rc1~git123", 0), ("1.0~rc1~git123", "1.0~rc1", -1),
    ("1.0~rc1", "1.0~rc1~git123", 1),
    ("1.0^", "1.0^", 0), ("1.0^", "1.0", 1), ("1.0", "1.0^", -1),
    ("1.0^git1", "1.0^git1", 0), ("1.0^git1", "1.0", 1), ("1.0", "1.0^git1", -1),
    ("1.0^git1", "1.0^git2", -1), ("1.0^git2", "1.0^git1", 1),
    ("1.0^git1", "1.01", -1), ("1.01", "1.0^git1", 1),
    ("1.0^20160101", "1.0^20160101", 0), ("1.0^20160101", "1.0.1", -1),
    ("1.0.1", "1.0^20160101", 1),
    ("1.0^20160101^git1", "1.0^20160101^git1", 0),
    ("1.0^20160102", "1.0^20160101^git1", 1), ("1.0^20160101^git1", "1.0^20160102", -1),
    ("1.0~rc1^git1", "1.0~rc1^git1", 0), ("1.0~rc1^git1", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc1^git1", -1),
    ("1.0^git1~pre", "1.0^git1~pre", 0), ("1.0^git1", "1.0^git1~pre", 1),
    ("1.0^git1~pre", "1.0^git1", -1),
]


@pytest.mark.parametrize(("a", "b", "expected"), RPMVERCMP)
def test_rpmvercmp_reference_cases(a: str, b: str, expected: int) -> None:
    assert rpm.rpmvercmp(a, b) == expected


@pytest.mark.parametrize(("a", "b", "expected"), [
    ("1.0.2k-19.el7", "1.0.2k-21.el7", -1),
    ("3.0.7-27.el9", "3.0.7-6.el9", 1),
    ("1:1.0-1", "2.0-1", 1),  # epoch
    ("1.0", "1.0-5.el9", 0),  # no release on one side: the release isn't compared
])
def test_rpm_evr(a: str, b: str, expected: int) -> None:
    assert rpm.compare(a, b) == expected


@pytest.mark.parametrize(("a", "b", "expected"), [
    ("1.0", "1.1", -1),
    ("1.0", "1.0.1", -1),
    ("1.0_alpha", "1.0", -1),
    ("1.0_alpha1", "1.0_beta", -1),
    ("1.0_beta2", "1.0_pre1", -1),
    ("1.0_rc1", "1.0", -1),
    ("1.0", "1.0_p1", -1),
    ("1.0_git20240101", "1.0", 1),
    ("1.0_cvs", "1.0_p1", -1),
    ("1.0a", "1.0", 1),
    ("1.0a", "1.0b", -1),
    ("1.2.4-r5", "1.2.4-r6", -1),
    ("1.2.4-r10", "1.2.4-r9", 1),
    ("1.01", "1.1", -1),  # leading zero after the first number: compared as strings
    ("10.0", "9.0", 1),
    ("1.36.1_p1-r0", "1.36.1-r0", 1),
])
def test_apk(a: str, b: str, expected: int) -> None:
    assert apk.compare(a, b) == expected
    assert apk.compare(b, a) == -expected


def test_apk_refuses_non_apk_versions() -> None:
    with pytest.raises(VersionError):
        apk.compare("1.0-beta", "1.0")


@pytest.mark.parametrize(("a", "b", "expected"), [
    ("2.0.0rc1", "2.0.0", -1),
    ("1.0.post1", "1.0", 1),
    ("1.0.dev1", "1.0a1", -1),
    ("1!0.1", "2.0", 1),
    ("2.31.0", "2.31", 0),
])
def test_pypi(a: str, b: str, expected: int) -> None:
    assert pypi.compare(a, b) == expected


def test_pypi_refuses_invalid() -> None:
    with pytest.raises(VersionError):
        pypi.compare("not-a-version", "1.0")


def test_dotted_only_takes_plain_numbers() -> None:
    assert dotted("2.4.57", "2.4.58") == -1
    assert dotted("1.2", "1.2.0") == 0
    with pytest.raises(VersionError):
        dotted("8.9p1", "9.6")
