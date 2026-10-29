"""Host findings (Nessus, Qualys): version-range reasoning, never certainty.

A network scanner usually learns a version from what the service says about itself (a banner,
a header). Linux distributions backport security fixes without changing that upstream
version, so "OpenSSH 8.9 is older than 9.6" can be true of the string and false of the
host. That is the commonest false positive in host scanning, and why host findings are
never 'confirmed_*'.

The rules, in order (first match wins):
1. The finding is for another platform than the host's OS       -> likely_false_positive
2. The scanner's own text shows installed >= fixed version      -> likely_false_positive
3. Qualys said it couldn't verify (potential)                    -> needs_review
4. Version inferred remotely, with no working login             -> needs_review
5. Otherwise (credentialed version check, or a directly
   observed condition such as a TLS setting)                    -> low_likelihood

All text matching is fixed patterns over what the tool wrote; nothing is guessed. A later
evidence agent can add facts (backlog B-032 area); code still picks the band.
"""

import re

from vmp.pipeline.assess_fp.common import fp
from vmp.pipeline.assess_fp.versions import VersionError, dotted, dpkg, rpm
from vmp.schema.enums import Confidence, FPBand, ScanType
from vmp.schema.finding import Finding, HostLocus
from vmp.schema.vulnerability import FPAssessment

# Nessus writes version facts as "Label : value" lines in plugin_output.
_INSTALLED = re.compile(r"^\s*Installed version\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_FIXED = re.compile(r"^\s*Fixed version\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_PACKAGE = re.compile(r"Remote package installed\s*:\s*(\S+)\s*\n\s*Should be\s*:\s*(\S+)",
                      re.IGNORECASE)
# How each tool says "I inferred this from a version", in its own words.
_INFERRED = (
    re.compile(r"self-reported version", re.IGNORECASE),  # Nessus descriptions
    re.compile(r"\bversion of .{1,80}? (?:installed|running) on the remote host is "
               r"(?:prior to|older than)", re.IGNORECASE | re.DOTALL),  # Nessus descriptions
    re.compile(r"^Vulnerable .{1,160}? detected\b", re.IGNORECASE | re.MULTILINE),  # Qualys
    re.compile(r"\(Unauthenticated Detection\)", re.IGNORECASE),  # Qualys titles
    re.compile(r"<\s*\d"),  # titles like "Apache 2.4.x < 2.4.58 Multiple Vulnerabilities"
)
_UNAUTH_CHECK = re.compile(r"\(Unauthenticated Detection\)", re.IGNORECASE)
# A banner carrying a distro package suffix: the distro may have backported the fix.
_BACKPORT = re.compile(r"(?i)\b(?:ubuntu|debian)\b|\+deb\d+u\d+|\.el\d|\bamzn\d|\.fc\d\d")
_DISTROS = ("ubuntu", "debian", "red hat", "centos", "oracle linux", "amazon linux", "suse",
            "fedora", "alpine", "rocky", "almalinux", "alma linux")


def assess_host(finding: Finding) -> FPAssessment:
    locus = finding.locus
    assert isinstance(locus, HostLocus)
    texts = _texts(finding)
    facts: list[str] = []

    if conflict := _platform_conflict(finding, locus.os):
        return fp(finding, FPBand.LIKELY_FALSE_POSITIVE,
                  f"This check is for {conflict[0]} but the host reports {conflict[1]}.",
                  [f"check platform: {conflict[0]}", f"host OS: {conflict[1]}"])

    authenticated = _authenticated(finding, facts)
    versions = version_facts(texts, locus.os, facts)
    if versions == "at_or_above_fix":
        return fp(finding, FPBand.LIKELY_FALSE_POSITIVE,
                  "The scanner's own output shows the installed version is already at or "
                  "above the fixed version.", facts)

    inferred = versions is not None or any(p.search(t) for p in _INFERRED for t in texts)
    if inferred:
        facts.append("detected by version, not by observing the weakness")
        if any(_BACKPORT.search(t) for t in _evidence_text(finding)):
            facts.append("the reported version carries a distro package suffix; distros "
                         "backport fixes without changing the upstream version")

    if finding.validation.confidence is Confidence.POTENTIAL:
        return fp(finding, FPBand.NEEDS_REVIEW,
                  f"{finding.source.tool.capitalize()} reported this as potential: its check "
                  "could not verify the weakness.", facts)
    if inferred and not authenticated:
        return fp(finding, FPBand.NEEDS_REVIEW,
                  "The version was read remotely without a working login, so a backported "
                  "fix would not be visible. Confirm the installed package on the host.", facts)
    if inferred:
        return fp(finding, FPBand.LOW_LIKELIHOOD,
                  "A credentialed check read the installed version on the host.", facts)
    facts.append("condition observed directly, not inferred from a version")
    return fp(finding, FPBand.LOW_LIKELIHOOD,
              "The scanner observed the condition itself rather than inferring it from a "
              "version.", facts)


def _texts(f: Finding) -> list[str]:
    extra = f.evidence.model_extra or {}
    return [f.classification.title, *(extra.get(k) or "" for k in ("description", "synopsis")),
            *_evidence_text(f)]


def _evidence_text(f: Finding) -> list[str]:
    """What the scanner saw on this host: Nessus plugin output, Qualys per-transport results."""
    extra = f.evidence.model_extra or {}
    out = [extra.get("plugin_output") or ""]
    out += [o.get("result") or "" for o in extra.get("observations") or []]
    return [t for t in out if t]


def logged_in(f: Finding) -> bool:
    """Did this check run with a working login? Unknown counts as no."""
    return _authenticated(f, [])


def _authenticated(f: Finding, facts: list[str]) -> bool:
    extra = f.evidence.model_extra or {}
    if _UNAUTH_CHECK.search(f.classification.title):
        facts.append("the check itself runs without a login (Qualys 'Unauthenticated "
                     "Detection')")
        return False
    if f.source.scan_type is ScanType.AUTHENTICATED_NETWORK:
        facts.append(f"login {extra['host_auth']}" if extra.get("host_auth")
                     else "credentialed scan")
        return True
    if host_auth := extra.get("host_auth"):
        facts.append(f"login {host_auth}")
    elif f.source.scan_type is ScanType.UNAUTHENTICATED_NETWORK:
        facts.append("scan ran without a login")
    else:
        facts.append("whether the scan logged in is unknown")
    return False


def version_facts(texts: list[str], os: str | None, facts: list[str]) -> str | None:
    """'below_fix' / 'at_or_above_fix' when the scanner's text allows an exact comparison."""
    joined = "\n".join(texts)
    pairs: list[tuple[str, str, str]] = []  # (installed, fixed, how compared)
    if (i := _INSTALLED.search(joined)) and (x := _FIXED.search(joined)):
        pairs.append((i[1].rstrip(",;"), x[1].rstrip(",;"), "dotted"))
    for installed, should in _PACKAGE.findall(joined):
        kind = _package_kind(installed, os)
        if kind:
            pairs.append((installed, should, kind))
    results = []
    for installed, fixed, kind in pairs:
        try:
            c = _compare(kind, installed, fixed)
        except VersionError:
            facts.append(f"installed {installed}, fixed {fixed}: not comparable by rule")
            continue
        facts.append(f"installed {installed}, fixed {fixed} (scanner output)")
        results.append(c)
    if not results:
        return None
    return "below_fix" if any(c < 0 for c in results) else "at_or_above_fix"


def _package_kind(name_version: str, os: str | None) -> str | None:
    """Nessus prints Debian packages as name_version and RPMs as name-version-release."""
    os_l = (os or "").lower()
    if "_" in name_version and ("deb" in name_version or "ubuntu" in name_version
                                or "debian" in os_l or "ubuntu" in os_l):
        return "dpkg"
    if re.search(r"\.(?:el|amzn|fc)\d", name_version) or any(
            d in os_l for d in ("red hat", "centos", "oracle linux", "amazon linux", "rocky")):
        return "rpm"
    return None


def _compare(kind: str, installed: str, fixed: str) -> int:
    if kind == "dotted":
        return dotted(installed, fixed)
    if kind == "dpkg":
        return dpkg.compare(installed.split("_", 1)[1], fixed.split("_", 1)[1])
    # rpm NVR: name-version-release, where the name itself may contain hyphens.
    vi, vf = installed.rsplit("-", 2), fixed.rsplit("-", 2)
    if len(vi) < 3 or len(vf) < 3:
        raise VersionError(f"not name-version-release: {installed!r}, {fixed!r}")
    return rpm.compare(f"{vi[1]}-{vi[2]}", f"{vf[1]}-{vf[2]}")


def _platform_conflict(f: Finding, os: str | None) -> tuple[str, str] | None:
    """(check platform, host OS) when they can't both be true; None when unsure."""
    host, check = _os_platform(os), _check_platform(f)
    if host is None or check is None or host == check:
        return None
    windows_vs_linux = "windows" in (host, check)
    # Two different named distros conflict; a generic "Linux" fingerprint conflicts with none.
    two_distros = host.startswith("linux:") and check.startswith("linux:")
    if windows_vs_linux or two_distros:
        return check.replace("linux:", "Linux: "), (os or "").strip()
    return None


def _os_platform(os: str | None) -> str | None:
    if not os:
        return None
    # Nessus lists alternative fingerprints one per line; disagreeing guesses mean unsure.
    guesses = {_classify_os(line) for line in os.splitlines() if line.strip()}
    return guesses.pop() if len(guesses) == 1 else None


def _classify_os(text: str) -> str | None:
    t = text.lower()
    if "windows" in t:
        return "windows"
    for d in _DISTROS:
        if d in t:
            return f"linux:{d}"
    return "linux" if "linux" in t else None


def _check_platform(f: Finding) -> str | None:
    family = (f.source.native_family or "").lower()
    title = f.classification.title.lower()
    if family.startswith("windows") or title.startswith(("microsoft windows", "ms windows")) \
            or re.search(r"\bms\d{2}-\d{3}\b|\bkb\d{6,7}\b", title):
        return "windows"
    if family.endswith("local security checks"):
        for d in _DISTROS:
            if family.startswith(d):
                return f"linux:{d}"
    return None
