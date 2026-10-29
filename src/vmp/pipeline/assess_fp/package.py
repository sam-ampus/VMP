"""Package findings: exact version math, so the answer is certain or there is no answer.

The skill's rule: never treat a package finding's applicability as uncertain when the version
math is exact. So every path ends in confirmed_applicable or confirmed_not_applicable, unless
the math can't be done (unknown ecosystem, unparseable version, fixes on several branches
with no range data). Then the band is needs_review and the facts say exactly why.

Order of evidence: the vendor's own statement through the tool (fixed version, fix status)
first, then OSV's affected ranges when the tool's data can't decide.
"""

from functools import cmp_to_key

from vmp.intel.records import OsvEvent, OsvPackage, OsvRange
from vmp.pipeline.assess_fp.common import fp
from vmp.pipeline.assess_fp.versions import BY_PURL_TYPE, Comparator, VersionError
from vmp.schema.enums import FixStatus, FPBand
from vmp.schema.finding import Finding, PackageLocus
from vmp.schema.vulnerability import FPAssessment

_VENDOR_AFFECTED = {FixStatus.AFFECTED, FixStatus.WILL_NOT_FIX, FixStatus.FIX_DEFERRED,
                    FixStatus.END_OF_LIFE}


def assess_package(finding: Finding, osv: OsvPackage | None = None) -> FPAssessment:
    locus = finding.locus
    assert isinstance(locus, PackageLocus)
    ptype = locus.purl.removeprefix("pkg:").split("/", 1)[0]
    installed = locus.installed_version
    facts = [f"installed {locus.package_name} {installed} ({ptype})"]

    if locus.fix_status is FixStatus.NOT_AFFECTED:
        return fp(finding, FPBand.CONFIRMED_NOT_APPLICABLE,
                  "The vendor marks this package version as not affected.", facts)

    compare = BY_PURL_TYPE.get(ptype)
    if compare is None:
        return fp(finding, FPBand.NEEDS_REVIEW,
                  f"No exact version comparison for '{ptype}' packages yet, so applicability "
                  "is not computed.", [*facts, f"no comparator for {ptype} (backlog B-024)"])
    try:
        if locus.fixed_version:
            decided = _against_fixes(compare, installed, locus.fixed_version, facts)
            if decided is not None:
                return fp(finding, *decided, facts)
        elif locus.fix_status in _VENDOR_AFFECTED:
            return fp(finding, FPBand.CONFIRMED_APPLICABLE,
                      f"The vendor lists this version as affected with no fix "
                      f"({locus.fix_status}).", facts)
        decided = _against_osv(compare, finding, locus, osv, facts)
    except VersionError as exc:
        return fp(finding, FPBand.NEEDS_REVIEW,
                  "A version could not be parsed by the ecosystem's rules, so applicability "
                  "is not computed.", [*facts, str(exc)])
    if decided is not None:
        return fp(finding, *decided, facts)
    return fp(finding, FPBand.NEEDS_REVIEW,
              "The tool's fix data and the intel can't decide applicability exactly.", facts)


def _against_fixes(compare: Comparator, installed: str, fixes: tuple[str, ...],
                   facts: list[str]) -> tuple[FPBand, str] | None:
    facts.append("fixed in " + ", ".join(fixes))
    below = [f for f in fixes if compare(installed, f) < 0]
    if len(below) == len(fixes):
        return (FPBand.CONFIRMED_APPLICABLE,
                f"Installed {installed} is older than every fixed version.")
    if not below:
        return (FPBand.CONFIRMED_NOT_APPLICABLE,
                f"Installed {installed} is at or above every fixed version, so the fix is "
                "already in place.")
    # Fixes on several release branches (e.g. 2.4.1 and 3.0.2) with the installed version
    # between them: which branch it belongs to is not something the version string says.
    facts.append(f"installed is between fixes on different branches ({', '.join(fixes)})")
    return None


def _against_osv(compare: Comparator, finding: Finding, locus: PackageLocus,
                 osv: OsvPackage | None, facts: list[str]) -> tuple[FPBand, str] | None:
    if osv is None:
        facts.append("no OSV data for this package")
        return None
    cves = set(finding.classification.cve) or {finding.source.native_id}
    for advisory in osv.advisories:
        if not cves & {advisory.id, *advisory.aliases}:
            continue
        for affected in advisory.affected:
            if affected.name != locus.package_name:
                continue
            ranges = [r for r in affected.ranges if r.type == "ECOSYSTEM"]
            if not ranges:
                continue
            hit = any(_in_range(compare, locus.installed_version, r) for r in ranges)
            facts.append(f"OSV {advisory.id}: installed is {'inside' if hit else 'outside'} "
                         "the affected ranges")
            if hit:
                return (FPBand.CONFIRMED_APPLICABLE,
                        "OSV's affected ranges include the installed version.")
            return (FPBand.CONFIRMED_NOT_APPLICABLE,
                    "OSV's affected ranges exclude the installed version.")
    facts.append("OSV has no range for this package and CVE")
    return None


def _in_range(compare: Comparator, version: str, r: OsvRange) -> bool:
    """OSV's range semantics: walk the events in version order, toggling 'affected'.

    "introduced: 0" means "from the beginning", so it sorts first and always applies.
    """
    def order(x: OsvEvent, y: OsvEvent) -> int:
        if x.version == y.version:
            return 0
        if "0" in (x.version, y.version):
            return -1 if x.version == "0" else 1
        return compare(x.version, y.version)

    events = sorted((e for e in r.events if e.kind in ("introduced", "fixed", "last_affected")),
                    key=cmp_to_key(order))
    affected = False
    for e in events:
        if e.kind == "introduced" and (e.version == "0" or compare(version, e.version) >= 0):
            affected = True
        elif e.kind in ("fixed", "last_affected"):
            # fixed: this version and later are safe; last_affected: only later ones are.
            past = compare(version, e.version)
            if past > 0 or (past == 0 and e.kind == "fixed"):
                affected = False
    return affected
