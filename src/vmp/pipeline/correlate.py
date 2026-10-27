"""Dedupe and correlation: Findings (what each tool saw, each time) -> Vulnerabilities.

Exact keys only. Each finding gets one or more correlation keys; findings that share any key
are the same Vulnerability (connected components, so the result doesn't depend on order):

| shape    | with a CVE                          | without a CVE                                  |
|----------|-------------------------------------|------------------------------------------------|
| host     | asset + CVE                         | asset + tool + native id + port + protocol     |
| package  | asset + package (no version) + CVE  | asset + tool + native id + package (no version)|
| endpoint | asset + method + templated path + params + CWE (see normalize.py), any tool   |

A CVE is a name every tool shares, so it correlates across tools. A Qualys QID and a Nessus
plugin id are not, so findings without a CVE correlate only within one tool, across scans.
Matching those across tools is a judgement call: the near-miss agent proposes, an analyst
decides (Stage 2+). Nothing here guesses.

Large groups are surfaced, not trusted blindly: union-find chains overlapping advisories, so
a group that merged several different checks, or spans many ports, gets a review flag with
its reason (REVIEW_THRESHOLDS). The flag changes nothing; an analyst confirms or splits.

Absence is flagged, never acted on: when a tool's latest scan covered the asset and did not
report the vulnerability, it is marked "not seen in latest scan" and stays open for an analyst
(decision 2026-10-27). A missed port or a failed login looks exactly like a fix.
"""

import hashlib
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from pydantic import AwareDatetime

from vmp.pipeline.normalize import endpoint_correlation_key
from vmp.schema.enums import VulnerabilityStatus
from vmp.schema.finding import EndpointLocus, Finding, HostLocus, PackageLocus
from vmp.schema.types import Model, NonEmptyStr
from vmp.schema.validation import ScanCoverage
from vmp.schema.vulnerability import HistoryEvent, Vulnerability


class NotSeen(Model):
    """One tool's latest scan covered the asset and did not report this vulnerability."""

    tool: NonEmptyStr
    last_seen: AwareDatetime
    latest_scan: AwareDatetime


class ReviewFlag(Model):
    """Why a group deserves a second look. Informational: the grouping and score stand."""

    reason: Literal["merged_checks", "many_ports"]
    detail: NonEmptyStr


@dataclass(frozen=True)
class ReviewThresholds:
    """Set from the real samples (2026-10-27): 7 of 898 groups merged 3+ checks and 2 spanned
    10+ ports. All were correct, but a reviewer should see them."""

    merged_checks: int = 3  # distinct (tool, check id) pairs joined through shared CVEs
    many_ports: int = 10


REVIEW_THRESHOLDS = ReviewThresholds()


class Correlated(Model):
    vulnerability: Vulnerability
    asset_ref: NonEmptyStr
    keys: tuple[NonEmptyStr, ...]  # why these findings are one vulnerability (the shared basis)
    tools: tuple[NonEmptyStr, ...]
    scans: tuple[NonEmptyStr, ...]
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    not_seen: tuple[NotSeen, ...] = ()
    review: tuple[ReviewFlag, ...] = ()


def correlation_keys(finding: Finding, routes: Sequence[str] = ()) -> tuple[str, ...]:
    loc, src, cves = finding.locus, finding.source, finding.classification.cve
    match loc:
        case HostLocus():
            if cves:
                return tuple(f"host|{loc.asset_ref}|{c}" for c in cves)
            return (f"host|{loc.asset_ref}|{src.tool}|{src.native_id}|"
                    f"{loc.port if loc.port is not None else '-'}|{loc.protocol or '-'}",)
        case PackageLocus():
            pkg = loc.purl.split("@", 1)[0]
            if cves:
                return tuple(f"package|{loc.asset_ref}|{pkg}|{c}" for c in cves)
            return (f"package|{loc.asset_ref}|{src.tool}|{src.native_id}|{pkg}",)
        case EndpointLocus():
            return (endpoint_correlation_key(loc, finding.classification.cwe, routes),)


def vulnerability_id(keys: Iterable[str]) -> str:
    """Derived from the smallest key, so it's stable while that key stays in the group.
    Once vulnerabilities are stored, ids are assigned once and kept (Stage 3)."""
    return "vln_" + hashlib.sha256(min(keys).encode()).hexdigest()[:16]


def correlate(findings: Sequence[Finding], coverage: Mapping[str, Sequence[ScanCoverage]],
              *, routes: Sequence[str] = (),
              thresholds: ReviewThresholds = REVIEW_THRESHOLDS) -> list[Correlated]:
    """coverage: tool -> every asset its scans covered, with when."""
    keys_of = {f.finding_id: correlation_keys(f, routes) for f in findings}
    groups = _components(keys_of)
    by_id = {f.finding_id: f for f in findings}
    latest = _latest_coverage(coverage)

    out = []
    for member_ids in groups:
        members = sorted((by_id[i] for i in member_ids), key=lambda f: f.finding_id)
        keys = tuple(sorted({k for f in members for k in keys_of[f.finding_id]}))
        first = min(f.source.first_detected for f in members)
        last = max(f.source.last_detected for f in members)
        vid = vulnerability_id(keys)
        out.append(Correlated(
            vulnerability=Vulnerability(
                vulnerability_id=vid, finding_ids=tuple(f.finding_id for f in members),
                status=VulnerabilityStatus.OPEN,
                history=(HistoryEvent(at=first, kind="created",
                                      detail=f"first seen by {members[0].source.tool}"),)),
            asset_ref=members[0].locus.asset_ref, keys=keys,
            tools=tuple(sorted({f.source.tool for f in members})),
            scans=tuple(sorted({f.source.scan_id for f in members})),
            first_seen=first, last_seen=last,
            not_seen=_not_seen(members, latest),
            review=_review(members, thresholds),
        ))
    return sorted(out, key=lambda c: c.vulnerability.vulnerability_id)


def _components(keys_of: Mapping[str, Sequence[str]]) -> list[set[str]]:
    """Union-find over findings that share a key."""
    parent = {fid: fid for fid in keys_of}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    owner: dict[str, str] = {}
    for fid in sorted(keys_of):
        for key in keys_of[fid]:
            if key in owner:
                a, b = find(owner[key]), find(fid)
                if a != b:
                    parent[max(a, b)] = min(a, b)
            else:
                owner[key] = fid
    groups: dict[str, set[str]] = defaultdict(set)
    for fid in keys_of:
        groups[find(fid)].add(fid)
    return list(groups.values())


def _review(members: Sequence[Finding], t: ReviewThresholds) -> tuple[ReviewFlag, ...]:
    flags = []
    checks: dict[tuple[str, str], set[str]] = defaultdict(set)
    for f in members:
        checks[(f.source.tool, f.source.native_id)].update(f.classification.cve)
    if len(checks) >= t.merged_checks:
        # The CVEs that join checks together: listed by more than one check.
        seen_by = Counter(c for cve_set in checks.values() for c in cve_set)
        cves = sorted(c for c, n in seen_by.items() if n > 1)
        listed = ", ".join(cves[:5]) + (", ..." if len(cves) > 5 else "")
        flags.append(ReviewFlag(reason="merged_checks", detail=(
            f"{len(checks)} different checks merged through {len(cves)} shared CVEs "
            f"({listed}); confirm they are one fix")))
    ports = {(f.locus.port, f.locus.protocol) for f in members if isinstance(f.locus, HostLocus)}
    if len(ports) >= t.many_ports:
        flags.append(ReviewFlag(reason="many_ports", detail=(
            f"reported on {len(ports)} ports of one asset; confirm it is one service, "
            "or one asset record covering several hosts")))
    return tuple(flags)


def _latest_coverage(coverage: Mapping[str, Sequence[ScanCoverage]]
                     ) -> dict[tuple[str, str], AwareDatetime]:
    latest: dict[tuple[str, str], AwareDatetime] = {}
    for tool, entries in coverage.items():
        for c in entries:
            k = (tool, c.asset_ref)
            if k not in latest or c.scanned_at > latest[k]:
                latest[k] = c.scanned_at
    return latest


def _not_seen(members: Sequence[Finding], latest: Mapping[tuple[str, str], AwareDatetime]
              ) -> tuple[NotSeen, ...]:
    """Per tool that ever reported it: did that tool's newest scan of the asset miss it?
    Only the same tool's silence counts; Qualys not reporting a Nessus finding says nothing."""
    out = []
    last_by_tool: dict[str, AwareDatetime] = {}
    for f in members:
        t = f.source.tool
        last_by_tool[t] = max(f.source.last_detected, last_by_tool.get(t, f.source.last_detected))
    asset = members[0].locus.asset_ref
    for tool, last in sorted(last_by_tool.items()):
        scanned = latest.get((tool, asset))
        if scanned is not None and scanned > last:
            out.append(NotSeen(tool=tool, last_seen=last, latest_scan=scanned))
    return tuple(out)
