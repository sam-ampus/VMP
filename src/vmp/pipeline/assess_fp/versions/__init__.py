"""Exact version comparison, one rule set per package ecosystem.

Written in-house for dpkg, rpm and apk, and `packaging` for PyPI (decision 2026-10-28): each
algorithm is short, published and tested against the ecosystem's own reference cases, and
every dependency is something a FedRAMP review has to justify. Ecosystems without a
comparator here (npm, Maven: backlog B-024) get no answer, never a guess.

`dotted` is not an ecosystem. It compares plain numeric versions like 2.4.57, the only kind
a host scanner's text is trusted for.
"""

import re
from collections.abc import Callable

from vmp.pipeline.assess_fp.versions import apk, dpkg, pypi, rpm
from vmp.pipeline.assess_fp.versions.errors import VersionError

Comparator = Callable[[str, str], int]

# purl type -> comparator
BY_PURL_TYPE: dict[str, Comparator] = {
    "deb": dpkg.compare, "rpm": rpm.compare, "apk": apk.compare, "pypi": pypi.compare,
}

_DOTTED = re.compile(r"^\d+(?:\.\d+)*$")


def dotted(a: str, b: str) -> int:
    """Compare purely numeric dotted versions (1.2 == 1.2.0). Anything else is refused."""
    if not (_DOTTED.match(a) and _DOTTED.match(b)):
        raise VersionError(f"not plain dotted numbers: {a!r}, {b!r}")
    pa, pb = [int(x) for x in a.split(".")], [int(x) for x in b.split(".")]
    width = max(len(pa), len(pb))
    pa, pb = pa + [0] * (width - len(pa)), pb + [0] * (width - len(pb))
    return (pa > pb) - (pa < pb)


__all__ = ["BY_PURL_TYPE", "Comparator", "VersionError", "apk", "dotted", "dpkg", "pypi", "rpm"]
