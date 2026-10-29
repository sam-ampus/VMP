"""Alpine (apk) version order: digits{.digits}[letter]{_suffix[n]}[-rN].

Compared in that order: the numbers (the first as a number; later ones as numbers unless
either has a leading zero, then as strings, so 1.01 < 1.1), the optional letter, the
suffixes, then the package revision. Suffixes _alpha < _beta < _pre < _rc sort before the
plain release, and _cvs < _svn < _git < _hg < _p after it. Follows apk-tools' version.c.
"""

import re
from itertools import zip_longest
from typing import Any

from vmp.pipeline.assess_fp.versions.errors import VersionError

_FORMAT = re.compile(
    r"^(?P<nums>\d+(?:\.\d+)*)(?P<letter>[a-z]?)"
    r"(?P<suffixes>(?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)"
    r"(?:-r(?P<rev>\d+))?$")
_SUFFIX = re.compile(r"_(alpha|beta|pre|rc|cvs|svn|git|hg|p)(\d*)")
# Relative to the plain release (0): pre-releases below, post-releases above.
_RANK = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1,
         "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}


def compare(a: str, b: str) -> int:
    """-1, 0 or 1 as a sorts before, equal to or after b."""
    pa, pb = _parse(a), _parse(b)
    for i, (x, y) in enumerate(zip_longest(pa[0], pb[0])):
        if x is None or y is None:
            # 1.0 vs 1.0.1: the version with more numbers is later.
            return -1 if x is None else 1
        if c := _num(x, y, first=i == 0):
            return c
    return _cmp(pa[1:], pb[1:])


def _num(x: str, y: str, *, first: bool) -> int:
    if not first and (x.startswith("0") or y.startswith("0")):
        return _cmp(x, y)
    return _cmp(int(x), int(y))


def _parse(v: str) -> tuple[list[str], str, list[tuple[int, int]], int]:
    m = _FORMAT.match(v.strip())
    if not m:
        raise VersionError(f"not an apk version: {v!r}")
    suffixes = [(_RANK[s], int(n or 0)) for s, n in _SUFFIX.findall(m["suffixes"])]
    # A version without suffixes is the plain release: rank 0, so pre < plain < post.
    return m["nums"].split("."), m["letter"], suffixes or [(0, 0)], int(m["rev"] or 0)


def _cmp(x: Any, y: Any) -> int:
    return int(x > y) - int(x < y)
