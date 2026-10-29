"""Debian/Ubuntu version order, as dpkg defines it (deb-version(7), dpkg's verrevcmp).

[epoch:]upstream[-revision]. Epoch compares as a number; upstream and revision compare
segment by segment: a run of non-digits by character order, then a run of digits as a number.
In the character order letters sort before other symbols, and '~' sorts before everything,
even the end of the string. That's why 1.0~rc1 < 1.0, and why Ubuntu's "1ubuntu1" sorts
after Debian's "1".
"""

from vmp.pipeline.assess_fp.versions.errors import VersionError


def compare(a: str, b: str) -> int:
    """-1, 0 or 1 as a sorts before, equal to or after b."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


def _split(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch, sep, rest = v.partition(":")
    if not sep:
        epoch, rest = "0", v
    if not epoch.isdigit():
        raise VersionError(f"dpkg epoch is not a number: {v!r}")
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    if not upstream or not upstream[0].isdigit():
        raise VersionError(f"dpkg upstream version must start with a digit: {v!r}")
    return int(epoch), upstream, revision


def _order(c: str) -> int:
    if c == "~":
        return -1
    if c.isascii() and c.isalpha():
        return ord(c)
    return ord(c) + 256


def _is_digit(s: str, i: int) -> bool:
    return i < len(s) and s[i] in "0123456789"


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not _is_digit(a, i)) or (j < len(b) and not _is_digit(b, j)):
            ac = _order(a[i]) if i < len(a) and not _is_digit(a, i) else 0
            bc = _order(b[j]) if j < len(b) and not _is_digit(b, j) else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i, j = i + 1, j + 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while _is_digit(a, i) and _is_digit(b, j):
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i, j = i + 1, j + 1
        if _is_digit(a, i):
            return 1
        if _is_digit(b, j):
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0
