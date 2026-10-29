"""RPM version order: [epoch:]version[-release], each part compared by rpmvercmp.

rpmvercmp splits on non-alphanumerics and compares segment by segment: numbers as numbers
(leading zeros ignored), letters as strings, and a number beats letters. '~' sorts before
everything, even the end (1.0~rc1 < 1.0); '^' sorts after the end but before any further
segment (1.0 < 1.0^git1 < 1.0.1). Ported from rpm's rpmvio.c; tested against rpm's own
rpmvercmp cases.
"""

from vmp.pipeline.assess_fp.versions.errors import VersionError

_DIGITS = frozenset("0123456789")
_ALPHA = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_ALNUM = _DIGITS | _ALPHA


def compare(a: str, b: str) -> int:
    """-1, 0 or 1 as a sorts before, equal to or after b."""
    ea, va, ra = _split(a)
    eb, vb, rb = _split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    # A missing release matches any release, as rpm does when one side doesn't give one.
    return rpmvercmp(va, vb) or (rpmvercmp(ra, rb) if ra and rb else 0)


def _split(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch, sep, rest = v.partition(":")
    if not sep:
        epoch, rest = "0", v
    if not epoch.isdigit():
        raise VersionError(f"rpm epoch is not a number: {v!r}")
    version, _, release = rest.partition("-")
    if not version:
        raise VersionError(f"empty rpm version: {v!r}")
    return int(epoch), version, release


def rpmvercmp(a: str, b: str) -> int:
    """Kept as one function: a line-for-line port is easiest to check against rpm's source."""
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and a[i] not in _ALNUM and a[i] not in "~^":
            i += 1
        while j < len(b) and b[j] not in _ALNUM and b[j] not in "~^":
            j += 1

        ta, tb = i < len(a) and a[i] == "~", j < len(b) and b[j] == "~"
        if ta or tb:
            if not ta:
                return 1
            if not tb:
                return -1
            i, j = i + 1, j + 1
            continue

        ca, cb = i < len(a) and a[i] == "^", j < len(b) and b[j] == "^"
        if ca or cb:
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if not ca:
                return 1
            if not cb:
                return -1
            i, j = i + 1, j + 1
            continue

        if i >= len(a) or j >= len(b):
            break

        kind = _DIGITS if a[i] in _DIGITS else _ALPHA
        si, sj = i, j
        while i < len(a) and a[i] in kind:
            i += 1
        while j < len(b) and b[j] in kind:
            j += 1
        seg_a, seg_b = a[si:i], b[sj:j]
        is_num = kind is _DIGITS
        if not seg_b:
            return 1 if is_num else -1
        if is_num:
            seg_a, seg_b = seg_a.lstrip("0"), seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return -1 if len(seg_a) < len(seg_b) else 1
        if seg_a != seg_b:
            return -1 if seg_a < seg_b else 1

    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1
