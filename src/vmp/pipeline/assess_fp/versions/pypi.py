"""Python package version order (PEP 440), via `packaging`, the reference implementation."""

from packaging.version import InvalidVersion, Version

from vmp.pipeline.assess_fp.versions.errors import VersionError


def compare(a: str, b: str) -> int:
    """-1, 0 or 1 as a sorts before, equal to or after b."""
    try:
        va, vb = Version(a), Version(b)
    except InvalidVersion as exc:
        raise VersionError(str(exc)) from exc
    return (va > vb) - (va < vb)
