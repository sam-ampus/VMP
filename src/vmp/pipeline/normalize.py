"""Endpoint normalisation, locked decision 4: many URLs, one endpoint.

Scanners report the endpoint they happened to hit: `/party/update_party/42/` today, `.../57/`
tomorrow, a bundle called `main.76a700c38298b5c8.js` that is renamed on every build. The thing
a developer fixes is the route, so the key is the route:

    resolved_asset + method + templated_path + sorted_param_names + cwe

- the host is replaced by the resolved asset (aliases already resolved at ingest), so the
  scheme, host case and default ports drop out with it;
- path segments that are IDs, UUIDs or content hashes become placeholders;
- parameter names are kept, values and fragments dropped.

When the customer has OpenAPI route templates, they are the authority (`routes`); the
patterns below are the fallback. Templating is conservative: a segment is only replaced
when it is unmistakably an identifier, because over-templating merges different routes.
"""

import re
from collections.abc import Iterable, Sequence
from urllib.parse import parse_qsl, urlsplit

from vmp.schema.finding import EndpointLocus
from vmp.schema.keys import MISSING

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_INT = re.compile(r"^\d+$")
# Hex content hash: 8+ hex chars with at least one digit and one letter (so "deadline" and
# "20261022" stay as they are; the second is an {id} by the integer rule anyway).
_HEX = re.compile(r"^(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{8,}$", re.I)
# Opaque token: 24+ base64url chars mixing letters and digits.
_TOKEN = re.compile(r"^(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9_-]{24,}$")


def template_segment(segment: str) -> str:
    if _INT.match(segment):
        return "{id}"
    if _UUID.match(segment):
        return "{uuid}"
    if _HEX.match(segment):
        return "{hash}"
    if _TOKEN.match(segment):
        return "{token}"
    if "." in segment:  # a file name: template its dot-separated parts, e.g. main.{hash}.js
        return ".".join("{hash}" if _HEX.match(p) else p for p in segment.split("."))
    return segment


def template_path(path: str, routes: Sequence[str] = ()) -> str:
    """'/party/update_party/42/' -> '/party/update_party/{id}/'. An OpenAPI route that
    matches wins over the heuristics."""
    path = path or "/"
    for route in routes:
        if _route_matches(route, path):
            return route
    return "/".join(template_segment(s) if s else s for s in path.split("/"))


def param_names(locus: EndpointLocus) -> tuple[str, ...]:
    """The tool's named parameters plus any query-string names, values dropped."""
    query = {name for name, _ in parse_qsl(urlsplit(locus.url).query, keep_blank_values=True)}
    return tuple(sorted({*locus.parameters, *query}))


def endpoint_correlation_key(locus: EndpointLocus, cwes: Iterable[str],
                             routes: Sequence[str] = ()) -> str:
    path = template_path(urlsplit(locus.url).path, routes)
    params = ",".join(param_names(locus)) or MISSING
    cwe = ",".join(sorted(set(cwes))) or MISSING
    return "|".join(["endpoint", locus.asset_ref, str(locus.method), path, params, cwe])


def _route_matches(route: str, path: str) -> bool:
    """'/users/{id}/orders' matches '/users/42/orders'. A placeholder matches one segment."""
    r, p = route.strip("/").split("/"), path.strip("/").split("/")
    return len(r) == len(p) and all(
        rs == ps or (rs.startswith("{") and rs.endswith("}")) for rs, ps in zip(r, p, strict=True))
