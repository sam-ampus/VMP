"""Endpoint normalisation (locked decision 4): templating is conservative and keyed on routes."""

import pytest

from vmp.pipeline.normalize import (
    endpoint_correlation_key,
    param_names,
    template_path,
    template_segment,
)
from vmp.schema.finding import EndpointLocus


def locus(url: str, method: str = "GET", params: tuple[str, ...] = (),
          asset: str = "ast_app") -> EndpointLocus:
    return EndpointLocus(type="endpoint", asset_ref=asset, url=url, method=method,  # type: ignore[arg-type]
                         parameters=params)


@pytest.mark.parametrize(("segment", "expected"), [
    ("42", "{id}"),
    ("3f2b8c1e-9d4a-4b6e-8f00-123456789abc", "{uuid}"),
    ("76a700c38298b5c8", "{hash}"),
    ("main.76a700c38298b5c8.js", "main.{hash}.js"),
    ("eyJhbGciOiJIUzI1NiJ9abc123xyz", "{token}"),
    # Left alone: words, short mixed names, dates-as-words, versions.
    ("update_party", "update_party"),
    ("deadline", "deadline"),
    ("v2", "v2"),
    ("api", "api"),
    ("styles.css", "styles.css"),
    ("cafe", "cafe"),
])
def test_template_segment(segment: str, expected: str) -> None:
    assert template_segment(segment) == expected


def test_skill_examples() -> None:
    assert template_path("/party/update_party/42/") == "/party/update_party/{id}/"
    assert template_path("/static/main.76a700c38298b5c8.js") == "/static/main.{hash}.js"


def test_openapi_route_wins_over_heuristics() -> None:
    # 'alice' would never be templated by the patterns; the customer's route says it's a param.
    assert template_path("/users/alice/orders", ["/users/{username}/orders"]) == (
        "/users/{username}/orders")
    assert template_path("/users/alice", ["/users/{username}/orders"]) == "/users/alice"


def test_params_are_names_only_from_tool_and_query() -> None:
    assert param_names(locus("https://a.example/s?q=1&page=2", params=("q", "sort"))) == (
        "page", "q", "sort")


def test_same_route_different_ids_scheme_port_query_values_and_fragment_is_one_key() -> None:
    a = endpoint_correlation_key(locus("https://app.example/u/42?x=1#top"), ["CWE-89"])
    b = endpoint_correlation_key(locus("http://APP.example:80/u/57?x=2"), ["CWE-89"])
    assert a == b == "endpoint|ast_app|GET|/u/{id}|x|CWE-89"


@pytest.mark.parametrize("change", [
    {"method": "POST"}, {"asset": "ast_other"}, {"params": ("y",)}])
def test_method_asset_and_param_names_separate_endpoints(change: dict[str, object]) -> None:
    base = endpoint_correlation_key(locus("https://app.example/u/42"), ["CWE-89"])
    kw: dict[str, object] = {"url": "https://app.example/u/42", **change}
    assert endpoint_correlation_key(locus(**kw), ["CWE-89"]) != base  # type: ignore[arg-type]


def test_different_cwes_on_one_endpoint_stay_separate() -> None:
    loc = locus("https://app.example/login", "POST")
    assert endpoint_correlation_key(loc, ["CWE-89"]) != endpoint_correlation_key(loc, ["CWE-79"])
