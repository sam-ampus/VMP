"""Asset inventory: CSV parsing, alias resolution, ambiguity errors, replayable identity."""

import json
from pathlib import Path
from typing import Any

import pytest

from vmp.assets import (
    Asset,
    AssetInventory,
    AssetInventoryError,
    AssetProvider,
    load_asset_csv,
    parse_asset_csv,
)
from vmp.schema.enums import AssetCriticality, Environment

HERE = Path(__file__).parent
REPO = HERE.parents[1]
HEADER = "asset_ref,name,aliases,internet_facing,criticality,environment,owner\n"


@pytest.fixture
def inventory() -> AssetInventory:
    return load_asset_csv(HERE / "inventory.csv")


def test_is_an_asset_provider(inventory: AssetInventory) -> None:
    provider: AssetProvider = inventory  # checked by mypy: the Protocol is satisfied
    assert provider.resolve("qa3app09") is not None


def test_every_fixture_finding_resolves(inventory: AssetInventory, batch: dict[str, Any]) -> None:
    for finding in batch["findings"]:
        ref = finding["locus"]["asset_ref"]
        asset = inventory.resolve(ref)
        assert asset is not None and asset.asset_ref == ref


def test_inventory_agrees_with_the_sample_scoring_vectors(inventory: AssetInventory) -> None:
    """The vectors assumed this asset context by hand; the inventory must supply the same."""
    cases = json.loads((REPO / "tests/scoring/vectors/w-0.1.json").read_text("utf-8"))["cases"]
    by_id = {c["id"]: c["input"] for c in cases}
    expected = {
        "sample_sqli_login": "ast_erp-fintec-solutions",
        "sample_cilium": "ast_k-client-image",
        "sample_rdp_mitm": "ast_10-31-112-29",
    }
    for case_id, ref in expected.items():
        asset = inventory.resolve(ref)
        assert asset is not None
        vector = by_id[case_id]
        assert asset.internet_facing == vector["internet_facing"], case_id
        assert asset.criticality == vector["asset_criticality"], case_id
        assert asset.environment == vector["environment"], case_id


@pytest.mark.parametrize("identifier", [
    "ast_10-31-112-29", "10.31.112.29", "qa3app09", "QA3APP09", "  qa3app09.corp.local ",
])
def test_resolves_by_ref_or_any_alias_case_insensitively(
    inventory: AssetInventory, identifier: str
) -> None:
    asset = inventory.resolve(identifier)
    assert asset is not None and asset.asset_ref == "ast_10-31-112-29"


def test_alias_resolution_joins_ip_and_hostname_of_one_application(
    inventory: AssetInventory,
) -> None:
    """The canonical-schema example: 192.168.100.10:8000 and erp.fintec.solutions are one app."""
    assert inventory.resolve("192.168.100.10:8000") == inventory.resolve("erp.fintec.solutions")


def test_ip_addresses_are_canonicalised() -> None:
    inv = AssetInventory([Asset(asset_ref="ast_v6", name="v6", aliases=("2001:DB8:0:0::1",))])
    assert inv.resolve("2001:db8::1") is not None


def test_unknown_asset_is_none_not_a_default(inventory: AssetInventory) -> None:
    assert inventory.resolve("10.99.99.99") is None


def test_blank_fields_stay_unknown(inventory: AssetInventory) -> None:
    asset = inventory.resolve("ast_unassessed-host")
    assert asset is not None
    assert (asset.internet_facing, asset.criticality, asset.environment, asset.owner) == (
        None, None, None, None)


def test_parsed_values_are_typed(inventory: AssetInventory) -> None:
    erp = inventory.resolve("erp.fintec.solutions")
    assert erp is not None
    assert erp.internet_facing is True
    assert erp.criticality is AssetCriticality.CRITICAL
    assert erp.environment is Environment.PRODUCTION


def test_alias_shared_by_two_assets_is_rejected() -> None:
    with pytest.raises(AssetInventoryError, match=r"'10\.0\.0\.1' maps to both ast_a and ast_b"):
        AssetInventory([
            Asset(asset_ref="ast_a", name="a", aliases=("10.0.0.1",)),
            Asset(asset_ref="ast_b", name="b", aliases=("10.0.0.1",)),
        ])


def test_alias_equal_to_another_assets_ref_is_rejected() -> None:
    with pytest.raises(AssetInventoryError, match="maps to both"):
        AssetInventory([
            Asset(asset_ref="ast_a", name="a"),
            Asset(asset_ref="ast_b", name="b", aliases=("AST_A",)),
        ])


def test_duplicate_asset_ref_is_rejected() -> None:
    with pytest.raises(AssetInventoryError, match="duplicate asset_ref ast_a"):
        AssetInventory([Asset(asset_ref="ast_a", name="a"), Asset(asset_ref="ast_a", name="b")])


def test_every_bad_row_is_reported_with_its_line() -> None:
    text = HEADER + (
        "ast_ok,ok,,true,high,production,\n"
        "ast_bad1,bad,,yes,,,\n"
        "bad ref,bad,,,,,\n"
        "ast_bad3,bad,,,severe,,\n"
    )
    with pytest.raises(AssetInventoryError) as exc:
        parse_asset_csv(text)
    lines = [e.split(":")[0] for e in exc.value.errors]
    assert lines == ["line 3", "line 4", "line 5"]


def test_header_must_match_exactly() -> None:
    with pytest.raises(AssetInventoryError, match=r"missing \['owner'\], unknown \['team'\]"):
        parse_asset_csv("asset_ref,name,aliases,internet_facing,criticality,environment,team\n")


def test_extra_values_in_a_row_are_rejected() -> None:
    with pytest.raises(AssetInventoryError, match="more values than columns"):
        parse_asset_csv(HEADER + "ast_a,a,,,,,,surprise\n")


def test_excel_bom_and_blank_lines_are_tolerated() -> None:
    assets = parse_asset_csv("﻿" + HEADER + "ast_a,a,,,,,\n,,,,,,\n")
    assert [a.asset_ref for a in assets] == ["ast_a"]


def test_inventory_id_ignores_row_order_but_not_content() -> None:
    a = Asset(asset_ref="ast_a", name="a", aliases=("x", "y"))
    b = Asset(asset_ref="ast_b", name="b", internet_facing=True)
    assert AssetInventory([a, b]).inventory_id == AssetInventory([b, a]).inventory_id
    assert Asset(asset_ref="ast_a", name="a", aliases=("y", "x")) == a
    changed = b.model_copy(update={"internet_facing": False})
    assert AssetInventory([a, changed]).inventory_id != AssetInventory([a, b]).inventory_id


def test_assets_are_immutable(inventory: AssetInventory) -> None:
    asset = inventory.assets[0]
    with pytest.raises(ValueError, match="frozen"):
        asset.internet_facing = True
