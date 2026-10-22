# 04 — Asset inventory (Stage 1, step 4)

*Built 2026-10-22.*

## Problem from first principles

The same CVE is a different risk on different machines. A critical bug on an internet-facing payments system is an emergency; on an isolated test box it's a backlog item. Scanners know *what* is wrong, but not *how much it matters here*. That context has to come from somewhere the organisation controls: an inventory.

What must be true:
- **A finding names its asset however the scanner saw it**: an IP, a hostname, an FQDN, `host:port` or an image name. All of these must land on **one** asset.
- **An identifier that could mean two assets must be refused.** Otherwise one finding silently borrows another asset's exposure and criticality. That's a wrong score with no error.
- **An asset we know nothing about must stay "unknown",** not quietly become "internal, low criticality". Locked into scoring on 2026-10-12: unknown scores 0 and is listed as missing.
- **A score must be replayable,** so we need to know *which* inventory it used.

## System view

```
connector ─► Finding.locus.asset_ref / ip / hostname / url host
                          │
                          ▼
              AssetProvider.resolve(identifier) ──► Asset | None
                          │                           internet_facing, criticality,
                          ▼                           environment  (None = unknown)
              ScoringInput (step 5 glue) ─► score() ─► RiskAssessment.asset_inventory_id
```

- **Sits at:** beside the pipeline. It's a lookup service used when building `ScoringInput`, and later by correlation and endpoint normalisation.
- **In:** a CSV file today. Later: a CMDB, ServiceNow or a cloud inventory.
- **Out:** a frozen `Asset`, or `None`.
- **May not know:** findings, scores or scanners. It answers "what is this asset?" and nothing else.

## What was built

| File | Holds |
|---|---|
| `src/vmp/assets/model.py` | `Asset` (frozen; each context field may be `None`); `normalise_identifier()` |
| `src/vmp/assets/inventory.py` | `AssetProvider` Protocol; `AssetInventory`, the in-memory lookup; `AssetInventoryError` |
| `src/vmp/assets/csv_source.py` | `parse_asset_csv()` (pure) and `load_asset_csv()` (file → inventory) |
| `src/vmp/schema/vulnerability.py` | `RiskAssessment.asset_inventory_id`, a new field |
| `tests/assets/` | 22 tests, plus `inventory.csv` matching the sample findings |

CSV format: `asset_ref,name,aliases,internet_facing,criticality,environment,owner`. Aliases are separated by `;`, and a blank cell means unknown.

## Choices and trade-offs

- **The Protocol is separate from the storage.** The plan named a `CsvAssetProvider`. Instead, CSV is only a *parser*, and `AssetInventory` doesn't care where its rows came from.
  - A CMDB adapter later is a new parser, not a new provider.
  - The intel layer uses the same split (parse vs fetch).
- **Ambiguity fails at load time, never at lookup.** Two assets claiming one alias, an alias equal to another asset's ref, or a duplicate ref: the whole inventory is rejected with every problem listed.
  - *Trade-off:* a messy real-world CMDB will be rejected until it's cleaned. That's deliberate, because guessing would corrupt scores silently.
  - If it hurts, the fix is an explicit override list, not a looser rule.
- **One spelling per identifier.** Lowercased, trimmed, and IPs put in canonical form (`2001:DB8:0:0::1` → `2001:db8::1`).
  - Port stripping and URL parsing are **not** done here. Those belong to endpoint normalisation (locked decision 4, Stage 2 step 7).
  - Here, `192.168.100.10:8000` is just an alias string.
- **Partial rows are allowed.** A host with only a name and IP is valid. Its blank fields reach scoring as `None` and show up in the UI as evidence gaps.
- **Content-addressed inventory id.** A SHA-256 of the sorted, normalised assets. Same inventory, same id, regardless of row order.
  - Stored on `RiskAssessment` next to `weights_version` and `intel_snapshot_id`.
  - With all three recorded, any score can be recomputed exactly. Without the inventory id, "why did this score change?" would have no answer when someone edits the CSV.
- **`owner` is stored as context only.** Owner *routing* stays out of scope (Donna's ask).

**Deviation from the plan:** the mock `seed/demo/assets.csv` moves to step 5. It has to match the hosts and images in whichever DefectDojo scans we pick, and those get chosen there. Writing it now would mean inventing assets and fixing them later.

## Systems-thinking angle

- **Stocks of trust.** Every downstream number (score, ranking, report) inherits the inventory's errors. A wrong `internet_facing` flag is worth ±15 points (+10 vs −5) on every finding for that asset. The cheapest place to stop an error is where it enters, which is why load-time validation is strict.
- **Interfaces as seams for change.** The thing most likely to change at the customer is *where asset data lives*, so that's exactly where the Protocol sits.
- **Cross-component consistency is tested, not assumed.** `test_inventory_agrees_with_the_sample_scoring_vectors` checks that the inventory supplies the same context the hand-written scoring vectors assumed. If either side drifts, the test fails.

## Applied AI tie-in

- **The evidence agent (role 1) will call `resolve()` as a tool.** Its output contract already allows "unknown", so the agent never has to invent exposure.
- **"None vs default" is the same lesson as "unknown is not no" in step 3.** An agent or retrieval step that returns nothing must not be read as a negative answer.
- **Reproducibility needs every input versioned**: weights, intel and assets. The same rule applies to an LLM eval: pin the prompts, the model and the data, or results can't be compared across runs.

## Code tour

1. `src/vmp/assets/model.py`: `Asset`, `normalise_identifier`.
2. `src/vmp/assets/inventory.py`: `AssetProvider`, then `AssetInventory.__init__` (where ambiguity is caught).
3. `src/vmp/assets/csv_source.py`: `parse_asset_csv` (how errors are collected per line).
4. `tests/assets/inventory.csv`, then `tests/assets/test_inventory.py`.

## Check yourself

1. Why is "an alias maps to two assets" an error at load rather than "pick the first match" at lookup? Give the concrete wrong score it would cause.
2. Someone flips `internet_facing` from `false` to `true` for the k-client image. What changes in the system, and how would you prove later which value a given score used?
3. The customer wants to use ServiceNow instead of a CSV. Which files change and which don't?
