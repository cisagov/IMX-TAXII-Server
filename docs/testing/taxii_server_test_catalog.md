# TAXII API Test Catalog

## How to Run Tests

You can run the entire test suite with the following command from the repository root:
```bash
pytest -v tests/
```

## Coverage

Run the coverage report with:
```bash
pytest --cov --cov-report=term --cov-report=xml:coverage.xml
```


## Adding a New Test

1. Place the test in `tests/` following the naming convention `test_*.py`.
2. Mark the test with relevant markers if needed (e.g., `@pytest.mark.parametrize`).
3. Run the test locally to ensure it passes before committing.
4. Add a brief description to this catalog so future contributors have context.

---

This file lists the tests in `tests/test_taxii_api.py` along with a brief description of the behavior they verify.

## Discovery
- **test_server_discovery_with_auth_header** – Server discovery with authentication header.
- **test_api_root_resource** – Verify presence of an API Root.
- **test_non_existent_api_root_resource** – Ensure 404 for missing API root.

## Collections CRUD
- **test_get_collections_resource** – Retrieve collections list.
- **test_get_collection** – Retrieve a specific collection by ID.
- **test_get_read_only_collection** – Ensure read‑only collection permissions.
- **test_get_write_only_collection** – Ensure write‑only collection permissions.
- **test_get_no_read_write_collection** – Ensure collection with neither read nor write.
- **test_get_collection_with_no_trailing_slash** – Verify 403 when URL lacks trailing slash.
- **test_get_non_existent_collection** – 404 for non‑existing collection.

## Object Operations
- **test_read_request_for_write_only_collection** – 403 on read of write‑only collection.
- **test_write_request_for_read_only_collection** – 403 on write to read‑only collection.
- **test_read_request_for_no_read_write_collection** – 403 on read when collection has no permissions.
- **test_write_request_for_no_read_write_collection** – 403 on write when collection has no permissions.
- **test_delete_object_from_collection** – Delete an existing object.
- **test_add_indicator_pattern_collection** – Add indicator object with pattern.
- **test_get_all_objects_from_collection** – Retrieve all objects from a collection.
- **test_get_all_collection_objects_empty_collection** – Ensure empty result for empty collection.
- **test_get_non_existent_object** – 404 for missing object.
- **test_get_object_versions** – Retrieve all versions of an object.
- **test_get_2_objects_from_collection_manifest** – Retrieve two objects from manifest.
- **test_get_indicator_type_object_from_collection** – Retrieve indicator object by type.
- **test_get_indicator_type_object_manifest_from_collection** – Retrieve manifest entries for indicator type.
- **test_get_object_last_version** – Retrieve latest version of an object.
- **test_get_object_of_specified_spec_version** – Retrieve an object of a specific STIX version.

## Filtering and Operators
- **test_logical_or_operator** – Logical OR filter.
- **test_logical_and_operator** – Logical AND filter.
- **test_logical_or_and_operator** – Combined OR and AND.
- **test_duplicate_filters** – Ensure duplicate filters are handled.

## Tiers and Relationships
- **test_tier1_testcase** – Tier 1 test case.
- **test_tier2_testcase** – Tier 2 test case.
- **test_tier3_testcase** – Tier 3 test case.
- **test_relationships_testcase** – Test relationships among objects.

## Calculations & Custom Properties
- **test_calculation_testcase** – Perform calculations.
- **test_custom_property** – Verify custom property handling.
- **test_match_country** – Filter by country.
- **test_match_administrative_area** – Filter by administrative area.
- **test_match_administrative_area_virginia** – Filter specifically for Virginia.

*Note: The catalog focuses on test names and intents; line numbers are omitted for brevity.*