#!/usr/bin/env python3
"""Red test: verify the shared-instance fixture index is complete.

This test fails until all required fixture scenarios have been populated
by running the probe scripts.
"""

import json
import os
import sys

FIXTURE_DIR = os.path.join(
    os.path.dirname(__file__), "..", "fixtures", "shared-instance"
)
INDEX_PATH = os.path.join(FIXTURE_DIR, "index.json")


def test_index_exists():
    """The fixture index file must exist."""
    assert os.path.exists(INDEX_PATH), f"Fixture index not found at {INDEX_PATH}"


def test_index_valid_json():
    """The fixture index must be valid JSON with required fields."""
    with open(INDEX_PATH) as f:
        index = json.load(f)

    assert "reference_version" in index, "Missing reference_version"
    assert "reference_commit" in index, "Missing reference_commit"
    assert "scenarios" in index, "Missing scenarios"
    assert index["reference_version"] == "1.1.4", \
        f"Wrong version: {index['reference_version']}"


def test_all_scenarios_have_directories():
    """Every scenario in the index must have a corresponding directory."""
    with open(INDEX_PATH) as f:
        index = json.load(f)

    missing = []
    for scenario_path in index["scenarios"]:
        full_path = os.path.join(FIXTURE_DIR, scenario_path)
        if not os.path.isdir(full_path):
            missing.append(scenario_path)

    assert not missing, f"Missing scenario directories: {missing}"


def test_all_scenarios_have_required_files():
    """Every scenario must have all required files listed in the index.

    This is the RED test — it fails until golden traces are captured.
    """
    with open(INDEX_PATH) as f:
        index = json.load(f)

    missing = []
    for scenario_path, info in index["scenarios"].items():
        for required_file in info.get("required_files", []):
            full_path = os.path.join(FIXTURE_DIR, scenario_path, required_file)
            if not os.path.exists(full_path):
                missing.append(f"{scenario_path}/{required_file}")

    assert not missing, \
        f"Missing {len(missing)} required fixture files:\n" + \
        "\n".join(f"  - {m}" for m in missing)


if __name__ == "__main__":
    tests = [
        test_index_exists,
        test_index_valid_json,
        test_all_scenarios_have_directories,
        test_all_scenarios_have_required_files,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  PASS: {test.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL: {test.__name__}: {e}")
            failed += 1

    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
