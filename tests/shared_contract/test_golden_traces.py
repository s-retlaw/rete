#!/usr/bin/env python3
"""Validate golden trace quality beyond mere file existence.

This test checks that captured traces contain valid, useful data:
JSON validity, correct version, non-trivial content, pickle deserialization.
"""

import functools
import json
import os
import pickle
import sys

FIXTURE_DIR = os.path.join(
    os.path.dirname(__file__), "..", "fixtures", "shared-instance"
)
INDEX_PATH = os.path.join(FIXTURE_DIR, "index.json")


@functools.lru_cache(maxsize=None)
def _load_index():
    with open(INDEX_PATH) as f:
        return json.load(f)


def _all_scenario_dirs():
    """Yield (scenario_path, full_dir_path) for each scenario."""
    index = _load_index()
    for scenario_path in index["scenarios"]:
        yield scenario_path, os.path.join(FIXTURE_DIR, scenario_path)


def test_all_metadata_valid_json():
    """Every metadata.json must parse as valid JSON."""
    errors = []
    for scenario, d in _all_scenario_dirs():
        path = os.path.join(d, "metadata.json")
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                json.load(f)
        except json.JSONDecodeError as e:
            errors.append(f"{scenario}/metadata.json: {e}")
    assert not errors, "Invalid JSON:\n" + "\n".join(errors)


def test_all_metadata_has_required_keys():
    """Each metadata.json must have scenario, mode, and rns_version."""
    errors = []
    for scenario, d in _all_scenario_dirs():
        path = os.path.join(d, "metadata.json")
        if not os.path.exists(path):
            continue
        with open(path) as f:
            meta = json.load(f)
        for key in ("scenario", "mode", "rns_version"):
            if key not in meta:
                errors.append(f"{scenario}: missing '{key}'")
    assert not errors, "Missing metadata keys:\n" + "\n".join(errors)


def test_all_metadata_correct_version():
    """rns_version must be 1.1.4 in all metadata files."""
    errors = []
    for scenario, d in _all_scenario_dirs():
        path = os.path.join(d, "metadata.json")
        if not os.path.exists(path):
            continue
        with open(path) as f:
            meta = json.load(f)
        ver = meta.get("rns_version")
        if ver != "1.1.4":
            errors.append(f"{scenario}: rns_version={ver!r}")
    assert not errors, "Wrong versions:\n" + "\n".join(errors)


def test_all_notes_non_trivial():
    """notes.md must have at least 50 characters of content."""
    errors = []
    for scenario, d in _all_scenario_dirs():
        path = os.path.join(d, "notes.md")
        if not os.path.exists(path):
            continue
        size = os.path.getsize(path)
        if size < 50:
            errors.append(f"{scenario}/notes.md: only {size} bytes")
    assert not errors, "Trivial notes:\n" + "\n".join(errors)


def test_control_logs_non_trivial():
    """control.log in control-status-query scenarios must have content.

    Other scenarios may have empty control.log since rnsd writes to its
    own log file, not stderr. The daemon stderr is only non-empty when
    probe_control.py writes its own formatted output.
    """
    errors = []
    for mode in ("unix", "tcp"):
        path = os.path.join(FIXTURE_DIR, mode, "control-status-query", "control.log")
        if not os.path.exists(path):
            continue
        size = os.path.getsize(path)
        if size < 10:
            errors.append(f"{mode}/control-status-query/control.log: only {size} bytes")
    assert not errors, "Trivial control logs:\n" + "\n".join(errors)


def test_packets_logs_non_trivial():
    """packets.log files must have at least 20 characters."""
    errors = []
    for scenario, d in _all_scenario_dirs():
        path = os.path.join(d, "packets.log")
        if not os.path.exists(path):
            continue
        size = os.path.getsize(path)
        if size < 20:
            errors.append(f"{scenario}/packets.log: only {size} bytes")
    assert not errors, "Trivial packets logs:\n" + "\n".join(errors)


def test_rpc_binaries_exist_and_sized():
    """rpc_*.bin files in control-status-query scenarios must have expected min sizes."""
    min_sizes = {
        "rpc_auth.bin": 100,    # auth exchange is ~120 bytes
        "rpc_request.bin": 30,  # pickle request is ~39 bytes
        "rpc_response.bin": 200,  # pickle response is ~450 bytes
    }
    errors = []
    for mode in ("unix", "tcp"):
        d = os.path.join(FIXTURE_DIR, mode, "control-status-query")
        if not os.path.isdir(d):
            continue
        for name, min_size in min_sizes.items():
            path = os.path.join(d, name)
            if not os.path.exists(path):
                errors.append(f"{mode}/control-status-query/{name}: missing")
                continue
            size = os.path.getsize(path)
            if size < min_size:
                errors.append(f"{mode}/control-status-query/{name}: {size} < {min_size}")
    assert not errors, "RPC binary issues:\n" + "\n".join(errors)


def test_rpc_request_deserializes():
    """rpc_request.bin must deserialize to {"get": "interface_stats"}."""
    errors = []
    for mode in ("unix", "tcp"):
        path = os.path.join(FIXTURE_DIR, mode, "control-status-query", "rpc_request.bin")
        if not os.path.exists(path):
            continue
        with open(path, "rb") as f:
            data = f.read()
        obj = pickle.loads(data)
        if not isinstance(obj, dict):
            errors.append(f"{mode}: not a dict, got {type(obj).__name__}")
        elif obj.get("get") != "interface_stats":
            errors.append(f"{mode}: unexpected request: {obj}")
    assert not errors, "Request deserialization:\n" + "\n".join(errors)


def test_rpc_response_deserializes():
    """rpc_response.bin must deserialize to a dict with 'interfaces' key."""
    errors = []
    for mode in ("unix", "tcp"):
        path = os.path.join(FIXTURE_DIR, mode, "control-status-query", "rpc_response.bin")
        if not os.path.exists(path):
            continue
        with open(path, "rb") as f:
            data = f.read()
        obj = pickle.loads(data)
        if not isinstance(obj, dict):
            errors.append(f"{mode}: not a dict, got {type(obj).__name__}")
        elif "interfaces" not in obj:
            errors.append(f"{mode}: missing 'interfaces' key, got: {list(obj.keys())}")
    assert not errors, "Response deserialization:\n" + "\n".join(errors)


def test_rpc_pickle_protocols():
    """Request must use protocol 2, response must use protocol 4+."""
    errors = []
    for mode in ("unix", "tcp"):
        req_path = os.path.join(FIXTURE_DIR, mode, "control-status-query", "rpc_request.bin")
        resp_path = os.path.join(FIXTURE_DIR, mode, "control-status-query", "rpc_response.bin")

        if os.path.exists(req_path):
            with open(req_path, "rb") as f:
                data = f.read()
            if data[0:1] != b'\x80' or data[1] != 2:
                errors.append(f"{mode} request: expected proto 2, got {data[1]}")

        if os.path.exists(resp_path):
            with open(resp_path, "rb") as f:
                data = f.read()
            if data[0:1] != b'\x80' or data[1] < 4:
                errors.append(f"{mode} response: expected proto >= 4, got {data[1]}")
    assert not errors, "Protocol version issues:\n" + "\n".join(errors)


def test_scenario_count():
    """index.json must have exactly 12 scenarios."""
    index = _load_index()
    count = len(index["scenarios"])
    assert count == 12, f"Expected 12 scenarios, got {count}"


def test_all_statuses_complete():
    """All scenario statuses must be 'complete' in index.json."""
    index = _load_index()
    not_complete = []
    for path, info in index["scenarios"].items():
        status = info.get("status", "unknown")
        if status != "complete":
            not_complete.append(f"{path}: {status}")
    assert not not_complete, \
        "Scenarios not complete:\n" + "\n".join(not_complete)


if __name__ == "__main__":
    tests = [
        test_all_metadata_valid_json,
        test_all_metadata_has_required_keys,
        test_all_metadata_correct_version,
        test_all_notes_non_trivial,
        test_control_logs_non_trivial,
        test_packets_logs_non_trivial,
        test_rpc_binaries_exist_and_sized,
        test_rpc_request_deserializes,
        test_rpc_response_deserializes,
        test_rpc_pickle_protocols,
        test_scenario_count,
        test_all_statuses_complete,
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
