#!/usr/bin/env python3
"""Red test: verify the reference contract documents are complete.

Checks that all required fields in REFERENCE.md and SCOPE.md are populated.
"""

import os
import sys

CONTRACTS_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "docs", "shared-instance", "contracts"
)


def test_reference_md_exists():
    """REFERENCE.md must exist."""
    path = os.path.join(CONTRACTS_DIR, "REFERENCE.md")
    assert os.path.exists(path), f"REFERENCE.md not found at {path}"


def test_reference_has_pinned_version():
    """REFERENCE.md must have a pinned Python RNS version."""
    path = os.path.join(CONTRACTS_DIR, "REFERENCE.md")
    with open(path) as f:
        content = f.read()

    assert "Pinned Reference Version" in content, \
        "REFERENCE.md missing 'Pinned Reference Version' section"
    assert "1.1.4" in content, \
        "REFERENCE.md does not pin version 1.1.4"
    assert "Git commit:" in content or "Git commit" in content, \
        "REFERENCE.md missing git commit pin"


def test_reference_has_two_socket_architecture():
    """REFERENCE.md must document the two-socket architecture."""
    path = os.path.join(CONTRACTS_DIR, "REFERENCE.md")
    with open(path) as f:
        content = f.read()

    assert "Two-Socket Architecture" in content, \
        "REFERENCE.md missing 'Two-Socket Architecture' section"
    assert "Data Socket" in content, \
        "REFERENCE.md missing 'Data Socket' section"
    assert "Control/RPC Socket" in content, \
        "REFERENCE.md missing 'Control/RPC Socket' section"


def test_reference_has_rpc_commands():
    """REFERENCE.md must list in-scope RPC commands."""
    path = os.path.join(CONTRACTS_DIR, "REFERENCE.md")
    with open(path) as f:
        content = f.read()

    assert "In-Scope RPC Commands" in content, \
        "REFERENCE.md missing 'In-Scope RPC Commands' section"
    assert "interface_stats" in content, \
        "REFERENCE.md missing interface_stats command"
    assert "path_table" in content, \
        "REFERENCE.md missing path_table command"


def test_scope_md_exists():
    """SCOPE.md must exist."""
    path = os.path.join(CONTRACTS_DIR, "SCOPE.md")
    assert os.path.exists(path), f"SCOPE.md not found at {path}"


def test_scope_has_frozen_config():
    """SCOPE.md must have a frozen config surface table."""
    path = os.path.join(CONTRACTS_DIR, "SCOPE.md")
    with open(path) as f:
        content = f.read()

    assert "Frozen Config Surface" in content, \
        "SCOPE.md missing 'Frozen Config Surface' section"

    required_keys = [
        "share_instance",
        "instance_name",
        "shared_instance_type",
        "shared_instance_port",
        "instance_control_port",
        "rpc_key",
    ]
    for key in required_keys:
        assert key in content, \
            f"SCOPE.md missing config key: {key}"


def test_diffs_md_exists():
    """DIFFS.md must exist."""
    path = os.path.join(CONTRACTS_DIR, "DIFFS.md")
    assert os.path.exists(path), f"DIFFS.md not found at {path}"


def test_golden_traces_md_exists():
    """GOLDEN_TRACES.md must exist."""
    path = os.path.join(CONTRACTS_DIR, "GOLDEN_TRACES.md")
    assert os.path.exists(path), f"GOLDEN_TRACES.md not found at {path}"


if __name__ == "__main__":
    tests = [
        test_reference_md_exists,
        test_reference_has_pinned_version,
        test_reference_has_two_socket_architecture,
        test_reference_has_rpc_commands,
        test_scope_md_exists,
        test_scope_has_frozen_config,
        test_diffs_md_exists,
        test_golden_traces_md_exists,
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
