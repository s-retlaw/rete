# rete — Reticulum Network Stack in Rust
#
# Run `just` to see all available recipes.
# Run `just <recipe>` to execute one.

# Default: list available recipes
default:
    @just --list --unsorted

# --------------------------------------------------------------------------
# Core development
# --------------------------------------------------------------------------

# Run all workspace tests (unit only, no external deps)
test:
    cargo test --workspace

# Unit tests with summary (shows full output + concise summary at end)
test-unit:
    #!/usr/bin/env bash
    set -o pipefail
    OUTPUT=$(cargo test --workspace 2>&1)
    RC=$?
    echo "$OUTPUT"
    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "  Unit Test Summary"
    echo "───────────────────────────────────────────────────"
    SUITE=""; TOTAL_PASS=0; TOTAL_FAIL=0; TOTAL_IGN=0
    while IFS= read -r line; do
        if echo "$line" | grep -qP '^\s+Running .*/deps/(\S+)'; then
            SUITE=$(echo "$line" | grep -oP 'deps/\K[^-]+' | sed 's/_/-/g')
        elif echo "$line" | grep -qP '^\s+Doc-tests '; then
            SUITE=$(echo "$line" | grep -oP 'Doc-tests \K\S+')"-docs"
        elif echo "$line" | grep -qP '^test result:'; then
            P=$(echo "$line" | grep -oP '\d+ passed' | grep -oP '\d+'); P=${P:-0}
            F=$(echo "$line" | grep -oP '\d+ failed' | grep -oP '\d+'); F=${F:-0}
            I=$(echo "$line" | grep -oP '\d+ ignored' | grep -oP '\d+'); I=${I:-0}
            if [ "$((P + F + I))" -gt 0 ]; then
                IGN_STR=""; [ "$I" -gt 0 ] && IGN_STR=", $I ignored"
                printf "  %-30s %s passed, %s failed%s\n" "$SUITE" "$P" "$F" "$IGN_STR"
            fi
            TOTAL_PASS=$((TOTAL_PASS + P)); TOTAL_FAIL=$((TOTAL_FAIL + F)); TOTAL_IGN=$((TOTAL_IGN + I))
        fi
    done <<< "$OUTPUT"
    echo "───────────────────────────────────────────────────"
    IGN_TOTAL=""; [ "$TOTAL_IGN" -gt 0 ] && IGN_TOTAL=", $TOTAL_IGN ignored"
    if [ "$TOTAL_FAIL" -eq 0 ]; then
        echo "  TOTAL: $TOTAL_PASS passed, $TOTAL_FAIL failed${IGN_TOTAL} ✓"
    else
        echo "  TOTAL: $TOTAL_PASS passed, $TOTAL_FAIL failed${IGN_TOTAL} ✗"
    fi
    echo "═══════════════════════════════════════════════════"
    exit $RC

# E2E interop against Python RNS (requires uv + rns)
test-e2e:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python live_interop.py

# E2E relay interop (3-node topology)
test-e2e-relay:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python relay_interop.py

# E2E transport relay interop (Rust as multi-interface transport relay)
test-e2e-transport-relay:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python transport_relay_interop.py

# E2E path request interop (Rust responds to path requests)
test-e2e-path-request:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python path_request_interop.py

# E2E proof routing interop (proofs route back through Rust relay)
test-e2e-proof-routing:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python proof_routing_interop.py

# All software tests (unit + E2E, no hardware)
test-all:
    #!/usr/bin/env bash
    set -o pipefail

    # --- Build everything upfront ---
    echo "Building..."
    cargo build -p rete-example-linux 2>&1
    echo ""

    # --- Unit tests ---
    UNIT_OUTPUT=$(cargo test --workspace 2>&1)
    UNIT_RC=$?
    echo "$UNIT_OUTPUT"

    # Parse unit results
    UNIT_PASS=0; UNIT_FAIL=0; UNIT_IGN=0; UNIT_SUITES=""
    SUITE=""
    while IFS= read -r line; do
        if echo "$line" | grep -qP '^\s+Running .*/deps/(\S+)'; then
            SUITE=$(echo "$line" | grep -oP 'deps/\K[^-]+' | sed 's/_/-/g')
        elif echo "$line" | grep -qP '^\s+Doc-tests '; then
            SUITE=$(echo "$line" | grep -oP 'Doc-tests \K\S+')"-docs"
        elif echo "$line" | grep -qP '^test result:'; then
            P=$(echo "$line" | grep -oP '\d+ passed' | grep -oP '\d+'); P=${P:-0}
            F=$(echo "$line" | grep -oP '\d+ failed' | grep -oP '\d+'); F=${F:-0}
            I=$(echo "$line" | grep -oP '\d+ ignored' | grep -oP '\d+'); I=${I:-0}
            if [ "$((P + F + I))" -gt 0 ]; then
                IGN_STR=""; [ "$I" -gt 0 ] && IGN_STR=", $I ignored"
                UNIT_SUITES+=$(printf "\n  %-30s %s passed, %s failed%s" "$SUITE" "$P" "$F" "$IGN_STR")
            fi
            UNIT_PASS=$((UNIT_PASS + P)); UNIT_FAIL=$((UNIT_FAIL + F)); UNIT_IGN=$((UNIT_IGN + I))
        fi
    done <<< "$UNIT_OUTPUT"

    if [ "$UNIT_RC" -ne 0 ]; then
        echo ""
        echo "═══════════════════════════════════════════════════"
        echo "  Unit tests FAILED — skipping E2E"
        echo "$UNIT_SUITES"
        echo "═══════════════════════════════════════════════════"
        exit $UNIT_RC
    fi

    echo ""

    # --- E2E tests ---
    E2E_ANY_FAIL=0

    # Helper to run one E2E suite and parse results
    run_e2e() {
        local label="$1" script="$2"
        local output rc
        output=$(cd tests/interop && uv run python "$script" 2>&1)
        rc=$?
        echo "$output"
        local p t f
        p=$(echo "$output" | grep -oP '\d+(?=/\d+ passed)' || echo "0")
        t=$(echo "$output" | grep -oP '(?<=Results: )\d+/\d+' | head -1 | cut -d/ -f2)
        t=${t:-0}; f=$((t - p))
        eval "${label}_PASS=$p"; eval "${label}_FAIL=$f"
        [ "$rc" -ne 0 ] && E2E_ANY_FAIL=1
        echo ""
    }

    run_e2e LIVE live_interop.py
    run_e2e RELAY relay_interop.py
    run_e2e TRANSPORT transport_relay_interop.py
    run_e2e PATHREQ path_request_interop.py
    run_e2e PROOF proof_routing_interop.py

    # --- Combined summary ---
    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "  Test Summary"
    echo "───────────────────────────────────────────────────"
    echo "  Unit tests:"
    echo "$UNIT_SUITES"
    IGN_TOTAL=""; [ "$UNIT_IGN" -gt 0 ] && IGN_TOTAL=", $UNIT_IGN ignored"
    echo ""
    printf "  %-30s %s passed, %s failed%s\n" "unit total" "$UNIT_PASS" "$UNIT_FAIL" "$IGN_TOTAL"
    echo ""
    echo "  E2E tests:"
    printf "  %-30s %s passed, %s failed\n" "live-interop" "$LIVE_PASS" "$LIVE_FAIL"
    printf "  %-30s %s passed, %s failed\n" "relay-interop" "$RELAY_PASS" "$RELAY_FAIL"
    printf "  %-30s %s passed, %s failed\n" "transport-relay-interop" "$TRANSPORT_PASS" "$TRANSPORT_FAIL"
    printf "  %-30s %s passed, %s failed\n" "path-request-interop" "$PATHREQ_PASS" "$PATHREQ_FAIL"
    printf "  %-30s %s passed, %s failed\n" "proof-routing-interop" "$PROOF_PASS" "$PROOF_FAIL"
    E2E_PASS=$((LIVE_PASS + RELAY_PASS + TRANSPORT_PASS + PATHREQ_PASS + PROOF_PASS))
    E2E_FAIL=$((LIVE_FAIL + RELAY_FAIL + TRANSPORT_FAIL + PATHREQ_FAIL + PROOF_FAIL))
    echo ""
    printf "  %-30s %s passed, %s failed\n" "e2e total" "$E2E_PASS" "$E2E_FAIL"
    echo "───────────────────────────────────────────────────"
    ALL_PASS=$((UNIT_PASS + E2E_PASS))
    ALL_FAIL=$((UNIT_FAIL + E2E_FAIL))
    if [ "$ALL_FAIL" -eq 0 ] && [ "$E2E_ANY_FAIL" -eq 0 ]; then
        echo "  ALL: $ALL_PASS passed, $ALL_FAIL failed ✓"
    else
        echo "  ALL: $ALL_PASS passed, $ALL_FAIL failed ✗"
    fi
    echo "═══════════════════════════════════════════════════"
    exit $((UNIT_RC + E2E_ANY_FAIL))

# Check all workspace crates compile
check:
    cargo check --workspace

# Run clippy on the workspace
lint:
    cargo clippy --workspace -- -D warnings

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Auto-format
fmt:
    cargo fmt --all

# Full CI suite (test + lint + fmt)
ci: test lint fmt-check

# Full CI with E2E
ci-full: test-unit lint fmt-check test-e2e

# --------------------------------------------------------------------------
# ESP32-C6 (serial — no WiFi needed, just USB cable)
# --------------------------------------------------------------------------

esp32c6_target := "riscv32imac-unknown-none-elf"
esp32c6_dir := "examples/esp32c6"
serial_port := env("SERIAL_PORT", "/dev/ttyUSB0")

# Build the ESP32-C6 serial firmware
build-esp32c6:
    cd {{esp32c6_dir}} && cargo +nightly build --release \
        --features esp32c6 --bin rete-esp32c6-serial \
        --target {{esp32c6_target}}

# Flash the ESP32-C6 serial firmware
flash-esp32c6: build-esp32c6
    espflash flash --port {{serial_port}} \
        {{esp32c6_dir}}/target/{{esp32c6_target}}/release/rete-esp32c6-serial

# Build the ESP32-C6 WiFi firmware
build-esp32c6-wifi:
    cd {{esp32c6_dir}} && SSID="${SSID:-YOUR_SSID}" PASSWORD="${PASSWORD:-YOUR_PASSWORD}" \
        RNSD_HOST="${RNSD_HOST:-192.168.1.100}" RNSD_PORT="${RNSD_PORT:-4242}" \
        cargo +nightly build --release \
        --features esp32c6,wifi --bin rete-esp32c6 \
        --target {{esp32c6_target}}

# Flash the ESP32-C6 WiFi firmware
flash-esp32c6-wifi: build-esp32c6-wifi
    espflash flash --port {{serial_port}} \
        {{esp32c6_dir}}/target/{{esp32c6_target}}/release/rete-esp32c6

# --------------------------------------------------------------------------
# Linux example
# --------------------------------------------------------------------------

# Run the Linux node over serial (talks to flashed ESP32-C6)
run-linux-serial *ARGS:
    cargo run -p rete-example-linux -- --serial {{serial_port}} {{ARGS}}

# Run the Linux node over TCP (talks to rnsd)
run-linux-tcp *ARGS:
    cargo run -p rete-example-linux -- --connect ${RNSD_ADDR:-127.0.0.1:4242} {{ARGS}}

# --------------------------------------------------------------------------
# End-to-end test: ESP32-C6 <-> Linux over serial
# --------------------------------------------------------------------------

# Flash ESP32-C6, exchange data with echo, verify round-trip
e2e-esp32c6: build-esp32c6
    #!/usr/bin/env bash
    set -euo pipefail
    # Pre-build Linux binary so it starts instantly after flash
    cargo build -p rete-example-linux
    # Flash ESP32
    espflash flash --port {{serial_port}} \
        {{esp32c6_dir}}/target/{{esp32c6_target}}/release/rete-esp32c6-serial
    echo ""
    echo "=== ESP32-C6 flashed ==="
    echo "=== Flow: Linux sends ping:<timestamp> → ESP32 echoes back echo:ping:<timestamp> ==="
    echo ""
    # Start Linux node immediately — catches ESP32 boot + initial announce.
    # HDLC decoder ignores bootloader/log output on serial.
    sleep 0.5
    OUTPUT=$(timeout 30 cargo run -p rete-example-linux -- \
        --serial {{serial_port}} --auto-reply-ping \
        --peer-seed rete-esp32c6-serial \
        2>&1 || true)
    echo "$OUTPUT"
    echo ""
    # Extract the ping timestamp from the log
    PING=$(echo "$OUTPUT" | grep -oP 'will send on start: \Kping:\d+' || true)
    if [ -z "$PING" ]; then
        echo "=== FAIL: could not find ping message ==="
        exit 1
    fi
    echo "=== Sent: $PING ==="
    # Check the echoed DATA contains "echo:<original ping>"
    if echo "$OUTPUT" | grep -q "DATA:.*:echo:$PING"; then
        ECHO_LINE=$(echo "$OUTPUT" | grep "DATA:.*:echo:$PING")
        echo "=== PASS: ESP32 echoed back: $ECHO_LINE ==="
    else
        echo "=== FAIL: expected DATA containing 'echo:$PING' ==="
        exit 1
    fi

# --------------------------------------------------------------------------
# End-to-end test: ESP32-C6 <-> Python RNS reference over serial
# --------------------------------------------------------------------------

# Flash ESP32-C6, send/receive data using Python RNS crypto
e2e-esp32c6-python: build-esp32c6
    #!/usr/bin/env bash
    set -euo pipefail
    # Flash ESP32
    espflash flash --port {{serial_port}} \
        {{esp32c6_dir}}/target/{{esp32c6_target}}/release/rete-esp32c6-serial
    echo ""
    echo "=== ESP32-C6 flashed ==="
    echo "=== Flow: Python RNS sends ping → ESP32 echoes back ==="
    echo ""
    sleep 0.5
    cd tests/interop && uv run python serial_interop.py \
        --port {{serial_port}} --timeout 10

# --------------------------------------------------------------------------
# Test vectors
# --------------------------------------------------------------------------

# Regenerate interop test vectors from Python RNS
gen-vectors:
    python3 generate_test_vectors.py --out tests/interop/vectors.json

# --------------------------------------------------------------------------
# Cross-compilation checks (no hardware needed)
# --------------------------------------------------------------------------

# Check rete-core compiles for RP2040 (ARM Cortex-M0+)
check-rp2040:
    cargo check -p rete-core --target thumbv6m-none-eabi

# Check rete-embassy compiles for host (no hardware)
check-embassy:
    cargo check -p rete-embassy

# Check all cross-compilation targets
check-all: check check-embassy check-rp2040 build-esp32c6
