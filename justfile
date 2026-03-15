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

# Run all workspace tests
test:
    cargo test --workspace

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

# Flash ESP32-C6, wait for boot, run Linux node to exchange messages
e2e-esp32c6: flash-esp32c6
    @echo ""
    @echo "=== ESP32-C6 flashed. Waiting for boot... ==="
    @sleep 2
    @echo "=== Starting Linux node (20s timeout) ==="
    @echo "=== Expect: DATA with 'hello from esp32' ==="
    @echo ""
    timeout 20 cargo run -p rete-example-linux -- \
        --serial {{serial_port}} --auto-reply "hello from linux" \
        || true

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
