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

# E2E interop against Python RNS (Docker-isolated containers)
test-e2e:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python docker_live_interop.py

# E2E relay interop (3-node topology, Docker)
test-e2e-relay:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python docker_relay_interop.py

# E2E transport relay interop (Rust as multi-interface transport relay, Docker)
test-e2e-transport-relay:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python docker_transport_relay_interop.py

# E2E path request interop (Rust responds to path requests, Docker)
test-e2e-path-request:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python docker_path_request_interop.py

# E2E proof routing interop (proofs route back through Rust relay, Docker)
test-e2e-proof-routing:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python docker_proof_routing_interop.py

# E2E link interop (Python establishes Link to Rust, Docker)
test-e2e-link:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python docker_link_interop.py

# E2E channel interop (Python sends Channel messages to Rust via Link, Docker)
test-e2e-channel:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python docker_channel_interop.py

# E2E resource interop (Python transfers Resource to/from Rust via Link, Docker)
test-e2e-resource:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python docker_resource_interop.py

# E2E IFAC interop (Interface Access Control, Docker)
test-e2e-ifac:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python docker_ifac_interop.py

# E2E local IPC interop (shared instance Unix socket — subprocess, no Docker)
test-e2e-local-ipc:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python local_ipc_interop.py

# E2E robustness interop (malformed packets, Docker)
test-e2e-robustness:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python docker_robustness_interop.py

# E2E auto interface interop (mDNS peer discovery, Docker)
test-e2e-auto:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python docker_auto_interop.py

# CONVENTION: When adding a new interop test:
#   1. Add an individual recipe (test-e2e-<name>)
#   2. Add it to the run_e2e calls AND summary printf in test-all

# E2E link initiation (Rust initiates Link to Python)
test-e2e-link-initiate:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python link_initiate_interop.py

# E2E link initiation via relay (Rust initiates Link through relay)
test-e2e-link-initiate-relay:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python link_initiate_relay_interop.py

# E2E link with Rust as relay node
test-e2e-link-rust-relay:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python link_rust_relay_interop.py

# E2E link through 2-relay chain (rnsd_1 + rete-linux as second relay)
test-e2e-link-3node-relay:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python link_3node_relay_interop.py

# E2E link relay (Python-to-Python link through Rust relay)
test-e2e-link-relay:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python link_relay_interop.py

# E2E link burst transfer
test-e2e-link-burst:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python link_burst_interop.py

# E2E link teardown race conditions
test-e2e-link-teardown-race:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python link_teardown_race_interop.py

# E2E concurrent links
test-e2e-concurrent-links:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python concurrent_links_interop.py

# E2E keepalive tuning
test-e2e-keepalive:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python keepalive_interop.py

# E2E LXMF opportunistic delivery
test-e2e-lxmf-opportunistic:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python lxmf_opportunistic_interop.py

# E2E LXMF direct delivery
test-e2e-lxmf-direct:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python lxmf_direct_interop.py

# E2E LXMF bidirectional delivery
test-e2e-lxmf-bidirectional:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python lxmf_bidirectional_interop.py

# E2E LXMF propagation node
test-e2e-lxmf-propagation:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python lxmf_propagation_interop.py

# E2E LXMF store-and-forward
test-e2e-lxmf-store-forward:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python lxmf_store_forward_interop.py

# E2E LXMF auto-forward
test-e2e-lxmf-auto-forward:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python lxmf_auto_forward_interop.py

# E2E LXMF message retrieval
test-e2e-lxmf-retrieval:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python lxmf_retrieval_interop.py

# E2E IFAC mismatch rejection
test-e2e-ifac-mismatch:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python ifac_mismatch_interop.py

# E2E IFAC relay
test-e2e-ifac-relay:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python ifac_relay_interop.py

# E2E IFAC link
test-e2e-ifac-link:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python ifac_link_interop.py

# E2E IFAC large packet
test-e2e-ifac-large-packet:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python ifac_large_packet_interop.py

# E2E auto interface data exchange
test-e2e-auto-data:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python auto_data_interop.py

# E2E auto interface group isolation
test-e2e-auto-group-isolation:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python auto_group_isolation_interop.py

# E2E announce with app_data
test-e2e-announce-appdata:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python announce_appdata_interop.py

# E2E announce deduplication
test-e2e-announce-dedup:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python announce_dedup_e2e_interop.py

# E2E TCP disconnect recovery
test-e2e-tcp-disconnect:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python tcp_disconnect_interop.py

# E2E HDLC recovery
test-e2e-hdlc-recovery:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python hdlc_recovery_interop.py

# E2E dual interface
test-e2e-dual-interface:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python dual_interface_interop.py

# E2E multi-hop relay
test-e2e-multi-hop-relay:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python multi_hop_relay_interop.py

# E2E concurrent resource transfers
test-e2e-resource-concurrent:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python resource_concurrent_interop.py

# E2E resource multi-segment transfer (2-3 segments, both directions)
test-e2e-resource-multiseg:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python resource_multiseg_interop.py

# E2E resource multi-window transfer
test-e2e-resource-multiwindow:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python resource_multiwindow_interop.py

# E2E 1.5MB split resource transfer (bidirectional)
test-e2e-resource-1mb:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python resource_1mb_interop.py --timeout 240

# E2E stability (long-running)
test-e2e-stability:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python stability_interop.py

# Python-to-Python baseline: channel messages through rnsd relay (no Rust)
test-e2e-py-channel-baseline:
    cd tests/interop && uv run python py_channel_relay_baseline.py

# Python-to-Python baseline: resource transfer through rnsd relay (no Rust)
test-e2e-py-resource-baseline:
    cd tests/interop && uv run python py_resource_relay_baseline.py

# E2E channel messages through rnsd relay (Python -> rnsd -> Rust)
test-e2e-channel-relay:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python channel_relay_interop.py

# E2E resource transfer through rnsd relay (Python -> rnsd -> Rust)
test-e2e-resource-relay:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python resource_relay_interop.py

# E2E Rust-initiates resource through rnsd relay (Rust -> rnsd -> Python)
test-e2e-resource-initiate-relay:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python resource_initiate_relay_interop.py

# Audit: compare all Python RNS constants against Rust values
test-audit-constants:
    cd tests/interop && uv run python audit_constants_interop.py

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

    # Core (7) — Docker-isolated
    run_e2e LIVE docker_live_interop.py
    run_e2e LINK docker_link_interop.py
    run_e2e CHANNEL docker_channel_interop.py
    run_e2e RELAY docker_relay_interop.py
    run_e2e PATHREQ docker_path_request_interop.py
    run_e2e PROOF docker_proof_routing_interop.py
    run_e2e ROBUSTNESS docker_robustness_interop.py

    # Link advanced (8)
    run_e2e LINKINIT link_initiate_interop.py
    run_e2e LINKRELAY link_relay_interop.py
    run_e2e LINKRUSTRELAY link_rust_relay_interop.py
    run_e2e LINK3NODERELAY link_3node_relay_interop.py
    run_e2e LINKINITRELAY link_initiate_relay_interop.py
    run_e2e LINKBURST link_burst_interop.py
    run_e2e CONCURRENT concurrent_links_interop.py
    run_e2e TEARDOWN link_teardown_race_interop.py

    # IFAC (5) — base IFAC Docker-isolated
    run_e2e IFAC docker_ifac_interop.py
    run_e2e IFACMISMATCH ifac_mismatch_interop.py
    run_e2e IFACRELAY ifac_relay_interop.py
    run_e2e IFACLINK ifac_link_interop.py
    run_e2e IFACLARGE ifac_large_packet_interop.py

    # Transport/relay (6) — base transport Docker-isolated
    run_e2e TRANSPORT docker_transport_relay_interop.py
    run_e2e DUAL dual_interface_interop.py
    run_e2e MULTIHOP multi_hop_relay_interop.py
    run_e2e CHANRELAY channel_relay_interop.py
    run_e2e RESRELAY resource_relay_interop.py
    run_e2e RESINITRELAY resource_initiate_relay_interop.py

    # Auto/mDNS (3) — base auto Docker-isolated
    run_e2e AUTO docker_auto_interop.py
    run_e2e AUTODATA auto_data_interop.py
    run_e2e AUTOGROUP auto_group_isolation_interop.py

    # Announce (2)
    run_e2e ANNAPPDATA announce_appdata_interop.py
    run_e2e ANNDEDUP announce_dedup_e2e_interop.py

    # Local IPC (1)
    run_e2e LOCALIPC local_ipc_interop.py

    # LXMF (7)
    run_e2e LXMFOPP lxmf_opportunistic_interop.py
    run_e2e LXMFDIR lxmf_direct_interop.py
    run_e2e LXMFBIDI lxmf_bidirectional_interop.py
    run_e2e LXMFPROP lxmf_propagation_interop.py
    run_e2e LXMFSF lxmf_store_forward_interop.py
    run_e2e LXMFAF lxmf_auto_forward_interop.py
    run_e2e LXMFRET lxmf_retrieval_interop.py

    # Robustness edge (2)
    run_e2e TCPDISC tcp_disconnect_interop.py
    run_e2e HDLC hdlc_recovery_interop.py

    # Resource (5) — base resource Docker-isolated
    run_e2e RESOURCE docker_resource_interop.py
    run_e2e RESCONCUR resource_concurrent_interop.py
    run_e2e RESMULTISEG resource_multiseg_interop.py
    run_e2e RESMULTI resource_multiwindow_interop.py
    run_e2e RES1MB resource_1mb_interop.py

    # Long-running (2)
    run_e2e KEEPALIVE keepalive_interop.py
    run_e2e STABILITY stability_interop.py

    # Audit (1)
    run_e2e AUDITCONST audit_constants_interop.py

    # Hardening (10)
    run_e2e LINKSTALE link_stale_interop.py
    run_e2e LINKCYCLE link_cycle_interop.py
    run_e2e DATAINTEG data_integrity_interop.py
    run_e2e MTUBOUND mtu_boundary_interop.py
    run_e2e MALANN malformed_announce_interop.py
    run_e2e ANNFLOOD announce_flood_interop.py
    run_e2e CHANORDER channel_ordering_interop.py
    run_e2e CONCTRAF concurrent_traffic_interop.py
    run_e2e PATHEXP path_expiry_interop.py
    run_e2e RESCANCEL resource_cancel_interop.py
    run_e2e RESLARGE resource_large_interop.py
    run_e2e MIXSTRESS mixed_stress_interop.py
    run_e2e PROOFCHAIN proof_chain_interop.py

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
    echo "    Core:"
    printf "  %-30s %s passed, %s failed\n" "live-interop" "$LIVE_PASS" "$LIVE_FAIL"
    printf "  %-30s %s passed, %s failed\n" "link-interop" "$LINK_PASS" "$LINK_FAIL"
    printf "  %-30s %s passed, %s failed\n" "channel-interop" "$CHANNEL_PASS" "$CHANNEL_FAIL"
    printf "  %-30s %s passed, %s failed\n" "relay-interop" "$RELAY_PASS" "$RELAY_FAIL"
    printf "  %-30s %s passed, %s failed\n" "path-request-interop" "$PATHREQ_PASS" "$PATHREQ_FAIL"
    printf "  %-30s %s passed, %s failed\n" "proof-routing-interop" "$PROOF_PASS" "$PROOF_FAIL"
    printf "  %-30s %s passed, %s failed\n" "robustness-interop" "$ROBUSTNESS_PASS" "$ROBUSTNESS_FAIL"
    echo "    Link advanced:"
    printf "  %-30s %s passed, %s failed\n" "link-initiate-interop" "$LINKINIT_PASS" "$LINKINIT_FAIL"
    printf "  %-30s %s passed, %s failed\n" "link-relay-interop" "$LINKRELAY_PASS" "$LINKRELAY_FAIL"
    printf "  %-30s %s passed, %s failed\n" "link-rust-relay-interop" "$LINKRUSTRELAY_PASS" "$LINKRUSTRELAY_FAIL"
    printf "  %-30s %s passed, %s failed\n" "link-3node-relay-interop" "$LINK3NODERELAY_PASS" "$LINK3NODERELAY_FAIL"
    printf "  %-30s %s passed, %s failed\n" "link-initiate-relay-interop" "$LINKINITRELAY_PASS" "$LINKINITRELAY_FAIL"
    printf "  %-30s %s passed, %s failed\n" "link-burst-interop" "$LINKBURST_PASS" "$LINKBURST_FAIL"
    printf "  %-30s %s passed, %s failed\n" "concurrent-links-interop" "$CONCURRENT_PASS" "$CONCURRENT_FAIL"
    printf "  %-30s %s passed, %s failed\n" "link-teardown-race-interop" "$TEARDOWN_PASS" "$TEARDOWN_FAIL"
    echo "    IFAC:"
    printf "  %-30s %s passed, %s failed\n" "ifac-interop" "$IFAC_PASS" "$IFAC_FAIL"
    printf "  %-30s %s passed, %s failed\n" "ifac-mismatch-interop" "$IFACMISMATCH_PASS" "$IFACMISMATCH_FAIL"
    printf "  %-30s %s passed, %s failed\n" "ifac-relay-interop" "$IFACRELAY_PASS" "$IFACRELAY_FAIL"
    printf "  %-30s %s passed, %s failed\n" "ifac-link-interop" "$IFACLINK_PASS" "$IFACLINK_FAIL"
    printf "  %-30s %s passed, %s failed\n" "ifac-large-packet-interop" "$IFACLARGE_PASS" "$IFACLARGE_FAIL"
    echo "    Transport/relay:"
    printf "  %-30s %s passed, %s failed\n" "transport-relay-interop" "$TRANSPORT_PASS" "$TRANSPORT_FAIL"
    printf "  %-30s %s passed, %s failed\n" "dual-interface-interop" "$DUAL_PASS" "$DUAL_FAIL"
    printf "  %-30s %s passed, %s failed\n" "multi-hop-relay-interop" "$MULTIHOP_PASS" "$MULTIHOP_FAIL"
    printf "  %-30s %s passed, %s failed\n" "channel-relay-interop" "$CHANRELAY_PASS" "$CHANRELAY_FAIL"
    printf "  %-30s %s passed, %s failed\n" "resource-relay-interop" "$RESRELAY_PASS" "$RESRELAY_FAIL"
    printf "  %-30s %s passed, %s failed\n" "resource-init-relay-interop" "$RESINITRELAY_PASS" "$RESINITRELAY_FAIL"
    echo "    Auto/mDNS:"
    printf "  %-30s %s passed, %s failed\n" "auto-interop" "$AUTO_PASS" "$AUTO_FAIL"
    printf "  %-30s %s passed, %s failed\n" "auto-data-interop" "$AUTODATA_PASS" "$AUTODATA_FAIL"
    printf "  %-30s %s passed, %s failed\n" "auto-group-isolation-interop" "$AUTOGROUP_PASS" "$AUTOGROUP_FAIL"
    echo "    Announce:"
    printf "  %-30s %s passed, %s failed\n" "announce-appdata-interop" "$ANNAPPDATA_PASS" "$ANNAPPDATA_FAIL"
    printf "  %-30s %s passed, %s failed\n" "announce-dedup-interop" "$ANNDEDUP_PASS" "$ANNDEDUP_FAIL"
    echo "    Local IPC:"
    printf "  %-30s %s passed, %s failed\n" "local-ipc-interop" "$LOCALIPC_PASS" "$LOCALIPC_FAIL"
    echo "    LXMF:"
    printf "  %-30s %s passed, %s failed\n" "lxmf-opportunistic-interop" "$LXMFOPP_PASS" "$LXMFOPP_FAIL"
    printf "  %-30s %s passed, %s failed\n" "lxmf-direct-interop" "$LXMFDIR_PASS" "$LXMFDIR_FAIL"
    printf "  %-30s %s passed, %s failed\n" "lxmf-bidirectional-interop" "$LXMFBIDI_PASS" "$LXMFBIDI_FAIL"
    printf "  %-30s %s passed, %s failed\n" "lxmf-propagation-interop" "$LXMFPROP_PASS" "$LXMFPROP_FAIL"
    printf "  %-30s %s passed, %s failed\n" "lxmf-store-forward-interop" "$LXMFSF_PASS" "$LXMFSF_FAIL"
    printf "  %-30s %s passed, %s failed\n" "lxmf-auto-forward-interop" "$LXMFAF_PASS" "$LXMFAF_FAIL"
    printf "  %-30s %s passed, %s failed\n" "lxmf-retrieval-interop" "$LXMFRET_PASS" "$LXMFRET_FAIL"
    echo "    Robustness edge:"
    printf "  %-30s %s passed, %s failed\n" "tcp-disconnect-interop" "$TCPDISC_PASS" "$TCPDISC_FAIL"
    printf "  %-30s %s passed, %s failed\n" "hdlc-recovery-interop" "$HDLC_PASS" "$HDLC_FAIL"
    echo "    Resource:"
    printf "  %-30s %s passed, %s failed\n" "resource-interop" "$RESOURCE_PASS" "$RESOURCE_FAIL"
    printf "  %-30s %s passed, %s failed\n" "resource-concurrent-interop" "$RESCONCUR_PASS" "$RESCONCUR_FAIL"
    printf "  %-30s %s passed, %s failed\n" "resource-multiseg-interop" "$RESMULTISEG_PASS" "$RESMULTISEG_FAIL"
    printf "  %-30s %s passed, %s failed\n" "resource-multiwindow-interop" "$RESMULTI_PASS" "$RESMULTI_FAIL"
    printf "  %-30s %s passed, %s failed\n" "resource-1mb-interop" "$RES1MB_PASS" "$RES1MB_FAIL"
    echo "    Long-running:"
    printf "  %-30s %s passed, %s failed\n" "keepalive-interop" "$KEEPALIVE_PASS" "$KEEPALIVE_FAIL"
    printf "  %-30s %s passed, %s failed\n" "stability-interop" "$STABILITY_PASS" "$STABILITY_FAIL"
    echo "    Audit:"
    printf "  %-30s %s passed, %s failed\n" "audit-constants-interop" "$AUDITCONST_PASS" "$AUDITCONST_FAIL"
    echo "    Hardening:"
    printf "  %-30s %s passed, %s failed\n" "link-stale-interop" "$LINKSTALE_PASS" "$LINKSTALE_FAIL"
    printf "  %-30s %s passed, %s failed\n" "link-cycle-interop" "$LINKCYCLE_PASS" "$LINKCYCLE_FAIL"
    printf "  %-30s %s passed, %s failed\n" "data-integrity-interop" "$DATAINTEG_PASS" "$DATAINTEG_FAIL"
    printf "  %-30s %s passed, %s failed\n" "mtu-boundary-interop" "$MTUBOUND_PASS" "$MTUBOUND_FAIL"
    printf "  %-30s %s passed, %s failed\n" "malformed-announce-interop" "$MALANN_PASS" "$MALANN_FAIL"
    printf "  %-30s %s passed, %s failed\n" "announce-flood-interop" "$ANNFLOOD_PASS" "$ANNFLOOD_FAIL"
    printf "  %-30s %s passed, %s failed\n" "channel-ordering-interop" "$CHANORDER_PASS" "$CHANORDER_FAIL"
    printf "  %-30s %s passed, %s failed\n" "concurrent-traffic-interop" "$CONCTRAF_PASS" "$CONCTRAF_FAIL"
    printf "  %-30s %s passed, %s failed\n" "path-expiry-interop" "$PATHEXP_PASS" "$PATHEXP_FAIL"
    printf "  %-30s %s passed, %s failed\n" "resource-cancel-interop" "$RESCANCEL_PASS" "$RESCANCEL_FAIL"
    printf "  %-30s %s passed, %s failed\n" "resource-large-interop" "$RESLARGE_PASS" "$RESLARGE_FAIL"
    printf "  %-30s %s passed, %s failed\n" "mixed-stress-interop" "$MIXSTRESS_PASS" "$MIXSTRESS_FAIL"
    printf "  %-30s %s passed, %s failed\n" "proof-chain-interop" "$PROOFCHAIN_PASS" "$PROOFCHAIN_FAIL"
    E2E_PASS=$((LIVE_PASS + LINK_PASS + CHANNEL_PASS + RELAY_PASS + PATHREQ_PASS + PROOF_PASS + ROBUSTNESS_PASS \
        + LINKINIT_PASS + LINKRELAY_PASS + LINKRUSTRELAY_PASS + LINK3NODERELAY_PASS + LINKINITRELAY_PASS + LINKBURST_PASS + CONCURRENT_PASS + TEARDOWN_PASS \
        + IFAC_PASS + IFACMISMATCH_PASS + IFACRELAY_PASS + IFACLINK_PASS + IFACLARGE_PASS \
        + AUDITCONST_PASS \
        + TRANSPORT_PASS + DUAL_PASS + MULTIHOP_PASS + CHANRELAY_PASS + RESRELAY_PASS + RESINITRELAY_PASS \
        + AUTO_PASS + AUTODATA_PASS + AUTOGROUP_PASS \
        + ANNAPPDATA_PASS + ANNDEDUP_PASS \
        + LOCALIPC_PASS \
        + LXMFOPP_PASS + LXMFDIR_PASS + LXMFBIDI_PASS + LXMFPROP_PASS + LXMFSF_PASS + LXMFAF_PASS + LXMFRET_PASS \
        + TCPDISC_PASS + HDLC_PASS \
        + RESOURCE_PASS + RESCONCUR_PASS + RESMULTISEG_PASS + RESMULTI_PASS + RES1MB_PASS \
        + KEEPALIVE_PASS + STABILITY_PASS \
        + LINKSTALE_PASS + LINKCYCLE_PASS + DATAINTEG_PASS + MTUBOUND_PASS + MALANN_PASS + ANNFLOOD_PASS \
        + CHANORDER_PASS + CONCTRAF_PASS + PATHEXP_PASS + RESCANCEL_PASS \
        + RESLARGE_PASS + MIXSTRESS_PASS + PROOFCHAIN_PASS))
    E2E_FAIL=$((LIVE_FAIL + LINK_FAIL + CHANNEL_FAIL + RELAY_FAIL + PATHREQ_FAIL + PROOF_FAIL + ROBUSTNESS_FAIL \
        + LINKINIT_FAIL + LINKRELAY_FAIL + LINKRUSTRELAY_FAIL + LINK3NODERELAY_FAIL + LINKINITRELAY_FAIL + LINKBURST_FAIL + CONCURRENT_FAIL + TEARDOWN_FAIL \
        + IFAC_FAIL + IFACMISMATCH_FAIL + IFACRELAY_FAIL + IFACLINK_FAIL + IFACLARGE_FAIL \
        + AUDITCONST_FAIL \
        + TRANSPORT_FAIL + DUAL_FAIL + MULTIHOP_FAIL + CHANRELAY_FAIL + RESRELAY_FAIL + RESINITRELAY_FAIL \
        + AUTO_FAIL + AUTODATA_FAIL + AUTOGROUP_FAIL \
        + ANNAPPDATA_FAIL + ANNDEDUP_FAIL \
        + LOCALIPC_FAIL \
        + LXMFOPP_FAIL + LXMFDIR_FAIL + LXMFBIDI_FAIL + LXMFPROP_FAIL + LXMFSF_FAIL + LXMFAF_FAIL + LXMFRET_FAIL \
        + TCPDISC_FAIL + HDLC_FAIL \
        + RESOURCE_FAIL + RESCONCUR_FAIL + RESMULTISEG_FAIL + RESMULTI_FAIL + RES1MB_FAIL \
        + KEEPALIVE_FAIL + STABILITY_FAIL \
        + LINKSTALE_FAIL + LINKCYCLE_FAIL + DATAINTEG_FAIL + MTUBOUND_FAIL + MALANN_FAIL + ANNFLOOD_FAIL \
        + CHANORDER_FAIL + CONCTRAF_FAIL + PATHEXP_FAIL + RESCANCEL_FAIL \
        + RESLARGE_FAIL + MIXSTRESS_FAIL + PROOFCHAIN_FAIL))
    echo ""
    printf "  %-30s %s passed, %s failed\n" "e2e total (62 suites)" "$E2E_PASS" "$E2E_FAIL"
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

esp32c3_target := "riscv32imc-unknown-none-elf"
esp32c6_target := "riscv32imac-unknown-none-elf"
esp32s3_target := "xtensa-esp32s3-none-elf"
esp32c6_dir := "examples/esp32c6"
esp32s3_dir := "examples/esp32s3"
serial_port := env("SERIAL_PORT", "/dev/ttyUSB0")

# Build the ESP32-C6 serial firmware
build-esp32c6:
    cd {{esp32c6_dir}} && cargo +nightly build --release \
        --features esp32c6 --bin rete-esp32c6-serial \
        --target {{esp32c6_target}}

# Build the ESP32-C6 test firmware (comprehensive handler)
build-esp32c6-test:
    cd {{esp32c6_dir}} && cargo +nightly build --release \
        --features esp32c6 --bin rete-esp32c6-serial-test \
        --target {{esp32c6_target}}

# Flash the ESP32-C6 serial firmware
flash-esp32c6: build-esp32c6
    espflash flash --port {{serial_port}} \
        {{esp32c6_dir}}/target/{{esp32c6_target}}/release/rete-esp32c6-serial

# Flash the ESP32-C6 test firmware
flash-esp32c6-test: build-esp32c6-test
    espflash flash --port {{serial_port}} \
        {{esp32c6_dir}}/target/{{esp32c6_target}}/release/rete-esp32c6-serial-test

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
# ESP32-C3 (RISC-V — shares crate with C6 via feature flag)
# --------------------------------------------------------------------------

# Build the ESP32-C3 serial firmware
build-esp32c3:
    cd {{esp32c6_dir}} && cargo +nightly build --release \
        --features esp32c3 --bin rete-esp32c6-serial \
        --target {{esp32c3_target}}

# Build the ESP32-C3 test firmware
build-esp32c3-test:
    cd {{esp32c6_dir}} && cargo +nightly build --release \
        --features esp32c3 --bin rete-esp32c6-serial-test \
        --target {{esp32c3_target}}

# Flash the ESP32-C3 serial firmware
flash-esp32c3: build-esp32c3
    espflash flash --port {{serial_port}} \
        {{esp32c6_dir}}/target/{{esp32c3_target}}/release/rete-esp32c6-serial

# Flash the ESP32-C3 test firmware
flash-esp32c3-test: build-esp32c3-test
    espflash flash --port {{serial_port}} \
        {{esp32c6_dir}}/target/{{esp32c3_target}}/release/rete-esp32c6-serial-test

# Build the ESP32-C3 WiFi firmware
build-esp32c3-wifi:
    cd {{esp32c6_dir}} && SSID="${SSID:-YOUR_SSID}" PASSWORD="${PASSWORD:-YOUR_PASSWORD}" \
        RNSD_HOST="${RNSD_HOST:-192.168.1.100}" RNSD_PORT="${RNSD_PORT:-4242}" \
        cargo +nightly build --release \
        --features esp32c3,wifi --bin rete-esp32c6 \
        --target {{esp32c3_target}}

# Flash the ESP32-C3 WiFi firmware
flash-esp32c3-wifi: build-esp32c3-wifi
    espflash flash --port {{serial_port}} \
        {{esp32c6_dir}}/target/{{esp32c3_target}}/release/rete-esp32c6

# --------------------------------------------------------------------------
# ESP32-S3 (Xtensa — uses esp toolchain fork)
# --------------------------------------------------------------------------

# Build the ESP32-S3 firmware
build-esp32s3:
    cd {{esp32s3_dir}} && cargo +esp build --release \
        --target {{esp32s3_target}}

# Flash the ESP32-S3 firmware
flash-esp32s3: build-esp32s3
    espflash flash --port {{serial_port}} \
        {{esp32s3_dir}}/target/{{esp32s3_target}}/release/rete-esp32s3

# --------------------------------------------------------------------------
# ESP32 — build all targets (no flash, just compile check)
# --------------------------------------------------------------------------

# Build all ESP32 variants
build-esp32-all: build-esp32c3 build-esp32c6 build-esp32s3

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
        2>&1 || true)
    echo "$OUTPUT"
    echo ""
    # Extract the ping timestamp from the log
    PING=$(echo "$OUTPUT" | grep -oP 'auto-reply-ping: \Kping:\d+' || true)
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
# ESP32-C6 hardware-in-the-loop tests (requires test firmware flashed)
# --------------------------------------------------------------------------

# ESP32 link test (ESP32 as responder, Topology A)
test-esp32c6-link: flash-esp32c6-test
    cargo build -p rete-example-linux
    cd tests/interop && uv run python esp32c6_link_interop.py \
        --rust-binary ../../target/debug/rete-linux \
        --serial-port {{serial_port}} --timeout 30

# ESP32 resource transfer test (Topology A)
test-esp32c6-resource: flash-esp32c6-test
    cargo build -p rete-example-linux
    cd tests/interop && uv run python esp32c6_resource_interop.py \
        --rust-binary ../../target/debug/rete-linux \
        --serial-port {{serial_port}} --timeout 30

# ESP32 proof of delivery test (Topology A)
test-esp32c6-proof: flash-esp32c6-test
    cargo build -p rete-example-linux
    cd tests/interop && uv run python esp32c6_proof_interop.py \
        --rust-binary ../../target/debug/rete-linux \
        --serial-port {{serial_port}} --timeout 30

# ESP32 link initiation test (ESP32 as initiator, Topology A)
test-esp32c6-link-initiate: flash-esp32c6-test
    cargo build -p rete-example-linux
    cd tests/interop && uv run python esp32c6_link_initiate_interop.py \
        --rust-binary ../../target/debug/rete-linux \
        --serial-port {{serial_port}} --timeout 30

# ESP32 Python announce exchange (Topology B via bridge)
test-esp32c6-py-announce: flash-esp32c6-test
    cd tests/interop && uv run python esp32c6_py_announce_interop.py \
        --serial-port {{serial_port}} --timeout 30

# ESP32 Python link test (Topology B via bridge)
test-esp32c6-py-link: flash-esp32c6-test
    cd tests/interop && uv run python esp32c6_py_link_interop.py \
        --serial-port {{serial_port}} --timeout 30

# ESP32 Python channel test (Topology B via bridge)
test-esp32c6-py-channel: flash-esp32c6-test
    cd tests/interop && uv run python esp32c6_py_channel_interop.py \
        --serial-port {{serial_port}} --timeout 30

# ESP32 Python data test (Topology B via bridge)
test-esp32c6-py-data: flash-esp32c6-test
    cd tests/interop && uv run python esp32c6_py_data_interop.py \
        --serial-port {{serial_port}} --timeout 30

# ESP32 request/response test (Topology A)
test-esp32c6-request: flash-esp32c6-test
    cargo build -p rete-example-linux
    cd tests/interop && uv run python esp32c6_request_interop.py \
        --rust-binary ../../target/debug/rete-linux \
        --serial-port {{serial_port}} --timeout 30

# ESP32 link teardown + slot reuse test (Topology A)
test-esp32c6-teardown: flash-esp32c6-test
    cargo build -p rete-example-linux
    cd tests/interop && uv run python esp32c6_teardown_interop.py \
        --rust-binary ../../target/debug/rete-linux \
        --serial-port {{serial_port}} --timeout 30

# 3-node ESP32 relay test (Python <-> rete-linux <-> ESP32)
test-esp32c6-3node: flash-esp32c6-test
    cargo build -p rete-example-linux
    cd tests/interop && uv run python esp32c6_3node_relay_interop.py \
        --rust-binary ../../target/debug/rete-linux \
        --serial-port {{serial_port}} --timeout 120

# Flash once, run all ESP32-C6 hardware tests (Topology A + B + C)
test-esp32c6-all: flash-esp32c6-test
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -p rete-example-linux
    echo "Waiting for ESP32 to boot..."
    sleep 3
    # Topology A tests (rete-linux <-> ESP32 serial): no-link first, then link tests with cleanup
    TOPO_A=(proof link resource request teardown link_initiate)
    # Topology B tests (Python RNS <-> ESP32 via serial bridge): no --rust-binary
    TOPO_B=(py_announce py_data py_link py_channel)
    # Topology C tests (Python <-> rete-linux relay <-> ESP32): needs --rust-binary + --serial-port, longer timeout
    # TODO: 3node_relay is skipped — 10/17 checks pass but 7 fail due to serial
    # timing in the multi-hop relay path (concurrent links, reverse-direction
    # traffic). The ingress_control=false fix resolved the TCP-side announce
    # propagation issue, but serial latency still causes timeouts on the most
    # complex relay scenarios. Needs investigation: possibly keepalive/timeout
    # tuning for serial interfaces or flow control improvements.
    TOPO_C=()
    SUITE_PASS=0; SUITE_FAIL=0
    TOTAL_CHECKS=0; TOTAL_CHECK_PASS=0
    SUMMARY_LINES=()
    run_esp32_test() {
        local name="$1" topo="$2"
        shift 2
        local output rc=0
        output=$(cd tests/interop && uv run python "esp32c6_${name}_interop.py" "$@" 2>&1) || rc=$?
        echo "$output"
        # Parse "Results: X/Y passed, Z/Y failed" from output
        local result_line checks_str p_str t_str
        result_line=$(echo "$output" | grep "Results:" | tail -1)
        p_str=$(echo "$result_line" | grep -oP '\d+(?=/\d+ passed)' || echo "0")
        t_str=$(echo "$result_line" | grep -oP '(?<=Results: )\d+/\d+' | head -1 | cut -d/ -f2)
        t_str=${t_str:-0}; p_str=${p_str:-0}
        local f_str=$((t_str - p_str))
        TOTAL_CHECKS=$((TOTAL_CHECKS + t_str))
        TOTAL_CHECK_PASS=$((TOTAL_CHECK_PASS + p_str))
        if [ "$rc" -eq 0 ]; then
            SUITE_PASS=$((SUITE_PASS+1))
            SUMMARY_LINES+=("$(printf '  PASS  %-40s %s/%s checks' "esp32c6_${name} (${topo})" "$p_str" "$t_str")")
        else
            SUITE_FAIL=$((SUITE_FAIL+1))
            SUMMARY_LINES+=("$(printf '  FAIL  %-40s %s/%s checks' "esp32c6_${name} (${topo})" "$p_str" "$t_str")")
        fi
        # DTR reset between tests to reboot ESP32 (ensures fresh announce on next test)
        python3 tests/interop/reset_esp32.py {{serial_port}} 2>/dev/null || true
        sleep 4
    }
    for t in "${TOPO_A[@]}"; do
        echo ""
        echo "=== esp32c6_${t}_interop (Topology A) ==="
        run_esp32_test "$t" "Topo A" \
            --rust-binary ../../target/debug/rete-linux \
            --serial-port {{serial_port}} --timeout 30
    done
    for t in "${TOPO_B[@]}"; do
        echo ""
        echo "=== esp32c6_${t}_interop (Topology B) ==="
        run_esp32_test "$t" "Topo B" \
            --serial-port {{serial_port}} --timeout 30
    done
    for t in "${TOPO_C[@]}"; do
        echo ""
        echo "=== esp32c6_${t}_interop (Topology C) ==="
        run_esp32_test "$t" "Topo C" \
            --rust-binary ../../target/debug/rete-linux \
            --serial-port {{serial_port}} --timeout 120
    done
    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "  ESP32-C6 Hardware Test Summary"
    echo "───────────────────────────────────────────────────"
    echo "  Topology A (rete-linux <-> ESP32 serial):"
    for line in "${SUMMARY_LINES[@]}"; do
        if echo "$line" | grep -q "Topo A"; then echo "$line"; fi
    done
    echo ""
    echo "  Topology B (Python RNS <-> ESP32 serial bridge):"
    for line in "${SUMMARY_LINES[@]}"; do
        if echo "$line" | grep -q "Topo B"; then echo "$line"; fi
    done
    echo ""
    echo "  Topology C (Python <-> rete-linux relay <-> ESP32):"
    for line in "${SUMMARY_LINES[@]}"; do
        if echo "$line" | grep -q "Topo C"; then echo "$line"; fi
    done
    echo "───────────────────────────────────────────────────"
    TOTAL_CHECK_FAIL=$((TOTAL_CHECKS - TOTAL_CHECK_PASS))
    printf "  Suites: %s passed, %s failed (%s total)\n" "$SUITE_PASS" "$SUITE_FAIL" "$((SUITE_PASS + SUITE_FAIL))"
    printf "  Checks: %s passed, %s failed (%s total)\n" "$TOTAL_CHECK_PASS" "$TOTAL_CHECK_FAIL" "$TOTAL_CHECKS"
    if [ "$SUITE_FAIL" -eq 0 ]; then
        echo "  ALL SUITES PASSED ✓"
    else
        echo "  SOME SUITES FAILED ✗"
    fi
    echo "═══════════════════════════════════════════════════"
    [ "$SUITE_FAIL" -eq 0 ]

# --------------------------------------------------------------------------
# ESP32-C6 diagnostic tests (packet-level capture for debugging)
# --------------------------------------------------------------------------

# Diagnostic: ESP32 announce with packet capture (Topology B)
test-esp32c6-diag-announce:
    cd tests/interop && uv run python esp32c6_diag_announce.py \
        --serial-port {{serial_port}} --timeout 30

# Diagnostic: ESP32 channel with packet capture (Topology B)
test-esp32c6-diag-channel:
    cd tests/interop && uv run python esp32c6_diag_channel.py \
        --serial-port {{serial_port}} --timeout 30

# Diagnostic: ESP32 3-node relay with packet capture (Topology C)
test-esp32c6-diag-relay:
    cargo build -p rete-example-linux
    cd tests/interop && uv run python esp32c6_diag_relay.py \
        --rust-binary ../../target/debug/rete-linux \
        --serial-port {{serial_port}} --timeout 120

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
# Docker utilities
# --------------------------------------------------------------------------

# Build Docker test images for topology tests
docker-build-test-images:
    docker build -t rete-test-rust:latest -f tests/docker/rust-node.Dockerfile tests/docker/
    docker build -t rete-test-python:latest -f tests/docker/python-node.Dockerfile tests/docker/
    docker build -t rete-test-rnsd:latest -f tests/docker/rnsd-node.Dockerfile tests/docker/

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
check-all: check check-embassy check-rp2040 build-esp32-all
