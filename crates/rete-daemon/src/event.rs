//! Node event handling: routes NodeEvent through the LXMF router and emits
//! structured stdout markers that the E2E test harness parses.

use std::cell::RefCell;

use rete_lxmf::{LXMessage, LxmfEvent, LxmfRouter};
use rete_stack::{HostedNodeCore, NodeStats, OutboundPacket};
use rete_tokio::{NodeCommand, NodeEvent};
use rete_transport::SnapshotStore as _;

use crate::file_store::AnyMessageStore;
use crate::identity::JsonFileStore;

/// Maximum age of propagation messages before pruning. Matches Python RNS default (30 days).
const PROPAGATION_TTL_SECS: u64 = 2_592_000;

pub fn on_event(
    event: NodeEvent,
    lxmf_router: &RefCell<LxmfRouter<AnyMessageStore>>,
    snapshot_store: &RefCell<JsonFileStore>,
    stats_tx: &tokio::sync::watch::Sender<Option<NodeStats>>,
    core: &mut HostedNodeCore,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Vec<OutboundPacket> {
    // Handle propagation pruning + periodic snapshot on tick events
    if let NodeEvent::Tick { .. } = &event {
        let now = rete_tokio::current_time_secs();
        let pruned = lxmf_router
            .borrow_mut()
            .prune_propagation(now, PROPAGATION_TTL_SECS);
        if pruned > 0 {
            tracing::debug!(pruned, "propagation: pruned expired messages");
        }

        // Save snapshot every ~5 minutes (60 ticks × 5s interval).
        // Process-global: if multiple daemon instances run in-process (uncommon),
        // they share this counter and may save slightly off-schedule.
        use std::sync::atomic::{AtomicU64, Ordering};
        static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
        let ticks = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        if ticks.is_multiple_of(60) && core.path_count() > 0 {
            let snap = core.save_snapshot(rete_transport::SnapshotDetail::Standard);
            if let Err(e) = snapshot_store.borrow_mut().save(&snap) {
                tracing::error!(error = ?e, "failed to save snapshot");
            } else {
                tracing::debug!(
                    paths = snap.paths.len(),
                    identities = snap.identities.len(),
                    "snapshot saved",
                );
            }
        }

        // Publish stats for monitoring endpoint (only if someone is listening)
        if stats_tx.receiver_count() > 0 {
            let stats = core.stats(now);
            let _ = stats_tx.send(Some(stats));
        }

        // Process outbound message queue
        let (out_pkts, _out_events) = lxmf_router.borrow_mut().process_outbound(core, rng, now);
        if !out_pkts.is_empty() {
            return out_pkts;
        }

        // Check peer syncs
        let sync_pkts = lxmf_router.borrow_mut().check_peer_syncs(core, rng, now);
        if !sync_pkts.is_empty() {
            tracing::debug!(links = sync_pkts.len(), "peer sync: initiated");
            return sync_pkts;
        }
    }

    // Use mutable handler — handles propagation deposit when enabled,
    // falls through to immutable handler otherwise.
    let now = rete_tokio::current_time_secs();
    let lxmf_event = lxmf_router.borrow_mut().handle_event_mut(event, now);
    match lxmf_event {
        LxmfEvent::MessageReceived { message, method } => {
            let source = hex::encode(message.source_hash);
            let title = String::from_utf8_lossy(&message.title);
            let content = String::from_utf8_lossy(&message.content);
            tracing::info!(
                %source, method = ?method, %title, %content,
                "LXMF message received",
            );
            tracing::info!(target: "rete::test_event", event = "LXMF_RECEIVED", %source, %title, %content);
        }
        LxmfEvent::PeerAnnounced {
            dest_hash,
            display_name,
        } => {
            let name = display_name
                .as_deref()
                .map(|n| String::from_utf8_lossy(n).to_string())
                .unwrap_or_default();
            tracing::info!(
                dest = %hex::encode(dest_hash),
                %name,
                "LXMF peer announced",
            );
            tracing::info!(target: "rete::test_event", event = "LXMF_PEER", dest = %hex::encode(dest_hash), %name);
        }
        LxmfEvent::PropagationDeposit {
            dest_hash,
            message_hash,
        } => {
            tracing::info!(
                dest = %hex::encode(dest_hash),
                msg_hash = %hex::encode(message_hash),
                "propagation deposit",
            );
            tracing::info!(target: "rete::test_event", event = "PROP_DEPOSIT", dest = %hex::encode(dest_hash), msg_hash = %hex::encode(message_hash));
        }
        LxmfEvent::PropagationRetrievalRequest {
            link_id,
            request_id,
            dest_hash,
            result,
        } => {
            let count = result.message_hashes.len();
            tracing::info!(
                link = %hex::encode(link_id),
                dest = %hex::encode(dest_hash),
                count,
                "propagation retrieval request",
            );
            tracing::info!(target: "rete::test_event", event = "PROP_RETRIEVAL_REQUEST", link = %hex::encode(link_id), dest = %hex::encode(dest_hash), count);

            let mut packets = Vec::new();

            // Send the response (count of messages)
            if let Ok(resp_pkt) =
                core.send_response(&link_id, &request_id, &result.response_data, rng)
            {
                packets.push(resp_pkt);
            }

            // Start sending messages as Resources via retrieval job
            if !result.message_hashes.is_empty() {
                let hashes = result.message_hashes;
                let retrieval_pkts = lxmf_router
                    .borrow_mut()
                    .start_retrieval_send(&link_id, hashes, core, rng);
                packets.extend(retrieval_pkts);
            }

            flush_stdout();
            return packets;
        }
        LxmfEvent::PropagationForward { dest_hash, count } => {
            tracing::info!(
                dest = %hex::encode(dest_hash),
                count,
                "propagation forward",
            );
            tracing::info!(target: "rete::test_event", event = "PROP_FORWARD", dest = %hex::encode(dest_hash), count);

            // Auto-forward: initiate a link to the destination
            let mut router = lxmf_router.borrow_mut();
            if !router.has_forward_job_for(&dest_hash) {
                let now = rete_tokio::current_time_secs();
                if let Some((pkt, link_id)) =
                    router.start_propagation_forward(&dest_hash, core, rng, now)
                {
                    tracing::info!(
                        dest = %hex::encode(dest_hash),
                        link = %hex::encode(link_id),
                        "propagation forward link initiated",
                    );
                    tracing::info!(target: "rete::test_event", event = "PROP_FORWARD_LINK", dest = %hex::encode(dest_hash), link = %hex::encode(link_id));
                    flush_stdout();
                    return vec![pkt];
                } else {
                    tracing::warn!(
                        dest = %hex::encode(dest_hash),
                        "propagation forward failed (no path or no messages)",
                    );
                }
            }
        }
        LxmfEvent::PeerDiscovered {
            dest_hash,
            identity_hash,
        } => {
            tracing::info!(
                dest = %hex::encode(dest_hash),
                identity = %hex::encode(identity_hash),
                "peer discovered",
            );
            tracing::info!(target: "rete::test_event", event = "PEER_DISCOVERED", dest = %hex::encode(dest_hash), identity = %hex::encode(identity_hash));
        }
        LxmfEvent::PeerSyncComplete {
            dest_hash,
            messages_sent,
        } => {
            tracing::info!(
                dest = %hex::encode(dest_hash),
                messages_sent,
                "peer sync complete",
            );
            tracing::info!(target: "rete::test_event", event = "PEER_SYNC_COMPLETE", dest = %hex::encode(dest_hash), messages_sent);
        }
        LxmfEvent::PeerOfferReceived {
            link_id,
            request_id,
            response_data,
        } => {
            tracing::info!(
                link = %hex::encode(link_id),
                response_len = response_data.len(),
                "peer offer received",
            );
            tracing::info!(target: "rete::test_event", event = "PEER_OFFER_RECEIVED", link = %hex::encode(link_id));

            // Send the response back
            if let Ok(pkt) = core.send_response(&link_id, &request_id, &response_data, rng) {
                flush_stdout();
                return vec![pkt];
            }
        }
        LxmfEvent::MessageDelivered {
            message_hash,
            dest_hash,
        } => {
            tracing::info!(target: "rete::test_event", event = "LXMF_DELIVERED", msg_hash = %hex::encode(&message_hash[..8]), dest = %hex::encode(dest_hash));
            tracing::info!(
                msg_hash = %hex::encode(&message_hash[..8]),
                dest = %hex::encode(dest_hash),
                "message delivered",
            );
        }
        LxmfEvent::MessageFailed {
            message_hash,
            dest_hash,
        } => {
            tracing::info!(target: "rete::test_event", event = "LXMF_FAILED", msg_hash = %hex::encode(&message_hash[..8]), dest = %hex::encode(dest_hash));
            tracing::error!(
                msg_hash = %hex::encode(&message_hash[..8]),
                dest = %hex::encode(dest_hash),
                "message failed",
            );
        }
        LxmfEvent::MessageRejectedStamp {
            source_hash,
            message_hash,
        } => {
            tracing::info!(target: "rete::test_event", event = "LXMF_REJECTED_STAMP", source = %hex::encode(source_hash), msg_hash = %hex::encode(&message_hash[..8]));
            tracing::warn!(
                source = %hex::encode(source_hash),
                msg_hash = %hex::encode(&message_hash[..8]),
                "message rejected (invalid stamp)",
            );
        }
        LxmfEvent::Other(event) => {
            // Check if this is a link event that advances a forward or sync job
            match &event {
                NodeEvent::LinkEstablished { link_id } => {
                    // Try forward jobs
                    let pkts = lxmf_router
                        .borrow_mut()
                        .advance_forward_on_link_established(link_id, core, rng);
                    if !pkts.is_empty() {
                        tracing::info!(
                            link = %hex::encode(link_id),
                            pkts = pkts.len(),
                            "propagation forward sending",
                        );
                        tracing::info!(target: "rete::test_event", event = "PROP_FORWARD_SENDING", link = %hex::encode(link_id));
                        on_node_event(event);
                        return pkts;
                    }

                    // Try outbound direct jobs
                    let pkts = lxmf_router
                        .borrow_mut()
                        .advance_outbound_on_link_established(link_id, core, rng);
                    if !pkts.is_empty() {
                        tracing::info!(link = %hex::encode(link_id), "LXMF outbound sending");
                        on_node_event(event);
                        return pkts;
                    }

                    // Try sync jobs
                    let pkts = lxmf_router.borrow_mut().advance_sync_on_link_established(
                        link_id,
                        core,
                        rng,
                        rete_tokio::current_time_secs(),
                    );
                    if !pkts.is_empty() {
                        tracing::debug!(link = %hex::encode(link_id), "peer sync identifying");
                        on_node_event(event);
                        return pkts;
                    }
                }
                NodeEvent::ResponseReceived {
                    link_id, ref data, ..
                } => {
                    // Advance sync job on offer response
                    let now = rete_tokio::current_time_secs();
                    let pkts = lxmf_router
                        .borrow_mut()
                        .advance_sync_on_response(link_id, data, core, rng, now);
                    if !pkts.is_empty() {
                        tracing::debug!(link = %hex::encode(link_id), "peer sync transferring");
                        on_node_event(event);
                        return pkts;
                    }
                }
                NodeEvent::ResourceComplete {
                    link_id,
                    resource_hash,
                    ref data,
                } => {
                    // Try advancing forward jobs first
                    let pkts = lxmf_router
                        .borrow_mut()
                        .advance_forward_on_resource_complete(link_id, resource_hash, core, rng);
                    if !pkts.is_empty() {
                        on_node_event(event);
                        return pkts;
                    }

                    // Try advancing retrieval jobs
                    let pkts = lxmf_router
                        .borrow_mut()
                        .advance_retrieval_on_resource_complete(link_id, resource_hash, core, rng);
                    if !pkts.is_empty() {
                        tracing::info!(
                            link = %hex::encode(link_id),
                            pkts = pkts.len(),
                            "propagation retrieval sending",
                        );
                        tracing::info!(target: "rete::test_event", event = "PROP_RETRIEVAL_SENDING", link = %hex::encode(link_id));
                        on_node_event(event);
                        return pkts;
                    }

                    // Try advancing sync jobs (outbound)
                    let now = rete_tokio::current_time_secs();
                    let (pkts, sync_event) = lxmf_router
                        .borrow_mut()
                        .advance_sync_on_resource_complete(link_id, core, rng, now);
                    if let Some(evt) = sync_event {
                        match &evt {
                            LxmfEvent::PeerSyncComplete {
                                dest_hash,
                                messages_sent,
                            } => {
                                tracing::info!(
                                    dest = %hex::encode(dest_hash),
                                    messages_sent,
                                    "peer sync complete",
                                );
                                tracing::info!(target: "rete::test_event", event = "PEER_SYNC_COMPLETE", dest = %hex::encode(dest_hash), messages_sent);
                            }
                            _ => {}
                        }
                        on_node_event(event);
                        return pkts;
                    }

                    // Try depositing as inbound sync resource
                    if lxmf_router.borrow().has_sync_job_for_link(link_id) {
                        let deposited = lxmf_router.borrow_mut().deposit_sync_resource(data, now);
                        if !deposited.is_empty() {
                            for (dest, hash) in &deposited {
                                tracing::info!(
                                    dest = %hex::encode(dest),
                                    msg_hash = %hex::encode(hash),
                                    "peer sync deposit",
                                );
                                tracing::info!(target: "rete::test_event", event = "PEER_SYNC_DEPOSIT", dest = %hex::encode(dest), msg_hash = %hex::encode(hash));
                            }
                            on_node_event(event);
                            return Vec::new();
                        }
                    }
                }
                NodeEvent::LinkClosed { link_id } => {
                    lxmf_router
                        .borrow_mut()
                        .cleanup_forward_jobs_for_link(link_id);
                    lxmf_router.borrow_mut().cleanup_sync_jobs_for_link(link_id);
                }
                _ => {}
            }
            // Fall through to normal event handling
            on_node_event(event);
        }
    }
    // Flush stdout so piped readers see LXMF output immediately.
    flush_stdout();
    Vec::new()
}

pub fn on_node_event(event: NodeEvent) {
    match event {
        NodeEvent::AnnounceReceived {
            dest_hash,
            identity_hash,
            hops,
            app_data,
        } => {
            tracing::info!(
                dest = %hex::encode(dest_hash),
                identity = %hex::encode(identity_hash),
                hops,
                app_data = app_data
                    .as_ref()
                    .map(|d| {
                        match std::str::from_utf8(d) {
                            Ok(s) => s.to_string(),
                            Err(_) => hex::encode(d),
                        }
                    })
                    .as_deref(),
                "announce received",
            );
            if let Some(ref ad) = app_data {
                tracing::info!(target: "rete::test_event", event = "ANNOUNCE", dest = %hex::encode(dest_hash), identity = %hex::encode(identity_hash), hops, app_data = %hex::encode(ad));
            } else {
                tracing::info!(target: "rete::test_event", event = "ANNOUNCE", dest = %hex::encode(dest_hash), identity = %hex::encode(identity_hash), hops);
            }
        }
        NodeEvent::DataReceived { dest_hash, payload } => {
            match std::str::from_utf8(&payload) {
                Ok(text) => {
                    tracing::info!(
                        dest = %hex::encode(dest_hash),
                        len = payload.len(),
                        %text,
                        "data received",
                    );
                    tracing::info!(target: "rete::test_event", event = "DATA", dest = %hex::encode(dest_hash), payload = %text);
                }
                Err(_) => {
                    tracing::info!(
                        dest = %hex::encode(dest_hash),
                        len = payload.len(),
                        hex = %hex::encode(&payload),
                        "data received",
                    );
                    tracing::info!(target: "rete::test_event", event = "DATA", dest = %hex::encode(dest_hash), payload = %hex::encode(&payload));
                }
            }
        }
        NodeEvent::ProofReceived { packet_hash } => {
            tracing::info!(
                packet_hash = %hex::encode(packet_hash),
                "proof received",
            );
            tracing::info!(target: "rete::test_event", event = "PROOF_RECEIVED", packet_hash = %hex::encode(packet_hash));
        }
        NodeEvent::LinkEstablished { link_id } => {
            tracing::info!(link = %hex::encode(link_id), "link established");
            tracing::info!(target: "rete::test_event", event = "LINK_ESTABLISHED", link = %hex::encode(link_id));
        }
        NodeEvent::LinkData {
            link_id,
            data,
            context,
        } => {
            tracing::debug!(
                link = %hex::encode(link_id),
                context = format_args!("{:#04x}", context),
                len = data.len(),
                "link data received",
            );
            match std::str::from_utf8(&data) {
                Ok(text) => tracing::info!(target: "rete::test_event", event = "LINK_DATA", link = %hex::encode(link_id), payload = %text),
                Err(_) => tracing::info!(target: "rete::test_event", event = "LINK_DATA", link = %hex::encode(link_id), payload = %hex::encode(&data)),
            }
        }
        NodeEvent::ChannelMessages { link_id, messages } => {
            tracing::debug!(
                link = %hex::encode(link_id),
                count = messages.len(),
                "channel messages received",
            );
            for (msg_type, payload) in &messages {
                tracing::debug!(msg_type = format_args!("0x{:04x}", msg_type), len = payload.len(), "channel message");
                match std::str::from_utf8(payload) {
                    Ok(text) => tracing::info!(target: "rete::test_event", event = "CHANNEL_MSG", link = %hex::encode(link_id), msg_type = format_args!("{:#06x}", msg_type), payload = %text),
                    Err(_) => tracing::info!(target: "rete::test_event", event = "CHANNEL_MSG", link = %hex::encode(link_id), msg_type = format_args!("{:#06x}", msg_type), payload = %hex::encode(payload)),
                }
            }
        }
        NodeEvent::RequestReceived {
            link_id,
            request_id,
            path_hash,
            data,
        } => {
            tracing::info!(
                link = %hex::encode(link_id),
                request_id = %hex::encode(request_id),
                path_hash = %hex::encode(path_hash),
                data_len = data.len(),
                "request received",
            );
            tracing::info!(target: "rete::test_event", event = "REQUEST_RECEIVED", link = %hex::encode(link_id), request_id = %hex::encode(request_id), path_hash = %hex::encode(path_hash), data_len = data.len());
        }
        NodeEvent::ResponseReceived {
            link_id,
            request_id,
            data,
        } => {
            tracing::info!(
                link = %hex::encode(link_id),
                request_id = %hex::encode(request_id),
                data_len = data.len(),
                "response received",
            );
            tracing::info!(target: "rete::test_event", event = "RESPONSE_RECEIVED", link = %hex::encode(link_id), request_id = %hex::encode(request_id), data_len = data.len());
        }
        NodeEvent::LinkClosed { link_id } => {
            tracing::info!(link = %hex::encode(link_id), "link closed");
            tracing::info!(target: "rete::test_event", event = "LINK_CLOSED", link = %hex::encode(link_id));
        }
        NodeEvent::ResourceOffered {
            link_id,
            resource_hash,
            total_size,
        } => {
            tracing::info!(
                link = %hex::encode(link_id),
                resource_hash = %hex::encode(resource_hash),
                total_size,
                "resource offered",
            );
            tracing::info!(target: "rete::test_event", event = "RESOURCE_OFFERED", link = %hex::encode(link_id), resource_hash = %hex::encode(resource_hash), total_size);
            tracing::debug!("RESOURCE_OFFERED event processed");
        }
        NodeEvent::ResourceProgress {
            link_id,
            resource_hash,
            current,
            total,
        } => {
            tracing::debug!(
                link = %hex::encode(link_id),
                resource_hash = %hex::encode(resource_hash),
                current,
                total,
                "resource progress",
            );
        }
        NodeEvent::ResourceComplete {
            link_id,
            resource_hash,
            ref data,
        } => {
            let data_display = match std::str::from_utf8(data) {
                Ok(text) => text.to_string(),
                Err(_) => hex::encode(data),
            };
            tracing::info!(
                link = %hex::encode(link_id),
                resource_hash = %hex::encode(resource_hash),
                len = data.len(),
                "resource complete",
            );
            tracing::info!(target: "rete::test_event", event = "RESOURCE_COMPLETE", link = %hex::encode(link_id), resource_hash = %hex::encode(resource_hash), payload = %data_display);
        }
        NodeEvent::ResourceFailed {
            link_id,
            resource_hash,
        } => {
            tracing::error!(
                link = %hex::encode(link_id),
                resource_hash = %hex::encode(resource_hash),
                "resource failed",
            );
            tracing::info!(target: "rete::test_event", event = "RESOURCE_FAILED", link = %hex::encode(link_id), resource_hash = %hex::encode(resource_hash));
        }
        NodeEvent::Tick { expired_paths, .. } => {
            if expired_paths > 0 {
                tracing::debug!(expired_paths, "tick: expired paths");
            }
        }
        NodeEvent::LinkIdentified {
            link_id,
            identity_hash,
            ..
        } => {
            tracing::debug!(
                link = %hex::encode(&link_id.as_bytes()[..4]),
                peer = %hex::encode(&identity_hash.as_bytes()[..4]),
                "link identified",
            );
        }
        NodeEvent::ResourceRejected {
            link_id,
            resource_hash,
        } => {
            tracing::warn!(
                link = %hex::encode(&link_id.as_bytes()[..4]),
                resource_hash = %hex::encode(&resource_hash[..4]),
                "resource rejected",
            );
            tracing::info!(target: "rete::test_event", event = "RESOURCE_REJECTED", link = %hex::encode(link_id), resource_hash = %hex::encode(resource_hash));
        }
        NodeEvent::RequestFailed {
            link_id,
            request_id,
            reason,
        } => {
            tracing::error!(
                link = %hex::encode(&link_id.as_bytes()[..4]),
                request_id = %hex::encode(&request_id.as_bytes()[..4]),
                reason = ?reason,
                "request failed",
            );
        }
        NodeEvent::RequestProgress {
            link_id,
            request_id,
            current,
            total,
        } => {
            tracing::debug!(
                link = %hex::encode(&link_id.as_bytes()[..4]),
                request_id = %hex::encode(&request_id.as_bytes()[..4]),
                current,
                total,
                "request progress",
            );
        }
    }
    // Flush stdout so piped readers (test harnesses) see output immediately.
    flush_stdout();
}

pub fn handle_lxmf_command(
    cmd: NodeCommand,
    core: &mut HostedNodeCore,
    lxmf_router: &RefCell<LxmfRouter<AnyMessageStore>>,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Option<Vec<OutboundPacket>> {
    let NodeCommand::AppCommand {
        name,
        dest_hash,
        link_id: _,
        payload,
    } = cmd
    else {
        return None;
    };

    match name.as_str() {
        "stats" => {
            let now = rete_tokio::current_time_secs();
            let stats = core.stats(now);
            match serde_json::to_string(&stats) {
                Ok(json) => {
                    tracing::info!(target: "rete::test_event", event = "STATS", payload = %json);
                    flush_stdout();
                }
                Err(e) => tracing::error!(error = %e, "stats: serialize error"),
            }
            None
        }
        "lxmf-send" => {
            let Some(dest_hash) = dest_hash else {
                tracing::error!("lxmf-send: missing dest_hash");
                return None;
            };
            let now_secs = rete_tokio::current_time_secs();
            let mut router = lxmf_router.borrow_mut();
            let source_hash = *router.delivery_dest_hash();
            let msg = match LXMessage::new(
                dest_hash,
                source_hash,
                core.identity(),
                b"",
                &payload,
                std::collections::BTreeMap::new(),
                now_secs as f64,
            ) {
                Ok(m) => m,
                Err(e) => {
                    tracing::error!(error = %e, "lxmf-send: failed to create message");
                    return None;
                }
            };

            let message_hash = router.handle_outbound(msg, now_secs, rng);
            tracing::info!(
                dest = %hex::encode(dest_hash),
                msg_hash = %hex::encode(&message_hash[..8]),
                "LXMF queued",
            );
            tracing::info!(target: "rete::test_event", event = "LXMF_SENT", dest = %hex::encode(dest_hash));
            flush_stdout();
            // The actual send happens in process_outbound on next tick
            None
        }
        "lxmf-announce" => {
            let now = rete_tokio::current_time_secs();
            let router = lxmf_router.borrow();
            router.queue_delivery_announce(core, rng, now);
            router.queue_propagation_announce(core, rng, now);
            let announces = core.flush_announces(now, rng);
            tracing::info!("LXMF delivery announce sent");
            Some(announces)
        }
        "lxmf-prop-announce" => {
            let now = rete_tokio::current_time_secs();
            let router = lxmf_router.borrow();
            if router.queue_propagation_announce(core, rng, now) {
                let announces = core.flush_announces(now, rng);
                tracing::info!("LXMF propagation announce sent");
                Some(announces)
            } else {
                tracing::warn!("propagation not enabled");
                None
            }
        }
        _ => {
            tracing::warn!(%name, "unknown app command");
            None
        }
    }
}

fn flush_stdout() {
    use std::io::Write;
    std::io::stdout().flush().ok();
}
