//! Node event handling: routes NodeEvent through the LXMF router and emits
//! structured events via [`ReteEvent`].

use std::cell::RefCell;

use rete_lxmf::{LXMessage, LxmfEvent, LxmfRouter};
use rete_stack::{HostedNodeCore, NodeStats, OutboundPacket};
use rete_tokio::{NodeCommand, NodeEvent};
use rete_transport::SnapshotStore as _;

use crate::file_store::AnyMessageStore;
use crate::identity::JsonFileStore;
use crate::rete_event::ReteEvent;

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
        LxmfEvent::MessageReceived { message, .. } => {
            ReteEvent::LxmfReceived {
                source: hex::encode(message.source_hash),
                title: String::from_utf8_lossy(&message.title).into_owned(),
                content: String::from_utf8_lossy(&message.content).into_owned(),
            }.emit();
        }
        LxmfEvent::PeerAnnounced { dest_hash, display_name } => {
            ReteEvent::LxmfPeer {
                dest: hex::encode(dest_hash),
                name: display_name
                    .as_deref()
                    .map(|n| String::from_utf8_lossy(n).into_owned())
                    .unwrap_or_default(),
            }.emit();
        }
        LxmfEvent::PropagationDeposit { dest_hash, message_hash } => {
            ReteEvent::PropDeposit {
                dest: hex::encode(dest_hash),
                msg_hash: hex::encode(message_hash),
            }.emit();
        }
        LxmfEvent::PropagationRetrievalRequest {
            link_id, request_id, dest_hash, result,
        } => {
            let count = result.message_hashes.len();
            ReteEvent::PropRetrievalRequest {
                link: hex::encode(link_id),
                dest: hex::encode(dest_hash),
                count,
            }.emit();

            let mut packets = Vec::new();
            if let Ok(resp_pkt) =
                core.send_response(&link_id, &request_id, &result.response_data, rng)
            {
                packets.push(resp_pkt);
            }
            if !result.message_hashes.is_empty() {
                let hashes = result.message_hashes;
                let retrieval_pkts = lxmf_router
                    .borrow_mut()
                    .start_retrieval_send(&link_id, hashes, core, rng);
                packets.extend(retrieval_pkts);
            }
            return packets;
        }
        LxmfEvent::PropagationForward { dest_hash, count } => {
            ReteEvent::PropForward {
                dest: hex::encode(dest_hash),
                count,
            }.emit();

            let mut router = lxmf_router.borrow_mut();
            if !router.has_forward_job_for(&dest_hash) {
                let now = rete_tokio::current_time_secs();
                if let Some((pkt, link_id)) =
                    router.start_propagation_forward(&dest_hash, core, rng, now)
                {
                    ReteEvent::PropForwardLink {
                        dest: hex::encode(dest_hash),
                        link: hex::encode(link_id),
                    }.emit();
                    return vec![pkt];
                } else {
                    tracing::warn!(
                        dest = %hex::encode(dest_hash),
                        "propagation forward failed (no path or no messages)",
                    );
                }
            }
        }
        LxmfEvent::PeerDiscovered { dest_hash, identity_hash } => {
            ReteEvent::PeerDiscovered {
                dest: hex::encode(dest_hash),
                identity: hex::encode(identity_hash),
            }.emit();
        }
        LxmfEvent::PeerSyncComplete { dest_hash, messages_sent } => {
            ReteEvent::PeerSyncComplete {
                dest: hex::encode(dest_hash),
                messages_sent,
            }.emit();
        }
        LxmfEvent::PeerOfferReceived { link_id, request_id, response_data } => {
            ReteEvent::PeerOfferReceived {
                link: hex::encode(link_id),
            }.emit();

            if let Ok(pkt) = core.send_response(&link_id, &request_id, &response_data, rng) {
                return vec![pkt];
            }
        }
        LxmfEvent::MessageDelivered { message_hash, dest_hash } => {
            ReteEvent::LxmfDelivered {
                msg_hash: hex::encode(&message_hash[..8]),
                dest: hex::encode(dest_hash),
            }.emit();
        }
        LxmfEvent::MessageFailed { message_hash, dest_hash } => {
            ReteEvent::LxmfFailed {
                msg_hash: hex::encode(&message_hash[..8]),
                dest: hex::encode(dest_hash),
            }.emit();
        }
        LxmfEvent::MessageRejectedStamp { source_hash, message_hash } => {
            ReteEvent::LxmfRejectedStamp {
                source: hex::encode(source_hash),
                msg_hash: hex::encode(&message_hash[..8]),
            }.emit();
        }
        LxmfEvent::Other(event) => {
            match &event {
                NodeEvent::LinkEstablished { link_id } => {
                    // Try forward jobs
                    let pkts = lxmf_router
                        .borrow_mut()
                        .advance_forward_on_link_established(link_id, core, rng);
                    if !pkts.is_empty() {
                        ReteEvent::PropForwardSending {
                            link: hex::encode(link_id),
                        }.emit();
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
                        link_id, core, rng, rete_tokio::current_time_secs(),
                    );
                    if !pkts.is_empty() {
                        tracing::debug!(link = %hex::encode(link_id), "peer sync identifying");
                        on_node_event(event);
                        return pkts;
                    }
                }
                NodeEvent::ResponseReceived { link_id, ref data, .. } => {
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
                NodeEvent::ResourceComplete { link_id, resource_hash, ref data } => {
                    let pkts = lxmf_router
                        .borrow_mut()
                        .advance_forward_on_resource_complete(link_id, resource_hash, core, rng);
                    if !pkts.is_empty() {
                        on_node_event(event);
                        return pkts;
                    }

                    let pkts = lxmf_router
                        .borrow_mut()
                        .advance_retrieval_on_resource_complete(link_id, resource_hash, core, rng);
                    if !pkts.is_empty() {
                        ReteEvent::PropRetrievalSending {
                            link: hex::encode(link_id),
                        }.emit();
                        on_node_event(event);
                        return pkts;
                    }

                    let now = rete_tokio::current_time_secs();
                    let (pkts, sync_event) = lxmf_router
                        .borrow_mut()
                        .advance_sync_on_resource_complete(link_id, core, rng, now);
                    if let Some(evt) = sync_event {
                        if let LxmfEvent::PeerSyncComplete { dest_hash, messages_sent } = &evt {
                            ReteEvent::PeerSyncComplete {
                                dest: hex::encode(dest_hash),
                                messages_sent: *messages_sent,
                            }.emit();
                        }
                        on_node_event(event);
                        return pkts;
                    }

                    if lxmf_router.borrow().has_sync_job_for_link(link_id) {
                        let deposited = lxmf_router.borrow_mut().deposit_sync_resource(data, now);
                        if !deposited.is_empty() {
                            for (dest, hash) in &deposited {
                                ReteEvent::PeerSyncDeposit {
                                    dest: hex::encode(dest),
                                    msg_hash: hex::encode(hash),
                                }.emit();
                            }
                            on_node_event(event);
                            return Vec::new();
                        }
                    }
                }
                NodeEvent::LinkClosed { link_id } => {
                    lxmf_router.borrow_mut().cleanup_forward_jobs_for_link(link_id);
                    lxmf_router.borrow_mut().cleanup_sync_jobs_for_link(link_id);
                }
                _ => {}
            }
            on_node_event(event);
        }
    }
    Vec::new()
}

pub fn on_node_event(event: NodeEvent) {
    match event {
        NodeEvent::AnnounceReceived { dest_hash, identity_hash, hops, app_data } => {
            ReteEvent::Announce {
                dest: hex::encode(dest_hash),
                identity: hex::encode(identity_hash),
                hops,
                app_data: app_data.as_ref().map(|d| hex::encode(d)),
            }.emit();
        }
        NodeEvent::DataReceived { dest_hash, payload } => {
            let payload_str = match std::str::from_utf8(&payload) {
                Ok(text) => text.to_string(),
                Err(_) => hex::encode(&payload),
            };
            ReteEvent::Data {
                dest: hex::encode(dest_hash),
                payload: payload_str,
            }.emit();
        }
        NodeEvent::ProofReceived { packet_hash } => {
            ReteEvent::ProofReceived {
                packet_hash: hex::encode(packet_hash),
            }.emit();
        }
        NodeEvent::LinkEstablished { link_id } => {
            ReteEvent::LinkEstablished {
                link: hex::encode(link_id),
            }.emit();
        }
        NodeEvent::LinkData { link_id, data, .. } => {
            let payload = match std::str::from_utf8(&data) {
                Ok(text) => text.to_string(),
                Err(_) => hex::encode(&data),
            };
            ReteEvent::LinkData {
                link: hex::encode(link_id),
                payload,
            }.emit();
        }
        NodeEvent::ChannelMessages { link_id, messages } => {
            for (msg_type, payload) in &messages {
                let payload_str = match std::str::from_utf8(payload) {
                    Ok(text) => text.to_string(),
                    Err(_) => hex::encode(payload),
                };
                ReteEvent::ChannelMsg {
                    link: hex::encode(link_id),
                    msg_type: format!("{:#06x}", msg_type),
                    payload: payload_str,
                }.emit();
            }
        }
        NodeEvent::RequestReceived { link_id, request_id, path_hash, data } => {
            ReteEvent::RequestReceived {
                link: hex::encode(link_id),
                request_id: hex::encode(request_id),
                path_hash: hex::encode(path_hash),
                data_len: data.len(),
            }.emit();
        }
        NodeEvent::ResponseReceived { link_id, request_id, data } => {
            ReteEvent::ResponseReceived {
                link: hex::encode(link_id),
                request_id: hex::encode(request_id),
                data_len: data.len(),
            }.emit();
        }
        NodeEvent::LinkClosed { link_id } => {
            ReteEvent::LinkClosed {
                link: hex::encode(link_id),
            }.emit();
        }
        NodeEvent::ResourceOffered { link_id, resource_hash, total_size } => {
            ReteEvent::ResourceOffered {
                link: hex::encode(link_id),
                resource_hash: hex::encode(resource_hash),
                total_size,
            }.emit();
        }
        NodeEvent::ResourceProgress { .. } => {
            // Debug-level only, not a structured event
        }
        NodeEvent::ResourceComplete { link_id, resource_hash, ref data } => {
            let payload = match std::str::from_utf8(data) {
                Ok(text) => text.to_string(),
                Err(_) => hex::encode(data),
            };
            ReteEvent::ResourceComplete {
                link: hex::encode(link_id),
                resource_hash: hex::encode(resource_hash),
                payload,
            }.emit();
        }
        NodeEvent::ResourceFailed { link_id, resource_hash } => {
            ReteEvent::ResourceFailed {
                link: hex::encode(link_id),
                resource_hash: hex::encode(resource_hash),
            }.emit();
        }
        NodeEvent::ResourceRejected { link_id, resource_hash } => {
            ReteEvent::ResourceRejected {
                link: hex::encode(link_id),
                resource_hash: hex::encode(resource_hash),
            }.emit();
        }
        NodeEvent::Tick { expired_paths, .. } => {
            if expired_paths > 0 {
                tracing::debug!(expired_paths, "tick: expired paths");
            }
        }
        NodeEvent::LinkIdentified { link_id, identity_hash, .. } => {
            tracing::debug!(
                link = %hex::encode(&link_id.as_bytes()[..4]),
                peer = %hex::encode(&identity_hash.as_bytes()[..4]),
                "link identified",
            );
        }
        NodeEvent::RequestFailed { link_id, request_id, reason } => {
            tracing::error!(
                link = %hex::encode(&link_id.as_bytes()[..4]),
                request_id = %hex::encode(&request_id.as_bytes()[..4]),
                reason = ?reason,
                "request failed",
            );
        }
        NodeEvent::RequestProgress { .. } => {
            // Debug-level only, not a structured event
        }
    }
}

pub fn handle_lxmf_command(
    cmd: NodeCommand,
    core: &mut HostedNodeCore,
    lxmf_router: &RefCell<LxmfRouter<AnyMessageStore>>,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Option<Vec<OutboundPacket>> {
    let NodeCommand::AppCommand {
        name, dest_hash, link_id: _, payload,
    } = cmd
    else {
        return None;
    };

    match name.as_str() {
        "stats" => {
            let now = rete_tokio::current_time_secs();
            let stats = core.stats(now);
            match serde_json::to_string(&stats) {
                Ok(json) => ReteEvent::Stats { payload: json }.emit(),
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
                dest_hash, source_hash, core.identity(),
                b"", &payload,
                std::collections::BTreeMap::new(),
                now_secs as f64,
            ) {
                Ok(m) => m,
                Err(e) => {
                    tracing::error!(error = %e, "lxmf-send: failed to create message");
                    return None;
                }
            };

            let _message_hash = router.handle_outbound(msg, now_secs, rng);
            ReteEvent::LxmfSent {
                dest: hex::encode(dest_hash),
            }.emit();
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
