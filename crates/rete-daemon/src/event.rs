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
            eprintln!("[rete] propagation: pruned {pruned} expired messages");
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
                eprintln!("[rete] failed to save snapshot: {e:?}");
            } else {
                eprintln!(
                    "[rete] snapshot saved: {} paths, {} identities",
                    snap.paths.len(),
                    snap.identities.len()
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
            eprintln!("[rete] peer sync: initiated {} link(s)", sync_pkts.len());
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
            eprintln!(
                "[rete] LXMF_RECEIVED from={} method={:?} title=\"{}\" content=\"{}\"",
                source, method, title, content,
            );
            println!("LXMF_RECEIVED:{}:{}:{}", source, title, content);
        }
        LxmfEvent::PeerAnnounced {
            dest_hash,
            display_name,
        } => {
            let name = display_name
                .as_deref()
                .map(|n| String::from_utf8_lossy(n).to_string())
                .unwrap_or_default();
            eprintln!(
                "[rete] LXMF_PEER dest={} name=\"{}\"",
                hex::encode(dest_hash),
                name,
            );
            println!("LXMF_PEER:{}:{}", hex::encode(dest_hash), name);
        }
        LxmfEvent::PropagationDeposit {
            dest_hash,
            message_hash,
        } => {
            eprintln!(
                "[rete] PROP_DEPOSIT dest={} msg={}",
                hex::encode(dest_hash),
                hex::encode(message_hash),
            );
            println!(
                "PROP_DEPOSIT:{}:{}",
                hex::encode(dest_hash),
                hex::encode(message_hash),
            );
        }
        LxmfEvent::PropagationRetrievalRequest {
            link_id,
            request_id,
            dest_hash,
            result,
        } => {
            let count = result.message_hashes.len();
            eprintln!(
                "[rete] PROP_RETRIEVAL_REQUEST link={} dest={} count={}",
                hex::encode(link_id),
                hex::encode(dest_hash),
                count,
            );
            println!(
                "PROP_RETRIEVAL_REQUEST:{}:{}:{}",
                hex::encode(link_id),
                hex::encode(dest_hash),
                count,
            );

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
            eprintln!(
                "[rete] PROP_FORWARD dest={} count={}",
                hex::encode(dest_hash),
                count,
            );
            println!("PROP_FORWARD:{}:{}", hex::encode(dest_hash), count);

            // Auto-forward: initiate a link to the destination
            let mut router = lxmf_router.borrow_mut();
            if !router.has_forward_job_for(&dest_hash) {
                let now = rete_tokio::current_time_secs();
                if let Some((pkt, link_id)) =
                    router.start_propagation_forward(&dest_hash, core, rng, now)
                {
                    eprintln!(
                        "[rete] PROP_FORWARD_LINK dest={} link={}",
                        hex::encode(dest_hash),
                        hex::encode(link_id),
                    );
                    println!(
                        "PROP_FORWARD_LINK:{}:{}",
                        hex::encode(dest_hash),
                        hex::encode(link_id),
                    );
                    flush_stdout();
                    return vec![pkt];
                } else {
                    eprintln!(
                        "[rete] PROP_FORWARD_FAIL dest={} (no path or no messages)",
                        hex::encode(dest_hash),
                    );
                }
            }
        }
        LxmfEvent::PeerDiscovered {
            dest_hash,
            identity_hash,
        } => {
            eprintln!(
                "[rete] PEER_DISCOVERED dest={} identity={}",
                hex::encode(dest_hash),
                hex::encode(identity_hash),
            );
            println!(
                "PEER_DISCOVERED:{}:{}",
                hex::encode(dest_hash),
                hex::encode(identity_hash),
            );
        }
        LxmfEvent::PeerSyncComplete {
            dest_hash,
            messages_sent,
        } => {
            eprintln!(
                "[rete] PEER_SYNC_COMPLETE dest={} sent={}",
                hex::encode(dest_hash),
                messages_sent,
            );
            println!(
                "PEER_SYNC_COMPLETE:{}:{}",
                hex::encode(dest_hash),
                messages_sent,
            );
        }
        LxmfEvent::PeerOfferReceived {
            link_id,
            request_id,
            response_data,
        } => {
            eprintln!(
                "[rete] PEER_OFFER_RECEIVED link={} response_len={}",
                hex::encode(link_id),
                response_data.len(),
            );
            println!("PEER_OFFER_RECEIVED:{}", hex::encode(link_id));

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
            println!(
                "LXMF_DELIVERED:{}:{}",
                hex::encode(&message_hash[..8]),
                hex::encode(dest_hash)
            );
            eprintln!(
                "[lxmf] message delivered: hash={}, dest={}",
                hex::encode(&message_hash[..8]),
                hex::encode(dest_hash)
            );
        }
        LxmfEvent::MessageFailed {
            message_hash,
            dest_hash,
        } => {
            println!(
                "LXMF_FAILED:{}:{}",
                hex::encode(&message_hash[..8]),
                hex::encode(dest_hash)
            );
            eprintln!(
                "[lxmf] message failed: hash={}, dest={}",
                hex::encode(&message_hash[..8]),
                hex::encode(dest_hash)
            );
        }
        LxmfEvent::MessageRejectedStamp {
            source_hash,
            message_hash,
        } => {
            println!(
                "LXMF_REJECTED_STAMP:{}:{}",
                hex::encode(source_hash),
                hex::encode(&message_hash[..8])
            );
            eprintln!(
                "[lxmf] message rejected (invalid stamp): source={}, hash={}",
                hex::encode(source_hash),
                hex::encode(&message_hash[..8])
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
                        eprintln!(
                            "[rete] PROP_FORWARD_SENDING link={} pkts={}",
                            hex::encode(link_id),
                            pkts.len(),
                        );
                        println!("PROP_FORWARD_SENDING:{}", hex::encode(link_id));
                        on_node_event(event);
                        return pkts;
                    }

                    // Try outbound direct jobs
                    let pkts = lxmf_router
                        .borrow_mut()
                        .advance_outbound_on_link_established(link_id, core, rng);
                    if !pkts.is_empty() {
                        eprintln!("[rete] LXMF_OUTBOUND_SENDING link={}", hex::encode(link_id),);
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
                        eprintln!("[rete] PEER_SYNC_IDENTIFYING link={}", hex::encode(link_id),);
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
                        eprintln!(
                            "[rete] PEER_SYNC_TRANSFERRING link={}",
                            hex::encode(link_id),
                        );
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
                        eprintln!(
                            "[rete] PROP_RETRIEVAL_SENDING link={} pkts={}",
                            hex::encode(link_id),
                            pkts.len(),
                        );
                        println!("PROP_RETRIEVAL_SENDING:{}", hex::encode(link_id));
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
                                eprintln!(
                                    "[rete] PEER_SYNC_COMPLETE dest={} sent={}",
                                    hex::encode(dest_hash),
                                    messages_sent,
                                );
                                println!(
                                    "PEER_SYNC_COMPLETE:{}:{}",
                                    hex::encode(dest_hash),
                                    messages_sent,
                                );
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
                                eprintln!(
                                    "[rete] PEER_SYNC_DEPOSIT dest={} msg={}",
                                    hex::encode(dest),
                                    hex::encode(hash),
                                );
                                println!(
                                    "PEER_SYNC_DEPOSIT:{}:{}",
                                    hex::encode(dest),
                                    hex::encode(hash),
                                );
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
            eprintln!(
                "[rete] ANNOUNCE dest={} identity={} hops={}{}",
                hex::encode(dest_hash),
                hex::encode(identity_hash),
                hops,
                app_data
                    .as_ref()
                    .map(|d| {
                        match std::str::from_utf8(d) {
                            Ok(s) => format!(" app_data=\"{s}\""),
                            Err(_) => format!(" app_data={}", hex::encode(d)),
                        }
                    })
                    .unwrap_or_default(),
            );
            if let Some(ref ad) = app_data {
                println!(
                    "ANNOUNCE:{}:{}:{}:{}",
                    hex::encode(dest_hash),
                    hex::encode(identity_hash),
                    hops,
                    hex::encode(ad),
                );
            } else {
                println!(
                    "ANNOUNCE:{}:{}:{}",
                    hex::encode(dest_hash),
                    hex::encode(identity_hash),
                    hops,
                );
            }
        }
        NodeEvent::DataReceived { dest_hash, payload } => {
            eprintln!(
                "[rete] DATA dest={} len={}",
                hex::encode(dest_hash),
                payload.len(),
            );
            match std::str::from_utf8(&payload) {
                Ok(text) => {
                    eprintln!("[rete]   text: {text}");
                    println!("DATA:{}:{}", hex::encode(dest_hash), text);
                }
                Err(_) => {
                    eprintln!("[rete]   hex: {}", hex::encode(&payload));
                    println!("DATA:{}:{}", hex::encode(dest_hash), hex::encode(&payload));
                }
            }
        }
        NodeEvent::ProofReceived { packet_hash } => {
            eprintln!(
                "[rete] PROOF received for packet {}",
                hex::encode(packet_hash),
            );
            println!("PROOF_RECEIVED:{}", hex::encode(packet_hash));
        }
        NodeEvent::LinkEstablished { link_id } => {
            eprintln!("[rete] LINK established: {}", hex::encode(link_id));
            println!("LINK_ESTABLISHED:{}", hex::encode(link_id));
        }
        NodeEvent::LinkData {
            link_id,
            data,
            context,
        } => {
            eprintln!(
                "[rete] LINK_DATA link={} ctx={:#04x} len={}",
                hex::encode(link_id),
                context,
                data.len(),
            );
            match std::str::from_utf8(&data) {
                Ok(text) => println!("LINK_DATA:{}:{}", hex::encode(link_id), text),
                Err(_) => println!("LINK_DATA:{}:{}", hex::encode(link_id), hex::encode(&data)),
            }
        }
        NodeEvent::ChannelMessages { link_id, messages } => {
            eprintln!(
                "[rete] CHANNEL messages on {}: {} msgs",
                hex::encode(link_id),
                messages.len()
            );
            for (msg_type, payload) in &messages {
                eprintln!("  type=0x{:04x} len={}", msg_type, payload.len());
                match std::str::from_utf8(payload) {
                    Ok(text) => println!(
                        "CHANNEL_MSG:{}:{:#06x}:{}",
                        hex::encode(link_id),
                        msg_type,
                        text
                    ),
                    Err(_) => println!(
                        "CHANNEL_MSG:{}:{:#06x}:{}",
                        hex::encode(link_id),
                        msg_type,
                        hex::encode(payload)
                    ),
                }
            }
        }
        NodeEvent::RequestReceived {
            link_id,
            request_id,
            path_hash,
            data,
        } => {
            eprintln!(
                "[rete] REQUEST on link={} req_id={} path_hash={} data_len={}",
                hex::encode(link_id),
                hex::encode(request_id),
                hex::encode(path_hash),
                data.len()
            );
            println!(
                "REQUEST_RECEIVED:{}:{}:{}:{}",
                hex::encode(link_id),
                hex::encode(request_id),
                hex::encode(path_hash),
                data.len()
            );
        }
        NodeEvent::ResponseReceived {
            link_id,
            request_id,
            data,
        } => {
            eprintln!(
                "[rete] RESPONSE on link={} req_id={} data_len={}",
                hex::encode(link_id),
                hex::encode(request_id),
                data.len()
            );
            println!(
                "RESPONSE_RECEIVED:{}:{}:{}",
                hex::encode(link_id),
                hex::encode(request_id),
                data.len()
            );
        }
        NodeEvent::LinkClosed { link_id } => {
            eprintln!("[rete] LINK closed: {}", hex::encode(link_id));
            println!("LINK_CLOSED:{}", hex::encode(link_id));
        }
        NodeEvent::ResourceOffered {
            link_id,
            resource_hash,
            total_size,
        } => {
            eprintln!(
                "[rete] RESOURCE offered on link={} hash={} size={}",
                hex::encode(link_id),
                hex::encode(resource_hash),
                total_size
            );
            println!(
                "RESOURCE_OFFERED:{}:{}:{}",
                hex::encode(link_id),
                hex::encode(resource_hash),
                total_size
            );
            eprintln!("[rete] RESOURCE_OFFERED event processed");
        }
        NodeEvent::ResourceProgress {
            link_id,
            resource_hash,
            current,
            total,
        } => {
            eprintln!(
                "[rete] RESOURCE progress on link={} hash={} {}/{}",
                hex::encode(link_id),
                hex::encode(resource_hash),
                current,
                total
            );
        }
        NodeEvent::ResourceComplete {
            link_id,
            resource_hash,
            ref data,
        } => {
            let display = match std::str::from_utf8(data) {
                Ok(text) => text.to_string(),
                Err(_) => hex::encode(data),
            };
            eprintln!(
                "[rete] RESOURCE complete on link={} hash={} len={}",
                hex::encode(link_id),
                hex::encode(resource_hash),
                data.len()
            );
            println!(
                "RESOURCE_COMPLETE:{}:{}:{}",
                hex::encode(link_id),
                hex::encode(resource_hash),
                display
            );
        }
        NodeEvent::ResourceFailed {
            link_id,
            resource_hash,
        } => {
            eprintln!(
                "[rete] RESOURCE failed on link={} hash={}",
                hex::encode(link_id),
                hex::encode(resource_hash)
            );
            println!(
                "RESOURCE_FAILED:{}:{}",
                hex::encode(link_id),
                hex::encode(resource_hash)
            );
        }
        NodeEvent::Tick { expired_paths, .. } => {
            if expired_paths > 0 {
                eprintln!("[rete] tick: expired {expired_paths} paths");
            }
        }
        NodeEvent::LinkIdentified {
            link_id,
            identity_hash,
            ..
        } => {
            eprintln!(
                "[rete] link {} identified: peer {}",
                hex::encode(&link_id.as_bytes()[..4]),
                hex::encode(&identity_hash.as_bytes()[..4])
            );
        }
        NodeEvent::ResourceRejected {
            link_id,
            resource_hash,
        } => {
            eprintln!(
                "[rete] RESOURCE rejected on link={} hash={}",
                hex::encode(&link_id.as_bytes()[..4]),
                hex::encode(&resource_hash[..4])
            );
            println!(
                "RESOURCE_REJECTED:{}:{}",
                hex::encode(link_id),
                hex::encode(resource_hash)
            );
        }
        NodeEvent::RequestFailed {
            link_id,
            request_id,
            reason,
        } => {
            eprintln!(
                "[rete] REQUEST failed link={} req={} reason={:?}",
                hex::encode(&link_id.as_bytes()[..4]),
                hex::encode(&request_id.as_bytes()[..4]),
                reason
            );
        }
        NodeEvent::RequestProgress {
            link_id,
            request_id,
            current,
            total,
        } => {
            eprintln!(
                "[rete] REQUEST progress link={} req={} {}/{}",
                hex::encode(&link_id.as_bytes()[..4]),
                hex::encode(&request_id.as_bytes()[..4]),
                current,
                total
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
                    println!("STATS:{json}");
                    flush_stdout();
                }
                Err(e) => eprintln!("[rete] stats: serialize error: {e}"),
            }
            None
        }
        "lxmf-send" => {
            let Some(dest_hash) = dest_hash else {
                eprintln!("[rete] lxmf-send: missing dest_hash");
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
                    eprintln!("[rete] lxmf-send: failed to create message: {e}");
                    return None;
                }
            };

            let message_hash = router.handle_outbound(msg, now_secs, rng);
            eprintln!(
                "[rete] LXMF queued for {} (hash={})",
                hex::encode(dest_hash),
                hex::encode(&message_hash[..8])
            );
            println!("LXMF_SENT:{}", hex::encode(dest_hash));
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
            eprintln!("[rete] LXMF delivery announce sent");
            Some(announces)
        }
        "lxmf-prop-announce" => {
            let now = rete_tokio::current_time_secs();
            let router = lxmf_router.borrow();
            if router.queue_propagation_announce(core, rng, now) {
                let announces = core.flush_announces(now, rng);
                eprintln!("[rete] LXMF propagation announce sent");
                Some(announces)
            } else {
                eprintln!("[rete] propagation not enabled");
                None
            }
        }
        _ => {
            eprintln!("[rete] unknown app command: {name}");
            None
        }
    }
}

fn flush_stdout() {
    use std::io::Write;
    std::io::stdout().flush().ok();
}
