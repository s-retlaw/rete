//! rete-tokio — Tokio runtime harness for Reticulum.
//!
//! Provides [`ReteNode`] which drives transport + interfaces in an async
//! event loop using `tokio::select!`.

use rete_core::{Identity, MTU, TRUNCATED_HASH_LEN, PacketBuilder, PacketType, DestType, HeaderType};
use rete_stack::ReteInterface;
use rete_transport::{HostedTransport, Transport, IngestResult};

use std::time::{SystemTime, UNIX_EPOCH};

/// Default announce interval in seconds.
pub const ANNOUNCE_INTERVAL_SECS: u64 = 300;

/// Tick interval in seconds (path expiry, announce retransmission).
pub const TICK_INTERVAL_SECS: u64 = 60;

/// Event emitted by the node's run loop.
#[derive(Debug)]
pub enum NodeEvent {
    /// A valid announce was received.
    AnnounceReceived {
        /// Destination hash of the announcing identity.
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        /// Identity hash of the announcer.
        identity_hash: [u8; TRUNCATED_HASH_LEN],
        /// Hop count at time of receipt.
        hops: u8,
        /// Application data from the announce (owned copy).
        app_data: Option<Vec<u8>>,
    },
    /// A data packet addressed to one of our destinations was received.
    DataReceived {
        /// Destination hash the packet was addressed to.
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        /// Payload data (owned copy).
        payload: Vec<u8>,
    },
    /// Periodic tick completed.
    Tick {
        /// Number of paths expired.
        expired_paths: usize,
    },
}

/// A Reticulum node running on the Tokio runtime.
///
/// Owns the transport state machine and drives one or more interfaces.
pub struct ReteNode {
    /// The local identity for this node.
    pub identity: Identity,
    /// Transport state (path table, announce queue, dedup).
    pub transport: HostedTransport,
    /// Application name for our destination.
    app_name: String,
    /// Destination aspects.
    aspects: Vec<String>,
    /// Our destination hash.
    dest_hash: [u8; TRUNCATED_HASH_LEN],
    /// Optional auto-reply message sent after receiving an announce.
    auto_reply: Option<Vec<u8>>,
}

impl ReteNode {
    /// Create a new node with the given identity and destination.
    pub fn new(identity: Identity, app_name: &str, aspects: &[&str]) -> Self {
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name(app_name, aspects, &mut name_buf)
            .expect("app_name + aspects must fit in 128 bytes");
        let id_hash = identity.hash();
        let dest_hash = rete_core::destination_hash(expanded, Some(&id_hash));

        ReteNode {
            identity,
            transport: Transport::new(),
            app_name: app_name.to_string(),
            aspects: aspects.iter().map(|s| s.to_string()).collect(),
            dest_hash,
            auto_reply: None,
        }
    }

    /// Returns our destination hash.
    pub fn dest_hash(&self) -> &[u8; TRUNCATED_HASH_LEN] {
        &self.dest_hash
    }

    /// Set an auto-reply message sent to any peer that announces.
    pub fn set_auto_reply(&mut self, msg: Option<Vec<u8>>) {
        self.auto_reply = msg;
    }

    /// Build an encrypted DATA packet addressed to a known destination.
    ///
    /// Uses HEADER_2 (transport) when the path was learned via a relay node.
    fn build_data_packet(&self, dest_hash: &[u8; TRUNCATED_HASH_LEN], plaintext: &[u8]) -> Option<Vec<u8>> {
        let pub_key = self.transport.recall_identity(dest_hash)?;
        let recipient = Identity::from_public_key(pub_key).ok()?;
        let mut rng = rand::thread_rng();
        let mut ct_buf = [0u8; MTU];
        let ct_len = recipient.encrypt(plaintext, &mut rng, &mut ct_buf).ok()?;
        let via = self.transport.get_path(dest_hash).and_then(|p| p.via);
        let mut pkt_buf = [0u8; MTU];
        let builder = PacketBuilder::new(&mut pkt_buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Single)
            .destination_hash(dest_hash)
            .context(0x00)
            .payload(&ct_buf[..ct_len]);
        let builder = if let Some(transport_id) = via {
            builder
                .header_type(HeaderType::Header2)
                .transport_type(1)
                .transport_id(&transport_id)
        } else {
            builder
        };
        let pkt_len = builder.build().ok()?;
        Some(pkt_buf[..pkt_len].to_vec())
    }

    /// Build and return a raw announce packet for this node.
    pub fn build_announce(&self, app_data: Option<&[u8]>) -> Vec<u8> {
        let aspects_refs: Vec<&str> = self.aspects.iter().map(|s| s.as_str()).collect();
        let mut rng = rand::thread_rng();
        let now = current_time_secs();
        let mut buf = [0u8; MTU];
        let n = Transport::<1024, 256, 4096>::create_announce(
            &self.identity,
            &self.app_name,
            &aspects_refs,
            app_data,
            &mut rng,
            now,
            &mut buf,
        )
        .expect("announce creation should not fail");
        buf[..n].to_vec()
    }

    /// Run the main event loop with a single interface.
    ///
    /// Sends an initial announce, then loops:
    /// - Receive packets from the interface → ingest → emit events
    /// - Periodically re-announce
    /// - Periodically tick (expire paths, retransmit announces)
    ///
    /// The `on_event` callback is invoked for each event.
    pub async fn run<I, F>(
        &mut self,
        iface: &mut I,
        mut on_event: F,
    ) where
        I: ReteInterface,
        F: FnMut(NodeEvent),
    {
        // Send initial announce
        let announce = self.build_announce(None);
        if let Err(e) = iface.send(&announce).await {
            eprintln!("[rete] failed to send initial announce: {:?}", e);
        } else {
            eprintln!(
                "[rete] sent announce for dest {}",
                hex(&self.dest_hash)
            );
        }

        let mut announce_timer = tokio::time::interval(
            std::time::Duration::from_secs(ANNOUNCE_INTERVAL_SECS),
        );
        let mut tick_timer = tokio::time::interval(
            std::time::Duration::from_secs(TICK_INTERVAL_SECS),
        );
        // Skip the immediate first tick (we just sent the announce)
        announce_timer.tick().await;
        tick_timer.tick().await;

        let mut recv_buf = [0u8; MTU];

        loop {
            tokio::select! {
                result = iface.recv(&mut recv_buf) => {
                    match result {
                        Ok(data) => {
                            let len = data.len();
                            // Copy into a mutable buffer for ingest (which increments hops)
                            let mut pkt_buf = [0u8; MTU];
                            pkt_buf[..len].copy_from_slice(data);
                            let now = current_time_secs();
                            match self.transport.ingest(&mut pkt_buf[..len], now) {
                                IngestResult::AnnounceReceived { dest_hash, identity_hash, hops, app_data } => {
                                    on_event(NodeEvent::AnnounceReceived {
                                        dest_hash,
                                        identity_hash,
                                        hops,
                                        app_data: app_data.map(|d| d.to_vec()),
                                    });
                                    if let Some(ref msg) = self.auto_reply {
                                        if let Some(pkt) = self.build_data_packet(&dest_hash, msg) {
                                            if let Err(e) = iface.send(&pkt).await {
                                                eprintln!("[rete] auto-reply send failed: {:?}", e);
                                            } else {
                                                println!("DATA_SENT:{}:{}", hex(&dest_hash), String::from_utf8_lossy(msg));
                                            }
                                        }
                                    }
                                }
                                IngestResult::LocalData { dest_hash, payload } => {
                                    let decrypted = if dest_hash == self.dest_hash {
                                        let mut dec_buf = [0u8; MTU];
                                        match self.identity.decrypt(payload, &mut dec_buf) {
                                            Ok(n) => dec_buf[..n].to_vec(),
                                            Err(_) => payload.to_vec(),
                                        }
                                    } else {
                                        payload.to_vec()
                                    };
                                    on_event(NodeEvent::DataReceived {
                                        dest_hash,
                                        payload: decrypted,
                                    });
                                }
                                IngestResult::Forward { raw } => {
                                    // Forward to all interfaces (we only have one for now)
                                    let _ = iface.send(raw).await;
                                }
                                IngestResult::Duplicate | IngestResult::Invalid => {
                                    // Silently drop
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[rete] recv error: {:?}", e);
                            break;
                        }
                    }
                }
                _ = announce_timer.tick() => {
                    let announce = self.build_announce(None);
                    if let Err(e) = iface.send(&announce).await {
                        eprintln!("[rete] failed to send periodic announce: {:?}", e);
                    }
                }
                _ = tick_timer.tick() => {
                    let now = current_time_secs();
                    let result = self.transport.tick(now);
                    on_event(NodeEvent::Tick {
                        expired_paths: result.expired_paths,
                    });

                    // Send pending outbound announces
                    let pending = self.transport.pending_outbound(now);
                    for ann_raw in pending {
                        if let Err(e) = iface.send(&ann_raw).await {
                            eprintln!("[rete] failed to retransmit announce: {:?}", e);
                        }
                    }
                }
            }
        }
    }
}

/// Get current time as seconds since UNIX epoch.
fn current_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Format bytes as hex string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
