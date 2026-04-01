//! Event dispatch — handle_event and handle_event_mut.

use rete_core::TRUNCATED_HASH_LEN;
use rete_stack::NodeEvent;

use crate::peer::{LxmPeer, SyncStrategy};
use crate::propagation::MessageStore;
use crate::DeliveryMethod;

use super::codec::{parse_lxmf_announce_data, try_parse_lxmf_announce_data};
use super::{LxmfEvent, LxmfRouter};

impl<S: MessageStore> LxmfRouter<S> {
    // -----------------------------------------------------------------------
    // Event handling
    // -----------------------------------------------------------------------

    /// Dispatch a NodeEvent through LXMF parsing.
    ///
    /// Returns an LxmfEvent — either a parsed LXMF message, a peer announce,
    /// a propagation event, or the original event wrapped as Other.
    ///
    /// Note: for propagation deposit handling, call `handle_event_mut` instead
    /// so that ResourceComplete events on the propagation link can be deposited
    /// into the store.
    pub fn handle_event(&self, event: NodeEvent) -> LxmfEvent {
        match event {
            NodeEvent::DataReceived {
                dest_hash,
                ref payload,
            } => {
                if let Some(msg) = self.try_parse_lxmf(&dest_hash, payload) {
                    LxmfEvent::MessageReceived {
                        message: msg,
                        method: DeliveryMethod::Opportunistic,
                    }
                } else {
                    LxmfEvent::Other(event)
                }
            }
            NodeEvent::LinkData { ref data, .. } => {
                // Direct delivery: small LXMF messages are sent as link data.
                // The data is the full packed LXMF message (same format as resource).
                if let Some(msg) = Self::try_parse_lxmf_resource(data) {
                    LxmfEvent::MessageReceived {
                        message: msg,
                        method: DeliveryMethod::Direct,
                    }
                } else {
                    LxmfEvent::Other(event)
                }
            }
            NodeEvent::ResourceComplete { ref data, .. } => {
                // Direct delivery: large LXMF messages are sent as resources.
                // Note: Python LXMF compresses resource data with bz2. The example
                // binary decompresses ResourceComplete data before it reaches here.
                // If you call handle_event() directly, decompress first.
                if let Some(msg) = Self::try_parse_lxmf_resource(data) {
                    LxmfEvent::MessageReceived {
                        message: msg,
                        method: DeliveryMethod::Direct,
                    }
                } else {
                    LxmfEvent::Other(event)
                }
            }
            NodeEvent::AnnounceReceived {
                dest_hash,
                ref app_data,
                ..
            } => {
                // Check if propagation has messages for this announcing dest
                if let Some(fwd) = self.check_propagation_forward(&dest_hash) {
                    return fwd;
                }
                // Try to parse announce app_data as LXMF format
                if let Some(ref data) = app_data {
                    if let Some(display_name) = try_parse_lxmf_announce_data(data) {
                        return LxmfEvent::PeerAnnounced {
                            dest_hash,
                            display_name: Some(display_name),
                        };
                    }
                }
                LxmfEvent::Other(event)
            }
            other => LxmfEvent::Other(other),
        }
    }

    /// Dispatch a NodeEvent through LXMF parsing, with mutable access for
    /// propagation deposit handling.
    ///
    /// This is the preferred method when propagation is enabled. When a
    /// ResourceComplete event is received and propagation is active, the
    /// resource data is deposited into the propagation store.
    ///
    /// Also handles `RequestReceived` events for propagation retrieval:
    /// if the path matches `/lxmf/propagation/retrieve`, returns
    /// `LxmfEvent::PropagationRetrievalRequest`.
    pub fn handle_event_mut(&mut self, event: NodeEvent, now: u64) -> LxmfEvent {
        // For ResourceComplete: try propagation deposit first if enabled
        if self.propagation.is_some() {
            if let NodeEvent::ResourceComplete { ref data, .. } = event {
                // Try to deposit into propagation store
                if let Some(deposit_event) = self.propagation_deposit(data, now) {
                    return deposit_event;
                }
                // If deposit failed (not valid LXMF), fall through to normal parsing
            }
        }

        // For RequestReceived: check if this is a propagation retrieval request
        if self.propagation.is_some() {
            if let NodeEvent::RequestReceived {
                link_id,
                request_id,
                path_hash,
                ref data,
            } = event
            {
                if let Some(result) = self.handle_propagation_request(&path_hash, data) {
                    // Extract the dest_hash from data
                    let mut dest_hash = [0u8; TRUNCATED_HASH_LEN];
                    if data.len() >= TRUNCATED_HASH_LEN {
                        dest_hash.copy_from_slice(&data[..TRUNCATED_HASH_LEN]);
                    }
                    return LxmfEvent::PropagationRetrievalRequest {
                        link_id,
                        request_id,
                        dest_hash,
                        result,
                    };
                }
                // Check if this is a peer offer request
                if let Some(response_data) = self.handle_offer_request(&path_hash, data) {
                    return LxmfEvent::PeerOfferReceived {
                        link_id,
                        request_id,
                        response_data,
                    };
                }
                // If not a retrieval or offer request, fall through
            }
        }

        // For AnnounceReceived: check if this is a propagation peer announce
        if self.autopeer {
            if let NodeEvent::AnnounceReceived {
                dest_hash,
                identity_hash,
                hops,
                ref app_data,
            } = event
            {
                if let Some(ref data) = app_data {
                    if let Some(parsed) = parse_lxmf_announce_data(data) {
                        if parsed.is_propagation
                            && hops <= self.autopeer_maxdepth
                            && !self.peers.contains_key(&dest_hash)
                            && self.peers.len() < self.max_peers
                            // Don't peer with ourselves
                            && self.propagation_dest_hash.map_or(true, |h| h != dest_hash)
                        {
                            let mut p = LxmPeer::new(dest_hash, identity_hash);
                            p.sync_strategy = SyncStrategy::Persistent;
                            self.peers.insert(dest_hash, p);
                            return LxmfEvent::PeerDiscovered {
                                dest_hash,
                                identity_hash,
                            };
                        }
                    }
                }
            }
        }

        // Fall through to immutable handling
        self.handle_event(event)
    }
}
