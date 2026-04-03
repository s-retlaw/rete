//! Event dispatch — handle_event and handle_event_mut.

use rete_core::{DestHash, TRUNCATED_HASH_LEN};
use rete_stack::NodeEvent;

use crate::peer::{LxmPeer, SyncStrategy};
use crate::propagation::MessageStore;
use crate::{DeliveryMethod, LXMessage, FIELD_TICKET};

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
                    // now=0: ticket expiry not checked in immutable path.
                    // Use handle_event_mut for correct ticket expiry.
                    self.validate_and_emit(msg, DeliveryMethod::Opportunistic, 0)
                } else {
                    LxmfEvent::Other(event)
                }
            }
            NodeEvent::LinkData { ref data, .. } => {
                if let Some(msg) = Self::try_parse_lxmf_resource(data) {
                    self.validate_and_emit(msg, DeliveryMethod::Direct, 0)
                } else {
                    LxmfEvent::Other(event)
                }
            }
            NodeEvent::ResourceComplete { ref data, .. } => {
                if let Some(msg) = Self::try_parse_lxmf_resource(data) {
                    self.validate_and_emit(msg, DeliveryMethod::Direct, 0)
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
                    let mut dest_bytes = [0u8; TRUNCATED_HASH_LEN];
                    if data.len() >= TRUNCATED_HASH_LEN {
                        dest_bytes.copy_from_slice(&data[..TRUNCATED_HASH_LEN]);
                    }
                    return LxmfEvent::PropagationRetrievalRequest {
                        link_id,
                        request_id,
                        dest_hash: DestHash::from(dest_bytes),
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

        // Check ProofReceived for delivery receipt correlation
        if let NodeEvent::ProofReceived { packet_hash } = &event {
            if let Some(receipt_event) = self.check_delivery_receipt(packet_hash) {
                return receipt_event;
            }
        }

        // Check LinkClosed for outbound direct job cleanup
        if let NodeEvent::LinkClosed { link_id } = &event {
            self.cleanup_outbound_jobs_for_link(link_id);
        }

        // For AnnounceReceived: update outbound stamp cost cache
        if let NodeEvent::AnnounceReceived {
            dest_hash,
            ref app_data,
            ..
        } = event
        {
            if let Some(ref data) = app_data {
                if let Some(parsed) = parse_lxmf_announce_data(data) {
                    if let Some(cost) = parsed.stamp_cost {
                        self.outbound_stamp_costs.insert(dest_hash, (now, cost));
                    }
                }
            }
        }

        // For ResourceComplete on outbound direct links: check for delivery
        if let NodeEvent::ResourceComplete { link_id, .. } = &event {
            self.advance_outbound_on_resource_complete(link_id);
        }

        // Fall through to immutable handling — but use now for stamp validation
        let lxmf_event = self.handle_event_with_now(event, now);

        // If an inbound message was accepted, extract tickets from it
        if let LxmfEvent::MessageReceived { ref message, .. } = lxmf_event {
            self.extract_and_store_ticket(message);
        }

        lxmf_event
    }

    /// Like `handle_event` but with `now` for correct ticket expiry checking.
    fn handle_event_with_now(&self, event: NodeEvent, now: u64) -> LxmfEvent {
        match event {
            NodeEvent::DataReceived {
                dest_hash,
                ref payload,
            } => {
                if let Some(msg) = self.try_parse_lxmf(&dest_hash, payload) {
                    self.validate_and_emit(msg, DeliveryMethod::Opportunistic, now)
                } else {
                    LxmfEvent::Other(event)
                }
            }
            NodeEvent::LinkData { ref data, .. } => {
                if let Some(msg) = Self::try_parse_lxmf_resource(data) {
                    self.validate_and_emit(msg, DeliveryMethod::Direct, now)
                } else {
                    LxmfEvent::Other(event)
                }
            }
            NodeEvent::ResourceComplete { ref data, .. } => {
                if let Some(msg) = Self::try_parse_lxmf_resource(data) {
                    self.validate_and_emit(msg, DeliveryMethod::Direct, now)
                } else {
                    LxmfEvent::Other(event)
                }
            }
            _ => self.handle_event(event),
        }
    }

    /// Validate inbound stamp and emit appropriate event.
    fn validate_and_emit(&self, msg: LXMessage, method: DeliveryMethod, now: u64) -> LxmfEvent {
        if let Some(cost) = self.inbound_stamp_cost {
            if cost > 0 {
                let tickets = self.tickets.get_inbound_tickets(&msg.source_hash, now);
                if !msg.validate_stamp(cost, &tickets) && self.enforce_stamps {
                    let message_hash = msg.hash();
                    return LxmfEvent::MessageRejectedStamp {
                        source_hash: msg.source_hash,
                        message_hash,
                    };
                }
            }
        }
        LxmfEvent::MessageReceived {
            message: msg,
            method,
        }
    }

    /// Extract ticket from a received message's fields and store it.
    fn extract_and_store_ticket(&mut self, msg: &LXMessage) {
        if let Some(ticket_data) = msg.fields.get(&FIELD_TICKET) {
            // Ticket field format: msgpack [expires_timestamp, ticket_bytes]
            let mut pos = 0;
            if let Ok(arr_len) = rete_core::msgpack::read_array_len(ticket_data, &mut pos) {
                if arr_len >= 2 {
                    if let Ok(expires) = rete_core::msgpack::read_uint(ticket_data, &mut pos) {
                        if let Ok(ticket_bytes) =
                            rete_core::msgpack::read_bin_or_str(ticket_data, &mut pos)
                        {
                            if ticket_bytes.len() >= 2 {
                                let mut ticket = [0u8; 2];
                                ticket.copy_from_slice(&ticket_bytes[..2]);
                                self.tickets
                                    .store_outbound(msg.source_hash, ticket, expires);
                            }
                        }
                    }
                }
            }
        }
    }
}
