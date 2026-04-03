//! Ticket cache — stores stamp tickets for bypassing proof-of-work.
//!
//! Inbound tickets: we issued these; used to validate incoming messages.
//! Outbound tickets: we received these; used to bypass PoW when sending.

use std::collections::HashMap;

use rete_core::{msgpack, TRUNCATED_HASH_LEN};

use crate::stamp::{STAMP_SIZE, TICKET_EXPIRY};

/// A single ticket entry with expiry.
#[derive(Debug, Clone)]
pub(super) struct TicketEntry {
    pub ticket: [u8; STAMP_SIZE],
    pub expires: u64, // unix timestamp
}

/// Cache of stamp tickets, keyed by destination hash.
pub(super) struct TicketCache {
    /// Tickets we issued (for validating inbound messages from that dest).
    inbound: HashMap<[u8; TRUNCATED_HASH_LEN], Vec<TicketEntry>>,
    /// Tickets we received (for bypassing PoW when sending to that dest).
    outbound: HashMap<[u8; TRUNCATED_HASH_LEN], Vec<TicketEntry>>,
}

impl TicketCache {
    pub fn new() -> Self {
        Self {
            inbound: HashMap::new(),
            outbound: HashMap::new(),
        }
    }

    /// Store a ticket we issued (for validating inbound messages).
    pub fn store_inbound(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        ticket: [u8; STAMP_SIZE],
        expires: u64,
    ) {
        self.inbound
            .entry(dest_hash)
            .or_default()
            .push(TicketEntry { ticket, expires });
    }

    /// Get valid inbound tickets for a source (for stamp validation).
    pub fn get_inbound_tickets(&self, source_hash: &[u8; TRUNCATED_HASH_LEN], now: u64) -> Vec<[u8; STAMP_SIZE]> {
        self.inbound
            .get(source_hash)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| now < e.expires)
                    .map(|e| e.ticket)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Store a ticket we received from a peer (for outbound PoW bypass).
    pub fn store_outbound(
        &mut self,
        source_hash: [u8; TRUNCATED_HASH_LEN],
        ticket: [u8; STAMP_SIZE],
        expires: u64,
    ) {
        self.outbound
            .entry(source_hash)
            .or_default()
            .push(TicketEntry { ticket, expires });
    }

    /// Get first valid outbound ticket for a destination (for PoW bypass).
    pub fn get_outbound_ticket(
        &self,
        dest_hash: &[u8; TRUNCATED_HASH_LEN],
        now: u64,
    ) -> Option<[u8; STAMP_SIZE]> {
        self.outbound
            .get(dest_hash)?
            .iter()
            .find(|e| now < e.expires)
            .map(|e| e.ticket)
    }

    /// Generate a new ticket for a destination and store it as inbound.
    pub fn generate_ticket<R: rand_core::RngCore>(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASH_LEN],
        rng: &mut R,
        now: u64,
    ) -> TicketEntry {
        let mut ticket = [0u8; STAMP_SIZE];
        rng.fill_bytes(&mut ticket);
        let expires = now + TICKET_EXPIRY;
        let entry = TicketEntry { ticket, expires };
        self.store_inbound(dest_hash, ticket, expires);
        entry
    }

    /// Prune expired tickets from both caches. Returns count removed.
    pub fn prune(&mut self, now: u64) -> usize {
        let mut removed = 0;
        for entries in self.inbound.values_mut() {
            let before = entries.len();
            entries.retain(|e| now < e.expires);
            removed += before - entries.len();
        }
        self.inbound.retain(|_, v| !v.is_empty());
        for entries in self.outbound.values_mut() {
            let before = entries.len();
            entries.retain(|e| now < e.expires);
            removed += before - entries.len();
        }
        self.outbound.retain(|_, v| !v.is_empty());
        removed
    }

    /// Export ticket cache as msgpack bytes for persistence.
    pub fn export(&self) -> Vec<u8> {
        // Format: [[[dest_hash, ticket, expires], ...],
        //          [[dest_hash, ticket, expires], ...]]
        let mut buf = Vec::new();
        buf.push(0x92); // fixarray(2)

        // Inbound entries
        let in_count: usize = self.inbound.values().map(|v| v.len()).sum();
        msgpack::write_array_header(&mut buf, in_count);
        for (dh, entries) in &self.inbound {
            for entry in entries {
                buf.push(0x93); // fixarray(3)
                msgpack::write_bin(&mut buf, dh);
                msgpack::write_bin(&mut buf, &entry.ticket);
                msgpack::write_uint(&mut buf, entry.expires);
            }
        }

        // Outbound entries
        let out_count: usize = self.outbound.values().map(|v| v.len()).sum();
        msgpack::write_array_header(&mut buf, out_count);
        for (dh, entries) in &self.outbound {
            for entry in entries {
                buf.push(0x93); // fixarray(3)
                msgpack::write_bin(&mut buf, dh);
                msgpack::write_bin(&mut buf, &entry.ticket);
                msgpack::write_uint(&mut buf, entry.expires);
            }
        }

        buf
    }

    /// Import ticket cache from msgpack bytes.
    pub fn import(&mut self, data: &[u8]) {
        let mut pos = 0;
        let arr_len = match msgpack::read_array_len(data, &mut pos) {
            Ok(n) => n,
            Err(_) => return,
        };
        if arr_len < 2 {
            return;
        }

        // Inbound
        let in_arr = msgpack::read_array_len(data, &mut pos).unwrap_or(0);
        for _ in 0..in_arr {
            if let Some((dh, ticket, expires)) = read_ticket_entry(data, &mut pos) {
                self.store_inbound(dh, ticket, expires);
            }
        }

        // Outbound
        let out_arr = msgpack::read_array_len(data, &mut pos).unwrap_or(0);
        for _ in 0..out_arr {
            if let Some((dh, ticket, expires)) = read_ticket_entry(data, &mut pos) {
                self.store_outbound(dh, ticket, expires);
            }
        }
    }
}

fn read_ticket_entry(
    data: &[u8],
    pos: &mut usize,
) -> Option<([u8; TRUNCATED_HASH_LEN], [u8; STAMP_SIZE], u64)> {
    let arr_len = msgpack::read_array_len(data, pos).ok()?;
    if arr_len < 3 {
        return None;
    }
    let dh_bytes = msgpack::read_bin_or_str(data, pos).ok()?;
    if dh_bytes.len() < TRUNCATED_HASH_LEN {
        return None;
    }
    let mut dh = [0u8; TRUNCATED_HASH_LEN];
    dh.copy_from_slice(&dh_bytes[..TRUNCATED_HASH_LEN]);

    let ticket_bytes = msgpack::read_bin_or_str(data, pos).ok()?;
    if ticket_bytes.len() < STAMP_SIZE {
        return None;
    }
    let mut ticket = [0u8; STAMP_SIZE];
    ticket.copy_from_slice(&ticket_bytes[..STAMP_SIZE]);

    let expires = msgpack::read_uint(data, pos).ok()?;
    Some((dh, ticket, expires))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_inbound_ticket() {
        let mut cache = TicketCache::new();
        let dh = [0xAA; 16];
        cache.store_inbound(dh, [0x12, 0x34], 1000);
        let tickets = cache.get_inbound_tickets(&dh, 500);
        assert_eq!(tickets.len(), 1);
        assert_eq!(tickets[0], [0x12, 0x34]);
    }

    #[test]
    fn test_recall_inbound_tickets_for_validation() {
        let mut cache = TicketCache::new();
        let dh = [0xBB; 16];
        cache.store_inbound(dh, [0x01, 0x02], 1000);
        cache.store_inbound(dh, [0x03, 0x04], 2000);

        // Both valid at t=500
        assert_eq!(cache.get_inbound_tickets(&dh, 500).len(), 2);
        // Only second valid at t=1500
        assert_eq!(cache.get_inbound_tickets(&dh, 1500).len(), 1);
        // None valid at t=3000
        assert_eq!(cache.get_inbound_tickets(&dh, 3000).len(), 0);
    }

    #[test]
    fn test_store_outbound_ticket() {
        let mut cache = TicketCache::new();
        let dh = [0xCC; 16];
        cache.store_outbound(dh, [0xAB, 0xCD], 5000);
        assert_eq!(cache.get_outbound_ticket(&dh, 1000), Some([0xAB, 0xCD]));
        assert_eq!(cache.get_outbound_ticket(&dh, 6000), None); // expired
    }

    #[test]
    fn test_recall_outbound_ticket_for_send() {
        let mut cache = TicketCache::new();
        let dh = [0xDD; 16];
        // No ticket stored
        assert_eq!(cache.get_outbound_ticket(&dh, 100), None);
        // Store one
        cache.store_outbound(dh, [0x55, 0x66], 2000);
        assert_eq!(cache.get_outbound_ticket(&dh, 100), Some([0x55, 0x66]));
    }

    #[test]
    fn test_ticket_expiry_prunes_old() {
        let mut cache = TicketCache::new();
        cache.store_inbound([0x01; 16], [0xAA, 0xBB], 100);
        cache.store_inbound([0x01; 16], [0xCC, 0xDD], 200);
        cache.store_outbound([0x02; 16], [0xEE, 0xFF], 150);

        let removed = cache.prune(180);
        assert_eq!(removed, 2); // first inbound + outbound expired
        assert_eq!(cache.get_inbound_tickets(&[0x01; 16], 180).len(), 1);
        assert_eq!(cache.get_outbound_ticket(&[0x02; 16], 180), None);
    }

    #[test]
    fn test_generate_ticket_returns_entry() {
        let mut cache = TicketCache::new();
        let mut rng = rand::thread_rng();
        let dh = [0x99; 16];
        let entry = cache.generate_ticket(dh, &mut rng, 1000);
        assert_eq!(entry.expires, 1000 + TICKET_EXPIRY);
        // Should be stored in inbound cache
        let tickets = cache.get_inbound_tickets(&dh, 1000);
        assert_eq!(tickets.len(), 1);
        assert_eq!(tickets[0], entry.ticket);
    }

    #[test]
    fn test_export_import_roundtrip() {
        let mut cache = TicketCache::new();
        cache.store_inbound([0x11; 16], [0xAA, 0xBB], 5000);
        cache.store_inbound([0x22; 16], [0xCC, 0xDD], 6000);
        cache.store_outbound([0x33; 16], [0xEE, 0xFF], 7000);

        let exported = cache.export();
        let mut imported = TicketCache::new();
        imported.import(&exported);

        assert_eq!(
            imported.get_inbound_tickets(&[0x11; 16], 1000),
            vec![[0xAA, 0xBB]]
        );
        assert_eq!(
            imported.get_inbound_tickets(&[0x22; 16], 1000),
            vec![[0xCC, 0xDD]]
        );
        assert_eq!(
            imported.get_outbound_ticket(&[0x33; 16], 1000),
            Some([0xEE, 0xFF])
        );
    }
}
