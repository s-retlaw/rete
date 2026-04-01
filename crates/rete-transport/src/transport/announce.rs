//! Announce queue, handling, rate limiting, path requests.

use crate::announce::{validate_announce, PendingAnnounce};
use crate::path::Path;
use rete_core::{
    DestType, HeaderType, Identity, Packet, PacketBuilder, PacketType, NAME_HASH_LEN,
    TRANSPORT_TYPE_TRANSPORT, TRUNCATED_HASH_LEN,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use super::{
    AnnounceRateEntry, IngestResult, ANNOUNCE_RATE_GRACE, ANNOUNCE_RATE_PENALTY,
    ANNOUNCE_RATE_TARGET, LOCAL_REBROADCASTS_MAX, PATH_REQUEST_DEST, PATH_REQUEST_GRACE,
    PATH_REQUEST_MI, PATHFINDER_G, PATHFINDER_M, PATHFINDER_R, PATHFINDER_RW_MS, Transport,
};

impl<const P: usize, const A: usize, const D: usize, const L: usize> Transport<P, A, D, L> {
    /// Queue an announce for transmission. Returns `false` if queue is full.
    pub fn queue_announce(&mut self, ann: PendingAnnounce) -> bool {
        self.announces.push_back(ann).is_ok()
    }

    /// Pop the next announce ready for transmission.
    pub fn next_announce(&mut self) -> Option<PendingAnnounce> {
        self.announces.pop_front()
    }

    /// Number of pending announces.
    pub fn announce_count(&self) -> usize {
        self.announces.len()
    }

    pub(super) fn handle_announce<'a>(
        &mut self,
        pkt: &Packet<'a>,
        raw: &'a [u8],
        now: u64,
        iface: u8,
    ) -> IngestResult<'a> {
        // Self-announce filtering
        let mut dh_check = [0u8; TRUNCATED_HASH_LEN];
        dh_check.copy_from_slice(pkt.destination_hash);
        if self.is_local_destination(&dh_check) {
            return IngestResult::Duplicate;
        }

        match validate_announce(pkt.destination_hash, pkt.payload, pkt.context_flag) {
            Ok(info) => {
                // Announce replay detection
                let mut replay_key = [0u8; 32];
                replay_key[..TRUNCATED_HASH_LEN].copy_from_slice(pkt.destination_hash);
                replay_key[TRUNCATED_HASH_LEN..TRUNCATED_HASH_LEN + 10]
                    .copy_from_slice(info.random_hash);
                let replay_hash: [u8; 32] = Sha256::digest(replay_key).into();
                if self.announce_dedup.check_and_insert(&replay_hash) {
                    // Track local rebroadcasts: if we have this announce
                    // pending, note that we heard it echoed back.
                    let mut dh_dup = [0u8; TRUNCATED_HASH_LEN];
                    dh_dup.copy_from_slice(pkt.destination_hash);
                    self.note_local_rebroadcast(&dh_dup, pkt.hops);
                    self.stats.packets_dropped_dedup += 1;
                    return IngestResult::Duplicate;
                }
                let mut dh = [0u8; TRUNCATED_HASH_LEN];
                dh.copy_from_slice(pkt.destination_hash);

                // Announce rate limiting
                let rate_blocked = {
                    let entry = self.announce_rate.get_mut(&dh);
                    match entry {
                        Some(re) => {
                            if now < re.blocked_until {
                                true
                            } else {
                                let interval = now.saturating_sub(re.last);
                                if interval < ANNOUNCE_RATE_TARGET {
                                    re.violations = re.violations.saturating_add(1);
                                } else {
                                    re.violations = re.violations.saturating_sub(1);
                                }
                                if re.violations > ANNOUNCE_RATE_GRACE {
                                    re.blocked_until =
                                        re.last + ANNOUNCE_RATE_TARGET + ANNOUNCE_RATE_PENALTY;
                                    true
                                } else {
                                    re.last = now;
                                    false
                                }
                            }
                        }
                        None => {
                            let _ = self.announce_rate.insert(
                                dh,
                                AnnounceRateEntry {
                                    last: now,
                                    violations: 0,
                                    blocked_until: 0,
                                },
                            );
                            false
                        }
                    }
                };
                if rate_blocked {
                    self.stats.announces_rate_limited += 1;
                    return IngestResult::Duplicate;
                }

                let should_update = match self.paths.get(&dh) {
                    None => true,
                    Some(existing) => {
                        pkt.hops <= existing.hops
                            || now.saturating_sub(existing.learned_at) > existing.expiry_time()
                    }
                };

                if should_update {
                    let mut path = match pkt.transport_id {
                        Some(tid) => {
                            let mut via = [0u8; TRUNCATED_HASH_LEN];
                            via.copy_from_slice(tid);
                            Path::via_repeater(via, pkt.hops, now)
                        }
                        None => Path {
                            hops: pkt.hops,
                            ..Path::direct(now)
                        },
                    };
                    path.announce_raw = Some(raw.to_vec());
                    path.received_on = Some(iface);
                    let _ = self.insert_path(dh, path);
                    self.stats.paths_learned += 1;
                }

                let mut pk = [0u8; 64];
                pk.copy_from_slice(info.pub_key);
                self.insert_identity(dh, pk);

                if pkt.hops < PATHFINDER_M {
                    let retransmit_raw = if let Some(local_id) = self.local_identity_hash {
                        let mut rebuild_buf = [0u8; rete_core::MTU];
                        let result = PacketBuilder::new(&mut rebuild_buf)
                            .header_type(HeaderType::Header2)
                            .transport_type(TRANSPORT_TYPE_TRANSPORT)
                            .packet_type(pkt.packet_type)
                            .dest_type(pkt.dest_type)
                            .hops(pkt.hops)
                            .transport_id(&local_id)
                            .destination_hash(pkt.destination_hash)
                            .context(pkt.context)
                            .payload(pkt.payload)
                            .build();
                        match result {
                            Ok(n) => Some(rebuild_buf[..n].to_vec()),
                            Err(_) => None,
                        }
                    } else {
                        None
                    };

                    let ann_raw = match retransmit_raw {
                        Some(v) => v,
                        None => raw.to_vec(),
                    };

                    if !ann_raw.is_empty() {
                        let pending = PendingAnnounce {
                            dest_hash: dh,
                            raw: ann_raw,
                            tx_count: 0,
                            retransmit_timeout: now, // Forward immediately; PATHFINDER_G applies to retransmissions
                            local: false,
                            local_rebroadcasts: 0,
                            block_rebroadcasts: false,
                            received_hops: pkt.hops,
                        };
                        let _ = self.queue_announce(pending);
                    }
                }

                let ratchet: Option<[u8; 32]> =
                    info.ratchet.and_then(|r| r.try_into().ok());

                self.stats.announces_received += 1;
                IngestResult::AnnounceReceived {
                    dest_hash: dh,
                    identity_hash: info.identity_hash,
                    hops: pkt.hops,
                    app_data: info.app_data,
                    ratchet,
                }
            }
            Err(_) => {
                self.stats.packets_dropped_invalid += 1;
                self.stats.crypto_failures += 1;
                IngestResult::Invalid
            }
        }
    }

    pub(super) fn handle_path_request<'a>(&mut self, payload: &[u8], now: u64) -> IngestResult<'a> {
        if payload.len() < TRUNCATED_HASH_LEN {
            return IngestResult::Invalid;
        }
        let mut requested = [0u8; TRUNCATED_HASH_LEN];
        requested.copy_from_slice(&payload[..TRUNCATED_HASH_LEN]);

        // Path request throttling: minimum interval between requests for same dest
        if let Some(&last_time) = self.path_request_times.get(&requested) {
            if now.saturating_sub(last_time) < PATH_REQUEST_MI {
                return IngestResult::Duplicate;
            }
        }
        let _ = self.path_request_times.insert(requested, now);

        // Check if we have a local destination for this hash
        if self.is_local_destination(&requested) {
            // Local destination — handled by NodeCore (it will announce in response)
            return IngestResult::PathRequestForward {
                payload: payload.to_vec(),
            };
        }

        // Check if we know a path (have a cached announce)
        if let Some(path) = self.paths.get(&requested) {
            if let Some(ref cached) = path.announce_raw {
                let pending = PendingAnnounce {
                    dest_hash: requested,
                    raw: cached.clone(),
                    tx_count: 0,
                    retransmit_timeout: now + PATH_REQUEST_GRACE,
                    local: false,
                    local_rebroadcasts: 0,
                    block_rebroadcasts: true,
                    received_hops: 0,
                };
                let _ = self.queue_announce(pending);
                return IngestResult::Duplicate;
            }
        }

        // Unknown path — forward to all interfaces if transport is enabled
        if self.local_identity_hash.is_some() {
            // Dedup: check if we've recently seen this exact path request
            let mut pr_key = [0u8; 32];
            pr_key[..TRUNCATED_HASH_LEN].copy_from_slice(&requested);
            // Include tag bytes in dedup if present
            if payload.len() > TRUNCATED_HASH_LEN {
                let tag_end = core::cmp::min(payload.len(), 32);
                let tag_start = TRUNCATED_HASH_LEN;
                pr_key[tag_start..tag_end].copy_from_slice(&payload[tag_start..tag_end]);
            }
            let pr_hash: [u8; 32] = Sha256::digest(pr_key).into();
            if self.announce_dedup.check_and_insert(&pr_hash) {
                return IngestResult::Duplicate;
            }

            IngestResult::PathRequestForward {
                payload: payload.to_vec(),
            }
        } else {
            IngestResult::Duplicate
        }
    }

    // -----------------------------------------------------------------------
    // Path request origination
    // -----------------------------------------------------------------------

    /// Build a path request packet for a destination.
    ///
    /// Sends a DATA packet addressed to `PATH_REQUEST_DEST` (PLAIN) with
    /// `dest_hash` as the payload.
    pub fn build_path_request(dest_hash: &[u8; TRUNCATED_HASH_LEN]) -> alloc::vec::Vec<u8> {
        let mut buf = [0u8; rete_core::MTU];
        let n = PacketBuilder::new(&mut buf)
            .packet_type(PacketType::Data)
            .dest_type(DestType::Plain)
            .destination_hash(&PATH_REQUEST_DEST)
            .context(0x00)
            .payload(dest_hash)
            .build()
            .expect("path request packet should always build");
        buf[..n].to_vec()
    }

    // -----------------------------------------------------------------------
    // Announce creation
    // -----------------------------------------------------------------------

    /// Create an announce packet for a local identity.
    ///
    /// When `ratchet_pub` is `Some`, the 32-byte ratchet public key is included
    /// in the announce payload and `context_flag` is set to 1.
    pub fn create_announce<R: RngCore + CryptoRng>(
        identity: &Identity,
        app_name: &str,
        aspects: &[&str],
        app_data: Option<&[u8]>,
        ratchet_pub: Option<&[u8; 32]>,
        rng: &mut R,
        now: u64,
        out: &mut [u8],
    ) -> Result<usize, rete_core::Error> {
        let mut name_buf = [0u8; 128];
        let expanded = rete_core::expand_name(app_name, aspects, &mut name_buf)?;

        let identity_hash = identity.hash();
        let dest_hash = rete_core::destination_hash(expanded, Some(&identity_hash));

        let name_digest = Sha256::digest(expanded.as_bytes());
        let mut name_hash = [0u8; NAME_HASH_LEN];
        name_hash.copy_from_slice(&name_digest[..NAME_HASH_LEN]);

        let mut random_hash = [0u8; 10];
        rng.fill_bytes(&mut random_hash[..5]);
        random_hash[5..10].copy_from_slice(&now.to_be_bytes()[3..8]);

        let pub_key = identity.public_key();
        let mut signed_data = [0u8; rete_core::MTU];
        let mut pos = 0;
        signed_data[pos..pos + TRUNCATED_HASH_LEN].copy_from_slice(&dest_hash);
        pos += TRUNCATED_HASH_LEN;
        signed_data[pos..pos + 64].copy_from_slice(&pub_key);
        pos += 64;
        signed_data[pos..pos + NAME_HASH_LEN].copy_from_slice(&name_hash);
        pos += NAME_HASH_LEN;
        signed_data[pos..pos + 10].copy_from_slice(&random_hash);
        pos += 10;
        if let Some(rp) = ratchet_pub {
            signed_data[pos..pos + 32].copy_from_slice(rp);
            pos += 32;
        }
        if let Some(ad) = app_data {
            signed_data[pos..pos + ad.len()].copy_from_slice(ad);
            pos += ad.len();
        }

        let signature = identity.sign(&signed_data[..pos])?;

        // Payload layout:
        //   pub_key[64] + name_hash[10] + random_hash[10]
        //   [+ ratchet[32] if context_flag]
        //   + signature[64] + [app_data]
        let mut payload = [0u8; rete_core::MTU];
        let mut ppos = 0;
        payload[ppos..ppos + 64].copy_from_slice(&pub_key);
        ppos += 64;
        payload[ppos..ppos + NAME_HASH_LEN].copy_from_slice(&name_hash);
        ppos += NAME_HASH_LEN;
        payload[ppos..ppos + 10].copy_from_slice(&random_hash);
        ppos += 10;
        if let Some(rp) = ratchet_pub {
            payload[ppos..ppos + 32].copy_from_slice(rp);
            ppos += 32;
        }
        payload[ppos..ppos + 64].copy_from_slice(&signature);
        ppos += 64;
        if let Some(ad) = app_data {
            payload[ppos..ppos + ad.len()].copy_from_slice(ad);
            ppos += ad.len();
        }

        let n = PacketBuilder::new(out)
            .packet_type(PacketType::Announce)
            .dest_type(DestType::Single)
            .context_flag(ratchet_pub.is_some())
            .destination_hash(&dest_hash)
            .context(0x00)
            .payload(&payload[..ppos])
            .build()?;

        Ok(n)
    }

    /// Returns announces that are due for retransmission.
    ///
    /// Python adds `random.random() * PATHFINDER_RW` (0-0.5s) of jitter to
    /// each retransmit timeout to prevent synchronized retransmissions on
    /// shared radio channels.
    pub fn pending_outbound<R: RngCore>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let mut to_send: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
        let mut keep: heapless::Deque<PendingAnnounce, A> = heapless::Deque::new();

        while let Some(mut ann) = self.announces.pop_front() {
            // Skip if blocked by local rebroadcast detection
            if ann.block_rebroadcasts && !ann.local {
                continue;
            }
            if ann.local || now >= ann.retransmit_timeout {
                to_send.push(ann.raw.clone());
                if ann.tx_count == 0 {
                    self.stats.announces_sent += 1;
                } else {
                    self.stats.announces_retransmitted += 1;
                }
                self.stats.packets_sent += 1;
                ann.tx_count += 1;
                // Next retransmission: PATHFINDER_G + random jitter (0..PATHFINDER_RW_MS ms)
                // Python: now + PATHFINDER_G + random.random() * PATHFINDER_RW
                let jitter_ms = (rng.next_u32() % PATHFINDER_RW_MS as u32) as u64;
                // Convert to seconds (integer math: add 1s if jitter >= 500ms)
                let jitter_secs = if jitter_ms >= 500 { 1 } else { 0 };
                ann.retransmit_timeout = now + PATHFINDER_G + jitter_secs;
                debug_assert!(ann.retransmit_timeout > now);
                ann.local = false;
                if ann.tx_count <= PATHFINDER_R && !ann.block_rebroadcasts {
                    let _ = keep.push_back(ann);
                }
            } else {
                let _ = keep.push_back(ann);
            }
        }

        self.announces = keep;
        to_send
    }

    /// Called when we hear a duplicate announce — tracks local rebroadcasts
    /// and suppresses retransmission if the announce has been locally rebroadcast
    /// enough times (LOCAL_REBROADCASTS_MAX).
    pub fn note_local_rebroadcast(&mut self, dest_hash: &[u8; TRUNCATED_HASH_LEN], heard_hops: u8) {
        for ann in self.announces.iter_mut() {
            if ann.dest_hash == *dest_hash {
                // Same hop count means a peer rebroadcast at our level
                if heard_hops.saturating_sub(1) == ann.received_hops {
                    ann.local_rebroadcasts += 1;
                    if ann.tx_count > 0 && ann.local_rebroadcasts >= LOCAL_REBROADCASTS_MAX {
                        ann.block_rebroadcasts = true;
                    }
                }
                // If we hear at one hop further, our rebroadcast was picked up
                if heard_hops.saturating_sub(1) == ann.received_hops + 1 && ann.tx_count > 0 {
                    ann.block_rebroadcasts = true;
                }
                break;
            }
        }
    }
}
