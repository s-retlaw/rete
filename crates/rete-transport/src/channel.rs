//! Channel — reliable ordered message delivery over a Link.
//!
//! Channels provide sequenced message delivery over an encrypted Link.
//! Each message has a 6-byte envelope header:
//!
//! ```text
//! [0:2]  message_type   u16 big-endian
//! [2:4]  sequence       u16 big-endian
//! [4:6]  length         u16 big-endian
//! [6:]   payload        variable
//! ```
//!
//! # Window adaptation (matches Python RNS Channel.py)
//!
//! The channel uses a graduated 3-tier window system:
//! - **Slow** (RTT > 750ms): window_max = 5, window_min = 2
//! - **Medium** (RTT 180-750ms): window_max = 12, window_min = 5
//! - **Fast** (RTT < 180ms): window_max = 48, window_min = 16
//!
//! Tier promotion requires `FAST_RATE_THRESHOLD` (10) sustained rounds at the
//! target rate. On timeout/retry, window and window_max shrink gradually.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Envelope header size: msgtype(2) + seq(2) + len(2) = 6 bytes.
pub const ENVELOPE_HEADER_SIZE: usize = 6;

/// System message type for Buffer/Stream data.
pub const MSG_TYPE_STREAM: u16 = 0xFF00;

// ---------------------------------------------------------------------------
// Window constants (matching Python RNS Channel.py exactly)
// ---------------------------------------------------------------------------

/// Initial window size at channel setup. Python: `Channel.WINDOW = 2`.
pub const DEFAULT_WINDOW: u16 = 2;

/// Absolute minimum window size. Python: `Channel.WINDOW_MIN = 2`.
pub const WINDOW_MIN: u16 = 2;

/// Minimum window limit for slow links. Python: `Channel.WINDOW_MIN_LIMIT_SLOW = 2`.
pub const WINDOW_MIN_LIMIT_SLOW: u16 = 2;

/// Minimum window limit for medium links. Python: `Channel.WINDOW_MIN_LIMIT_MEDIUM = 5`.
pub const WINDOW_MIN_LIMIT_MEDIUM: u16 = 5;

/// Minimum window limit for fast links. Python: `Channel.WINDOW_MIN_LIMIT_FAST = 16`.
pub const WINDOW_MIN_LIMIT_FAST: u16 = 16;

/// Maximum window for slow links. Python: `Channel.WINDOW_MAX_SLOW = 5`.
pub const WINDOW_MAX_SLOW: u16 = 5;

/// Maximum window for medium-speed links. Python: `Channel.WINDOW_MAX_MEDIUM = 12`.
pub const WINDOW_MAX_MEDIUM: u16 = 12;

/// Maximum window for fast links. Python: `Channel.WINDOW_MAX_FAST = 48`.
pub const WINDOW_MAX_FAST: u16 = 48;

/// Global maximum window (for calculating maps/guards).
/// Python: `Channel.WINDOW_MAX = WINDOW_MAX_FAST`.
pub const WINDOW_MAX: u16 = WINDOW_MAX_FAST;

/// Sustained rounds at fast/medium rate before promoting window tier.
/// Python: `Channel.FAST_RATE_THRESHOLD = 10`.
pub const FAST_RATE_THRESHOLD: u16 = 10;

/// RTT threshold for "fast" classification (seconds → ms).
/// Python: `Channel.RTT_FAST = 0.18` (180ms).
pub const RTT_FAST_MS: u64 = 180;

/// RTT threshold for "medium" classification (seconds → ms).
/// Python: `Channel.RTT_MEDIUM = 0.75` (750ms).
pub const RTT_MEDIUM_MS: u64 = 750;

/// RTT threshold for "slow" classification (seconds → ms).
/// Python: `Channel.RTT_SLOW = 1.45` (1450ms).
pub const RTT_SLOW_MS: u64 = 1450;

/// Minimum flexibility between window_max and window_min.
/// Python: `Channel.WINDOW_FLEXIBILITY = 4`.
pub const WINDOW_FLEXIBILITY: u16 = 4;

/// Sequence number maximum. Python: `Channel.SEQ_MAX = 0xFFFF`.
pub const SEQ_MAX: u16 = 0xFFFF;

/// Sequence number modulus. Python: `Channel.SEQ_MODULUS = SEQ_MAX + 1 = 0x10000`.
pub const SEQ_MODULUS: u32 = (SEQ_MAX as u32) + 1;

/// Maximum retries before teardown.
pub const MAX_RETRIES: u8 = 5;

/// Maximum reorder buffer size (prevents unbounded memory growth).
pub const MAX_RX_BUFFER: usize = 64;

/// A channel envelope — header + payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelEnvelope {
    /// Application-defined message type.
    pub message_type: u16,
    /// Sequence number.
    pub sequence: u16,
    /// Payload data.
    pub payload: Vec<u8>,
}

impl ChannelEnvelope {
    /// Pack an envelope into bytes.
    pub fn pack(&self) -> Vec<u8> {
        let len = self.payload.len() as u16;
        let mut out = Vec::with_capacity(ENVELOPE_HEADER_SIZE + self.payload.len());
        out.extend_from_slice(&self.message_type.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Unpack an envelope from bytes.
    pub fn unpack(data: &[u8]) -> Option<Self> {
        if data.len() < ENVELOPE_HEADER_SIZE {
            return None;
        }
        let message_type = u16::from_be_bytes([data[0], data[1]]);
        let sequence = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]) as usize;
        if data.len() < ENVELOPE_HEADER_SIZE + length {
            return None;
        }
        let payload = data[ENVELOPE_HEADER_SIZE..ENVELOPE_HEADER_SIZE + length].to_vec();
        Some(ChannelEnvelope {
            message_type,
            sequence,
            payload,
        })
    }
}

/// A pending outbound message (awaiting delivery confirmation).
#[derive(Debug, Clone)]
struct PendingMessage {
    envelope: ChannelEnvelope,
    retries: u8,
    sent_at: u64,
}

/// Reliable ordered channel over a Link.
///
/// Uses a graduated 3-tier window system matching Python RNS Channel.py.
pub struct Channel {
    /// Next outbound sequence number.
    tx_sequence: u16,
    /// Next expected inbound sequence number.
    rx_sequence: u16,
    /// Outbound window: messages sent but not yet confirmed.
    tx_pending: VecDeque<PendingMessage>,
    /// Inbound reorder buffer: out-of-order messages waiting for delivery.
    rx_buffer: VecDeque<ChannelEnvelope>,
    /// Delivered inbound messages ready for the application.
    rx_ready: VecDeque<ChannelEnvelope>,
    /// Current window size (max unconfirmed messages).
    window: u16,
    /// Current maximum window size (adapts based on RTT tier).
    window_max: u16,
    /// Current minimum window size (adapts based on RTT tier).
    window_min: u16,
    /// Minimum flexibility between window_max and window_min.
    window_flexibility: u16,
    /// Counter for sustained fast-rate rounds.
    fast_rate_rounds: u16,
    /// Counter for sustained medium-rate rounds.
    medium_rate_rounds: u16,
    /// Retry timeout in seconds.
    retry_timeout: u64,
    /// Whether the channel should be torn down.
    pub teardown: bool,
    /// Smoothed RTT in milliseconds (0 = not measured yet).
    rtt_ms: u64,
}

impl Default for Channel {
    fn default() -> Self {
        Self::new()
    }
}

impl Channel {
    /// Create a new channel with default settings.
    ///
    /// Starts conservatively: window=2, window_max=5 (slow tier).
    /// Matches Python: `Channel.__init__()` with RTT < RTT_SLOW.
    pub fn new() -> Self {
        Channel {
            tx_sequence: 0,
            rx_sequence: 0,
            tx_pending: VecDeque::new(),
            rx_buffer: VecDeque::new(),
            rx_ready: VecDeque::new(),
            window: DEFAULT_WINDOW,
            window_max: WINDOW_MAX_SLOW,
            window_min: WINDOW_MIN,
            window_flexibility: WINDOW_FLEXIBILITY,
            fast_rate_rounds: 0,
            medium_rate_rounds: 0,
            retry_timeout: 15,
            teardown: false,
            rtt_ms: 0,
        }
    }

    /// Update the smoothed RTT estimate.
    ///
    /// Does NOT directly change the window — window adaptation happens in
    /// `mark_delivered()` and `pending_retransmit()` based on sustained
    /// rate classification, matching Python's graduated system.
    pub fn update_rtt(&mut self, rtt_ms: u64) {
        // Exponential moving average
        if self.rtt_ms == 0 {
            self.rtt_ms = rtt_ms;
        } else {
            self.rtt_ms = (self.rtt_ms * 7 + rtt_ms) / 8;
        }
    }

    /// Get the current smoothed RTT in milliseconds.
    pub fn rtt_ms(&self) -> u64 {
        self.rtt_ms
    }

    /// Get the current window size.
    pub fn window(&self) -> u16 {
        self.window
    }

    /// Get the current window maximum.
    pub fn window_max(&self) -> u16 {
        self.window_max
    }

    /// Get the current window minimum.
    pub fn window_min(&self) -> u16 {
        self.window_min
    }

    /// Queue a message for sending. Returns the packed envelope bytes,
    /// or `None` if the window is full.
    pub fn send(&mut self, message_type: u16, payload: &[u8]) -> Option<Vec<u8>> {
        if !self.is_ready_to_send() {
            return None;
        }
        let envelope = ChannelEnvelope {
            message_type,
            sequence: self.tx_sequence,
            payload: payload.to_vec(),
        };
        let packed = envelope.pack();
        self.tx_pending.push_back(PendingMessage {
            envelope,
            retries: 0,
            sent_at: 0, // will be set on actual send
        });
        self.tx_sequence = self.tx_sequence.wrapping_add(1);
        Some(packed)
    }

    /// Whether the channel can accept another outbound message.
    pub fn is_ready_to_send(&self) -> bool {
        (self.tx_pending.len() as u16) < self.window
    }

    /// Process a received channel message (after decryption).
    pub fn receive(&mut self, data: &[u8]) {
        if let Some(envelope) = ChannelEnvelope::unpack(data) {
            // Use wrapping distance to handle u16 wrap-around correctly.
            let diff = envelope.sequence.wrapping_sub(self.rx_sequence);
            if diff == 0 {
                // In order — deliver immediately
                self.rx_ready.push_back(envelope);
                self.rx_sequence = self.rx_sequence.wrapping_add(1);
                // Check if any buffered messages are now in order
                self.flush_rx_buffer();
            } else if diff < 32768 {
                // Out of order but within forward half of sequence space — buffer
                if self.rx_buffer.len() >= MAX_RX_BUFFER {
                    return; // buffer full, drop
                }
                // Insert in sorted order (by wrapping distance from rx_sequence)
                let pos = self
                    .rx_buffer
                    .iter()
                    .position(|e| e.sequence.wrapping_sub(self.rx_sequence) > diff)
                    .unwrap_or(self.rx_buffer.len());
                self.rx_buffer.insert(pos, envelope);
            }
            // diff >= 32768: behind us (duplicate or very old), ignore
        }
    }

    /// Drain buffered messages that are now sequential.
    fn flush_rx_buffer(&mut self) {
        while let Some(front) = self.rx_buffer.front() {
            if front.sequence.wrapping_sub(self.rx_sequence) == 0 {
                let env = self.rx_buffer.pop_front().unwrap();
                self.rx_ready.push_back(env);
                self.rx_sequence = self.rx_sequence.wrapping_add(1);
            } else {
                break;
            }
        }
    }

    /// Pop the next delivered inbound message.
    pub fn next_received(&mut self) -> Option<ChannelEnvelope> {
        self.rx_ready.pop_front()
    }

    /// Mark a message as delivered (confirmed by proof) and adapt the window.
    ///
    /// `link_rtt_secs` is the Link's current measured RTT in seconds (f32).
    /// Used for graduated window tier promotion matching Python Channel._packet_tx_op.
    ///
    /// Window adaptation:
    /// 1. Remove the confirmed message from pending
    /// 2. Grow window by 1 (up to window_max)
    /// 3. Classify RTT and track sustained rounds at each tier
    /// 4. Promote window_max/window_min when FAST_RATE_THRESHOLD rounds sustained
    pub fn mark_delivered(&mut self, sequence: u16, link_rtt_secs: f32) {
        let before = self.tx_pending.len();
        self.tx_pending.retain(|m| m.envelope.sequence != sequence);
        let removed = self.tx_pending.len() < before;

        if removed {
            // Grow window by 1 (up to window_max)
            if self.window < self.window_max {
                self.window += 1;
            }

            // RTT-based tier promotion (matches Python Channel._packet_tx_op lines 504-527)
            let rtt_ms = (link_rtt_secs * 1000.0) as u64;
            if rtt_ms > 0 {
                if rtt_ms > RTT_FAST_MS {
                    // Not fast — reset fast counter
                    self.fast_rate_rounds = 0;

                    if rtt_ms > RTT_MEDIUM_MS {
                        // Slow — reset medium counter too
                        self.medium_rate_rounds = 0;
                    } else {
                        // Medium rate
                        self.medium_rate_rounds += 1;
                        if self.window_max < WINDOW_MAX_MEDIUM
                            && self.medium_rate_rounds == FAST_RATE_THRESHOLD
                        {
                            self.window_max = WINDOW_MAX_MEDIUM;
                            self.window_min = WINDOW_MIN_LIMIT_MEDIUM;
                        }
                    }
                } else {
                    // Fast rate
                    self.fast_rate_rounds += 1;
                    if self.window_max < WINDOW_MAX_FAST
                        && self.fast_rate_rounds == FAST_RATE_THRESHOLD
                    {
                        self.window_max = WINDOW_MAX_FAST;
                        self.window_min = WINDOW_MIN_LIMIT_FAST;
                    }
                }
            }
        }
    }

    /// Get pending messages that need retransmission.
    ///
    /// On timeout, shrinks the window and window_max matching Python
    /// Channel._packet_timeout (lines 563-570).
    pub fn pending_retransmit(&mut self, now: u64) -> Vec<Vec<u8>> {
        let mut retransmits = Vec::new();
        let mut had_timeout = false;
        for msg in &mut self.tx_pending {
            if msg.sent_at > 0 && now.saturating_sub(msg.sent_at) > self.retry_timeout {
                msg.retries += 1;
                if msg.retries > MAX_RETRIES {
                    self.teardown = true;
                    return retransmits;
                }
                msg.sent_at = now;
                retransmits.push(msg.envelope.pack());
                had_timeout = true;
            }
        }

        // Shrink window on timeout (matches Python Channel._packet_timeout)
        if had_timeout {
            if self.window > self.window_min {
                self.window -= 1;
            }
            if self.window_max > self.window_min + self.window_flexibility {
                self.window_max -= 1;
            }
        }

        retransmits
    }

    /// Set the timestamp for the most recently sent message.
    pub fn mark_sent(&mut self, now: u64) {
        if let Some(last) = self.tx_pending.back_mut() {
            if last.sent_at == 0 {
                last.sent_at = now;
            }
        }
    }

    /// Number of pending outbound messages.
    pub fn pending_count(&self) -> usize {
        self.tx_pending.len()
    }

    /// Number of messages ready for delivery.
    pub fn ready_count(&self) -> usize {
        self.rx_ready.len()
    }

    /// The sequence number that will be assigned to the next `send()` call.
    pub fn next_tx_sequence(&self) -> u16 {
        self.tx_sequence
    }

    /// Compute the retry timeout for a given number of tries.
    ///
    /// Matches Python: `pow(1.5, tries - 1) * max(rtt * 2.5, 0.025) * (queue_depth + 1.5)`
    /// Returns timeout in seconds.
    pub fn compute_retry_timeout(&self, tries: u8) -> f64 {
        let rtt_secs = self.rtt_ms as f64 / 1000.0;
        let base = 1.5_f64.powi(tries.saturating_sub(1) as i32);
        let rtt_factor = (rtt_secs * 2.5).max(0.025);
        let queue_factor = self.tx_pending.len() as f64 + 1.5;
        base * rtt_factor * queue_factor
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_pack_unpack() {
        let env = ChannelEnvelope {
            message_type: 0x1234,
            sequence: 42,
            payload: b"hello".to_vec(),
        };
        let packed = env.pack();
        assert_eq!(packed.len(), ENVELOPE_HEADER_SIZE + 5);

        let unpacked = ChannelEnvelope::unpack(&packed).unwrap();
        assert_eq!(unpacked, env);
    }

    #[test]
    fn channel_send_sequences() {
        let mut ch = Channel::new();
        let p0 = ch.send(0x01, b"msg0").unwrap();
        let p1 = ch.send(0x01, b"msg1").unwrap();

        let e0 = ChannelEnvelope::unpack(&p0).unwrap();
        let e1 = ChannelEnvelope::unpack(&p1).unwrap();
        assert_eq!(e0.sequence, 0);
        assert_eq!(e1.sequence, 1);
    }

    #[test]
    fn channel_receive_in_order() {
        let mut ch = Channel::new();

        // Simulate receiving 3 messages in order
        for i in 0u16..3 {
            let env = ChannelEnvelope {
                message_type: 0x01,
                sequence: i,
                payload: alloc::format!("msg{}", i).into_bytes(),
            };
            ch.receive(&env.pack());
        }

        assert_eq!(ch.ready_count(), 3);
        for i in 0u16..3 {
            let msg = ch.next_received().unwrap();
            assert_eq!(msg.sequence, i);
        }
    }

    #[test]
    fn channel_receive_out_of_order() {
        let mut ch = Channel::new();

        let e1 = ChannelEnvelope {
            message_type: 0x01,
            sequence: 1,
            payload: b"msg1".to_vec(),
        };
        let e0 = ChannelEnvelope {
            message_type: 0x01,
            sequence: 0,
            payload: b"msg0".to_vec(),
        };
        let e2 = ChannelEnvelope {
            message_type: 0x01,
            sequence: 2,
            payload: b"msg2".to_vec(),
        };

        ch.receive(&e1.pack()); // buffered (waiting for 0)
        assert_eq!(ch.ready_count(), 0);

        ch.receive(&e0.pack()); // delivers 0, then flushes 1
        assert_eq!(ch.ready_count(), 2);

        ch.receive(&e2.pack()); // delivers 2
        assert_eq!(ch.ready_count(), 3);

        assert_eq!(ch.next_received().unwrap().sequence, 0);
        assert_eq!(ch.next_received().unwrap().sequence, 1);
        assert_eq!(ch.next_received().unwrap().sequence, 2);
    }

    #[test]
    fn channel_window_blocks_send() {
        let mut ch = Channel::new();
        // Fill the window (default 2)
        for _ in 0..DEFAULT_WINDOW {
            assert!(ch.send(0x01, b"data").is_some());
        }
        // Window full
        assert!(!ch.is_ready_to_send());
        assert!(ch.send(0x01, b"blocked").is_none());
    }

    #[test]
    fn channel_retry_on_timeout() {
        let mut ch = Channel::new();
        ch.send(0x01, b"retry me").unwrap();
        ch.mark_sent(100);

        // Before timeout
        let retransmits = ch.pending_retransmit(110);
        assert!(retransmits.is_empty());

        // After timeout
        let retransmits = ch.pending_retransmit(116);
        assert_eq!(retransmits.len(), 1);
    }

    #[test]
    fn channel_max_retries_teardown() {
        let mut ch = Channel::new();
        ch.send(0x01, b"fail").unwrap();
        ch.mark_sent(100);

        // Exhaust retries
        let mut now = 100;
        for _ in 0..=MAX_RETRIES {
            now += ch.retry_timeout + 1;
            ch.pending_retransmit(now);
        }

        assert!(ch.teardown);
    }

    #[test]
    fn test_sequence_wrap_around() {
        let mut ch = Channel::new();
        ch.tx_sequence = u16::MAX - 1;

        let p1 = ch.send(0x01, b"wrap-1").unwrap();
        let e1 = ChannelEnvelope::unpack(&p1).unwrap();
        assert_eq!(e1.sequence, u16::MAX - 1);
        ch.mark_delivered(u16::MAX - 1, 0.0);

        let p2 = ch.send(0x01, b"wrap-2").unwrap();
        let e2 = ChannelEnvelope::unpack(&p2).unwrap();
        assert_eq!(e2.sequence, u16::MAX);
        ch.mark_delivered(u16::MAX, 0.0);

        assert_eq!(ch.next_tx_sequence(), 0, "sequence should wrap to 0");
        let p3 = ch.send(0x01, b"wrap-3").unwrap();
        let e3 = ChannelEnvelope::unpack(&p3).unwrap();
        assert_eq!(e3.sequence, 0);
    }

    #[test]
    fn test_rx_buffer_at_max() {
        let mut ch = Channel::new();

        for i in 1..=(MAX_RX_BUFFER as u16) {
            let env = ChannelEnvelope {
                message_type: 0x01,
                sequence: i,
                payload: alloc::format!("msg{}", i).into_bytes(),
            };
            ch.receive(&env.pack());
        }

        assert_eq!(ch.ready_count(), 0);

        let overflow = ChannelEnvelope {
            message_type: 0x01,
            sequence: (MAX_RX_BUFFER as u16) + 1,
            payload: b"overflow".to_vec(),
        };
        ch.receive(&overflow.pack());

        let e0 = ChannelEnvelope {
            message_type: 0x01,
            sequence: 0,
            payload: b"msg0".to_vec(),
        };
        ch.receive(&e0.pack());

        assert_eq!(ch.ready_count(), MAX_RX_BUFFER + 1);
    }

    #[test]
    fn test_mark_delivered_nonexistent() {
        let mut ch = Channel::new();
        ch.send(0x01, b"msg0").unwrap();

        ch.mark_delivered(999, 0.0); // should not panic
        assert_eq!(ch.pending_count(), 1, "original pending should remain");
    }

    #[test]
    fn test_next_tx_sequence_getter() {
        let mut ch = Channel::new();
        assert_eq!(ch.next_tx_sequence(), 0);

        ch.send(0x01, b"a").unwrap();
        assert_eq!(ch.next_tx_sequence(), 1);

        ch.send(0x01, b"b").unwrap();
        assert_eq!(ch.next_tx_sequence(), 2);
    }

    // -----------------------------------------------------------------------
    // Constants match Python RNS
    // -----------------------------------------------------------------------

    #[test]
    fn test_constants_match_python() {
        assert_eq!(DEFAULT_WINDOW, 2, "Python: Channel.WINDOW = 2");
        assert_eq!(WINDOW_MIN, 2, "Python: Channel.WINDOW_MIN = 2");
        assert_eq!(WINDOW_MIN_LIMIT_SLOW, 2);
        assert_eq!(WINDOW_MIN_LIMIT_MEDIUM, 5);
        assert_eq!(WINDOW_MIN_LIMIT_FAST, 16);
        assert_eq!(WINDOW_MAX_SLOW, 5);
        assert_eq!(WINDOW_MAX_MEDIUM, 12);
        assert_eq!(WINDOW_MAX_FAST, 48);
        assert_eq!(WINDOW_MAX, WINDOW_MAX_FAST);
        assert_eq!(FAST_RATE_THRESHOLD, 10);
        assert_eq!(RTT_FAST_MS, 180, "Python: Channel.RTT_FAST = 0.18");
        assert_eq!(RTT_MEDIUM_MS, 750, "Python: Channel.RTT_MEDIUM = 0.75");
        assert_eq!(RTT_SLOW_MS, 1450, "Python: Channel.RTT_SLOW = 1.45");
        assert_eq!(WINDOW_FLEXIBILITY, 4);
        assert_eq!(SEQ_MAX, 0xFFFF);
        assert_eq!(SEQ_MODULUS, 0x10000);
    }

    // -----------------------------------------------------------------------
    // Graduated window adaptation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_initial_window_is_slow_tier() {
        let ch = Channel::new();
        assert_eq!(ch.window, DEFAULT_WINDOW);
        assert_eq!(ch.window_max, WINDOW_MAX_SLOW);
        assert_eq!(ch.window_min, WINDOW_MIN);
    }

    #[test]
    fn test_window_grows_on_delivery() {
        let mut ch = Channel::new();
        ch.send(0x01, b"msg0").unwrap();
        ch.send(0x01, b"msg1").unwrap();
        assert_eq!(ch.window, 2);

        // Deliver first message with slow RTT
        ch.mark_delivered(0, 1.0);
        assert_eq!(ch.window, 3, "window should grow by 1 on delivery");
    }

    #[test]
    fn test_window_capped_at_window_max() {
        let mut ch = Channel::new();
        // Start at slow tier: window_max = 5
        // Deliver several messages to grow window
        for i in 0..10u16 {
            ch.send(0x01, b"data").unwrap();
            ch.mark_delivered(i, 1.0); // slow RTT
        }
        assert_eq!(
            ch.window, WINDOW_MAX_SLOW,
            "window should not exceed window_max for slow tier"
        );
    }

    #[test]
    fn test_medium_tier_promotion() {
        let mut ch = Channel::new();
        // Simulate sustained medium-rate rounds (RTT = 0.5s = 500ms)
        for i in 0..FAST_RATE_THRESHOLD {
            ch.send(0x01, b"data").unwrap();
            ch.mark_delivered(i, 0.5); // 500ms = medium rate
        }
        assert_eq!(
            ch.window_max, WINDOW_MAX_MEDIUM,
            "should promote to medium tier after {} sustained rounds",
            FAST_RATE_THRESHOLD
        );
        assert_eq!(ch.window_min, WINDOW_MIN_LIMIT_MEDIUM);
    }

    #[test]
    fn test_fast_tier_promotion() {
        let mut ch = Channel::new();
        // First promote to medium
        for i in 0..FAST_RATE_THRESHOLD {
            ch.send(0x01, b"data").unwrap();
            ch.mark_delivered(i, 0.5);
        }
        // Then sustain fast rate
        for i in FAST_RATE_THRESHOLD..2 * FAST_RATE_THRESHOLD {
            ch.send(0x01, b"data").unwrap();
            ch.mark_delivered(i, 0.01); // 10ms = fast rate
        }
        assert_eq!(ch.window_max, WINDOW_MAX_FAST);
        assert_eq!(ch.window_min, WINDOW_MIN_LIMIT_FAST);
    }

    #[test]
    fn test_fast_rate_resets_on_slow_rtt() {
        let mut ch = Channel::new();
        // Build up 9 fast rounds
        for i in 0..9u16 {
            ch.send(0x01, b"data").unwrap();
            ch.mark_delivered(i, 0.01);
        }
        assert_eq!(ch.fast_rate_rounds, 9);

        // One slow RTT resets the counter
        ch.send(0x01, b"data").unwrap();
        ch.mark_delivered(9, 1.0);
        assert_eq!(ch.fast_rate_rounds, 0, "fast counter should reset on slow RTT");
    }

    #[test]
    fn test_window_shrinks_on_timeout() {
        let mut ch = Channel::new();
        // Grow window first
        for i in 0..5u16 {
            ch.send(0x01, b"data").unwrap();
            ch.mark_delivered(i, 1.0);
        }
        let window_before = ch.window;
        assert!(window_before > WINDOW_MIN);

        // Send a message and let it timeout
        ch.send(0x01, b"timeout").unwrap();
        ch.mark_sent(100);
        ch.pending_retransmit(116); // triggers timeout

        assert_eq!(
            ch.window,
            window_before - 1,
            "window should shrink by 1 on timeout"
        );
    }

    #[test]
    fn test_window_max_shrinks_on_timeout() {
        let mut ch = Channel::new();
        // Promote to medium tier first
        for i in 0..FAST_RATE_THRESHOLD {
            ch.send(0x01, b"data").unwrap();
            ch.mark_delivered(i, 0.5);
        }
        assert_eq!(ch.window_max, WINDOW_MAX_MEDIUM);
        let wmax_before = ch.window_max;

        // Grow window to something > window_min
        for i in FAST_RATE_THRESHOLD..FAST_RATE_THRESHOLD + 10 {
            ch.send(0x01, b"data").unwrap();
            ch.mark_delivered(i, 0.5);
        }

        // Timeout
        ch.send(0x01, b"timeout").unwrap();
        ch.mark_sent(100);
        ch.pending_retransmit(116);

        // window_max should shrink if > window_min + window_flexibility
        if wmax_before > ch.window_min + WINDOW_FLEXIBILITY {
            assert!(ch.window_max < wmax_before, "window_max should shrink on timeout");
        }
    }

    #[test]
    fn test_retry_timeout_formula() {
        let mut ch = Channel::new();
        ch.rtt_ms = 200; // 200ms RTT
        ch.send(0x01, b"data").unwrap();

        // tries=1: 1.5^0 * max(0.2*2.5, 0.025) * (1+1.5) = 1 * 0.5 * 2.5 = 1.25
        let timeout = ch.compute_retry_timeout(1);
        assert!((timeout - 1.25).abs() < 0.01, "timeout should be ~1.25, got {}", timeout);

        // tries=2: 1.5^1 * 0.5 * 2.5 = 1.875
        let timeout2 = ch.compute_retry_timeout(2);
        assert!((timeout2 - 1.875).abs() < 0.01, "timeout should be ~1.875, got {}", timeout2);
    }
}
