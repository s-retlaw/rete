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

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Envelope header size: msgtype(2) + seq(2) + len(2) = 6 bytes.
pub const ENVELOPE_HEADER_SIZE: usize = 6;

/// System message type for Buffer/Stream data.
pub const MSG_TYPE_STREAM: u16 = 0xFF00;

/// Default channel window size.
pub const DEFAULT_WINDOW: u16 = 4;

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
    /// Window size (max unconfirmed messages).
    window: u16,
    /// Retry timeout in seconds.
    retry_timeout: u64,
    /// Whether the channel should be torn down.
    pub teardown: bool,
}

impl Default for Channel {
    fn default() -> Self {
        Self::new()
    }
}

impl Channel {
    /// Create a new channel with default settings.
    pub fn new() -> Self {
        Channel {
            tx_sequence: 0,
            rx_sequence: 0,
            tx_pending: VecDeque::new(),
            rx_buffer: VecDeque::new(),
            rx_ready: VecDeque::new(),
            window: DEFAULT_WINDOW,
            retry_timeout: 15,
            teardown: false,
        }
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

    /// Mark a message as delivered (confirmed by proof).
    pub fn mark_delivered(&mut self, sequence: u16) {
        self.tx_pending.retain(|m| m.envelope.sequence != sequence);
    }

    /// Get pending messages that need retransmission.
    pub fn pending_retransmit(&mut self, now: u64) -> Vec<Vec<u8>> {
        let mut retransmits = Vec::new();
        for msg in &mut self.tx_pending {
            if msg.sent_at > 0 && now.saturating_sub(msg.sent_at) > self.retry_timeout {
                msg.retries += 1;
                if msg.retries > MAX_RETRIES {
                    self.teardown = true;
                    return retransmits;
                }
                msg.sent_at = now;
                retransmits.push(msg.envelope.pack());
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
        let p2 = ch.send(0x01, b"msg2").unwrap();

        let e0 = ChannelEnvelope::unpack(&p0).unwrap();
        let e1 = ChannelEnvelope::unpack(&p1).unwrap();
        let e2 = ChannelEnvelope::unpack(&p2).unwrap();
        assert_eq!(e0.sequence, 0);
        assert_eq!(e1.sequence, 1);
        assert_eq!(e2.sequence, 2);
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

        // Send out of order: 1, 0, 2
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

        // All should be in order
        assert_eq!(ch.next_received().unwrap().sequence, 0);
        assert_eq!(ch.next_received().unwrap().sequence, 1);
        assert_eq!(ch.next_received().unwrap().sequence, 2);
    }

    #[test]
    fn channel_window_blocks_send() {
        let mut ch = Channel::new();
        // Fill the window (default 4)
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
        // Send messages until sequence wraps at u16::MAX.
        let mut ch = Channel::new();

        // Set tx_sequence close to u16::MAX by sending and immediately
        // clearing the pending queue.
        ch.tx_sequence = u16::MAX - 1;

        // Send at u16::MAX - 1
        let p1 = ch.send(0x01, b"wrap-1").unwrap();
        let e1 = ChannelEnvelope::unpack(&p1).unwrap();
        assert_eq!(e1.sequence, u16::MAX - 1);
        ch.mark_delivered(u16::MAX - 1);

        // Send at u16::MAX
        let p2 = ch.send(0x01, b"wrap-2").unwrap();
        let e2 = ChannelEnvelope::unpack(&p2).unwrap();
        assert_eq!(e2.sequence, u16::MAX);
        ch.mark_delivered(u16::MAX);

        // Send at 0 (wrapped)
        assert_eq!(ch.next_tx_sequence(), 0, "sequence should wrap to 0");
        let p3 = ch.send(0x01, b"wrap-3").unwrap();
        let e3 = ChannelEnvelope::unpack(&p3).unwrap();
        assert_eq!(e3.sequence, 0);
    }

    #[test]
    fn test_rx_buffer_at_max() {
        // Receive MAX_RX_BUFFER out-of-order messages (all with seq > current).
        // Buffer should not grow beyond MAX_RX_BUFFER.
        let mut ch = Channel::new();

        // Send messages with sequences 1..=MAX_RX_BUFFER (skipping 0)
        // so they are all out-of-order (waiting for seq 0).
        for i in 1..=(MAX_RX_BUFFER as u16) {
            let env = ChannelEnvelope {
                message_type: 0x01,
                sequence: i,
                payload: alloc::format!("msg{}", i).into_bytes(),
            };
            ch.receive(&env.pack());
        }

        assert_eq!(ch.ready_count(), 0, "no messages should be ready (missing seq 0)");

        // Try to add one more — should be dropped (buffer full)
        let overflow = ChannelEnvelope {
            message_type: 0x01,
            sequence: (MAX_RX_BUFFER as u16) + 1,
            payload: b"overflow".to_vec(),
        };
        ch.receive(&overflow.pack());

        // Now deliver seq 0 — should flush all buffered messages
        let e0 = ChannelEnvelope {
            message_type: 0x01,
            sequence: 0,
            payload: b"msg0".to_vec(),
        };
        ch.receive(&e0.pack());

        // seq 0 + all MAX_RX_BUFFER buffered = MAX_RX_BUFFER + 1 delivered
        assert_eq!(ch.ready_count(), MAX_RX_BUFFER + 1);
    }

    #[test]
    fn test_mark_delivered_nonexistent() {
        // mark_delivered for a nonexistent sequence should not panic.
        let mut ch = Channel::new();
        ch.send(0x01, b"msg0").unwrap();

        // Mark a sequence that doesn't exist
        ch.mark_delivered(999); // should not panic
        assert_eq!(ch.pending_count(), 1, "original pending should remain");
    }

    #[test]
    fn test_next_tx_sequence_getter() {
        // next_tx_sequence() should return the correct value after sending.
        let mut ch = Channel::new();
        assert_eq!(ch.next_tx_sequence(), 0);

        ch.send(0x01, b"a").unwrap();
        assert_eq!(ch.next_tx_sequence(), 1);

        ch.send(0x01, b"b").unwrap();
        assert_eq!(ch.next_tx_sequence(), 2);

        ch.send(0x01, b"c").unwrap();
        assert_eq!(ch.next_tx_sequence(), 3);
    }
}
