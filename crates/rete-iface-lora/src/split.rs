//! LoRa split packet handling — matches RNode firmware protocol.
//!
//! LoRa radios have a 255-byte maximum payload per frame. RNS MTU is 500
//! bytes. The RNode firmware prepends a 1-byte header to EVERY LoRa frame
//! (both split and non-split). Packets larger than 254 bytes are split
//! into two LoRa frames.
//!
//! Protocol (matching RNode firmware `transmit()` and `receive_callback()`):
//!
//! **Header byte** (always present on every LoRa frame):
//! ```text
//! [7:4] sequence number (random upper nibble)
//! [3:1] reserved (0)
//! [0]   FLAG_SPLIT (1 = this frame is part of a split packet)
//! ```
//!
//! **TX rules** (from firmware `transmit()`):
//! - Packets <= 254 bytes: single frame = header(FLAG_SPLIT=0) + data
//! - Packets 255..=508 bytes: two frames, each with header(FLAG_SPLIT=1)
//!   - Frame 1: header + first 254 data bytes (total 255 bytes)
//!   - Frame 2: header + remaining data bytes
//!
//! **RX rules** (from firmware `receive_callback()`):
//! - Header byte is always read and stripped from every frame.
//! - Split detection is state-based (using `seq` variable), not length-based.
//! - If FLAG_SPLIT && no split pending: start new split (first fragment).
//! - If FLAG_SPLIT && seq matches: complete split (second fragment).
//! - If FLAG_SPLIT && seq mismatch: discard old, start new split.
//! - If !FLAG_SPLIT && split pending: discard stale split, deliver as complete.
//! - If !FLAG_SPLIT && no split pending: deliver as complete.

/// Maximum LoRa radio frame size (bytes).
pub const LORA_MTU: usize = 255;

/// Single-frame data capacity (SINGLE_MTU - HEADER_L in firmware).
/// Packets up to this size fit in one frame (with header).
pub const SINGLE_MTU_DATA: usize = LORA_MTU - HEADER_L;

/// Maximum RNS packet size over split LoRa (2 * 254 = 508).
/// Matches firmware `MTU = 508`.
pub const LORA_HW_MTU: usize = 508;

/// Header length in bytes (always 1, matches firmware HEADER_L).
const HEADER_L: usize = 1;

/// Maximum data bytes per split frame (255 - 1 header byte = 254).
const SPLIT_DATA_PER_FRAME: usize = LORA_MTU - HEADER_L;

/// Split packet flag (bit 0 of header byte).
const FLAG_SPLIT: u8 = 0x01;

/// Sentinel for "no split in progress".
const SEQ_UNSET: u8 = 0xFF;

/// Result of splitting a packet for transmission.
pub enum SplitResult<'a> {
    /// Packet fits in one frame — header(FLAG_SPLIT=0) + data.
    Single { frame: &'a [u8] },
    /// Packet was split into two frames, each with header(FLAG_SPLIT=1).
    Split {
        frame1: &'a [u8],
        frame2: &'a [u8],
    },
}

/// Prepare a packet for LoRa transmission, splitting if necessary.
///
/// Matches RNode firmware `transmit()`: every frame gets a 1-byte header.
/// Packets <= 254 bytes → single frame (header + data).
/// Packets 255..=508 bytes → two frames (each with header + data).
///
/// `packet` is the raw RNS packet bytes. `tx_buf` is scratch space for
/// building the framed output (must be >= `LORA_MTU * 2`). `seq` is the
/// upper-nibble sequence number (0..15), matching firmware's `random(256) & 0xF0`.
///
/// Returns `None` if the packet exceeds `LORA_HW_MTU`.
pub fn split_for_tx<'a>(
    packet: &[u8],
    tx_buf: &'a mut [u8; LORA_MTU * 2],
    seq: u8,
) -> Option<SplitResult<'a>> {
    if packet.len() > LORA_HW_MTU {
        return None; // Too large even for split
    }

    if packet.len() <= SINGLE_MTU_DATA {
        // Fits in one frame: header(FLAG_SPLIT=0) + data.
        // Firmware: header = random(256) & 0xF0 (no FLAG_SPLIT)
        let header = (seq << 4) & 0xF0; // upper nibble only, FLAG_SPLIT=0
        tx_buf[0] = header;
        tx_buf[1..1 + packet.len()].copy_from_slice(packet);
        return Some(SplitResult::Single {
            frame: &tx_buf[..1 + packet.len()],
        });
    }

    // Split into two frames: header(FLAG_SPLIT=1) + data each.
    // Firmware: header = (random(256) & 0xF0) | FLAG_SPLIT
    let header = ((seq << 4) & 0xF0) | FLAG_SPLIT;

    // Frame 1: header + first 254 bytes = 255 bytes total
    let split_at = SPLIT_DATA_PER_FRAME;
    tx_buf[0] = header;
    tx_buf[1..1 + split_at].copy_from_slice(&packet[..split_at]);
    let frame1_len = HEADER_L + split_at; // 255

    // Frame 2: header + remaining bytes
    let remaining = packet.len() - split_at;
    let frame2_start = LORA_MTU;
    tx_buf[frame2_start] = header;
    tx_buf[frame2_start + 1..frame2_start + 1 + remaining]
        .copy_from_slice(&packet[split_at..]);
    let frame2_len = HEADER_L + remaining;

    Some(SplitResult::Split {
        frame1: &tx_buf[..frame1_len],
        frame2: &tx_buf[frame2_start..frame2_start + frame2_len],
    })
}

/// Stateful reassembler for split LoRa packets.
pub struct SplitReassembler {
    /// Buffered first fragment data (without header).
    buf: [u8; SPLIT_DATA_PER_FRAME],
    /// Length of buffered data.
    buf_len: usize,
    /// Expected sequence number for the second fragment.
    expected_seq: u8,
}

impl SplitReassembler {
    pub const fn new() -> Self {
        Self {
            buf: [0u8; SPLIT_DATA_PER_FRAME],
            buf_len: 0,
            expected_seq: SEQ_UNSET,
        }
    }

    /// Returns true if we're waiting for a split continuation.
    pub fn pending(&self) -> bool {
        self.expected_seq != SEQ_UNSET
    }

    /// Reset split state (e.g. on timeout).
    pub fn reset(&mut self) {
        self.expected_seq = SEQ_UNSET;
        self.buf_len = 0;
    }

    /// Process a received LoRa frame. Returns the complete packet if available.
    ///
    /// Matches RNode firmware `receive_callback()`: the header byte is always
    /// read and stripped. Split detection is state-based (using `expected_seq`),
    /// not length-based.
    ///
    /// `frame` is the raw bytes from the LoRa radio (header + data).
    /// `out` is the reassembly buffer (must be >= `LORA_HW_MTU`).
    ///
    /// Returns `Some(len)` if a complete packet is available in `out[..len]`.
    pub fn feed<'a>(&mut self, frame: &[u8], out: &'a mut [u8]) -> Option<usize> {
        if frame.is_empty() {
            return None;
        }

        // Always read and strip the header byte (matches firmware).
        let header = frame[0];
        let data = &frame[1..];
        let is_split = (header & FLAG_SPLIT) != 0;
        let sequence = header >> 4;

        if is_split && !self.pending() {
            // First fragment of a new split packet.
            // Firmware: `isSplitPacket(header) && seq == SEQ_UNSET`
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
            self.expected_seq = sequence;
            return None; // Waiting for second fragment
        }

        if is_split && self.pending() && sequence == self.expected_seq {
            // Second fragment — sequence matches, complete the packet.
            // Firmware: `isSplitPacket(header) && seq == sequence`
            let total = self.buf_len + data.len();
            if total <= out.len() {
                out[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
                out[self.buf_len..total].copy_from_slice(data);
                self.reset();
                return Some(total);
            }
            // Output buffer too small — drop
            self.reset();
            return None;
        }

        if is_split && self.pending() && sequence != self.expected_seq {
            // Sequence mismatch — discard old split, start new one.
            // Firmware: `isSplitPacket(header) && seq != sequence`
            // Resets read_len=0, stores new seq, reads data.
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
            self.expected_seq = sequence;
            return None;
        }

        // Not a split fragment — deliver as complete packet.
        // Firmware: `!isSplitPacket(header)` branch.
        if self.pending() {
            // Discard stale split buffer (firmware resets read_len and seq).
            self.reset();
        }

        let len = data.len();
        if len <= out.len() {
            out[..len].copy_from_slice(data);
            Some(len)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- TX tests ----

    #[test]
    fn small_packet_single_frame_with_header() {
        // Firmware: packets <= 254 bytes get header(FLAG_SPLIT=0) + data.
        let packet = [0x42; 100];
        let mut tx_buf = [0u8; LORA_MTU * 2];
        let result = split_for_tx(&packet, &mut tx_buf, 0).unwrap();
        match result {
            SplitResult::Single { frame } => {
                assert_eq!(frame.len(), 101); // 1 header + 100 data
                assert_eq!(frame[0] & FLAG_SPLIT, 0); // FLAG_SPLIT not set
                assert_eq!(&frame[1..], &packet[..]);
            }
            SplitResult::Split { .. } => panic!("expected single frame"),
        }
    }

    #[test]
    fn max_single_frame_254_bytes() {
        // 254 data bytes = max that fits in one frame (header + 254 = 255).
        let packet = [0xAA; 254];
        let mut tx_buf = [0u8; LORA_MTU * 2];
        let result = split_for_tx(&packet, &mut tx_buf, 3).unwrap();
        match result {
            SplitResult::Single { frame } => {
                assert_eq!(frame.len(), 255); // 1 + 254 = full LoRa frame
                assert_eq!(frame[0], 3 << 4); // seq=3, FLAG_SPLIT=0
                assert_eq!(&frame[1..], &packet[..]);
            }
            SplitResult::Split { .. } => panic!("254 bytes should fit in single frame"),
        }
    }

    #[test]
    fn split_threshold_at_255_bytes() {
        // Firmware: split when size > SINGLE_MTU - HEADER_L = 254.
        // 255 data bytes must split.
        let packet = [0xBB; 255];
        let mut tx_buf = [0u8; LORA_MTU * 2];
        let result = split_for_tx(&packet, &mut tx_buf, 9).unwrap();
        match result {
            SplitResult::Single { .. } => panic!("255 bytes should split (firmware threshold)"),
            SplitResult::Split { frame1, frame2 } => {
                // Frame 1: header + 254 data bytes = 255
                assert_eq!(frame1.len(), 255);
                assert_eq!(frame1[0], (9 << 4) | FLAG_SPLIT);
                assert_eq!(&frame1[1..], &packet[..254]);

                // Frame 2: header + 1 remaining byte = 2
                assert_eq!(frame2.len(), 2);
                assert_eq!(frame2[0], (9 << 4) | FLAG_SPLIT);
                assert_eq!(frame2[1], 0xBB);
            }
        }
    }

    #[test]
    fn split_256_bytes() {
        let packet: [u8; 256] = core::array::from_fn(|i| i as u8);
        let mut tx_buf = [0u8; LORA_MTU * 2];
        let result = split_for_tx(&packet, &mut tx_buf, 5).unwrap();
        match result {
            SplitResult::Single { .. } => panic!("256 bytes should split"),
            SplitResult::Split { frame1, frame2 } => {
                assert_eq!(frame1.len(), 255);
                assert_eq!(frame1[0], (5 << 4) | FLAG_SPLIT);
                assert_eq!(&frame1[1..], &packet[..254]);

                assert_eq!(frame2.len(), 3); // header + 2 remaining
                assert_eq!(frame2[0], (5 << 4) | FLAG_SPLIT);
                assert_eq!(&frame2[1..], &packet[254..]);
            }
        }
    }

    #[test]
    fn split_max_hw_mtu() {
        let packet = [0xFF; 508];
        let mut tx_buf = [0u8; LORA_MTU * 2];
        let result = split_for_tx(&packet, &mut tx_buf, 15).unwrap();
        match result {
            SplitResult::Single { .. } => panic!("508 bytes should split"),
            SplitResult::Split { frame1, frame2 } => {
                assert_eq!(frame1.len(), 255); // header + 254
                assert_eq!(frame2.len(), 255); // header + 254
            }
        }
    }

    #[test]
    fn too_large_returns_none() {
        let packet = [0; 509];
        let mut tx_buf = [0u8; LORA_MTU * 2];
        assert!(split_for_tx(&packet, &mut tx_buf, 0).is_none());
    }

    #[test]
    fn header_seq_upper_nibble_only() {
        // Firmware: header = random(256) & 0xF0 [| FLAG_SPLIT]
        // Verify that only the upper nibble carries the sequence.
        let packet = [0x42; 10];
        let mut tx_buf = [0u8; LORA_MTU * 2];
        let result = split_for_tx(&packet, &mut tx_buf, 0xAB).unwrap();
        match result {
            SplitResult::Single { frame } => {
                // seq 0xAB → (0xAB << 4) & 0xF0 = 0xB0
                assert_eq!(frame[0], 0xB0);
            }
            _ => panic!("expected single"),
        }
    }

    // ---- RX tests ----

    #[test]
    fn reassemble_non_split_strips_header() {
        // Firmware always strips header byte, even for non-split frames.
        let mut ra = SplitReassembler::new();
        let frame = [0x50, 0xAA, 0xBB, 0xCC]; // header=0x50 (seq=5, no split), data=3 bytes
        let mut out = [0u8; 512];
        let len = ra.feed(&frame, &mut out).unwrap();
        assert_eq!(len, 3);
        assert_eq!(&out[..len], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn reassemble_split_roundtrip() {
        // Full TX→RX roundtrip for a split packet.
        let packet: [u8; 300] = core::array::from_fn(|i| i as u8);
        let mut tx_buf = [0u8; LORA_MTU * 2];
        let seq = 7u8;
        let result = split_for_tx(&packet, &mut tx_buf, seq).unwrap();

        let (frame1, frame2) = match result {
            SplitResult::Split { frame1, frame2 } => {
                (frame1.to_vec(), frame2.to_vec())
            }
            _ => panic!("should split"),
        };

        let mut ra = SplitReassembler::new();
        let mut out = [0u8; 512];

        // First fragment — returns None (waiting for second)
        assert!(ra.feed(&frame1, &mut out).is_none());
        assert!(ra.pending());

        // Second fragment — returns reassembled packet
        let len = ra.feed(&frame2, &mut out).unwrap();
        assert_eq!(len, 300);
        assert_eq!(&out[..len], &packet[..]);
        assert!(!ra.pending());
    }

    #[test]
    fn reassemble_single_frame_roundtrip() {
        // Full TX→RX roundtrip for a non-split packet.
        let packet = [0x42; 100];
        let mut tx_buf = [0u8; LORA_MTU * 2];
        let result = split_for_tx(&packet, &mut tx_buf, 3).unwrap();

        let frame = match result {
            SplitResult::Single { frame } => frame.to_vec(),
            _ => panic!("should be single"),
        };

        let mut ra = SplitReassembler::new();
        let mut out = [0u8; 512];
        let len = ra.feed(&frame, &mut out).unwrap();
        assert_eq!(len, 100);
        assert_eq!(&out[..len], &packet[..]);
    }

    #[test]
    fn reassemble_split_timeout_reset() {
        let mut ra = SplitReassembler::new();
        let mut out = [0u8; 512];

        // Feed first fragment of a split
        let header = (3u8 << 4) | FLAG_SPLIT;
        let mut frame1 = [0u8; 255];
        frame1[0] = header;
        assert!(ra.feed(&frame1, &mut out).is_none());
        assert!(ra.pending());

        // Reset (simulating timeout)
        ra.reset();
        assert!(!ra.pending());

        // Feed a complete non-split packet (with header)
        let complete = [0x00, 0xBB, 0xCC]; // header=0x00, data=[0xBB, 0xCC]
        let len = ra.feed(&complete, &mut out).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&out[..len], &[0xBB, 0xCC]);
    }

    #[test]
    fn reassemble_non_split_clears_stale() {
        let mut ra = SplitReassembler::new();
        let mut out = [0u8; 512];

        // Feed first fragment
        let header = (2u8 << 4) | FLAG_SPLIT;
        let mut frame1 = [0u8; 255];
        frame1[0] = header;
        assert!(ra.feed(&frame1, &mut out).is_none());
        assert!(ra.pending());

        // Feed a non-split complete packet (stale split should be dropped)
        // Header: seq=0, FLAG_SPLIT=0
        let complete = [0x00, 0xCC, 0xDD];
        let len = ra.feed(&complete, &mut out).unwrap();
        assert_eq!(&out[..len], &[0xCC, 0xDD]);
        assert!(!ra.pending());
    }

    #[test]
    fn reassemble_seq_mismatch_starts_new_split() {
        // Firmware: split + seq mismatch → discard old, start new split.
        // This is state-based, NOT length-based.
        let mut ra = SplitReassembler::new();
        let mut out = [0u8; 512];

        // Feed first fragment with seq=3
        let header1 = (3u8 << 4) | FLAG_SPLIT;
        let mut frame1 = [0u8; 100]; // Not 255 bytes — still a split frame
        frame1[0] = header1;
        assert!(ra.feed(&frame1, &mut out).is_none());
        assert!(ra.pending());
        assert_eq!(ra.expected_seq, 3);

        // Feed another split frame with different seq=5
        let header2 = (5u8 << 4) | FLAG_SPLIT;
        let mut frame2 = [0u8; 80];
        frame2[0] = header2;
        // Should discard old split and start new one
        assert!(ra.feed(&frame2, &mut out).is_none());
        assert!(ra.pending());
        assert_eq!(ra.expected_seq, 5); // Now expecting seq=5
    }

    #[test]
    fn empty_frame_returns_none() {
        let mut ra = SplitReassembler::new();
        let mut out = [0u8; 512];
        assert!(ra.feed(&[], &mut out).is_none());
    }

    #[test]
    fn header_only_frame_yields_empty_data() {
        // A frame with just a header byte (no data) — edge case.
        let mut ra = SplitReassembler::new();
        let mut out = [0u8; 512];
        let frame = [0x30]; // header only, seq=3, no split
        let len = ra.feed(&frame, &mut out).unwrap();
        assert_eq!(len, 0); // Zero data bytes after stripping header
    }

    // ---- Firmware-specific behavior tests ----

    #[test]
    fn firmware_constants_match() {
        // Verify our constants match firmware Config.h and Framing.h.
        assert_eq!(FLAG_SPLIT, 0x01);          // Framing.h
        assert_eq!(SEQ_UNSET, 0xFF);           // Framing.h
        assert_eq!(LORA_MTU, 255);             // Config.h SINGLE_MTU
        assert_eq!(LORA_HW_MTU, 508);          // Config.h MTU
        assert_eq!(HEADER_L, 1);               // Config.h HEADER_L
        assert_eq!(SPLIT_DATA_PER_FRAME, 254); // SINGLE_MTU - HEADER_L
    }

    #[test]
    fn firmware_split_threshold_exact() {
        // Firmware splits when size > SINGLE_MTU - HEADER_L (254).
        // 254 data bytes → single frame.
        let packet_254 = [0u8; 254];
        let mut tx_buf = [0u8; LORA_MTU * 2];
        assert!(matches!(
            split_for_tx(&packet_254, &mut tx_buf, 0),
            Some(SplitResult::Single { .. })
        ));

        // 255 data bytes → split.
        let packet_255 = [0u8; 255];
        assert!(matches!(
            split_for_tx(&packet_255, &mut tx_buf, 0),
            Some(SplitResult::Split { .. })
        ));
    }

    #[test]
    fn firmware_header_always_present() {
        // Even a 1-byte packet gets a header.
        let packet = [0x42];
        let mut tx_buf = [0u8; LORA_MTU * 2];
        let result = split_for_tx(&packet, &mut tx_buf, 0).unwrap();
        match result {
            SplitResult::Single { frame } => {
                assert_eq!(frame.len(), 2); // 1 header + 1 data
                assert_eq!(frame[0] & FLAG_SPLIT, 0); // No split flag
                assert_eq!(frame[1], 0x42);
            }
            _ => panic!("expected single"),
        }
    }

    #[test]
    fn firmware_rx_state_based_not_length_based() {
        // Key difference from old code: first fragment detection is
        // state-based (seq == SEQ_UNSET), not length-based (len == 255).
        // A split fragment shorter than 255 bytes should still be recognized.
        let mut ra = SplitReassembler::new();
        let mut out = [0u8; 512];

        // First fragment: 100 bytes (header + 99 data), FLAG_SPLIT set
        let header = (4u8 << 4) | FLAG_SPLIT;
        let mut frame1 = [0xAA; 100];
        frame1[0] = header;
        assert!(ra.feed(&frame1, &mut out).is_none());
        assert!(ra.pending());

        // Second fragment with matching seq: 50 bytes
        let mut frame2 = [0xBB; 50];
        frame2[0] = header; // Same header
        let len = ra.feed(&frame2, &mut out).unwrap();
        assert_eq!(len, 99 + 49); // data from both fragments
    }
}
