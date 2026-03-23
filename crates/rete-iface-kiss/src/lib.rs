//! rete-iface-kiss — KISS TNC serial interface for rete.
//!
//! Provides KISS framing (encode/decode) for serial TNC communication.
//! `no_std` compatible, no allocator required.

#![no_std]

/// KISS special bytes.
pub const FEND: u8 = 0xC0;
pub const FESC: u8 = 0xDB;
pub const TFEND: u8 = 0xDC;
pub const TFESC: u8 = 0xDD;

/// KISS command bytes.
pub const CMD_DATA: u8 = 0x00;
pub const CMD_TXDELAY: u8 = 0x01;
pub const CMD_P: u8 = 0x02;
pub const CMD_SLOTTIME: u8 = 0x03;
pub const CMD_TXTAIL: u8 = 0x04;
pub const CMD_FULLDUPLEX: u8 = 0x05;
pub const CMD_SETHARDWARE: u8 = 0x06;
pub const CMD_READY: u8 = 0x0F;
pub const CMD_RETURN: u8 = 0xFF;
pub const CMD_UNKNOWN: u8 = 0xFE;

/// Encode a data frame into a KISS-escaped TX buffer.
///
/// Returns the number of bytes written to `out`, or `None` if `out` is too small.
///
/// Frame format: `[FEND] [CMD_DATA|port] [escaped_data] [FEND]`
pub fn encode_frame(data: &[u8], port: u8, out: &mut [u8]) -> Option<usize> {
    // Worst case: FEND + CMD + (each byte doubled) + FEND
    let mut pos = 0;

    if out.is_empty() {
        return None;
    }

    // Start delimiter
    *out.get_mut(pos)? = FEND;
    pos += 1;

    // Command byte: upper nibble = port, lower nibble = CMD_DATA
    *out.get_mut(pos)? = (port << 4) | CMD_DATA;
    pos += 1;

    // Escaped data
    for &byte in data {
        match byte {
            FEND => {
                *out.get_mut(pos)? = FESC;
                pos += 1;
                *out.get_mut(pos)? = TFEND;
                pos += 1;
            }
            FESC => {
                *out.get_mut(pos)? = FESC;
                pos += 1;
                *out.get_mut(pos)? = TFESC;
                pos += 1;
            }
            b => {
                *out.get_mut(pos)? = b;
                pos += 1;
            }
        }
    }

    // End delimiter
    *out.get_mut(pos)? = FEND;
    pos += 1;

    Some(pos)
}

/// KISS frame decoder state machine.
///
/// Feed bytes one at a time via `feed()`. When a complete data frame is
/// received, `feed()` returns the number of data bytes in the internal buffer,
/// which can be read via `data()`.
pub struct KissDecoder<const N: usize> {
    buf: [u8; N],
    pos: usize,
    in_frame: bool,
    escape: bool,
    command: u8,
}

impl<const N: usize> Default for KissDecoder<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> KissDecoder<N> {
    /// Create a new decoder with an internal buffer of `N` bytes.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; N],
            pos: 0,
            in_frame: false,
            escape: false,
            command: CMD_UNKNOWN,
        }
    }

    /// Feed a single byte into the decoder.
    ///
    /// Returns `Some(len)` when a complete data frame has been received,
    /// where `len` is the number of payload bytes. Read them with `data()`.
    /// Returns `None` if more bytes are needed.
    pub fn feed(&mut self, byte: u8) -> Option<usize> {
        if self.in_frame && byte == FEND && self.command == CMD_DATA && self.pos > 0 {
            // End of data frame
            self.in_frame = false;
            let len = self.pos;
            return Some(len);
        }

        if byte == FEND {
            // Start of new frame
            self.in_frame = true;
            self.command = CMD_UNKNOWN;
            self.pos = 0;
            self.escape = false;
            return None;
        }

        if !self.in_frame {
            return None;
        }

        if self.pos == 0 && self.command == CMD_UNKNOWN {
            // First byte after FEND is command (strip port nibble)
            self.command = byte & 0x0F;
            return None;
        }

        if self.command != CMD_DATA {
            return None;
        }

        // Data byte (possibly escaped)
        if byte == FESC {
            self.escape = true;
            return None;
        }

        let decoded = if self.escape {
            self.escape = false;
            match byte {
                TFEND => FEND,
                TFESC => FESC,
                _ => byte, // invalid escape, pass through
            }
        } else {
            byte
        };

        if self.pos < N {
            self.buf[self.pos] = decoded;
            self.pos += 1;
        }
        // else: overflow, silently drop (frame will still complete)

        None
    }

    /// Returns the decoded data from the last complete frame.
    pub fn data(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    /// Reset the decoder state.
    pub fn reset(&mut self) {
        self.pos = 0;
        self.in_frame = false;
        self.escape = false;
        self.command = CMD_UNKNOWN;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_simple_frame() {
        let data = [0x12, 0x34, 0x56];
        let mut out = [0u8; 32];
        let n = encode_frame(&data, 0, &mut out).unwrap();
        assert_eq!(&out[..n], &[FEND, CMD_DATA, 0x12, 0x34, 0x56, FEND]);
    }

    #[test]
    fn encode_escapes_fend_and_fesc() {
        let data = [0x12, FEND, FESC, 0x34];
        let mut out = [0u8; 32];
        let n = encode_frame(&data, 0, &mut out).unwrap();
        assert_eq!(
            &out[..n],
            &[FEND, CMD_DATA, 0x12, FESC, TFEND, FESC, TFESC, 0x34, FEND]
        );
    }

    #[test]
    fn encode_with_port() {
        let data = [0xAA];
        let mut out = [0u8; 32];
        let n = encode_frame(&data, 2, &mut out).unwrap();
        assert_eq!(&out[..n], &[FEND, 0x20 | CMD_DATA, 0xAA, FEND]);
    }

    #[test]
    fn encode_buffer_too_small() {
        let data = [0x12, 0x34, 0x56];
        let mut out = [0u8; 4]; // needs at least 6
        assert!(encode_frame(&data, 0, &mut out).is_none());
    }

    #[test]
    fn decode_simple_frame() {
        let mut dec = KissDecoder::<128>::new();
        let frame = [FEND, CMD_DATA, 0x12, 0x34, 0x56, FEND];
        let mut result = None;
        for &b in &frame {
            if let Some(n) = dec.feed(b) {
                result = Some(n);
            }
        }
        assert_eq!(result, Some(3));
        assert_eq!(dec.data(), &[0x12, 0x34, 0x56]);
    }

    #[test]
    fn decode_escaped_frame() {
        let mut dec = KissDecoder::<128>::new();
        // Data contains FEND and FESC escaped
        let frame = [FEND, CMD_DATA, 0x12, FESC, TFEND, FESC, TFESC, 0x34, FEND];
        let mut result = None;
        for &b in &frame {
            if let Some(n) = dec.feed(b) {
                result = Some(n);
            }
        }
        assert_eq!(result, Some(4));
        assert_eq!(dec.data(), &[0x12, FEND, FESC, 0x34]);
    }

    #[test]
    fn decode_ignores_non_data_commands() {
        let mut dec = KissDecoder::<128>::new();
        // A TXDELAY command frame — should not produce output
        let frame = [FEND, CMD_TXDELAY, 0x40, FEND];
        for &b in &frame {
            assert!(dec.feed(b).is_none());
        }
    }

    #[test]
    fn roundtrip_encode_decode() {
        let original = [0x00, FEND, 0xFF, FESC, 0x42, FEND, FESC, 0x00];
        let mut encoded = [0u8; 64];
        let n = encode_frame(&original, 0, &mut encoded).unwrap();

        let mut dec = KissDecoder::<128>::new();
        let mut result = None;
        for &b in &encoded[..n] {
            if let Some(len) = dec.feed(b) {
                result = Some(len);
            }
        }
        assert_eq!(result, Some(original.len()));
        assert_eq!(dec.data(), &original);
    }

    #[test]
    fn multiple_frames() {
        let mut dec = KissDecoder::<128>::new();

        // First frame
        let frame1 = [FEND, CMD_DATA, 0xAA, 0xBB, FEND];
        let mut r = None;
        for &b in &frame1 {
            if let Some(n) = dec.feed(b) {
                r = Some(n);
            }
        }
        assert_eq!(r, Some(2));
        assert_eq!(dec.data(), &[0xAA, 0xBB]);

        // Second frame (decoder resets on FEND)
        let frame2 = [FEND, CMD_DATA, 0xCC, FEND];
        let mut r2 = None;
        for &b in &frame2 {
            if let Some(n) = dec.feed(b) {
                r2 = Some(n);
            }
        }
        assert_eq!(r2, Some(1));
        assert_eq!(dec.data(), &[0xCC]);
    }
}
