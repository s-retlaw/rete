//! HDLC-like byte-stuffing codec for Reticulum TCP transport.
//!
//! Frame format: `FLAG | escaped_payload | FLAG`
//!
//! Escaping rules:
//! - `0x7E` (FLAG) in payload → `0x7D 0x5E`
//! - `0x7D` (ESC)  in payload → `0x7D 0x5D`
//!
//! This is the framing used by Python RNS for its TCP interface.

use crate::Error;

/// HDLC frame delimiter.
pub const FLAG: u8 = 0x7E;
/// HDLC escape byte.
pub const ESC: u8 = 0x7D;
/// XOR mask applied to escaped bytes.
pub const ESC_MASK: u8 = 0x20;

/// Maximum HDLC-encoded frame size (worst case: every byte escaped + 2 flags).
pub const MAX_ENCODED: usize = crate::MTU * 2 + 2;

/// HDLC-encode `data` into `out`.
///
/// Writes `FLAG || escaped(data) || FLAG` and returns the number of bytes
/// written.
///
/// # Errors
/// [`Error::BufferTooSmall`] if `out` cannot hold the framed result.
pub fn encode(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let mut pos = 0;

    // Helper to write a byte with bounds check
    macro_rules! put {
        ($b:expr) => {
            if pos >= out.len() {
                return Err(Error::BufferTooSmall);
            }
            out[pos] = $b;
            pos += 1;
        };
    }

    put!(FLAG);
    for &b in data {
        if b == FLAG || b == ESC {
            put!(ESC);
            put!(b ^ ESC_MASK);
        } else {
            put!(b);
        }
    }
    put!(FLAG);

    Ok(pos)
}

/// Streaming HDLC frame decoder.
///
/// Feed bytes one at a time via [`feed`](HdlcDecoder::feed). When a complete
/// frame is received (closing FLAG), the decoded payload is available via
/// [`frame`](HdlcDecoder::frame).
///
/// The internal buffer is `BUF_SIZE` bytes. Frames exceeding this are
/// silently dropped (buffer resets on overflow).
pub struct HdlcDecoder<const BUF_SIZE: usize> {
    buf: [u8; BUF_SIZE],
    len: usize,
    in_frame: bool,
    escape: bool,
}

impl<const N: usize> Default for HdlcDecoder<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> HdlcDecoder<N> {
    /// Create a new decoder with an empty buffer.
    pub const fn new() -> Self {
        HdlcDecoder {
            buf: [0u8; N],
            len: 0,
            in_frame: false,
            escape: false,
        }
    }

    /// Feed a single byte into the decoder.
    ///
    /// Returns `true` if a complete frame is now available via
    /// [`frame()`](HdlcDecoder::frame).
    pub fn feed(&mut self, byte: u8) -> bool {
        if byte == FLAG {
            if self.in_frame && self.len > 0 {
                // Closing FLAG — frame complete
                self.in_frame = false;
                self.escape = false;
                return true;
            }
            // Opening FLAG (or empty frame) — start new frame
            self.in_frame = true;
            self.escape = false;
            self.len = 0;
            return false;
        }

        if !self.in_frame {
            return false;
        }

        if self.escape {
            self.escape = false;
            let unescaped = byte ^ ESC_MASK;
            if self.len < N {
                self.buf[self.len] = unescaped;
                self.len += 1;
            } else {
                // Buffer overflow — drop frame
                self.in_frame = false;
                self.len = 0;
            }
            return false;
        }

        if byte == ESC {
            self.escape = true;
            return false;
        }

        // Normal byte
        if self.len < N {
            self.buf[self.len] = byte;
            self.len += 1;
        } else {
            // Buffer overflow — drop frame
            self.in_frame = false;
            self.len = 0;
        }
        false
    }

    /// Returns the last decoded frame, or `None` if no complete frame is ready.
    ///
    /// The returned slice is valid until the next call to [`feed`](HdlcDecoder::feed).
    pub fn frame(&self) -> Option<&[u8]> {
        if !self.in_frame && self.len > 0 {
            Some(&self.buf[..self.len])
        } else {
            None
        }
    }

    /// Reset the decoder state, discarding any partial frame.
    pub fn reset(&mut self) {
        self.len = 0;
        self.in_frame = false;
        self.escape = false;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec;

    #[test]
    fn encode_simple() {
        let data = b"hello";
        let mut out = [0u8; 64];
        let n = encode(data, &mut out).unwrap();
        assert_eq!(out[0], FLAG);
        assert_eq!(&out[1..6], b"hello");
        assert_eq!(out[n - 1], FLAG);
        assert_eq!(n, 7); // FLAG + 5 + FLAG
    }

    #[test]
    fn encode_escapes_flag() {
        let data = &[0x01, FLAG, 0x02];
        let mut out = [0u8; 64];
        let n = encode(data, &mut out).unwrap();
        // FLAG 0x01 ESC 0x5E 0x02 FLAG
        assert_eq!(&out[..n], &[FLAG, 0x01, ESC, FLAG ^ ESC_MASK, 0x02, FLAG]);
    }

    #[test]
    fn encode_escapes_esc() {
        let data = &[ESC];
        let mut out = [0u8; 64];
        let n = encode(data, &mut out).unwrap();
        assert_eq!(&out[..n], &[FLAG, ESC, ESC ^ ESC_MASK, FLAG]);
    }

    #[test]
    fn encode_buffer_too_small() {
        let data = b"hello";
        let mut out = [0u8; 3]; // too small for FLAG + data + FLAG
        assert_eq!(encode(data, &mut out), Err(Error::BufferTooSmall));
    }

    #[test]
    fn decode_round_trip() {
        let data = b"hello world";
        let mut encoded = [0u8; 64];
        let n = encode(data, &mut encoded).unwrap();

        let mut dec: HdlcDecoder<64> = HdlcDecoder::new();
        let mut got_frame = false;
        for &b in &encoded[..n] {
            if dec.feed(b) {
                got_frame = true;
            }
        }
        assert!(got_frame);
        assert_eq!(dec.frame().unwrap(), data);
    }

    #[test]
    fn decode_with_escapes() {
        // Encode data containing FLAG and ESC bytes
        let data = vec![0x01, FLAG, ESC, 0x02];
        let mut encoded = [0u8; 64];
        let n = encode(&data, &mut encoded).unwrap();

        let mut dec: HdlcDecoder<64> = HdlcDecoder::new();
        let mut got_frame = false;
        for &b in &encoded[..n] {
            if dec.feed(b) {
                got_frame = true;
            }
        }
        assert!(got_frame);
        assert_eq!(dec.frame().unwrap(), &data[..]);
    }

    #[test]
    fn decode_multiple_frames() {
        let mut encoded = [0u8; 128];
        let n1 = encode(b"first", &mut encoded).unwrap();
        let n2 = encode(b"second", &mut encoded[n1..]).unwrap();

        let mut dec: HdlcDecoder<64> = HdlcDecoder::new();
        let mut frames = alloc::vec::Vec::new();
        for &b in &encoded[..n1 + n2] {
            if dec.feed(b) {
                frames.push(alloc::vec::Vec::from(dec.frame().unwrap()));
            }
        }
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], b"first");
        assert_eq!(frames[1], b"second");
    }

    #[test]
    fn decode_ignores_bytes_before_flag() {
        // Garbage before the opening FLAG should be ignored
        let mut encoded = [0u8; 64];
        let n = encode(b"test", &mut encoded).unwrap();

        let mut stream = alloc::vec::Vec::new();
        stream.extend_from_slice(&[0xFF, 0x00, 0x42]); // garbage
        stream.extend_from_slice(&encoded[..n]);

        let mut dec: HdlcDecoder<64> = HdlcDecoder::new();
        let mut got_frame = false;
        for &b in &stream {
            if dec.feed(b) {
                got_frame = true;
            }
        }
        assert!(got_frame);
        assert_eq!(dec.frame().unwrap(), b"test");
    }

    #[test]
    fn decode_empty_frame_ignored() {
        // FLAG FLAG should not produce a frame (empty)
        let mut dec: HdlcDecoder<64> = HdlcDecoder::new();
        assert!(!dec.feed(FLAG));
        assert!(!dec.feed(FLAG));
        assert!(dec.frame().is_none());
    }

    #[test]
    fn decode_overflow_drops_frame() {
        // Buffer too small for the frame data
        let mut dec: HdlcDecoder<4> = HdlcDecoder::new();
        dec.feed(FLAG);
        for i in 0..5u8 {
            dec.feed(i);
        }
        // 5th byte overflows buffer, frame is dropped
        assert!(!dec.feed(FLAG));
        assert!(dec.frame().is_none());
    }
}
