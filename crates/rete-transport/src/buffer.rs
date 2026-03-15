//! Buffer — stream-oriented data transfer over a Channel.
//!
//! A Buffer provides a byte-stream abstraction over the message-oriented
//! Channel. Data is segmented into [`StreamDataMessage`]s with a 2-byte header:
//!
//! ```text
//! [0:2]  flags/stream_id   u16 big-endian
//!        bit 15: EOF
//!        bit 14: compressed
//!        bits 13:0: stream_id
//! [2:]   data              variable
//! ```

extern crate alloc;

use alloc::vec::Vec;

/// A stream data message header + payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamDataMessage {
    /// Stream identifier (14 bits, 0..16383).
    pub stream_id: u16,
    /// Whether this is the last message in the stream.
    pub eof: bool,
    /// Whether the data is compressed.
    pub compressed: bool,
    /// Stream data payload.
    pub data: Vec<u8>,
}

impl StreamDataMessage {
    /// Pack the message into bytes.
    pub fn pack(&self) -> Vec<u8> {
        let mut flags: u16 = self.stream_id & 0x3FFF;
        if self.eof {
            flags |= 0x8000;
        }
        if self.compressed {
            flags |= 0x4000;
        }
        let mut out = Vec::with_capacity(2 + self.data.len());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Unpack a message from bytes.
    pub fn unpack(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        let flags = u16::from_be_bytes([data[0], data[1]]);
        let stream_id = flags & 0x3FFF;
        let eof = flags & 0x8000 != 0;
        let compressed = flags & 0x4000 != 0;
        let payload = data[2..].to_vec();
        Some(StreamDataMessage {
            stream_id,
            eof,
            compressed,
            data: payload,
        })
    }
}

/// A receive buffer for reassembling a byte stream from channel messages.
pub struct StreamBuffer {
    /// Stream ID we're tracking.
    stream_id: u16,
    /// Accumulated data.
    data: Vec<u8>,
    /// Whether EOF has been received.
    eof: bool,
}

impl StreamBuffer {
    /// Create a new buffer for the given stream ID.
    pub fn new(stream_id: u16) -> Self {
        StreamBuffer {
            stream_id,
            data: Vec::new(),
            eof: false,
        }
    }

    /// Feed a stream message into the buffer.
    ///
    /// Returns `true` if the message was accepted (matching stream_id).
    pub fn feed(&mut self, msg: &StreamDataMessage) -> bool {
        if msg.stream_id != self.stream_id {
            return false;
        }
        self.data.extend_from_slice(&msg.data);
        if msg.eof {
            self.eof = true;
        }
        true
    }

    /// Read all accumulated data, clearing the buffer.
    pub fn read(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.data)
    }

    /// Peek at accumulated data without consuming it.
    pub fn peek(&self) -> &[u8] {
        &self.data
    }

    /// Whether EOF has been signalled.
    pub fn is_eof(&self) -> bool {
        self.eof
    }

    /// Number of bytes available.
    pub fn available(&self) -> usize {
        self.data.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_message_pack_unpack() {
        let msg = StreamDataMessage {
            stream_id: 42,
            eof: true,
            compressed: false,
            data: b"stream data".to_vec(),
        };
        let packed = msg.pack();
        let unpacked = StreamDataMessage::unpack(&packed).unwrap();
        assert_eq!(unpacked, msg);
        assert!(unpacked.eof);
        assert!(!unpacked.compressed);
        assert_eq!(unpacked.stream_id, 42);
    }

    #[test]
    fn stream_message_flags() {
        let msg = StreamDataMessage {
            stream_id: 0x1234,
            eof: false,
            compressed: true,
            data: Vec::new(),
        };
        let packed = msg.pack();
        let flags = u16::from_be_bytes([packed[0], packed[1]]);
        assert_eq!(flags & 0x3FFF, 0x1234); // stream_id
        assert_eq!(flags & 0x8000, 0); // not EOF
        assert_ne!(flags & 0x4000, 0); // compressed
    }

    #[test]
    fn buffer_feed_and_read() {
        let mut buf = StreamBuffer::new(1);

        let msg1 = StreamDataMessage {
            stream_id: 1,
            eof: false,
            compressed: false,
            data: b"hello ".to_vec(),
        };
        let msg2 = StreamDataMessage {
            stream_id: 1,
            eof: false,
            compressed: false,
            data: b"world".to_vec(),
        };

        assert!(buf.feed(&msg1));
        assert!(buf.feed(&msg2));
        assert_eq!(buf.available(), 11);

        let data = buf.read();
        assert_eq!(data, b"hello world");
        assert_eq!(buf.available(), 0);
    }

    #[test]
    fn buffer_eof_signalling() {
        let mut buf = StreamBuffer::new(1);
        assert!(!buf.is_eof());

        let msg = StreamDataMessage {
            stream_id: 1,
            eof: true,
            compressed: false,
            data: b"final".to_vec(),
        };
        buf.feed(&msg);
        assert!(buf.is_eof());
    }

    #[test]
    fn stream_id_filtering() {
        let mut buf = StreamBuffer::new(1);

        let wrong = StreamDataMessage {
            stream_id: 2,
            eof: false,
            compressed: false,
            data: b"wrong stream".to_vec(),
        };
        assert!(!buf.feed(&wrong));
        assert_eq!(buf.available(), 0);

        let right = StreamDataMessage {
            stream_id: 1,
            eof: false,
            compressed: false,
            data: b"right stream".to_vec(),
        };
        assert!(buf.feed(&right));
        assert_eq!(buf.available(), 12);
    }
}
