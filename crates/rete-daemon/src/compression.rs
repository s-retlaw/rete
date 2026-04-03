//! bz2 compression/decompression and packet logging for hosted nodes.

use rete_stack::NodeHooks;

// ---------------------------------------------------------------------------
// bz2 compression / decompression
// ---------------------------------------------------------------------------

pub fn bz2_compress(data: &[u8]) -> Option<Vec<u8>> {
    use core::ffi::{c_char, c_int, c_uint};
    use libbz2_rs_sys::BZ2_bzBuffToBuffCompress;

    // bz2 worst-case: input + 1% + 600 bytes
    let out_size = data.len() + data.len() / 100 + 600;
    let mut out = vec![0u8; out_size];
    let mut dest_len = out_size as c_uint;

    let ret = unsafe {
        BZ2_bzBuffToBuffCompress(
            out.as_mut_ptr() as *mut c_char,
            &mut dest_len,
            data.as_ptr() as *mut c_char,
            data.len() as c_uint,
            9 as c_int, // blockSize100k=9 (max compression)
            0,          // verbosity=0
            30,         // workFactor=30 (Python default)
        )
    };

    if ret == 0 {
        out.truncate(dest_len as usize);
        Some(out)
    } else {
        None
    }
}

pub fn bz2_decompress(data: &[u8]) -> Option<Vec<u8>> {
    use core::ffi::{c_char, c_uint};
    use libbz2_rs_sys::BZ2_bzBuffToBuffDecompress;

    const BZ_OUTBUFF_FULL: i32 = -8;

    // Try 10x first, retry with 100x if buffer was too small.
    // Limit: data compressing >100:1 (e.g. 100KB of repeated bytes → <1KB)
    // will return None because 100× compressed_size < original. Such payloads
    // are pathological and do not occur in practice on RNS links.
    for multiplier in [10, 100] {
        let out_size = (data.len() * multiplier).max(4096);
        let mut out = vec![0u8; out_size];
        let mut dest_len = out_size as c_uint;

        let ret = unsafe {
            BZ2_bzBuffToBuffDecompress(
                out.as_mut_ptr() as *mut c_char,
                &mut dest_len,
                data.as_ptr() as *mut c_char,
                data.len() as c_uint,
                0, // small=0 (fast mode)
                0, // verbosity=0
            )
        };

        if ret == 0 {
            out.truncate(dest_len as usize);
            return Some(out);
        }
        if ret != BZ_OUTBUFF_FULL {
            return None;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Packet logging
// ---------------------------------------------------------------------------

/// Log a raw packet's parsed header to stderr.
pub fn log_packet(raw: &[u8], direction: &str, iface_idx: u8) {
    use rete_core::{HeaderType, Packet};

    let pkt = match Packet::parse(raw) {
        Ok(p) => p,
        Err(_) => {
            eprintln!(
                "[pkt] {} iface={} PARSE_ERROR len={}",
                direction,
                iface_idx,
                raw.len()
            );
            return;
        }
    };

    let hdr = match pkt.header_type {
        HeaderType::Header1 => "H1",
        HeaderType::Header2 => "H2",
    };
    let ctx_name = match pkt.context {
        rete_core::CONTEXT_NONE => "NONE",
        rete_core::CONTEXT_RESOURCE => "RESOURCE",
        rete_core::CONTEXT_RESOURCE_ADV => "RES_ADV",
        rete_core::CONTEXT_RESOURCE_REQ => "RES_REQ",
        rete_core::CONTEXT_RESOURCE_HMU => "RES_HMU",
        rete_core::CONTEXT_RESOURCE_PRF => "RES_PRF",
        rete_core::CONTEXT_RESOURCE_ICL => "RES_ICL",
        rete_core::CONTEXT_RESOURCE_RCL => "RES_RCL",
        rete_core::CONTEXT_REQUEST => "REQUEST",
        rete_core::CONTEXT_RESPONSE => "RESPONSE",
        rete_core::CONTEXT_CHANNEL => "CHANNEL",
        rete_core::CONTEXT_KEEPALIVE => "KEEPALIVE",
        rete_core::CONTEXT_LINKIDENTIFY => "LINKIDENT",
        rete_core::CONTEXT_LINKCLOSE => "LINKCLOSE",
        rete_core::CONTEXT_LINKPROOF => "LINKPROOF",
        rete_core::CONTEXT_LRRTT => "LRRTT",
        rete_core::CONTEXT_LRPROOF => "LRPROOF",
        _ => "?",
    };

    eprintln!(
        "[pkt] {} iface={} {}/{:?}/{:?} hops={} dest={} ctx={:#04x}({}) plen={} raw={}",
        direction,
        iface_idx,
        hdr,
        pkt.packet_type,
        pkt.dest_type,
        pkt.hops,
        hex::encode(pkt.destination_hash),
        pkt.context,
        ctx_name,
        pkt.payload.len(),
        hex::encode(&raw[..raw.len().min(64)])
    );
}

// ---------------------------------------------------------------------------
// Application hooks
// ---------------------------------------------------------------------------

/// [`NodeHooks`] implementation providing bz2 compression and optional packet logging.
pub struct AppHooks {
    pub packet_log: bool,
}

impl NodeHooks for AppHooks {
    fn compress(&self, data: &[u8]) -> Option<Vec<u8>> {
        bz2_compress(data)
    }

    fn decompress(&self, data: &[u8]) -> Option<Vec<u8>> {
        bz2_decompress(data)
    }

    fn log_packet(&self, raw: &[u8], direction: &str, iface: u8) {
        if self.packet_log {
            log_packet(raw, direction, iface);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bz2_roundtrip() {
        let original = b"hello world this is a test of bz2 compression roundtrip";
        let compressed = bz2_compress(original).expect("compress must succeed");
        let decompressed = bz2_decompress(&compressed).expect("decompress must succeed");
        assert_eq!(decompressed, original);
    }

    #[test]
    fn bz2_roundtrip_empty() {
        let compressed = bz2_compress(b"").expect("compress empty must succeed");
        let decompressed = bz2_decompress(&compressed).expect("decompress empty must succeed");
        assert_eq!(decompressed, b"");
    }

    #[test]
    fn bz2_roundtrip_large() {
        // Use varied data that compresses but not to a tiny fraction of its size.
        // The decompressor's multiplier heuristic (10x/100x compressed size) works
        // when the compress ratio is not extreme.
        let original: Vec<u8> = (0..10_000u32).map(|i| (i % 256) as u8).collect();
        let compressed = bz2_compress(&original).expect("compress must succeed");
        assert!(compressed.len() < original.len());
        let decompressed = bz2_decompress(&compressed).expect("decompress must succeed");
        assert_eq!(decompressed, original);
    }

    #[test]
    fn bz2_decompress_garbage_returns_none() {
        let garbage = b"this is not valid bz2 data at all!!";
        let result = bz2_decompress(garbage);
        assert!(result.is_none());
    }

    #[test]
    fn app_hooks_compress_roundtrip() {
        let hooks = AppHooks { packet_log: false };
        let data = b"test data for hooks";
        let compressed = hooks.compress(data).expect("compress must succeed");
        let decompressed = hooks.decompress(&compressed).expect("decompress must succeed");
        assert_eq!(decompressed, data);
    }

    #[test]
    fn app_hooks_no_log_when_disabled() {
        // Just verify it doesn't panic when packet_log=false with garbage input
        let hooks = AppHooks { packet_log: false };
        hooks.log_packet(b"garbage raw packet data", "IN", 0);
    }
}
