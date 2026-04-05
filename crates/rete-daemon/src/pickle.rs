//! Minimal Python pickle codec (protocol 2 + 4).
//!
//! Only the ~20 opcodes observed in RNS shared-instance RPC traffic are
//! implemented.  This is **not** a general-purpose pickle library.

// ── Pickle opcodes ──────────────────────────────────────────────────────────

const PROTO: u8 = 0x80;
const STOP: u8 = b'.';
const NONE: u8 = b'N';
const NEWTRUE: u8 = 0x88;
const NEWFALSE: u8 = 0x89;
const BININT1: u8 = b'K';
const BININT: u8 = b'J';
const BINFLOAT: u8 = b'G';
const SHORT_BINBYTES: u8 = b'C';
const BINUNICODE: u8 = b'X';
const SHORT_BINUNICODE: u8 = 0x8c;
const EMPTY_LIST: u8 = b']';
const EMPTY_DICT: u8 = b'}';
const APPEND: u8 = b'a';
const SETITEM: u8 = b's';
const SETITEMS: u8 = b'u';
const MARK: u8 = b'(';
const BINPUT: u8 = b'q';
const BINGET: u8 = b'h';
const MEMOIZE: u8 = 0x94;
const FRAME: u8 = 0x95;
const GLOBAL: u8 = b'c';
const TUPLE2: u8 = 0x86;
const REDUCE: u8 = b'R';

// ── Public value type ───────────────────────────────────────────────────────

/// A Python pickle value (subset).
#[derive(Debug, Clone, PartialEq)]
pub enum PickleValue {
    None,
    Bool(bool),
    Int(i64),
    Float(f64),
    Bytes(Vec<u8>),
    String(String),
    List(Vec<PickleValue>),
    Dict(Vec<(PickleValue, PickleValue)>),
}

impl PickleValue {
    /// Get as string reference.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PickleValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as i64.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            PickleValue::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// Get as dict reference.
    pub fn as_dict(&self) -> Option<&[(PickleValue, PickleValue)]> {
        match self {
            PickleValue::Dict(d) => Some(d),
            _ => None,
        }
    }

    /// Look up a string key in a dict.
    pub fn get(&self, key: &str) -> Option<&PickleValue> {
        self.as_dict().and_then(|pairs| {
            pairs
                .iter()
                .find(|(k, _)| k.as_str() == Some(key))
                .map(|(_, v)| v)
        })
    }

    /// Get as byte slice reference.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            PickleValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Get as list reference.
    pub fn as_list(&self) -> Option<&[PickleValue]> {
        match self {
            PickleValue::List(l) => Some(l),
            _ => None,
        }
    }
}

// ── Decode error ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum DecodeError {
    UnexpectedEof,
    UnknownOpcode(u8),
    StackUnderflow,
    InvalidUtf8,
    NoResult,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::UnexpectedEof => write!(f, "unexpected end of pickle data"),
            DecodeError::UnknownOpcode(op) => write!(f, "unknown pickle opcode 0x{op:02x}"),
            DecodeError::StackUnderflow => write!(f, "pickle stack underflow"),
            DecodeError::InvalidUtf8 => write!(f, "invalid UTF-8 in pickle string"),
            DecodeError::NoResult => write!(f, "pickle produced no result"),
        }
    }
}

impl std::error::Error for DecodeError {}

// ── Sentinel for MARK ───────────────────────────────────────────────────────

/// Internal stack sentinel; never exposed to callers.
#[derive(Debug, Clone)]
enum StackItem {
    Value(PickleValue),
    Mark,
}

// ── Decoder ─────────────────────────────────────────────────────────────────

/// Decode a pickle byte stream into a [`PickleValue`].
pub fn decode(data: &[u8]) -> Result<PickleValue, DecodeError> {
    let mut pos = 0;
    let mut stack: Vec<StackItem> = Vec::new();
    let mut memo: Vec<Option<PickleValue>> = Vec::new();
    let mut memo_counter: usize = 0;

    loop {
        if pos >= data.len() {
            return Err(DecodeError::UnexpectedEof);
        }
        let op = data[pos];
        pos += 1;

        match op {
            PROTO => {
                // 1-byte protocol version — skip.
                need(data, pos, 1)?;
                pos += 1;
            }

            FRAME => {
                // 8-byte little-endian frame length — skip (we decode all bytes).
                need(data, pos, 8)?;
                pos += 8;
            }

            STOP => {
                return match stack.pop() {
                    Some(StackItem::Value(v)) => Ok(v),
                    _ => Err(DecodeError::NoResult),
                };
            }

            // ── Singletons ──────────────────────────────────────────────
            NONE => stack.push(StackItem::Value(PickleValue::None)),
            NEWTRUE => stack.push(StackItem::Value(PickleValue::Bool(true))),
            NEWFALSE => stack.push(StackItem::Value(PickleValue::Bool(false))),

            // ── Integers ────────────────────────────────────────────────
            BININT1 => {
                need(data, pos, 1)?;
                let v = data[pos] as i64;
                pos += 1;
                stack.push(StackItem::Value(PickleValue::Int(v)));
            }
            BININT => {
                need(data, pos, 4)?;
                let v = i32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                    as i64;
                pos += 4;
                stack.push(StackItem::Value(PickleValue::Int(v)));
            }

            // ── Float ───────────────────────────────────────────────────
            BINFLOAT => {
                need(data, pos, 8)?;
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[pos..pos + 8]);
                let v = f64::from_be_bytes(buf); // pickle floats are big-endian IEEE 754
                pos += 8;
                stack.push(StackItem::Value(PickleValue::Float(v)));
            }

            // ── Bytes ───────────────────────────────────────────────────
            SHORT_BINBYTES => {
                need(data, pos, 1)?;
                let n = data[pos] as usize;
                pos += 1;
                need(data, pos, n)?;
                let v = data[pos..pos + n].to_vec();
                pos += n;
                stack.push(StackItem::Value(PickleValue::Bytes(v)));
            }

            // ── Strings ─────────────────────────────────────────────────
            BINUNICODE => {
                need(data, pos, 4)?;
                let n = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                    as usize;
                pos += 4;
                need(data, pos, n)?;
                let s = std::str::from_utf8(&data[pos..pos + n])
                    .map_err(|_| DecodeError::InvalidUtf8)?
                    .to_owned();
                pos += n;
                stack.push(StackItem::Value(PickleValue::String(s)));
            }
            SHORT_BINUNICODE => {
                need(data, pos, 1)?;
                let n = data[pos] as usize;
                pos += 1;
                need(data, pos, n)?;
                let s = std::str::from_utf8(&data[pos..pos + n])
                    .map_err(|_| DecodeError::InvalidUtf8)?
                    .to_owned();
                pos += n;
                stack.push(StackItem::Value(PickleValue::String(s)));
            }

            // ── Collections ─────────────────────────────────────────────
            EMPTY_LIST => stack.push(StackItem::Value(PickleValue::List(Vec::new()))),
            EMPTY_DICT => stack.push(StackItem::Value(PickleValue::Dict(Vec::new()))),
            MARK => stack.push(StackItem::Mark),

            APPEND => {
                let val = pop_value(&mut stack)?;
                let list = top_value_mut(&mut stack)?;
                match list {
                    PickleValue::List(l) => l.push(val),
                    _ => return Err(DecodeError::StackUnderflow),
                }
            }

            SETITEM => {
                let val = pop_value(&mut stack)?;
                let key = pop_value(&mut stack)?;
                let dict = top_value_mut(&mut stack)?;
                match dict {
                    PickleValue::Dict(d) => d.push((key, val)),
                    _ => return Err(DecodeError::StackUnderflow),
                }
            }

            SETITEMS => {
                // Pop everything down to the most recent MARK.
                let pairs = pop_to_mark(&mut stack)?;
                let dict = top_value_mut(&mut stack)?;
                match dict {
                    PickleValue::Dict(d) => {
                        let mut it = pairs.into_iter();
                        while let (Some(k), Some(v)) = (it.next(), it.next()) {
                            d.push((k, v));
                        }
                    }
                    _ => return Err(DecodeError::StackUnderflow),
                }
            }

            // ── Protocol 2 bytes reconstruction ────────────────────────
            // In proto 2, bytes(b'\x00..') is encoded as:
            //   GLOBAL '_codecs\nencode\n'
            //   BINUNICODE <raw string data>
            //   BINUNICODE 'latin1'
            //   TUPLE2
            //   REDUCE
            // We push a sentinel for GLOBAL, build the tuple, and reduce.
            GLOBAL => {
                // Read two newline-terminated strings: module\nname\n
                let mod_end = data[pos..].iter().position(|&b| b == b'\n')
                    .ok_or(DecodeError::UnexpectedEof)?;
                pos += mod_end + 1; // skip module + newline
                let name_end = data[pos..].iter().position(|&b| b == b'\n')
                    .ok_or(DecodeError::UnexpectedEof)?;
                let _func_name = &data[pos..pos + name_end];
                pos += name_end + 1;
                // Push a sentinel — the REDUCE handler will interpret it.
                stack.push(StackItem::Value(PickleValue::String("__global__".into())));
            }
            TUPLE2 => {
                let b = pop_value(&mut stack)?;
                let a = pop_value(&mut stack)?;
                stack.push(StackItem::Value(PickleValue::List(vec![a, b])));
            }
            REDUCE => {
                let args = pop_value(&mut stack)?;
                let callable = pop_value(&mut stack)?;
                // Recognize _codecs.encode(string, 'latin1') -> bytes
                let result = if callable.as_str() == Some("__global__") {
                    decode_latin1_bytes(&args)
                } else {
                    None
                };
                stack.push(StackItem::Value(result.unwrap_or(PickleValue::None)));
            }

            // ── Memo ────────────────────────────────────────────────────
            BINPUT => {
                need(data, pos, 1)?;
                let idx = data[pos] as usize;
                pos += 1;
                if let Some(StackItem::Value(v)) = stack.last() {
                    memo_set(&mut memo, idx, v.clone());
                }
            }
            BINGET => {
                need(data, pos, 1)?;
                let idx = data[pos] as usize;
                pos += 1;
                let v = memo.get(idx)
                    .and_then(Option::as_ref)
                    .ok_or(DecodeError::StackUnderflow)?
                    .clone();
                stack.push(StackItem::Value(v));
            }
            MEMOIZE => {
                if let Some(StackItem::Value(v)) = stack.last() {
                    memo_set(&mut memo, memo_counter, v.clone());
                    memo_counter += 1;
                }
            }

            _ => return Err(DecodeError::UnknownOpcode(op)),
        }
    }
}

// ── Decoder helpers ─────────────────────────────────────────────────────────

/// Try to decode a `_codecs.encode(string, 'latin1')` REDUCE call as bytes.
fn decode_latin1_bytes(args: &PickleValue) -> Option<PickleValue> {
    let items = args.as_list()?;
    if items.len() != 2 {
        return None;
    }
    let s = items[0].as_str()?;
    Some(PickleValue::Bytes(s.chars().map(|c| c as u8).collect()))
}

fn need(data: &[u8], pos: usize, n: usize) -> Result<(), DecodeError> {
    if pos + n > data.len() {
        Err(DecodeError::UnexpectedEof)
    } else {
        Ok(())
    }
}

fn pop_value(stack: &mut Vec<StackItem>) -> Result<PickleValue, DecodeError> {
    match stack.pop() {
        Some(StackItem::Value(v)) => Ok(v),
        _ => Err(DecodeError::StackUnderflow),
    }
}

fn top_value_mut(stack: &mut [StackItem]) -> Result<&mut PickleValue, DecodeError> {
    match stack.last_mut() {
        Some(StackItem::Value(v)) => Ok(v),
        _ => Err(DecodeError::StackUnderflow),
    }
}

fn memo_set(memo: &mut Vec<Option<PickleValue>>, idx: usize, val: PickleValue) {
    if memo.len() <= idx {
        memo.resize_with(idx + 1, || None);
    }
    memo[idx] = Some(val);
}

fn pop_to_mark(stack: &mut Vec<StackItem>) -> Result<Vec<PickleValue>, DecodeError> {
    let mut items = Vec::new();
    loop {
        match stack.pop() {
            Some(StackItem::Mark) => {
                items.reverse();
                return Ok(items);
            }
            Some(StackItem::Value(v)) => items.push(v),
            None => return Err(DecodeError::StackUnderflow),
        }
    }
}

// ── Encoder ─────────────────────────────────────────────────────────────────

/// Encode a [`PickleValue`] as pickle protocol 4.
pub fn encode(value: &PickleValue) -> Vec<u8> {
    let mut body = Vec::new();
    let mut memo_counter: usize = 0;
    encode_value(value, &mut body, &mut memo_counter, PickleProto::V4);
    body.push(STOP);

    // Protocol 4 wraps in PROTO + FRAME header.
    let mut out = Vec::with_capacity(2 + 9 + body.len());
    out.push(PROTO);
    out.push(4);
    out.push(FRAME);
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Encode a [`PickleValue`] as pickle protocol 2 (simpler, used for requests).
pub fn encode_proto2(value: &PickleValue) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(PROTO);
    out.push(2);

    let mut memo_counter: usize = 0;
    encode_value(value, &mut out, &mut memo_counter, PickleProto::V2);
    out.push(STOP);
    out
}

#[derive(Clone, Copy)]
enum PickleProto { V2, V4 }

fn emit_memo(out: &mut Vec<u8>, memo: &mut usize, proto: PickleProto) {
    match proto {
        PickleProto::V4 => out.push(MEMOIZE),
        PickleProto::V2 => { out.push(BINPUT); out.push(*memo as u8); }
    }
    *memo += 1;
}

fn encode_value(value: &PickleValue, out: &mut Vec<u8>, memo: &mut usize, proto: PickleProto) {
    match value {
        PickleValue::None => out.push(NONE),
        PickleValue::Bool(true) => out.push(NEWTRUE),
        PickleValue::Bool(false) => out.push(NEWFALSE),
        PickleValue::Int(n) => {
            if *n >= 0 && *n <= 255 {
                out.push(BININT1);
                out.push(*n as u8);
            } else {
                out.push(BININT);
                out.extend_from_slice(&(*n as i32).to_le_bytes());
            }
        }
        PickleValue::Float(f) => {
            out.push(BINFLOAT);
            out.extend_from_slice(&f.to_be_bytes());
        }
        PickleValue::Bytes(b) => {
            debug_assert!(b.len() <= 255, "SHORT_BINBYTES limited to 255 bytes");
            out.push(SHORT_BINBYTES);
            out.push(b.len() as u8);
            out.extend_from_slice(b);
        }
        PickleValue::String(s) => {
            match proto {
                PickleProto::V4 => {
                    debug_assert!(s.len() <= 255, "SHORT_BINUNICODE limited to 255 bytes");
                    out.push(SHORT_BINUNICODE);
                    out.push(s.len() as u8);
                }
                PickleProto::V2 => {
                    out.push(BINUNICODE);
                    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
                }
            }
            out.extend_from_slice(s.as_bytes());
        }
        PickleValue::List(items) => {
            out.push(EMPTY_LIST);
            emit_memo(out, memo, proto);
            for item in items {
                encode_value(item, out, memo, proto);
                out.push(APPEND);
            }
        }
        PickleValue::Dict(pairs) => {
            out.push(EMPTY_DICT);
            emit_memo(out, memo, proto);
            match proto {
                PickleProto::V4 if !pairs.is_empty() => {
                    out.push(MARK);
                    for (k, v) in pairs {
                        encode_value(k, out, memo, proto);
                        encode_value(v, out, memo, proto);
                    }
                    out.push(SETITEMS);
                }
                PickleProto::V2 => {
                    for (k, v) in pairs {
                        encode_value(k, out, memo, proto);
                        encode_value(v, out, memo, proto);
                        out.push(SETITEM);
                    }
                }
                _ => {} // V4 with empty pairs — nothing to emit
            }
        }
    }
    // Post-value memoization: V4 memoizes String+Bytes, V2 only String.
    let should_memo = match proto {
        PickleProto::V4 => matches!(value, PickleValue::String(_) | PickleValue::Bytes(_)),
        PickleProto::V2 => matches!(value, PickleValue::String(_)),
    };
    if should_memo {
        emit_memo(out, memo, proto);
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/shared-instance/unix/control-status-query"
    );

    #[test]
    fn decode_golden_request() {
        let data = std::fs::read(format!("{FIXTURE_DIR}/rpc_request.bin")).unwrap();
        assert_eq!(data.len(), 39);

        let val = decode(&data).unwrap();
        let dict = val.as_dict().expect("expected dict");
        assert_eq!(dict.len(), 1);
        assert_eq!(
            dict[0],
            (
                PickleValue::String("get".into()),
                PickleValue::String("interface_stats".into())
            )
        );
    }

    #[test]
    fn decode_golden_response() {
        let data = std::fs::read(format!("{FIXTURE_DIR}/rpc_response.bin")).unwrap();
        assert_eq!(data.len(), 452);

        let val = decode(&data).unwrap();
        let dict = val.as_dict().expect("expected dict");

        // Top-level keys: interfaces, rxb, txb, rxs, txs, rss
        let keys: Vec<&str> = dict.iter().filter_map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["interfaces", "rxb", "txb", "rxs", "txs", "rss"]);

        // interfaces is a list with one entry
        let ifaces = val.get("interfaces").unwrap().as_list().unwrap();
        assert_eq!(ifaces.len(), 1);

        // The single interface has expected keys
        let iface = &ifaces[0];
        assert!(iface.get("name").is_some());
        assert_eq!(
            iface.get("name").unwrap().as_str().unwrap(),
            "Shared Instance[rns/default]"
        );
        assert_eq!(
            iface.get("type").unwrap().as_str().unwrap(),
            "LocalServerInterface"
        );
        assert!(iface.get("hash").is_some());
        assert_eq!(iface.get("clients").unwrap().as_int().unwrap(), 0);
        assert!(matches!(
            iface.get("status").unwrap(),
            PickleValue::Bool(true)
        ));
        assert_eq!(iface.get("mode").unwrap().as_int().unwrap(), 1);

        // Top-level stats
        assert_eq!(val.get("rxb").unwrap().as_int().unwrap(), 0);
        assert_eq!(val.get("txb").unwrap().as_int().unwrap(), 0);
        assert!(matches!(val.get("rss").unwrap(), PickleValue::None));
    }

    #[test]
    fn decode_truncated_input() {
        let data = [0x80, 0x02]; // PROTO only, no STOP
        assert!(matches!(decode(&data), Err(DecodeError::UnexpectedEof)));
    }

    #[test]
    fn decode_unknown_opcode() {
        let data = [0x80, 0x02, 0xFF]; // unknown opcode
        assert!(matches!(
            decode(&data),
            Err(DecodeError::UnknownOpcode(0xFF))
        ));
    }

    #[test]
    fn encode_proto2_golden_request() {
        // Encode {"get": "interface_stats"} as proto 2 and compare to golden fixture.
        let value = PickleValue::Dict(vec![(
            PickleValue::String("get".into()),
            PickleValue::String("interface_stats".into()),
        )]);
        let encoded = encode_proto2(&value);
        let golden = std::fs::read(format!("{FIXTURE_DIR}/rpc_request.bin")).unwrap();
        assert_eq!(
            encoded, golden,
            "proto2 encode must match golden request fixture"
        );
    }

    #[test]
    fn roundtrip_proto4() {
        let value = PickleValue::Dict(vec![
            (PickleValue::String("count".into()), PickleValue::Int(42)),
            (
                PickleValue::String("name".into()),
                PickleValue::String("test".into()),
            ),
            (
                PickleValue::String("active".into()),
                PickleValue::Bool(true),
            ),
            (PickleValue::String("rate".into()), PickleValue::Float(3.14)),
            (
                PickleValue::String("data".into()),
                PickleValue::Bytes(vec![0xDE, 0xAD]),
            ),
            (PickleValue::String("empty".into()), PickleValue::None),
            (
                PickleValue::String("items".into()),
                PickleValue::List(vec![PickleValue::Int(1), PickleValue::Int(2)]),
            ),
        ]);

        let encoded = encode(&value);
        let decoded = decode(&encoded).unwrap();

        // Compare structure (memo indices may differ but values must match).
        let d1 = value.as_dict().unwrap();
        let d2 = decoded.as_dict().unwrap();
        assert_eq!(d1.len(), d2.len());
        for (i, ((k1, v1), (k2, v2))) in d1.iter().zip(d2.iter()).enumerate() {
            assert_eq!(k1, k2, "key mismatch at index {i}");
            assert_eq!(v1, v2, "value mismatch at key {:?}", k1);
        }
    }

    #[test]
    fn roundtrip_golden_response_decode_reencode_decode() {
        // Decode golden response, re-encode as proto4, decode again — structure must match.
        let golden = std::fs::read(format!("{FIXTURE_DIR}/rpc_response.bin")).unwrap();
        let val1 = decode(&golden).unwrap();
        let reencoded = encode(&val1);
        let val2 = decode(&reencoded).unwrap();
        assert_eq!(val1, val2);
    }
}
