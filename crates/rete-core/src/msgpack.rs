//! Msgpack primitive codec — shared building blocks for wire format encoding.
//!
//! Read functions work in `no_std` without `alloc`. Write functions require
//! the `alloc` feature because they append to `Vec<u8>`.

/// Errors from msgpack decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgpackError {
    /// Input data is truncated or too short.
    Truncated,
    /// Expected an array header, found something else.
    ExpectedArray,
    /// Expected a map header, found something else.
    ExpectedMap,
    /// Expected a bin header, found something else.
    ExpectedBin,
    /// Expected a str header, found something else.
    ExpectedStr,
    /// Expected a uint (or compatible integer), found something else.
    ExpectedUint,
    /// Expected a float64 (or float32), found something else.
    ExpectedFloat,
    /// Unsupported msgpack type encountered during skip.
    UnsupportedType,
}

impl MsgpackError {
    /// Convert to a static string for backward compatibility with `&'static str` error callers.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Truncated => "unexpected end of msgpack data",
            Self::ExpectedArray => "expected msgpack array",
            Self::ExpectedMap => "expected msgpack map",
            Self::ExpectedBin => "expected msgpack bin",
            Self::ExpectedStr => "expected msgpack str",
            Self::ExpectedUint => "expected msgpack uint",
            Self::ExpectedFloat => "expected msgpack float",
            Self::UnsupportedType => "unsupported msgpack type",
        }
    }
}

impl core::fmt::Display for MsgpackError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Read functions (no alloc required)
// ---------------------------------------------------------------------------

/// Read a msgpack array length. Supports fixarray, array16, and array32.
pub fn read_array_len(data: &[u8], pos: &mut usize) -> Result<usize, MsgpackError> {
    if *pos >= data.len() {
        return Err(MsgpackError::Truncated);
    }
    let b = data[*pos];
    *pos += 1;
    if b & 0xf0 == 0x90 {
        // fixarray
        Ok((b & 0x0f) as usize)
    } else if b == 0xdc {
        // array16
        if *pos + 2 > data.len() {
            return Err(MsgpackError::Truncated);
        }
        let n = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        Ok(n as usize)
    } else if b == 0xdd {
        // array32
        if *pos + 4 > data.len() {
            return Err(MsgpackError::Truncated);
        }
        let n = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
        *pos += 4;
        Ok(n as usize)
    } else {
        Err(MsgpackError::ExpectedArray)
    }
}

/// Read a msgpack map length. Supports fixmap, map16, and map32.
pub fn read_map_len(data: &[u8], pos: &mut usize) -> Result<usize, MsgpackError> {
    if *pos >= data.len() {
        return Err(MsgpackError::Truncated);
    }
    let b = data[*pos];
    *pos += 1;
    if b & 0xf0 == 0x80 {
        // fixmap
        Ok((b & 0x0f) as usize)
    } else if b == 0xde {
        // map16
        if *pos + 2 > data.len() {
            return Err(MsgpackError::Truncated);
        }
        let n = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        Ok(n as usize)
    } else if b == 0xdf {
        // map32
        if *pos + 4 > data.len() {
            return Err(MsgpackError::Truncated);
        }
        let n = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
        *pos += 4;
        Ok(n as usize)
    } else {
        Err(MsgpackError::ExpectedMap)
    }
}

/// Read a msgpack bin value (zero-copy). Supports bin8, bin16, and bin32.
pub fn read_bin<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], MsgpackError> {
    if *pos >= data.len() {
        return Err(MsgpackError::Truncated);
    }
    let b = data[*pos];
    *pos += 1;
    let len = match b {
        0xc4 => {
            // bin8
            if *pos >= data.len() {
                return Err(MsgpackError::Truncated);
            }
            let n = data[*pos] as usize;
            *pos += 1;
            n
        }
        0xc5 => {
            // bin16
            if *pos + 2 > data.len() {
                return Err(MsgpackError::Truncated);
            }
            let n = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            n
        }
        0xc6 => {
            // bin32
            if *pos + 4 > data.len() {
                return Err(MsgpackError::Truncated);
            }
            let n = u32::from_be_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
            ]) as usize;
            *pos += 4;
            n
        }
        _ => return Err(MsgpackError::ExpectedBin),
    };
    if *pos + len > data.len() {
        return Err(MsgpackError::Truncated);
    }
    let result = &data[*pos..*pos + len];
    *pos += len;
    Ok(result)
}

/// Read a msgpack string value (zero-copy). Supports fixstr, str8, str16, and str32.
pub fn read_str<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], MsgpackError> {
    if *pos >= data.len() {
        return Err(MsgpackError::Truncated);
    }
    let b = data[*pos];
    *pos += 1;
    let len = if b & 0xe0 == 0xa0 {
        // fixstr
        (b & 0x1f) as usize
    } else if b == 0xd9 {
        // str8
        if *pos >= data.len() {
            return Err(MsgpackError::Truncated);
        }
        let n = data[*pos] as usize;
        *pos += 1;
        n
    } else if b == 0xda {
        // str16
        if *pos + 2 > data.len() {
            return Err(MsgpackError::Truncated);
        }
        let n = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
        *pos += 2;
        n
    } else if b == 0xdb {
        // str32
        if *pos + 4 > data.len() {
            return Err(MsgpackError::Truncated);
        }
        let n = u32::from_be_bytes([
            data[*pos],
            data[*pos + 1],
            data[*pos + 2],
            data[*pos + 3],
        ]) as usize;
        *pos += 4;
        n
    } else {
        return Err(MsgpackError::ExpectedStr);
    };
    if *pos + len > data.len() {
        return Err(MsgpackError::Truncated);
    }
    let result = &data[*pos..*pos + len];
    *pos += len;
    Ok(result)
}

/// Read a msgpack bin or str value (zero-copy). Python msgpack sometimes encodes
/// bytes as either bin or str depending on version/settings.
pub fn read_bin_or_str<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], MsgpackError> {
    if *pos >= data.len() {
        return Err(MsgpackError::Truncated);
    }
    let b = data[*pos];
    if (b & 0xe0 == 0xa0) || b == 0xd9 || b == 0xda || b == 0xdb {
        read_str(data, pos)
    } else {
        read_bin(data, pos)
    }
}

/// Read a msgpack unsigned integer.
///
/// Also accepts booleans (false→0, true→1) and signed integers (as unsigned)
/// for compatibility with Python msgpack encoding variants.
pub fn read_uint(data: &[u8], pos: &mut usize) -> Result<u64, MsgpackError> {
    if *pos >= data.len() {
        return Err(MsgpackError::Truncated);
    }
    let b = data[*pos];
    *pos += 1;
    match b {
        // positive fixint
        0x00..=0x7f => Ok(b as u64),
        // false → 0
        0xc2 => Ok(0),
        // true → 1
        0xc3 => Ok(1),
        // uint8
        0xcc => {
            if *pos >= data.len() {
                return Err(MsgpackError::Truncated);
            }
            let v = data[*pos] as u64;
            *pos += 1;
            Ok(v)
        }
        // uint16
        0xcd => {
            if *pos + 2 > data.len() {
                return Err(MsgpackError::Truncated);
            }
            let v = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as u64;
            *pos += 2;
            Ok(v)
        }
        // uint32
        0xce => {
            if *pos + 4 > data.len() {
                return Err(MsgpackError::Truncated);
            }
            let v = u32::from_be_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
            ]) as u64;
            *pos += 4;
            Ok(v)
        }
        // uint64
        0xcf => {
            if *pos + 8 > data.len() {
                return Err(MsgpackError::Truncated);
            }
            let v = u64::from_be_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
                data[*pos + 4],
                data[*pos + 5],
                data[*pos + 6],
                data[*pos + 7],
            ]);
            *pos += 8;
            Ok(v)
        }
        // int8
        0xd0 => {
            if *pos >= data.len() {
                return Err(MsgpackError::Truncated);
            }
            let v = data[*pos] as i8;
            *pos += 1;
            Ok(v as u64)
        }
        // int16
        0xd1 => {
            if *pos + 2 > data.len() {
                return Err(MsgpackError::Truncated);
            }
            let v = i16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Ok(v as u64)
        }
        // int32
        0xd2 => {
            if *pos + 4 > data.len() {
                return Err(MsgpackError::Truncated);
            }
            let v = i32::from_be_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
            ]);
            *pos += 4;
            Ok(v as u64)
        }
        // int64
        0xd3 => {
            if *pos + 8 > data.len() {
                return Err(MsgpackError::Truncated);
            }
            let v = i64::from_be_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
                data[*pos + 4],
                data[*pos + 5],
                data[*pos + 6],
                data[*pos + 7],
            ]);
            *pos += 8;
            Ok(v as u64)
        }
        // negative fixint (-32 to -1)
        0xe0..=0xff => Ok(b as i8 as u64),
        _ => Err(MsgpackError::ExpectedUint),
    }
}

/// Read a msgpack float64 value. Also accepts float32 (promoted to f64) and
/// integer types (cast to f64) for compatibility with Python msgpack timestamps.
pub fn read_float64(data: &[u8], pos: &mut usize) -> Result<f64, MsgpackError> {
    if *pos >= data.len() {
        return Err(MsgpackError::Truncated);
    }
    let b = data[*pos];
    *pos += 1;
    if b == 0xcb {
        // float64
        if *pos + 8 > data.len() {
            return Err(MsgpackError::Truncated);
        }
        let bytes = [
            data[*pos],
            data[*pos + 1],
            data[*pos + 2],
            data[*pos + 3],
            data[*pos + 4],
            data[*pos + 5],
            data[*pos + 6],
            data[*pos + 7],
        ];
        *pos += 8;
        Ok(f64::from_be_bytes(bytes))
    } else if b == 0xca {
        // float32
        if *pos + 4 > data.len() {
            return Err(MsgpackError::Truncated);
        }
        let bytes = [data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]];
        *pos += 4;
        Ok(f32::from_be_bytes(bytes) as f64)
    } else {
        // Fall back to reading an integer (Python sometimes encodes timestamps as int)
        *pos -= 1;
        let v = read_uint(data, pos).map_err(|_| MsgpackError::ExpectedFloat)?;
        Ok(v as f64)
    }
}

/// Read a msgpack unsigned integer or nil. Returns `None` for nil, `Some(v)` for uint.
pub fn read_uint_or_nil(data: &[u8], pos: &mut usize) -> Result<Option<u64>, MsgpackError> {
    if *pos >= data.len() {
        return Err(MsgpackError::Truncated);
    }
    if data[*pos] == 0xc0 {
        *pos += 1;
        Ok(None)
    } else {
        read_uint(data, pos).map(Some)
    }
}

/// Read a msgpack bin/str or nil. Returns `None` for nil, `Some(bytes)` otherwise.
pub fn read_bin_or_nil<'a>(
    data: &'a [u8],
    pos: &mut usize,
) -> Result<Option<&'a [u8]>, MsgpackError> {
    if *pos >= data.len() {
        return Err(MsgpackError::Truncated);
    }
    if data[*pos] == 0xc0 {
        *pos += 1;
        Ok(None)
    } else {
        read_bin_or_str(data, pos).map(Some)
    }
}

/// Skip a single msgpack value at `pos`. Advances `pos` past it.
pub fn skip_value(data: &[u8], pos: &mut usize) -> Result<(), MsgpackError> {
    if *pos >= data.len() {
        return Err(MsgpackError::Truncated);
    }
    let b = data[*pos];
    match b {
        // nil, false, true
        0xc0 | 0xc2 | 0xc3 => {
            *pos += 1;
        }
        // positive fixint
        0x00..=0x7f => {
            *pos += 1;
        }
        // negative fixint
        0xe0..=0xff => {
            *pos += 1;
        }
        // fixstr
        b if b & 0xe0 == 0xa0 => {
            let _ = read_str(data, pos)?;
        }
        // fixmap
        b if b & 0xf0 == 0x80 => {
            let n = (b & 0x0f) as usize;
            *pos += 1;
            for _ in 0..n {
                skip_value(data, pos)?;
                skip_value(data, pos)?;
            }
        }
        // fixarray
        b if b & 0xf0 == 0x90 => {
            let n = (b & 0x0f) as usize;
            *pos += 1;
            for _ in 0..n {
                skip_value(data, pos)?;
            }
        }
        // bin8, bin16, bin32
        0xc4 | 0xc5 | 0xc6 => {
            let _ = read_bin(data, pos)?;
        }
        // float32
        0xca => {
            *pos += 5;
        }
        // float64
        0xcb => {
            *pos += 9;
        }
        // uint8
        0xcc => {
            *pos += 2;
        }
        // uint16
        0xcd => {
            *pos += 3;
        }
        // uint32
        0xce => {
            *pos += 5;
        }
        // uint64
        0xcf => {
            *pos += 9;
        }
        // int8
        0xd0 => {
            *pos += 2;
        }
        // int16
        0xd1 => {
            *pos += 3;
        }
        // int32
        0xd2 => {
            *pos += 5;
        }
        // int64
        0xd3 => {
            *pos += 9;
        }
        // str8, str16, str32
        0xd9 | 0xda | 0xdb => {
            let _ = read_str(data, pos)?;
        }
        // array16, array32
        0xdc | 0xdd => {
            let n = read_array_len(data, pos)?;
            for _ in 0..n {
                skip_value(data, pos)?;
            }
        }
        // map16, map32
        0xde | 0xdf => {
            let n = read_map_len(data, pos)?;
            for _ in 0..n {
                skip_value(data, pos)?;
                skip_value(data, pos)?;
            }
        }
        _ => return Err(MsgpackError::UnsupportedType),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Write functions (require alloc)
// ---------------------------------------------------------------------------

#[cfg(feature = "alloc")]
extern crate alloc;

/// Write a msgpack bin value (bin8/bin16/bin32 header + data).
#[cfg(feature = "alloc")]
pub fn write_bin(buf: &mut alloc::vec::Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len < 256 {
        buf.push(0xc4); // bin8
        buf.push(len as u8);
    } else if len < 65536 {
        buf.push(0xc5); // bin16
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xc6); // bin32
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
    buf.extend_from_slice(data);
}

/// Write a msgpack unsigned integer (fixint/uint8/uint16/uint32/uint64).
#[cfg(feature = "alloc")]
pub fn write_uint(buf: &mut alloc::vec::Vec<u8>, val: u64) {
    if val < 128 {
        buf.push(val as u8); // positive fixint
    } else if val < 256 {
        buf.push(0xcc);
        buf.push(val as u8);
    } else if val < 65536 {
        buf.push(0xcd);
        buf.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val < 0x1_0000_0000 {
        buf.push(0xce);
        buf.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        buf.push(0xcf);
        buf.extend_from_slice(&val.to_be_bytes());
    }
}

/// Write a msgpack nil value.
#[cfg(feature = "alloc")]
pub fn write_nil(buf: &mut alloc::vec::Vec<u8>) {
    buf.push(0xc0);
}

/// Write a msgpack fixmap header for `n` entries (n must be < 16).
#[cfg(feature = "alloc")]
pub fn write_fixmap(buf: &mut alloc::vec::Vec<u8>, n: u8) {
    debug_assert!(n < 16);
    buf.push(0x80 | n);
}

/// Write a msgpack fixstr of length 1 (single ASCII character key).
#[cfg(feature = "alloc")]
pub fn write_fixstr1(buf: &mut alloc::vec::Vec<u8>, ch: u8) {
    buf.push(0xa1); // fixstr of length 1
    buf.push(ch);
}

/// Write a msgpack fixarray header for `n` elements (n must be < 16).
#[cfg(feature = "alloc")]
pub fn write_fixarray(buf: &mut alloc::vec::Vec<u8>, n: u8) {
    debug_assert!(n < 16);
    buf.push(0x90 | n);
}

/// Write a msgpack array header (fixarray/array16/array32).
#[cfg(feature = "alloc")]
pub fn write_array_header(buf: &mut alloc::vec::Vec<u8>, len: usize) {
    if len <= 15 {
        buf.push(0x90 | len as u8);
    } else if len <= 0xFFFF {
        buf.push(0xdc);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xdd);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

/// Write a msgpack map header (fixmap/map16/map32).
#[cfg(feature = "alloc")]
pub fn write_map_header(buf: &mut alloc::vec::Vec<u8>, len: usize) {
    if len <= 15 {
        buf.push(0x80 | len as u8);
    } else if len <= 0xFFFF {
        buf.push(0xde);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0xdf);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

/// Write a msgpack float64 value.
#[cfg(feature = "alloc")]
pub fn write_float64(buf: &mut alloc::vec::Vec<u8>, val: f64) {
    buf.push(0xcb);
    buf.extend_from_slice(&val.to_be_bytes());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    // --- read_array_len ---

    #[test]
    fn test_read_array_len_fixarray() {
        let data = [0x93]; // fixarray(3)
        let mut pos = 0;
        assert_eq!(read_array_len(&data, &mut pos).unwrap(), 3);
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_read_array_len_array16() {
        let data = [0xdc, 0x01, 0x00]; // array16(256)
        let mut pos = 0;
        assert_eq!(read_array_len(&data, &mut pos).unwrap(), 256);
        assert_eq!(pos, 3);
    }

    #[test]
    fn test_read_array_len_array32() {
        let data = [0xdd, 0x00, 0x01, 0x00, 0x00]; // array32(65536)
        let mut pos = 0;
        assert_eq!(read_array_len(&data, &mut pos).unwrap(), 65536);
        assert_eq!(pos, 5);
    }

    #[test]
    fn test_read_array_len_error() {
        let data = [0xc0]; // nil, not array
        let mut pos = 0;
        assert_eq!(read_array_len(&data, &mut pos), Err(MsgpackError::ExpectedArray));
    }

    // --- read_map_len ---

    #[test]
    fn test_read_map_len_fixmap() {
        let data = [0x82]; // fixmap(2)
        let mut pos = 0;
        assert_eq!(read_map_len(&data, &mut pos).unwrap(), 2);
    }

    #[test]
    fn test_read_map_len_map16() {
        let data = [0xde, 0x00, 0x20]; // map16(32)
        let mut pos = 0;
        assert_eq!(read_map_len(&data, &mut pos).unwrap(), 32);
    }

    #[test]
    fn test_read_map_len_map32() {
        let data = [0xdf, 0x00, 0x01, 0x00, 0x00]; // map32(65536)
        let mut pos = 0;
        assert_eq!(read_map_len(&data, &mut pos).unwrap(), 65536);
    }

    // --- read_bin ---

    #[test]
    fn test_read_bin8() {
        let data = [0xc4, 0x03, 0x01, 0x02, 0x03]; // bin8(3)
        let mut pos = 0;
        assert_eq!(read_bin(&data, &mut pos).unwrap(), &[1, 2, 3]);
        assert_eq!(pos, 5);
    }

    #[test]
    fn test_read_bin_not_str() {
        let data = [0xa3, 0x41, 0x42, 0x43]; // fixstr("ABC")
        let mut pos = 0;
        assert_eq!(read_bin(&data, &mut pos), Err(MsgpackError::ExpectedBin));
    }

    // --- read_str ---

    #[test]
    fn test_read_str_fixstr() {
        let data = [0xa3, 0x41, 0x42, 0x43]; // fixstr("ABC")
        let mut pos = 0;
        assert_eq!(read_str(&data, &mut pos).unwrap(), b"ABC");
        assert_eq!(pos, 4);
    }

    #[test]
    fn test_read_str_not_bin() {
        let data = [0xc4, 0x01, 0x41]; // bin8
        let mut pos = 0;
        assert_eq!(read_str(&data, &mut pos), Err(MsgpackError::ExpectedStr));
    }

    // --- read_bin_or_str ---

    #[test]
    fn test_read_bin_or_str_bin() {
        let data = [0xc4, 0x02, 0xAA, 0xBB]; // bin8(2)
        let mut pos = 0;
        assert_eq!(read_bin_or_str(&data, &mut pos).unwrap(), &[0xAA, 0xBB]);
    }

    #[test]
    fn test_read_bin_or_str_str() {
        let data = [0xa2, 0x41, 0x42]; // fixstr("AB")
        let mut pos = 0;
        assert_eq!(read_bin_or_str(&data, &mut pos).unwrap(), b"AB");
    }

    // --- read_uint ---

    #[test]
    fn test_read_uint_fixint() {
        let data = [42];
        let mut pos = 0;
        assert_eq!(read_uint(&data, &mut pos).unwrap(), 42);
    }

    #[test]
    fn test_read_uint_uint8() {
        let data = [0xcc, 200];
        let mut pos = 0;
        assert_eq!(read_uint(&data, &mut pos).unwrap(), 200);
    }

    #[test]
    fn test_read_uint_uint16() {
        let data = [0xcd, 0x01, 0x00];
        let mut pos = 0;
        assert_eq!(read_uint(&data, &mut pos).unwrap(), 256);
    }

    #[test]
    fn test_read_uint_uint32() {
        let data = [0xce, 0x00, 0x01, 0x00, 0x00];
        let mut pos = 0;
        assert_eq!(read_uint(&data, &mut pos).unwrap(), 65536);
    }

    #[test]
    fn test_read_uint_uint64() {
        let data = [0xcf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let mut pos = 0;
        assert_eq!(read_uint(&data, &mut pos).unwrap(), 0x1_0000_0000);
    }

    #[test]
    fn test_read_uint_bool_false() {
        let data = [0xc2];
        let mut pos = 0;
        assert_eq!(read_uint(&data, &mut pos).unwrap(), 0);
    }

    #[test]
    fn test_read_uint_bool_true() {
        let data = [0xc3];
        let mut pos = 0;
        assert_eq!(read_uint(&data, &mut pos).unwrap(), 1);
    }

    #[test]
    fn test_read_uint_int8() {
        let data = [0xd0, 0x05];
        let mut pos = 0;
        assert_eq!(read_uint(&data, &mut pos).unwrap(), 5);
    }

    #[test]
    fn test_read_uint_negative_fixint() {
        let data = [0xff]; // -1
        let mut pos = 0;
        // -1 as i8 cast to u64 wraps
        assert_eq!(read_uint(&data, &mut pos).unwrap(), u64::MAX);
    }

    // --- read_float64 ---

    #[test]
    fn test_read_float64() {
        let mut data = vec![0xcb];
        data.extend_from_slice(&1.5f64.to_be_bytes());
        let mut pos = 0;
        assert_eq!(read_float64(&data, &mut pos).unwrap(), 1.5);
    }

    #[test]
    fn test_read_float32() {
        let mut data = vec![0xca];
        data.extend_from_slice(&2.5f32.to_be_bytes());
        let mut pos = 0;
        let v = read_float64(&data, &mut pos).unwrap();
        assert!((v - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_read_float64_uint_fallback() {
        let data = [42]; // positive fixint
        let mut pos = 0;
        assert_eq!(read_float64(&data, &mut pos).unwrap(), 42.0);
    }

    // --- read_uint_or_nil ---

    #[test]
    fn test_read_uint_or_nil_some() {
        let data = [42];
        let mut pos = 0;
        assert_eq!(read_uint_or_nil(&data, &mut pos).unwrap(), Some(42));
    }

    #[test]
    fn test_read_uint_or_nil_none() {
        let data = [0xc0]; // nil
        let mut pos = 0;
        assert_eq!(read_uint_or_nil(&data, &mut pos).unwrap(), None);
    }

    // --- read_bin_or_nil ---

    #[test]
    fn test_read_bin_or_nil_some() {
        let data = [0xc4, 0x01, 0x42]; // bin8(1)
        let mut pos = 0;
        assert_eq!(read_bin_or_nil(&data, &mut pos).unwrap(), Some(&[0x42][..]));
    }

    #[test]
    fn test_read_bin_or_nil_none() {
        let data = [0xc0]; // nil
        let mut pos = 0;
        assert_eq!(read_bin_or_nil(&data, &mut pos).unwrap(), None);
    }

    // --- skip_value ---

    #[test]
    fn test_skip_nil() {
        let data = [0xc0, 0x42];
        let mut pos = 0;
        skip_value(&data, &mut pos).unwrap();
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_skip_fixint() {
        let data = [0x05, 0x42];
        let mut pos = 0;
        skip_value(&data, &mut pos).unwrap();
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_skip_bin8() {
        let data = [0xc4, 0x02, 0xAA, 0xBB, 0x42];
        let mut pos = 0;
        skip_value(&data, &mut pos).unwrap();
        assert_eq!(pos, 4);
    }

    #[test]
    fn test_skip_fixstr() {
        let data = [0xa2, 0x41, 0x42, 0xFF];
        let mut pos = 0;
        skip_value(&data, &mut pos).unwrap();
        assert_eq!(pos, 3);
    }

    #[test]
    fn test_skip_fixmap() {
        // fixmap(1) { fixint(1): fixint(2) }
        let data = [0x81, 0x01, 0x02, 0xFF];
        let mut pos = 0;
        skip_value(&data, &mut pos).unwrap();
        assert_eq!(pos, 3);
    }

    #[test]
    fn test_skip_fixarray() {
        // fixarray(2) [ fixint(1), fixint(2) ]
        let data = [0x92, 0x01, 0x02, 0xFF];
        let mut pos = 0;
        skip_value(&data, &mut pos).unwrap();
        assert_eq!(pos, 3);
    }

    #[test]
    fn test_skip_float64() {
        let mut data = vec![0xcb];
        data.extend_from_slice(&1.0f64.to_be_bytes());
        data.push(0xFF);
        let mut pos = 0;
        skip_value(&data, &mut pos).unwrap();
        assert_eq!(pos, 9);
    }

    // --- write_bin ---

    #[test]
    fn test_write_bin_small() {
        let mut buf = Vec::new();
        write_bin(&mut buf, &[1, 2, 3]);
        assert_eq!(buf, vec![0xc4, 0x03, 1, 2, 3]);
    }

    #[test]
    fn test_write_bin_medium() {
        let data = vec![0u8; 300];
        let mut buf = Vec::new();
        write_bin(&mut buf, &data);
        assert_eq!(buf[0], 0xc5); // bin16
        assert_eq!(u16::from_be_bytes([buf[1], buf[2]]), 300);
        assert_eq!(buf.len(), 3 + 300);
    }

    // --- write_uint ---

    #[test]
    fn test_write_uint_fixint() {
        let mut buf = Vec::new();
        write_uint(&mut buf, 42);
        assert_eq!(buf, vec![42]);
    }

    #[test]
    fn test_write_uint_uint8() {
        let mut buf = Vec::new();
        write_uint(&mut buf, 200);
        assert_eq!(buf, vec![0xcc, 200]);
    }

    #[test]
    fn test_write_uint_uint16() {
        let mut buf = Vec::new();
        write_uint(&mut buf, 256);
        assert_eq!(buf, vec![0xcd, 0x01, 0x00]);
    }

    #[test]
    fn test_write_uint_uint32() {
        let mut buf = Vec::new();
        write_uint(&mut buf, 70000);
        assert_eq!(buf[0], 0xce);
        assert_eq!(
            u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]),
            70000
        );
    }

    #[test]
    fn test_write_uint_uint64() {
        let mut buf = Vec::new();
        write_uint(&mut buf, 0x1_0000_0000);
        assert_eq!(buf[0], 0xcf);
        assert_eq!(buf.len(), 9);
    }

    // --- write_nil ---

    #[test]
    fn test_write_nil() {
        let mut buf = Vec::new();
        write_nil(&mut buf);
        assert_eq!(buf, vec![0xc0]);
    }

    // --- write_fixmap ---

    #[test]
    fn test_write_fixmap() {
        let mut buf = Vec::new();
        write_fixmap(&mut buf, 3);
        assert_eq!(buf, vec![0x83]);
    }

    // --- write_fixstr1 ---

    #[test]
    fn test_write_fixstr1() {
        let mut buf = Vec::new();
        write_fixstr1(&mut buf, b't');
        assert_eq!(buf, vec![0xa1, b't']);
    }

    // --- write_fixarray ---

    #[test]
    fn test_write_fixarray() {
        let mut buf = Vec::new();
        write_fixarray(&mut buf, 4);
        assert_eq!(buf, vec![0x94]);
    }

    // --- write_array_header ---

    #[test]
    fn test_write_array_header_fix() {
        let mut buf = Vec::new();
        write_array_header(&mut buf, 5);
        assert_eq!(buf, vec![0x95]);
    }

    #[test]
    fn test_write_array_header_16() {
        let mut buf = Vec::new();
        write_array_header(&mut buf, 300);
        assert_eq!(buf[0], 0xdc);
        assert_eq!(u16::from_be_bytes([buf[1], buf[2]]), 300);
    }

    #[test]
    fn test_write_array_header_32() {
        let mut buf = Vec::new();
        write_array_header(&mut buf, 70000);
        assert_eq!(buf[0], 0xdd);
        assert_eq!(
            u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]),
            70000
        );
    }

    // --- write_float64 ---

    #[test]
    fn test_write_float64() {
        let mut buf = Vec::new();
        write_float64(&mut buf, 1.5);
        assert_eq!(buf[0], 0xcb);
        assert_eq!(f64::from_be_bytes(buf[1..9].try_into().unwrap()), 1.5);
    }

    // --- roundtrip tests ---

    #[test]
    fn test_roundtrip_bin() {
        let original = b"hello world";
        let mut buf = Vec::new();
        write_bin(&mut buf, original);
        let mut pos = 0;
        let decoded = read_bin(&buf, &mut pos).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(pos, buf.len());
    }

    #[test]
    fn test_roundtrip_uint() {
        for &val in &[0u64, 1, 127, 128, 255, 256, 65535, 65536, 0x1_0000_0000, u64::MAX] {
            let mut buf = Vec::new();
            write_uint(&mut buf, val);
            let mut pos = 0;
            let decoded = read_uint(&buf, &mut pos).unwrap();
            assert_eq!(decoded, val, "roundtrip failed for {val}");
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn test_roundtrip_array_header() {
        for &len in &[0usize, 1, 15, 16, 255, 256, 65535, 65536] {
            let mut buf = Vec::new();
            write_array_header(&mut buf, len);
            let mut pos = 0;
            let decoded = read_array_len(&buf, &mut pos).unwrap();
            assert_eq!(decoded, len, "roundtrip failed for array len {len}");
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn test_roundtrip_float64() {
        let mut buf = Vec::new();
        write_float64(&mut buf, 1234567.89);
        let mut pos = 0;
        let decoded = read_float64(&buf, &mut pos).unwrap();
        assert_eq!(decoded, 1234567.89);
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            MsgpackError::Truncated.to_string(),
            "unexpected end of msgpack data"
        );
    }
}
