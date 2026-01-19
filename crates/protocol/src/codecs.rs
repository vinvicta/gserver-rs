//! Graal protocol binary codecs with exact C++ compatibility
//!
//! These codecs implement the custom variable-length encoding used by Graal.
//! All bytes have +32 added (ASCII space offset), and each byte uses 7 bits for data.

use bytes::{Buf, BufMut, BytesMut};
use gserver_core::{GServerError, Result};

/// Trait for types that can be encoded/decoded using Graal protocol
pub trait GSerializable: Sized {
    fn write_g(&self, buf: &mut BytesMut);
    fn read_g(buf: &mut BytesMut) -> Result<Self>;
}

/// Write a single GChar (1 byte, -32 to 191 range when signed)
///
/// # Format
/// - 1 byte: value + 32
/// - Range: -32 to 191 (when interpreted as signed)
/// - Encoding: value + 32 (offset by ASCII space)
#[inline]
pub fn write_gchar(buf: &mut BytesMut, val: i8) {
    // GChar adds 32 offset, so -32 becomes 0, 0 becomes 32, etc.
    // This allows the full signed i8 range to be encoded
    let val = (val as i16 + 32) as u8;
    buf.put_u8(val);
}

/// Read a single GChar
#[inline]
pub fn read_gchar(buf: &mut BytesMut) -> Result<i8> {
    if buf.remaining() < 1 {
        return Err(GServerError::InvalidData("Not enough bytes for GChar".into()));
    }
    let val = buf.get_u8();
    Ok((val.wrapping_sub(32)) as i8)
}

/// Write a GShort (2 bytes, max 28767)
///
/// # Format
/// - Byte 0: (value >> 7) + 32, capped at 223
/// - Byte 1: (value % 128) + 32
#[inline]
pub fn write_gshort(buf: &mut BytesMut, val: i16) {
    let mut val = if val < 0 { 0 } else { val as u16 };
    val = val.min(28767);

    let byte0 = (val >> 7).min(223) as u8;
    let byte1 = (val - ((byte0 as u16) << 7)) as u8;

    buf.put_u8(byte0 + 32);
    buf.put_u8(byte1 + 32);
}

/// Read a GShort
#[inline]
pub fn read_gshort(buf: &mut BytesMut) -> Result<i16> {
    if buf.remaining() < 2 {
        return Err(GServerError::InvalidData("Not enough bytes for GShort".into()));
    }

    let byte0 = buf.get_u8();
    let byte1 = buf.get_u8();

    // Subtract the 32 offset from each byte, then reconstruct
    let val = (((byte0.wrapping_sub(32)) as i16) << 7) + (byte1.wrapping_sub(32)) as i16;
    Ok(val)
}

/// Write a GInt (3 bytes, max 3682303)
///
/// # Format
/// - Byte 0: ((value >> 14) & 0xFF) + 32, capped at 223
/// - Byte 1: ((value >> 7) & 0xFF) + 32, capped at 223
/// - Byte 2: (value & 0x7F) + 32
#[inline]
pub fn write_gint(buf: &mut BytesMut, val: i32) {
    let mut val = if val < 0 { 0 } else { val as u32 };
    val = val.min(3_682_303);

    let byte0 = (val >> 14).min(223);
    let mut remaining = val - (byte0 << 14);

    let byte1 = (remaining >> 7).min(223);
    remaining -= byte1 << 7;

    let byte2 = remaining.min(127);

    buf.put_u8(byte0 as u8 + 32);
    buf.put_u8(byte1 as u8 + 32);
    buf.put_u8(byte2 as u8 + 32);
}

/// Read a GInt
#[inline]
pub fn read_gint(buf: &mut BytesMut) -> Result<i32> {
    if buf.remaining() < 3 {
        return Err(GServerError::InvalidData("Not enough bytes for GInt".into()));
    }

    let byte0 = buf.get_u8();
    let byte1 = buf.get_u8();
    let byte2 = buf.get_u8();

    // Subtract the 32 offset from each byte, then reconstruct using addition
    let val = (((byte0.wrapping_sub(32)) as i32) << 14)
        + (((byte1.wrapping_sub(32)) as i32) << 7)
        + (byte2.wrapping_sub(32)) as i32;

    Ok(val)
}

/// Write a GInt4 (4 bytes, max 471347295)
///
/// # Format
/// Similar to GInt but with 4 bytes
#[inline]
pub fn write_gint4(buf: &mut BytesMut, val: i32) {
    let mut val = if val < 0 { 0 } else { val as u32 };
    val = val.min(471_347_295);

    let byte0 = (val >> 21).min(223);
    let mut remaining = val - ((byte0 as u32) << 21);

    let byte1 = (remaining >> 14).min(223);
    remaining -= (byte1 as u32) << 14;

    let byte2 = (remaining >> 7).min(223);
    remaining -= (byte2 as u32) << 7;

    let byte3 = remaining;

    buf.put_u8(byte0 as u8 + 32);
    buf.put_u8(byte1 as u8 + 32);
    buf.put_u8(byte2 as u8 + 32);
    buf.put_u8(byte3 as u8 + 32);
}

/// Read a GInt4
#[inline]
pub fn read_gint4(buf: &mut BytesMut) -> Result<i32> {
    if buf.remaining() < 4 {
        return Err(GServerError::InvalidData("Not enough bytes for GInt4".into()));
    }

    let byte0 = buf.get_u8();
    let byte1 = buf.get_u8();
    let byte2 = buf.get_u8();
    let byte3 = buf.get_u8();

    let val = (((((byte0 as i32) << 7) + (byte1 as i32)) << 7) + (byte2 as i32)) << 7
        + (byte3 as i32) - 0x4081020;
    Ok(val)
}

/// Write a GUInt5 (5 bytes, max 0xFFFFFFFF)
///
/// # Format
/// Variable-length encoding using 7 bits per byte + 32 offset
/// First byte uses only 4 bits (capped at 15)
#[inline]
pub fn write_guint5(buf: &mut BytesMut, val: u32) {
    let mut val = val.min(0xFFFFFFFF);

    // First byte: 4 bits only (capped at 15)
    let byte0 = ((val >> 28) & 0xFF).min(15) as u8;
    val -= (byte0 as u32) << 28;

    // Remaining bytes: 7 bits each
    let byte1 = ((val >> 21) & 0xFF).min(223) as u8;
    val -= (byte1 as u32) << 21;

    let byte2 = ((val >> 14) & 0xFF).min(223) as u8;
    val -= (byte2 as u32) << 14;

    let byte3 = ((val >> 7) & 0xFF).min(223) as u8;
    let byte4 = (val & 0x7F) as u8;

    buf.put_u8(byte0 + 32);
    buf.put_u8(byte1 + 32);
    buf.put_u8(byte2 + 32);
    buf.put_u8(byte3 + 32);
    buf.put_u8(byte4 + 32);
}

/// Read a GUInt5
#[inline]
pub fn read_guint5(buf: &mut BytesMut) -> Result<u32> {
    if buf.remaining() < 5 {
        return Err(GServerError::InvalidData("Not enough bytes for GUInt5".into()));
    }

    let byte0 = buf.get_u8();
    let byte1 = buf.get_u8();
    let byte2 = buf.get_u8();
    let byte3 = buf.get_u8();
    let byte4 = buf.get_u8();

    // Subtract the 32 offset from each byte, then reconstruct using addition
    let b0 = byte0.wrapping_sub(32) as u64;
    let b1 = byte1.wrapping_sub(32) as u64;
    let b2 = byte2.wrapping_sub(32) as u64;
    let b3 = byte3.wrapping_sub(32) as u64;
    let b4 = byte4.wrapping_sub(32) as u64;

    // Build up the value step by step to avoid overflow
    let val = b0;
    let val = val.wrapping_shl(7).wrapping_add(b1);
    let val = val.wrapping_shl(7).wrapping_add(b2);
    let val = val.wrapping_shl(7).wrapping_add(b3);
    let val = val.wrapping_shl(7).wrapping_add(b4);

    Ok(val as u32)
}

/// Write a GString (length-prefixed string)
///
/// # Format
/// - GChar: length (1 byte, max 191 chars)
/// - String bytes (not null-terminated)
#[inline]
pub fn write_gstring(buf: &mut BytesMut, val: &str) {
    let bytes = val.as_bytes();
    let len = bytes.len().min(191);
    write_gchar(buf, len as i8);
    buf.put_slice(&bytes[..len]);
}

/// Read a GString
#[inline]
pub fn read_gstring(buf: &mut BytesMut) -> Result<String> {
    let len = read_gchar(buf)?;
    if len < 0 {
        return Ok(String::new());
    }
    let len = len as usize;

    if buf.remaining() < len {
        return Err(GServerError::InvalidData("Not enough bytes for GString".into()));
    }

    let bytes = buf.copy_to_bytes(len);
    String::from_utf8(bytes.to_vec())
        .map_err(|e| GServerError::InvalidData(format!("Invalid UTF-8: {}", e)))
}

/// Read a GUShort (unsigned GShort)
///
/// Same as GShort but interpreted as unsigned
#[inline]
pub fn read_gushort(buf: &mut BytesMut) -> Result<u16> {
    Ok(read_gshort(buf)? as u16)
}

/// Read a GUInt (unsigned GInt)
///
/// Same as GInt but interpreted as unsigned
#[inline]
pub fn read_guint(buf: &mut BytesMut) -> Result<u32> {
    Ok(read_gint(buf)? as u32)
}

/// Read a GUChar (unsigned GChar)
///
/// Same as GChar but interpreted as unsigned (0-191 range)
#[inline]
pub fn read_guchar(buf: &mut BytesMut) -> Result<u8> {
    Ok(read_gchar(buf)? as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gchar_roundtrip() {
        let test_cases = vec![0i8, 32, 64, 127, -32, -1];

        for val in test_cases {
            let mut buf = BytesMut::new();
            write_gchar(&mut buf, val);
            let decoded = read_gchar(&mut buf).unwrap();
            assert_eq!(val, decoded, "Failed for {}", val);
        }
    }

    #[test]
    fn test_gshort_roundtrip() {
        // GShort doesn't support negative values (they get clamped to 0)
        let test_cases = vec![0i16, 100, 1000, 28767];

        for val in test_cases {
            let mut buf = BytesMut::new();
            write_gshort(&mut buf, val);
            let decoded = read_gshort(&mut buf).unwrap();
            assert_eq!(val, decoded, "Failed for {}", val);
        }
    }

    #[test]
    fn test_gint_roundtrip() {
        // GInt doesn't support negative values (they get clamped to 0)
        // Max encodable value is (223 << 14) + (223 << 7) + 127 = 3,682,303
        let test_cases = vec![0i32, 100, 10000, 3682303];

        for val in test_cases {
            let mut buf = BytesMut::new();
            write_gint(&mut buf, val);
            let decoded = read_gint(&mut buf).unwrap();
            assert_eq!(val, decoded, "Failed for {}", val);
        }
    }

    #[test]
    fn test_guint5_roundtrip() {
        let test_cases = vec![0u32, 100, 10000, 3682399, 0xFFFFFFFF];

        for val in test_cases {
            let mut buf = BytesMut::new();
            write_guint5(&mut buf, val);
            let decoded = read_guint5(&mut buf).unwrap();
            assert_eq!(val, decoded, "Failed for {}", val);
        }
    }

    #[test]
    fn test_gstring_roundtrip() {
        let test_cases = vec!["", "Hello", "Test", "Graal Online"];

        for val in test_cases {
            let mut buf = BytesMut::new();
            write_gstring(&mut buf, val);
            let decoded = read_gstring(&mut buf).unwrap();
            assert_eq!(val, decoded, "Failed for {}", val);
        }
    }

    #[test]
    fn test_guint5_encoding_matches_spec() {
        // Test specific values to ensure exact byte-for-byte compatibility
        let mut buf = BytesMut::new();
        write_guint5(&mut buf, 0);

        let bytes = &buf[..];
        assert_eq!(bytes[0], 32); // 0 + 32
        assert_eq!(bytes[1], 32); // 0 + 32
        assert_eq!(bytes[2], 32); // 0 + 32
        assert_eq!(bytes[3], 32); // 0 + 32
        assert_eq!(bytes[4], 32); // 0 + 32
    }
}
