//! Compression layer for protocol packets

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use gserver_core::Result;
use std::io::{Read, Write};

/// Compression method used for packets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionType {
    None = 0,
    Zlib = 1,
    Bzip2 = 2,
}

/// Compress data using the specified method
pub fn compress(data: &[u8], method: CompressionType) -> Result<Vec<u8>> {
    match method {
        CompressionType::None => Ok(data.to_vec()),
        CompressionType::Zlib => {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(data)?;
            Ok(encoder.finish()?)
        }
        CompressionType::Bzip2 => {
            let mut compressed = Vec::new();
            {
                let mut encoder = bzip2::write::BzEncoder::new(
                    &mut compressed,
                    bzip2::Compression::default(),
                );
                encoder.write_all(data)?;
            }
            Ok(compressed)
        }
    }
}

/// Decompress data using the specified method
pub fn decompress(data: &[u8], method: CompressionType) -> Result<Vec<u8>> {
    match method {
        CompressionType::None => Ok(data.to_vec()),
        CompressionType::Zlib => {
            let mut decoder = ZlibDecoder::new(data);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            Ok(decompressed)
        }
        CompressionType::Bzip2 => {
            let mut decoder = bzip2::read::BzDecoder::new(data);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            Ok(decompressed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zlib_roundtrip() {
        let original = b"Hello, World! This is a test of the compression system.";

        let compressed = compress(original, CompressionType::Zlib).unwrap();
        let decompressed = decompress(&compressed, CompressionType::Zlib).unwrap();

        assert_eq!(original, &decompressed[..]);
    }

    #[test]
    fn test_none_roundtrip() {
        let original = b"Uncompressed data";

        let compressed = compress(original, CompressionType::None).unwrap();
        assert_eq!(original, &compressed[..]);

        let decompressed = decompress(&compressed, CompressionType::None).unwrap();
        assert_eq!(original, &decompressed[..]);
    }
}
