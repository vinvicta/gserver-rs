//! # GServer Protocol Library
//!
//! This library implements the Graal Online binary protocol with exact byte-level
//! compatibility with the C++ GS2Emu implementation.
//!
//! ## Architecture
//!
//! The protocol is organized into several layers:
//!
//! ### 1. Codecs Layer ([`codecs`])
//! Binary encoding/decoding functions for the Graal variable-length integer format:
//! - GChar: 1-byte signed integer (-32 to 191)
//! - GShort: 2-byte integer (max 28767)
//! - GInt: 3-byte integer (max 3682399)
//! - GInt4: 4-byte integer (max 471347295)
//! - GUInt5: 5-byte variable-length unsigned (max 4294967295)
//! - GString: Length-prefixed string
//!
//! ### 2. Packet Types ([`packets`])
//! Enumerations of all 160+ packet types defined in the Graal protocol:
//! - Client-to-Server (PLI_*): Packets from Graal client to server
//! - Server-to-Client (PLO_*): Packets from server to Graal client
//! - Server-to-ListServer (SVI_*): Server to list server communication
//! - ListServer-to-Server (SVO_*): List server to game server communication
//!
//! ### 3. Packet Structures ([`packet_types`])
//! Concrete data structures for individual packet types with:
//! - Serialization/deserialization methods
//! - Extensive documentation
//! - Type-safe field access
//!
//! ### 4. Compression ([`compression`])
//! Packet compression using zlib or bzip2 algorithms.
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use gserver_protocol::{LevelWarpPacket, codecs::*};
//! use bytes::BytesMut;
//!
//! // Create a level warp packet
//! let packet = LevelWarpPacket::new(
//!     12345,  // mod_time
//!     64,     // x (pixels)
//!     64,     // y (pixels)
//!     "onlinestartlocal.nw".to_string(),
//! );
//!
//! // Serialize it
//! let mut buf = BytesMut::new();
//! write_guint5(&mut buf, packet.mod_time);
//! write_gshort(&mut buf, packet.x / 2);
//! write_gshort(&mut buf, packet.y / 2);
//! write_gstring(&mut buf, &packet.level);
//! ```
//!
//! ## Protocol Compatibility
//!
//! This implementation maintains **exact byte-level compatibility** with the C++ version:
//! - All integer encodings match CString::readG*() / writeG*() methods
//! - Packet structure layouts match IEnums.h definitions
//! - Compression parameters match GS2Emu defaults
//!
//! ## Version Support
//!
//! The Graal protocol has evolved across multiple client generations:
//! - **Original (v1.x)**: Basic protocol
//! - **Classic (v2.x-3.x)**: Added features
//! - **NewMain (v4.x-5.007)**: Major protocol updates
//! - **Modern (v5.1+)**: Current protocol with all features
//!
//! This library supports all generations through feature flags.

pub mod codecs;
pub mod compression;
pub mod packets;
pub mod packet_types;
pub mod packet_structures;
pub mod packet_builder;
pub mod showimg;
pub mod level;
pub mod map;
pub mod gs1;
pub mod rc;
pub mod nc;

// Re-export commonly used items
pub use codecs::*;
pub use compression::*;
pub use packets::*;
pub use packet_types::*;
pub use packet_builder::*;
pub use showimg::*;
pub use level::*;
pub use map::*;
pub use gs1::*;
pub use rc::*;
pub use nc::*;
