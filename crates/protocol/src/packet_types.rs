//! # Individual Packet Structures
//!
//! This module contains the actual data structures for each packet type.
//! Each packet structure implements serialization/deserialization using
//! the Graal binary protocol codecs.
//!
//! ## Design Philosophy
//!
//! - **Exact byte compatibility**: All structures match C++ implementation exactly
//! - **Well-documented**: Every field is documented with its purpose and format
//! - **Type-safe**: Use Rust's type system to prevent invalid data
//! - **Testable**: All packets can be tested with round-trip encoding

use bytes::{Buf, BufMut, BytesMut};
use gserver_core::Result;
use super::{codecs::*, packets::*};

/// Represents a complete packet from client to server
///
/// # Invariant
/// The packet_data byte vector must contain valid packet data according to the
/// Graal protocol specification for the given packet_type.
#[derive(Debug, Clone)]
pub struct PacketIn {
    /// Type identifier for this packet
    pub packet_type: PacketTypeIn,

    /// Raw packet data (excluding packet type byte)
    pub packet_data: Vec<u8>,
}

impl PacketIn {
    /// Create a new inbound packet
    ///
    /// # Arguments
    /// * `packet_type` - The type of this packet
    /// * `packet_data` - The packet payload (excluding packet type byte)
    #[inline]
    pub fn new(packet_type: PacketTypeIn, packet_data: Vec<u8>) -> Self {
        Self {
            packet_type,
            packet_data,
        }
    }

    /// Deserialize a packet from a byte buffer
    ///
    /// # Arguments
    /// * `buf` - Buffer containing packet data (first byte is packet type)
    ///
    /// # Returns
    /// The parsed packet or an error if deserialization fails
    ///
    /// # Example
    /// ```no_run
    /// use gserver_protocol::PacketIn;
    /// use bytes::BytesMut;
    ///
    /// let mut buf = BytesMut::from(&[0x00, 0x20, 0x74, 0x65, 0x73, 0x74][..]);
    /// let packet = PacketIn::deserialize(&mut buf).unwrap();
    /// ```
    pub fn deserialize(buf: &mut BytesMut) -> Result<Self> {
        if buf.remaining() < 1 {
            return Err(gserver_core::GServerError::InvalidData(
                "Packet buffer is empty".into(),
            ));
        }

        let packet_type_byte = buf.get_u8();
        let packet_type = PacketTypeIn::from_u8(packet_type_byte)
            .ok_or_else(|| gserver_core::GServerError::Protocol(format!(
                "Unknown packet type: {}",
                packet_type_byte
            )))?;

        let packet_data = buf.to_vec();
        buf.advance(buf.remaining()); // Consume all remaining data

        Ok(Self {
            packet_type,
            packet_data,
        })
    }

    /// Serialize this packet to a byte buffer
    ///
    /// # Arguments
    /// * `buf` - Buffer to write the serialized packet to
    ///
    /// # Example
    /// ```no_run
    /// use gserver_protocol::PacketIn;
    /// use gserver_protocol::PacketTypeIn;
    /// use bytes::BytesMut;
    ///
    /// let packet = PacketIn::new(PacketTypeIn::LevelWarp, vec![0x20, 0x74]);
    /// let mut buf = BytesMut::new();
    /// packet.serialize(&mut buf);
    /// ```
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_u8(self.packet_type.as_u8());
        buf.put_slice(&self.packet_data);
    }
}

/// Represents a complete packet from server to client
#[derive(Debug, Clone)]
pub struct PacketOut {
    /// Type identifier for this packet
    pub packet_type: PacketTypeOut,

    /// Raw packet data (excluding packet type byte)
    pub packet_data: Vec<u8>,
}

impl PacketOut {
    /// Create a new outbound packet
    #[inline]
    pub fn new(packet_type: PacketTypeOut, packet_data: Vec<u8>) -> Self {
        Self {
            packet_type,
            packet_data,
        }
    }

    /// Deserialize a packet from a byte buffer
    pub fn deserialize(buf: &mut BytesMut) -> Result<Self> {
        if buf.remaining() < 1 {
            return Err(gserver_core::GServerError::InvalidData(
                "Packet buffer is empty".into(),
            ));
        }

        let packet_type_byte = buf.get_u8();
        let packet_type = PacketTypeOut::from_u8(packet_type_byte)
            .ok_or_else(|| gserver_core::GServerError::Protocol(format!(
                "Unknown packet type: {}",
                packet_type_byte
            )))?;

        let packet_data = buf.to_vec();
        buf.advance(buf.remaining());

        Ok(Self {
            packet_type,
            packet_data,
        })
    }

    /// Serialize this packet to a byte buffer
    ///
    /// # GChar Encoding
    /// Packet types are GChar-encoded: the value written is (enum_value + 32)
    /// This matches the C++ implementation's writeGChar() behavior.
    ///
    /// # Newline Termination
    /// All packets are terminated with '\n' except PLO_RAWDATA (RawData = 100)
    /// This matches the C++ CFileQueue behavior where packets are split by newlines.
    pub fn serialize(&self, buf: &mut BytesMut) {
        // GChar-encode packet type: add 32 to the value (matching C++ writeGChar)
        buf.put_u8(self.packet_type.as_u8().wrapping_add(32));
        buf.put_slice(&self.packet_data);

        // CRITICAL: Append newline for packet splitting
        // PLO_RAWDATA (100) is the only exception - used for large file transfers
        if self.packet_type != PacketTypeOut::RawData {
            buf.put_u8(b'\n');
        }
    }
}

// ============================================================================
// LEVEL WARP PACKET
// ============================================================================

/// Client request to warp to a different level
///
/// # Purpose
/// This packet is sent by the client when they need to change levels.
///
/// # Packet Structure
/// ```text
/// Packet ID: 0 (PLI_LEVELWARP)
/// {
///     GINT5 modtime;    // Level file modification time (for caching)
///     GSHORT x;         // X coordinate (pixels / 2)
///     GSHORT y;         // Y coordinate (pixels / 2)
///     GSTRING level;    // Target level name (e.g., "onlinestartlocal.nw")
/// }
/// ```
///
/// # Usage
/// - Initial login warping
/// - Walking between levels on a map (gmap)
/// - Warping via script (warp command)
/// - Server warps (serverwarp command)
///
/// # Notes
/// - X and Y coordinates are in pixels but divided by 2 (Graal uses half-pixel precision)
/// - modtime is used to verify the client has the correct version of the level
/// - Level names use relative paths: "folder/level.nw"
#[derive(Debug, Clone, PartialEq)]
pub struct LevelWarpPacket {
    /// Level file modification time (Unix timestamp)
    /// Used for client-side caching validation
    pub mod_time: u32,

    /// X coordinate in pixels (divided by 2)
    /// Valid range: 0-28767 (maps to 0-57534 pixels)
    pub x: i16,

    /// Y coordinate in pixels (divided by 2)
    /// Valid range: 0-28767 (maps to 0-57534 pixels)
    pub y: i16,

    /// Target level name
    /// Examples: "onlinestartlocal.nw", "guildhall1.nw", "maps/island.nw"
    pub level: String,
}

impl LevelWarpPacket {
    /// Create a new level warp packet
    ///
    /// # Arguments
    /// * `mod_time` - Level file modification time (Unix timestamp)
    /// * `x` - X coordinate in pixels (will be divided by 2)
    /// * `y` - Y coordinate in pixels (will be divided by 2)
    /// * `level` - Target level name
    #[inline]
    pub fn new(mod_time: u32, x: i16, y: i16, level: String) -> Self {
        Self {
            mod_time,
            x: x / 2,
            y: y / 2,
            level,
        }
    }

    /// Deserialize a level warp packet from buffer
    ///
    /// # Format
    /// ```text
    /// {GINT5 modtime}{GSHORT x*2}{GSHORT y*2}{GSTRING level}
    /// ```
    pub fn deserialize(buf: &mut BytesMut) -> Result<Self> {
        let mod_time = read_guint5(buf)?;
        let x = read_gshort(buf)?;
        let y = read_gshort(buf)?;
        let level = read_gstring(buf)?;

        Ok(Self {
            mod_time,
            x,
            y,
            level,
        })
    }

    /// Serialize this packet to a buffer
    pub fn serialize(&self, buf: &mut BytesMut) {
        write_guint5(buf, self.mod_time);
        write_gshort(buf, self.x);
        write_gshort(buf, self.y);
        write_gstring(buf, &self.level);
    }
}

// ============================================================================
// BOARD MODIFY PACKET
// ============================================================================

/// Client request to modify level tiles
///
/// # Purpose
/// This packet is sent when a player places or removes tiles in a level.
/// Used for building, terraforming, and other level modification features.
///
/// # Packet Structure
/// ```text
/// Packet ID: 1 (PLI_BOARDMODIFY)
/// {
///     GSHORT x;         // X coordinate (tiles)
///     GSHORT y;         // Y coordinate (tiles)
///     GSHORT width;     // Width of area to modify (tiles)
///     GSHORT height;    // Height of area to modify (tiles)
///     TILE_DATA[];      // Array of tile indices
/// }
/// ```
///
/// # Tile Data Format
/// Each tile is represented by a 16-bit unsigned integer:
/// - Bits 0-9: Tile index (0-1023)
/// - Bits 10-15: Layer flags and attributes
///
/// # Usage
/// - Building structures
/// - Placing roads/paths
/// - Creating water/lava
/// - Terraforming (raising/lowering terrain)
///
/// # Permissions
/// - Requires appropriate account rights (build rights, admin, etc.)
/// - Some areas may be protected from modification
/// - Changes are not permanent unless saved to disk
#[derive(Debug, Clone, PartialEq)]
pub struct BoardModifyPacket {
    /// X coordinate in tiles
    pub x: i16,

    /// Y coordinate in tiles
    pub y: i16,

    /// Width in tiles
    pub width: i16,

    /// Height in tiles
    pub height: i16,

    /// Array of tile data
    /// Length = width * height
    pub tiles: Vec<u16>,
}

impl BoardModifyPacket {
    /// Create a new board modify packet
    ///
    /// # Arguments
    /// * `x` - X coordinate in tiles
    /// * `y` - Y coordinate in tiles
    /// * `width` - Width in tiles
    /// * `height` - Height in tiles
    /// * `tiles` - Array of tile indices (length must equal width * height)
    #[inline]
    pub fn new(x: i16, y: i16, width: i16, height: i16, tiles: Vec<u16>) -> Self {
        assert_eq!(
            tiles.len() as i16,
            width * height,
            "Tile array size must equal width * height"
        );
        Self {
            x,
            y,
            width,
            height,
            tiles,
        }
    }

    /// Deserialize a board modify packet
    pub fn deserialize(buf: &mut BytesMut) -> Result<Self> {
        let x = read_gshort(buf)?;
        let y = read_gshort(buf)?;
        let width = read_gshort(buf)?;
        let height = read_gshort(buf)?;

        let tile_count = (width * height) as usize;
        let mut tiles = Vec::with_capacity(tile_count);

        for _ in 0..tile_count {
            tiles.push(read_gshort(buf)? as u16);
        }

        Ok(Self {
            x,
            y,
            width,
            height,
            tiles,
        })
    }

    /// Serialize this packet
    pub fn serialize(&self, buf: &mut BytesMut) {
        write_gshort(buf, self.x);
        write_gshort(buf, self.y);
        write_gshort(buf, self.width);
        write_gshort(buf, self.height);

        for tile in &self.tiles {
            write_gshort(buf, *tile as i16);
        }
    }
}

// ============================================================================
// PLAYER PROPS PACKET
// ============================================================================

/// Player properties update packet
///
/// # Purpose
/// Sent by client to update their own player properties,
/// or sent by server to update player properties for other clients.
///
/// # Common Properties
/// - Position (x, y)
/// - Sprite (appearance)
/// - Colors (head, body, sleeve, shoe)
/// - Status (powerups, effects)
/// - Guild tag
/// - Nickname display
///
/// # Packet Structure
/// Properties are sent as key-value pairs using GString encoding.
/// The exact format depends on the server generation.
#[derive(Debug, Clone, PartialEq)]
pub struct PlayerPropsPacket {
    /// Player ID
    pub player_id: u16,

    /// Property data (format depends on server generation)
    pub props_data: Vec<u8>,
}

impl PlayerPropsPacket {
    /// Create a new player props packet
    #[inline]
    pub fn new(player_id: u16, props_data: Vec<u8>) -> Self {
        Self {
            player_id,
            props_data,
        }
    }
}

// ============================================================================
// LANGUAGE PACKET
// ============================================================================

/// Client language preference packet
///
/// # Purpose
/// Sent by client to indicate their language preference.
/// Used for translations and server messages.
///
/// # Packet Structure
/// ```text
/// Packet ID: 5 (PLI_LANGUAGE)
/// {
///     GSTRING language;  // Language name (e.g., "English", "German")
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct LanguagePacket {
    /// Language name
    pub language: String,
}

impl LanguagePacket {
    /// Create a new language packet
    #[inline]
    pub fn new(language: String) -> Self {
        Self { language }
    }

    /// Deserialize from buffer
    pub fn deserialize(buf: &mut BytesMut) -> Result<Self> {
        let language = read_gstring(buf)?;
        Ok(Self { language })
    }
}

// ============================================================================
// FLAG SET PACKET
// ============================================================================

/// Flag set packet
///
/// # Purpose
/// Sets a client-side flag (server.*, this.*, etc.)
///
/// # Packet Structure
/// ```text
/// Packet ID: 18 (PLI_FLAGSET)
/// {
///     GSTRING flag_name;  // e.g., "server.flag.name=value" or "server.flag.name"
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct FlagSetPacket {
    /// Flag name (may include =value)
    pub flag_name: String,

    /// Flag value (if provided with =)
    pub flag_value: Option<String>,
}

impl FlagSetPacket {
    /// Create a new flag set packet
    #[inline]
    pub fn new(flag_name: String, flag_value: Option<String>) -> Self {
        Self { flag_name, flag_value }
    }

    /// Deserialize from buffer
    pub fn deserialize(buf: &mut BytesMut) -> Result<Self> {
        let data = read_gstring(buf)?;

        // Check if there's a value (=)
        let (flag_name, flag_value) = if let Some(pos) = data.find('=') {
            let name = data[..pos].to_string();
            let value = data[pos + 1..].to_string();
            (name, Some(value))
        } else {
            (data.clone(), None)
        };

        Ok(Self { flag_name, flag_value })
    }

    /// Get the full flag string
    pub fn as_full_flag(&self) -> String {
        if let Some(ref value) = self.flag_value {
            format!("{}={}", self.flag_name, value)
        } else {
            self.flag_name.clone()
        }
    }
}

// ============================================================================
// SHOW IMG PLAYER PACKET
// ============================================================================

/// Show image packet from client
///
/// # Purpose
/// Client requests to show an image overlay
///
/// # Packet Structure
/// ```text
/// Packet ID: 4 (PLI_SHOWIMGPLAYER)
/// {
///     GSTRING params;  // Comma-separated: index,x,y,image,r,g,b,zoom,mode
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ShowImgPlayerPacket {
    /// Image index
    pub index: u8,

    /// X position
    pub x: f32,

    /// Y position
    pub y: f32,

    /// Image filename
    pub image: String,

    /// Red colorization
    pub r: u8,

    /// Green colorization
    pub g: u8,

    /// Blue colorization
    pub b: u8,

    /// Zoom level
    pub zoom: i16,

    /// Mode flags
    pub mode: u8,
}

impl ShowImgPlayerPacket {
    /// Deserialize from buffer
    pub fn deserialize(buf: &mut BytesMut) -> Result<Self> {
        let data = read_gstring(buf)?;
        let parts: Vec<&str> = data.split(',').collect();

        if parts.len() < 9 {
            return Err(gserver_core::GServerError::InvalidData(
                "ShowImgPlayer packet requires 9 parameters".to_string()
            ));
        }

        let index = parts[0].parse().unwrap_or(0);
        let x = parts[1].parse().unwrap_or(0.0);
        let y = parts[2].parse().unwrap_or(0.0);
        let image = parts[3].to_string();
        let r = parts[4].parse().unwrap_or(0);
        let g = parts[5].parse().unwrap_or(0);
        let b = parts[6].parse().unwrap_or(0);
        let zoom = parts[7].parse().unwrap_or(256);
        let mode = parts[8].parse().unwrap_or(0);

        Ok(Self {
            index, x, y, image, r, g, b, zoom, mode,
        })
    }
}

// ============================================================================
// HURT PLAYER PACKET
// ============================================================================

/// Hurt player packet
///
/// # Purpose
/// Client sends damage to another player
///
/// # Packet Structure
/// ```text
/// Packet ID: 7 (PLI_HURTPLAYER)
/// {
///     GSTRING victim_id;  // Player ID to hurt
///     GSTRING damage;     // Damage amount
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct HurtPlayerPacket {
    /// Victim player ID
    pub victim_id: u16,

    /// Damage amount
    pub damage: f32,

    /// Damage type (optional)
    pub damage_type: u8,
}

impl HurtPlayerPacket {
    /// Deserialize from buffer
    pub fn deserialize(buf: &mut BytesMut) -> Result<Self> {
        let data = read_gstring(buf)?;
        let parts: Vec<&str> = data.split(',').collect();

        let victim_id = parts.get(0)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let damage = parts.get(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);

        let damage_type = parts.get(2)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Ok(Self {
            victim_id,
            damage,
            damage_type,
        })
    }
}

// ============================================================================
// ITEM ADD PACKET
// ============================================================================

/// Add item packet
///
/// # Purpose
/// Client drops/places an item
///
/// # Packet Structure
/// ```text
/// Packet ID: 6 (PLI_ITEMADD)
/// {
///     GCHAR x;        // X position (tiles * 2)
///     GCHAR y;        // Y position (tiles * 2)
///     GCHAR item;     // Item type
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ItemAddPacket {
    /// X position (tiles)
    pub x: f32,

    /// Y position (tiles)
    pub y: f32,

    /// Item type
    pub item_type: u8,
}

impl ItemAddPacket {
    /// Deserialize from buffer
    pub fn deserialize(buf: &mut BytesMut) -> Result<Self> {
        let x = read_gchar(buf)? as f32 / 2.0;
        let y = read_gchar(buf)? as f32 / 2.0;
        let item_type = read_gchar(buf)? as u8;

        Ok(Self { x, y, item_type })
    }
}

// ============================================================================
// CHEST OPEN PACKET
// ============================================================================

/// Open chest packet
///
/// # Purpose
/// Client opens a chest
///
/// # Packet Structure
/// ```text
/// Packet ID: 21 (PLI_OPENCHEST)
/// {
///     GCHAR x;        // X position
///     GCHAR y;        // Y position
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct OpenChestPacket {
    /// X position (tiles)
    pub x: u8,

    /// Y position (tiles)
    pub y: u8,
}

impl OpenChestPacket {
    /// Deserialize from buffer
    pub fn deserialize(buf: &mut BytesMut) -> Result<Self> {
        let x = read_gchar(buf)? as u8;
        let y = read_gchar(buf)? as u8;

        Ok(Self { x, y })
    }
}

// ============================================================================
// BOMB ADD PACKET
// ============================================================================

/// Add bomb packet
///
/// # Purpose
/// Client places a bomb
///
/// # Packet Structure
/// ```text
/// Packet ID: 10 (PLI_BOMBADD)
/// {
///     GCHAR x;        // X position
///     GCHAR y;        // Y position
///     GCHAR power;    // Bomb power
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct BombAddPacket {
    /// X position (pixels)
    pub x: f32,

    /// Y position (pixels)
    pub y: f32,

    /// Bomb power
    pub power: u8,
}

impl BombAddPacket {
    /// Deserialize from buffer
    pub fn deserialize(buf: &mut BytesMut) -> Result<Self> {
        let x = read_gchar(buf)? as f32 * 8.0;
        let y = read_gchar(buf)? as f32 * 8.0;
        let power = read_gchar(buf)? as u8;

        Ok(Self { x, y, power })
    }
}

// ============================================================================
// HORSE ADD PACKET
// ============================================================================

/// Add horse packet
///
/// # Purpose
/// Client spawns/rides a horse
///
/// # Packet Structure
/// ```text
/// Packet ID: 11 (PLI_HORSEADD)
/// {
///     GCHAR x;        // X position
///     GCHAR y;        // Y position
///     GSTRING horse;  // Horse image
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct HorseAddPacket {
    /// X position (pixels)
    pub x: f32,

    /// Y position (pixels)
    pub y: f32,

    /// Horse image
    pub horse_image: String,
}

impl HorseAddPacket {
    /// Deserialize from buffer
    pub fn deserialize(buf: &mut BytesMut) -> Result<Self> {
        let x = read_gchar(buf)? as f32 * 8.0;
        let y = read_gchar(buf)? as f32 * 8.0;
        let horse_image = read_gstring(buf)?;

        Ok(Self { x, y, horse_image })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level_warp_roundtrip() {
        let original = LevelWarpPacket::new(12345, 64, 64, "testlevel.nw".to_string());

        let mut buf = BytesMut::new();
        original.serialize(&mut buf);

        let deserialized = LevelWarpPacket::deserialize(&mut buf).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_board_modify_roundtrip() {
        let tiles = vec![100u16, 101, 102, 103];
        let original = BoardModifyPacket::new(10, 10, 2, 2, tiles);

        let mut buf = BytesMut::new();
        original.serialize(&mut buf);

        let deserialized = BoardModifyPacket::deserialize(&mut buf).unwrap();

        assert_eq!(original, deserialized);
    }
}
