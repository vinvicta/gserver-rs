//! # Core Packet Structures
//!
//! This module contains the data structures for the 20 most critical packets
//! needed for basic GServer functionality.
//!
//! These structures define the data payloads that accompany each packet type.

use bytes::{Buf, BufMut, BytesMut};

// ============================================================================
// MOVEMENT PACKETS (4)
// ============================================================================

/// PLO_MOVE / PLO_MOVE2 - Server sends player movement to clients
///
/// Sent when a player moves to notify other players.
#[derive(Debug, Clone, PartialEq)]
pub struct MovePacket {
    /// Player ID
    pub player_id: u16,
    /// X position in pixels (divided by 16 = tile coordinate)
    pub x: i16,
    /// Y position in pixels (divided by 16 = tile coordinate)
    pub y: i16,
}

/// PLI_ADJACENTLEVEL - Client requests adjacent level data
///
/// Used for gmap/bigmap to preload adjacent levels.
#[derive(Debug, Clone, PartialEq)]
pub struct AdjacentLevelPacket {
    /// X position on the gmap
    pub gmap_x: u8,
    /// Y position on the gmap
    pub gmap_y: u8,
}

/// PLO_PLAYERWARP / PLO_PLAYERWARP2 - Server warps player to new level
///
/// Sent to move a player to a different level.
#[derive(Debug, Clone, PartialEq)]
pub struct PlayerWarpPacket {
    /// X position in pixels
    pub x: i16,
    /// Y position in pixels
    pub y: i16,
    /// Z position in pixels
    pub z: i16,
    /// GMap X coordinate (for gmaps)
    pub gmap_x: u8,
    /// GMap Y coordinate (for gmaps)
    pub gmap_y: u8,
    /// Level name
    pub level: String,
}

// ============================================================================
// CHAT PACKETS (3)
// ============================================================================

/// PLI_TOALL - Client sends message to all players
///
/// Global chat message.
#[derive(Debug, Clone, PartialEq)]
pub struct ToAllPacket {
    /// Message text
    pub message: String,
}

/// PLO_TOALL - Server sends message to all players
///
/// Broadcast a message to all players.
#[derive(Debug, Clone, PartialEq)]
pub struct ToAllServerPacket {
    /// Player ID who sent the message
    pub player_id: u16,
    /// Message text
    pub message: String,
}

/// PLI_PRIVATEMESSAGE / PLO_PRIVATEMESSAGE - Private message between players
///
#[derive(Debug, Clone, PartialEq)]
pub struct PrivateMessagePacket {
    /// Sender player ID
    pub from_player_id: u16,
    /// Receiver player ID (0 if using account_name)
    pub to_player_id: u16,
    /// Receiver account name (empty if using player_id)
    pub account_name: String,
    /// Message text
    pub message: String,
}

/// PLO_SAY2 - Server sends speech bubble or sign text
///
/// Used for player speech bubbles and signs.
#[derive(Debug, Clone, PartialEq)]
pub struct Say2Packet {
    /// Player ID (0 for signs)
    pub player_id: u16,
    /// Text to display
    pub text: String,
}

// ============================================================================
// COMBAT PACKETS (4)
// ============================================================================

/// PLI_HURTPLAYER - Client hurts another player
///
/// Player-to-player combat.
#[derive(Debug, Clone, PartialEq)]
pub struct HurtPlayerPacket {
    /// Player ID being hurt
    pub player_id: u16,
    /// Damage amount
    pub damage: u8,
    /// X direction of hurt
    pub hurt_dx: i8,
    /// Y direction of hurt
    pub hurt_dy: i8,
}

/// PLO_HURTPLAYER - Server sends hurt notification
///
#[derive(Debug, Clone, PartialEq)]
pub struct HurtPlayerServerPacket {
    /// Player ID being hurt
    pub player_id: u16,
    /// Damage amount
    pub damage: u8,
    /// X position
    pub x: i16,
    /// Y position
    pub y: i16,
}

/// PLI_EXPLOSION / PLO_EXPLOSION - Create explosion effect
///
#[derive(Debug, Clone, PartialEq)]
pub struct ExplosionPacket {
    /// X position in pixels
    pub x: f32,
    /// Y position in pixels
    pub y: f32,
    /// Explosion width
    pub width: u8,
    /// Explosion height
    pub height: u8,
}

/// PLI_BOMBADD / PLO_BOMBADD - Place a bomb
///
#[derive(Debug, Clone, PartialEq)]
pub struct BombAddPacket {
    /// Bomb ID
    pub bomb_id: u32,
    /// Owner player ID
    pub owner_id: u16,
    /// X position in pixels
    pub x: i16,
    /// Y position in pixels
    pub y: i16,
    /// Owner X position
    pub owner_x: i16,
    /// Owner Y position
    pub owner_y: i16,
    /// Bomb power (0-3)
    pub power: u8,
    /// Bomb type (bomb, joltbomb, superbomb, firebomb)
    pub bomb_type: u8,
}

/// PLI_BOMBDEL / PLO_BOMBDEL - Remove a bomb
///
#[derive(Debug, Clone, PartialEq)]
pub struct BombDelPacket {
    /// Bomb ID to delete
    pub bomb_id: u32,
}

// ============================================================================
// ITEM PACKETS (4)
// ============================================================================

/// PLI_ITEMADD / PLO_ITEMADD - Add item to level
///
/// Items that players can pick up (gralats, hearts, etc.).
#[derive(Debug, Clone, PartialEq)]
pub struct ItemAddPacket {
    /// Item ID
    pub item_id: u32,
    /// X position in pixels
    pub x: i16,
    /// Y position in pixels
    pub y: i16,
    /// Item image name
    pub image: String,
}

/// PLI_ITEMDEL / PLO_ITEMDEL - Remove item from level
///
#[derive(Debug, Clone, PartialEq)]
pub struct ItemDelPacket {
    /// Item ID to delete
    pub item_id: u32,
}

/// PLI_OPENCHEST / PLO_LEVELCHEST - Open a chest
///
#[derive(Debug, Clone, PartialEq)]
pub struct OpenChestPacket {
    /// Chest ID
    pub chest_id: u32,
    /// X position in tiles
    pub x: i16,
    /// Y position in tiles
    pub y: i16,
    /// Chest image name
    pub image: String,
}

/// PLI_ITEMTAKE - Player takes an item
///
#[derive(Debug, Clone, PartialEq)]
pub struct ItemTakePacket {
    /// Item ID taken
    pub item_id: u32,
    /// Player ID taking it
    pub player_id: u16,
}

// ============================================================================
// BOARD PACKETS (2)
// ============================================================================

/// PLI_REQUESTUPDATEBOARD - Client requests board tile updates
///
/// Used to refresh level tiles.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestUpdateBoardPacket {
    /// Level name
    pub level: String,
    /// Level modification time (for caching)
    pub modtime: u64,
    /// X position in tiles
    pub x: i16,
    /// Y position in tiles
    pub y: i16,
    /// Width in tiles
    pub width: u16,
    /// Height in tiles
    pub height: u16,
}

/// PLI_BOARDMODIFY / PLO_BOARDMODIFY - Modify level tiles
///
/// Used to place/remove tiles in the level.
#[derive(Debug, Clone, PartialEq)]
pub struct BoardModifyPacket {
    /// X position in tiles
    pub x: i16,
    /// Y position in tiles
    pub y: i16,
    /// Width in tiles
    pub width: u16,
    /// Height in tiles
    pub height: u16,
    /// Tile data (row-major order)
    pub tiles: Vec<u16>,
}

// ============================================================================
// ADDITIONAL CORE PACKETS
// ============================================================================

/// PLI_PLAYERPROPS / PLO_PLAYERPROPS - Update player properties
///
/// Critical for player state synchronization.
#[derive(Debug, Clone, PartialEq)]
pub struct PlayerPropsPacket {
    /// Player ID
    pub player_id: u16,
    /// Modification time
    pub modtime: u64,
    /// Property data (encoded)
    pub data: Vec<u8>,
}

/// PLI_LEVELWARP - Player requests level warp
///
#[derive(Debug, Clone, PartialEq)]
pub struct LevelWarpPacket {
    /// Level modification time (for caching)
    pub modtime: u64,
    /// X position in pixels (divided by 2)
    pub x: i16,
    /// Y position in pixels (divided by 2)
    pub y: i16,
    /// Target level name
    pub level: String,
}

/// PLO_LEVELBOARD - Send level board data to client
///
/// Sends the tile data for a level.
#[derive(Debug, Clone, PartialEq)]
pub struct LevelBoardPacket {
    /// Level name
    pub level: String,
    /// Level width in tiles
    pub width: u16,
    /// Level height in tiles
    pub height: u16,
    /// Tile data (row-major order)
    pub tiles: Vec<u16>,
    /// Board modifications
    pub modifications: Vec<BoardModification>,
}

/// Board tile modification
#[derive(Debug, Clone, PartialEq)]
pub struct BoardModification {
    /// X position
    pub x: i16,
    /// Y position
    pub y: i16,
    /// Tile index
    pub tile: u16,
}

/// PLO_OTHERPLPROPS - Send other player's properties
///
/// Sent when a new player enters the level or updates properties.
#[derive(Debug, Clone, PartialEq)]
pub struct OtherPlayerPropsPacket {
    /// Player ID
    pub player_id: u16,
    /// Property data (encoded)
    pub data: Vec<u8>,
}

/// PLO_NPCPROPS - Send NPC properties to client
///
/// Updates NPC state on client.
#[derive(Debug, Clone, PartialEq)]
pub struct NpcPropsPacket {
    /// NPC ID
    pub npc_id: u32,
    /// Modification time
    pub modtime: u64,
    /// Property data (encoded)
    pub data: Vec<u8>,
}

/// PLI_ARROWADD / PLO_ARROWADD - Fire an arrow
///
#[derive(Debug, Clone, PartialEq)]
pub struct ArrowAddPacket {
    /// Arrow ID
    pub arrow_id: u32,
    /// Owner player ID
    pub owner_id: u16,
    /// X position in pixels
    pub x: f32,
    /// Y position in pixels
    pub y: f32,
    /// X velocity
    pub vx: f32,
    /// Y velocity
    pub vy: f32,
}

/// PLI_HORSEADD / PLO_HORSEADD - Spawn a horse
///
#[derive(Debug, Clone, PartialEq)]
pub struct HorseAddPacket {
    /// Horse ID
    pub horse_id: u32,
    /// Owner player ID
    pub owner_id: u16,
    /// X position in pixels
    pub x: i16,
    /// Y position in pixels
    pub y: i16,
    /// Horse image name
    pub image: String,
    /// Horse bushes (bomb count)
    pub bushes: u8,
}

/// PLI_HORSEDEL / PLO_HORSEDEL - Remove a horse
///
#[derive(Debug, Clone, PartialEq)]
pub struct HorseDelPacket {
    /// Horse ID to delete
    pub horse_id: u32,
}

// ============================================================================
// ENCODING/DECODING TRAITS
// ============================================================================

/// Error type for packet encoding/decoding
#[derive(Debug, Clone, PartialEq)]
pub enum PacketError {
    /// Not enough data to decode packet
    InsufficientData,
    /// Invalid packet data
    InvalidData,
    /// Invalid string encoding
    InvalidString,
    /// IO error
    Io(String),
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketError::InsufficientData => write!(f, "Insufficient data"),
            PacketError::InvalidData => write!(f, "Invalid data"),
            PacketError::InvalidString => write!(f, "Invalid string"),
            PacketError::Io(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for PacketError {}

/// Trait for encoding packets to bytes
pub trait Encode {
    /// Encode the packet to a byte buffer
    fn encode(&self, buf: &mut BytesMut) -> Result<(), PacketError>;
}

/// Trait for decoding packets from bytes
pub trait Decode: Sized {
    /// Decode a packet from a byte buffer
    fn decode(buf: &mut BytesMut) -> Result<Self, PacketError>;
}

// ============================================================================
// IMPLEMENTATIONS
// ============================================================================

impl Encode for String {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), PacketError> {
        let len = self.len() as u8;
        buf.put_u8(len);
        buf.put_slice(self.as_bytes());
        Ok(())
    }
}

impl Decode for String {
    fn decode(buf: &mut BytesMut) -> Result<Self, PacketError> {
        if buf.remaining() < 1 {
            return Err(PacketError::InsufficientData);
        }
        let len = buf.get_u8() as usize;
        if buf.remaining() < len {
            return Err(PacketError::InsufficientData);
        }
        let mut bytes = vec![0u8; len];
        buf.copy_to_slice(&mut bytes);
        String::from_utf8(bytes).map_err(|_| PacketError::InvalidString)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_string_encode_decode() {
        let mut buf = BytesMut::new();
        let original = "Hello, World!".to_string();

        original.encode(&mut buf).unwrap();
        let decoded = String::decode(&mut buf).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_move_packet() {
        let packet = MovePacket {
            player_id: 123,
            x: 160,
            y: 320,
        };

        assert_eq!(packet.player_id, 123);
        assert_eq!(packet.x, 160);
        assert_eq!(packet.y, 320);
    }

    #[test]
    fn test_bomb_add_packet() {
        let packet = BombAddPacket {
            bomb_id: 456,
            owner_id: 789,
            x: 100,
            y: 200,
            owner_x: 105,
            owner_y: 205,
            power: 2,
            bomb_type: 0,
        };

        assert_eq!(packet.bomb_id, 456);
        assert_eq!(packet.owner_id, 789);
        assert_eq!(packet.power, 2);
    }

    #[test]
    fn test_to_all_packet() {
        let packet = ToAllPacket {
            message: "Hello everyone!".to_string(),
        };

        assert_eq!(packet.message, "Hello everyone!");
    }

    #[test]
    fn test_hurt_player_packet() {
        let packet = HurtPlayerPacket {
            player_id: 100,
            damage: 2,
            hurt_dx: 1,
            hurt_dy: 0,
        };

        assert_eq!(packet.player_id, 100);
        assert_eq!(packet.damage, 2);
        assert_eq!(packet.hurt_dx, 1);
        assert_eq!(packet.hurt_dy, 0);
    }

    #[test]
    fn test_item_add_packet() {
        let packet = ItemAddPacket {
            item_id: 999,
            x: 50,
            y: 75,
            image: "rupee.png".to_string(),
        };

        assert_eq!(packet.item_id, 999);
        assert_eq!(packet.image, "rupee.png");
    }

    #[test]
    fn test_board_modify_packet() {
        let packet = BoardModifyPacket {
            x: 10,
            y: 10,
            width: 5,
            height: 5,
            tiles: vec![100; 25],
        };

        assert_eq!(packet.x, 10);
        assert_eq!(packet.y, 10);
        assert_eq!(packet.width, 5);
        assert_eq!(packet.height, 5);
        assert_eq!(packet.tiles.len(), 25);
    }
}
