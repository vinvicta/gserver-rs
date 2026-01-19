//! # Packet Builder
//!
//! This module provides builder functions for constructing server-to-client packets.
//!
//! ## Design Philosophy
//!
//! - **Exact byte compatibility**: All packets match C++ implementation exactly
//! - **Well-documented**: Every packet builder is documented with its purpose and format
//! - **Type-safe**: Use Rust's type system to prevent invalid data
//! - **Testable**: All packet builders can be tested with round-trip encoding
//!
//! ## Usage
//!
//! ```rust
//! use gserver_protocol::packet_builder::*;
//! use bytes::BytesMut;
//!
//! let mut buf = BytesMut::new();
//! build_level_name(&mut buf, "onlinestartlocal.nw");
//! ```

use bytes::{BufMut, BytesMut};
use super::{codecs::*, packets::*};

/// Build a level name packet (PLO_LEVELNAME = 6)
///
/// # Purpose
/// Sends the name of the current level to the client.
/// This is typically sent after a level warp or login.
///
/// # Packet Format
/// ```text
/// {6}{GSTRING level}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `level` - Level name (e.g., "onlinestartlocal.nw")
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_LEVELNAME << level` in PlayerClient.cpp:1320
///
/// # Example
/// ```rust
/// use gserver_protocol::packet_builder::*;
/// use bytes::BytesMut;
///
/// let mut buf = BytesMut::new();
/// build_level_name(&mut buf, "onlinestartlocal.nw");
/// ```
pub fn build_level_name(buf: &mut BytesMut, level: &str) {
    buf.put_u8(PacketTypeOut::LevelName.as_u8().wrapping_add(32));
    write_gstring(buf, level);
    buf.put_u8(b'\n');
}

/// Build a level board packet (PLO_RAWDATA = 100)
///
/// # Purpose
/// Sends raw level board data (tiles) to the client.
/// This is the main data packet for level loading.
///
/// # Packet Format
/// ```text
/// {100}{GINT4 size}{RAW_DATA}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `size` - Size of the raw data in bytes
/// * `data` - Raw board data (64x64 tiles x 2 bytes)
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_RAWDATA >> (int)size` in PlayerClient.cpp:1325
///
/// # Notes
/// - The board data contains 64x64 tiles, each tile is 2 bytes (16-bit tile index)
/// - Total size is typically 8192 bytes (64 * 64 * 2)
/// - Tiles are stored in row-major order (x first, then y)
pub fn build_raw_data(buf: &mut BytesMut, size: u32, data: &[u8]) {
    // PLO_RAWDATA (100) is NOT GChar-encoded and does NOT get a newline
    buf.put_u8(PacketTypeOut::RawData.as_u8());
    write_gint4(buf, size as i32);
    buf.put_slice(data);
}

/// Build a level modification time packet (PLO_LEVELMODTIME = 39)
///
/// # Purpose
/// Sends the file modification time of the level.
/// Used for client-side caching validation.
///
/// # Packet Format
/// ```text
/// {39}{GINT4 modtime}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `modtime` - Level file modification time (Unix timestamp)
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_LEVELMODTIME >> (long long)modTime` in PlayerClient.cpp:1349
pub fn build_level_modtime(buf: &mut BytesMut, modtime: u64) {
    buf.put_u8(PacketTypeOut::LevelModTime.as_u8().wrapping_add(32));
    write_gint4(buf, modtime as i32);
    buf.put_u8(b'\n');
}

/// Build a set active level packet (PLO_SETACTIVELEVEL = 156)
///
/// # Purpose
/// Sets the active level for the client.
/// This tells the client which level to focus on.
///
/// # Packet Format
/// ```text
/// {156}{GSTRING level}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `level` - Level name
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_SETACTIVELEVEL << level` in PlayerClient.cpp:1386
pub fn build_set_active_level(buf: &mut BytesMut, level: &str) {
    buf.put_u8(PacketTypeOut::SetActiveLevel.as_u8().wrapping_add(32));
    write_gstring(buf, level);
    buf.put_u8(b'\n');
}

/// Build a new world time packet (PLO_NEWWORLDTIME = 42)
///
/// # Purpose
/// Sends the current server world time to the client.
/// Used for time-based events and day/night cycles.
///
/// # Packet Format
/// ```text
/// {42}{GINT4 time}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `time` - World time value
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_NEWWORLDTIME << CString().writeGInt4(time)` in PlayerClient.cpp:1381
pub fn build_new_world_time(buf: &mut BytesMut, time: u32) {
    buf.put_u8(PacketTypeOut::NewWorldTime.as_u8().wrapping_add(32));
    write_gint4(buf, time as i32);
    buf.put_u8(b'\n');
}

/// Build a ghost icon packet (PLO_GHOSTICON = 174)
///
/// # Purpose
/// Tells the client whether ghost players (trial accounts) are present.
/// A value of 0 means no ghosts.
///
/// # Packet Format
/// ```text
/// {174}{GCHAR count}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `count` - Number of ghost players (0 = no ghosts)
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_GHOSTICON >> (char)count` in PlayerClient.cpp:1370
pub fn build_ghost_icon(buf: &mut BytesMut, count: u8) {
    buf.put_u8(PacketTypeOut::GhostIcon.as_u8().wrapping_add(32));
    write_gchar(buf, count as i8);
    buf.put_u8(b'\n');
}

/// Build an is-leader packet (PLO_ISLEADER = 10)
///
/// # Purpose
/// Tells the client they are the leader of the level.
/// The leader has special privileges like controlling NPCs.
///
/// # Packet Format
/// ```text
/// {10}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_ISLEADER` in PlayerClient.cpp:1377
pub fn build_is_leader(buf: &mut BytesMut) {
    buf.put_u8(PacketTypeOut::IsLeader.as_u8().wrapping_add(32));
    buf.put_u8(b'\n');
}

/// Build a signature packet (PLO_SIGNATURE = 25)
///
/// # Purpose
/// Sends a signature byte to verify the server type.
/// 73 (0x49) indicates more than 8 players will be playing.
///
/// # Packet Format
/// ```text
/// {25}{GCHAR signature}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `signature` - Signature byte (typically 73)
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_SIGNATURE >> (char)73` in Player.cpp:658
pub fn build_signature(buf: &mut BytesMut, signature: u8) {
    buf.put_u8(PacketTypeOut::Signature.as_u8().wrapping_add(32));
    write_gchar(buf, signature as i8);
    buf.put_u8(b'\n');
}

/// Build a warp failed packet (PLO_WARPFAILED = 15)
///
/// # Purpose
/// Tells the client that a level warp failed.
/// Sent when the requested level cannot be loaded.
///
/// # Packet Format
/// ```text
/// {15}{GSTRING level}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `level` - Level name that failed to load
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_WARPFAILED << level` in PlayerClient.cpp:1267
pub fn build_warp_failed(buf: &mut BytesMut, level: &str) {
    buf.put_u8(PacketTypeOut::WarpFailed.as_u8().wrapping_add(32));
    write_gstring(buf, level);
    buf.put_u8(b'\n');
}

/// Build an other player props packet (PLO_OTHERPLPROPS = 8)
///
/// # Purpose
/// Sends properties of another player to the client.
/// Used when players join/leave levels or update their properties.
///
/// # Packet Format
/// ```text
/// {8}{GSHORT player_id}{PROPERTY_DATA}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `player_id` - ID of the other player
/// * `props_data` - Serialized property data
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_OTHERPLPROPS >> (short)id` in Player.cpp:737
pub fn build_other_player_props(buf: &mut BytesMut, player_id: u16, props_data: &[u8]) {
    buf.put_u8(PacketTypeOut::OtherPlayerProps.as_u8().wrapping_add(32));
    write_gshort(buf, player_id as i16);
    buf.put_slice(props_data);
    buf.put_u8(b'\n');
}

/// Build an add player packet (PLO_ADDPLAYER = 55)
///
/// # Purpose
/// Adds a player to the client's player list.
/// Sent when a new player connects or joins the level.
///
/// # Packet Format
/// ```text
/// {55}{GSHORT player_id}{GSTRING account_name}{PROPERTY_DATA}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `player_id` - ID of the player to add
/// * `account_name` - Account name of the player
/// * `props_data` - Serialized property data
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_ADDPLAYER >> (short)id` in Player.cpp:731
pub fn build_add_player(buf: &mut BytesMut, player_id: u16, account_name: &str, props_data: &[u8]) {
    buf.put_u8(PacketTypeOut::AddPlayer.as_u8().wrapping_add(32));
    write_gshort(buf, player_id as i16);
    write_gstring(buf, account_name);
    buf.put_slice(props_data);
    buf.put_u8(b'\n');
}

/// Build a chat packet (PLO_TOALL = 13)
///
/// # Purpose
/// Sends a chat message from a player to all players.
///
/// # Packet Format
/// ```text
/// {13}{GSTRING message}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `message` - Chat message
///
/// # C++ Equivalence
/// Matches chat message sending in various Player functions
pub fn build_chat(buf: &mut BytesMut, message: &str) {
    buf.put_u8(PacketTypeOut::ToAll.as_u8().wrapping_add(32));
    write_gstring(buf, message);
    buf.put_u8(b'\n');
}

/// Build a disconnect message packet (PLO_DISCMESSAGE = 16)
///
/// # Purpose
/// Sends a disconnect message to the client before disconnecting.
///
/// # Packet Format
/// ```text
/// {16}{GSTRING message}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `message` - Disconnect message
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_DISCMESSAGE << message` throughout Player.cpp
pub fn build_disconnect_message(buf: &mut BytesMut, message: &str) {
    buf.put_u8(PacketTypeOut::DiscMessage.as_u8().wrapping_add(32));
    write_gstring(buf, message);
    buf.put_u8(b'\n');
}

/// Build a player warp packet (PLO_PLAYERWARP = 14)
///
/// # Purpose
/// Warps the player to a new location (server-initiated).
/// This is the CRITICAL packet that triggers the client to send PLI_LEVELWARP.
///
/// # Packet Format
/// ```text
/// {46}{GCHAR x}{GCHAR y}{GSTRING level_name}
/// ```
/// Note: 46 = 14 + 32 (GChar encoding)
/// x and y are GChar values: pixel_coordinate / 8 (halftiles)
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `x` - X coordinate in **pixels** (will be divided by 8 for GChar)
/// * `y` - Y coordinate in **pixels** (will be divided by 8 for GChar)
/// * `level_name` - Level name to warp to (e.g., "onlinestartlocal.nw")
///
/// # C++ Equivalence
/// Matches PlayerClient.cpp:1170:
/// ```cpp
/// sendPacket(CString() >> (char)PLO_PLAYERWARP
///     << getProp<PlayerProp::X>().serialize()   // GChar: pixel / 8
///     << getProp<PlayerProp::Y>().serialize()   // GChar: pixel / 8
///     << levelName);
/// ```
/// PropertyTileCoordinate::serialize() writes: `pixelCoordinate / 8` as GChar
pub fn build_player_warp(buf: &mut BytesMut, x: i32, y: i32, level_name: &str) {
    buf.put_u8(PacketTypeOut::PlayerWarp.as_u8().wrapping_add(32));
    // X and Y are stored as pixel coordinates, serialized as GChar = pixel / 8
    // This represents halftiles (8 pixels = 0.5 tiles)
    let x_halftile = (x / 8) as i8;
    let y_halftile = (y / 8) as i8;
    write_gchar(buf, x_halftile);
    write_gchar(buf, y_halftile);
    write_gstring(buf, level_name);
    buf.put_u8(b'\n');
}

/// Build a clear weapons packet (PLO_CLEARWEAPONS = 194)
///
/// # Purpose
/// Clears all weapons from the client.
/// Sent on login to initialize the weapon list.
///
/// # Packet Format
/// ```text
/// {194}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_CLEARWEAPONS` in PlayerRC.cpp:211
pub fn build_clear_weapons(buf: &mut BytesMut) {
    buf.put_u8(PacketTypeOut::ClearWeapons.as_u8().wrapping_add(32));
    buf.put_u8(b'\n');
}

/// Build a server list connected packet (custom)
///
/// # Purpose
/// Tells the client that the server is connected to the listserver.
///
/// # Packet Format
/// ```text
/// {168}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_SERVERLISTCONNECTED` in PlayerRC.cpp:228
pub fn build_serverlist_connected(buf: &mut BytesMut) {
    // This is custom packet 168
    buf.put_u8(168u8.wrapping_add(32));
    buf.put_u8(b'\n');
}

/// Build a has NPC server packet (PLO_HASNPCSERVER = 44)
///
/// # Purpose
/// Tells the client that the server has an NPC server.
/// Disables certain client-side features.
///
/// # Packet Format
/// ```text
/// {44}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_HASNPCSERVER` in Player.cpp:673
pub fn build_has_npc_server(buf: &mut BytesMut) {
    buf.put_u8(PacketTypeOut::HasNpcServer.as_u8().wrapping_add(32));
    buf.put_u8(b'\n');
}

/// Build a max upload file size packet (PLO_RC_MAXUPLOADFILESIZE = 103)
///
/// # Purpose
/// Tells the RC client the maximum file upload size.
///
/// # Packet Format
/// ```text
/// {103}{GINT4 size}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `size` - Maximum upload file size in bytes
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_RC_MAXUPLOADFILESIZE >> (long long)size` in PlayerRC.cpp:250
pub fn build_max_upload_file_size(buf: &mut BytesMut, size: u64) {
    buf.put_u8(PacketTypeOut::RcMaxUploadFileSize.as_u8().wrapping_add(32));
    write_gint4(buf, size as i32);
    buf.put_u8(b'\n');
}

/// Build a staff guilds packet (PLO_STAFFGUILDS = 47)
///
/// # Purpose
/// Sends the list of staff guilds to the RC client.
/// These guilds are shown in the "Staff" section of the playerlist.
///
/// # Packet Format
/// ```text
/// {47}{GSTRING guild1},{GSTRING guild2},...
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `guilds` - List of staff guild names
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_STAFFGUILDS` in PlayerRC.cpp:234
pub fn build_staff_guilds(buf: &mut BytesMut, guilds: &[String]) {
    buf.put_u8(PacketTypeOut::StaffGuilds.as_u8().wrapping_add(32));
    for (i, guild) in guilds.iter().enumerate() {
        if i > 0 {
            buf.put_u8(b',');
        }
        write_gstring(buf, guild);
    }
    buf.put_u8(b'\n');
}

/// Build a status list packet (PLO_STATUSLIST = 180)
///
/// # Purpose
/// Sends the list of available status icons to the client.
///
/// # Packet Format
/// ```text
/// {180}{GSTRING status1},{GSTRING status2},...
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `statuses` - List of status icon names
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_STATUSLIST` in PlayerRC.cpp:242
pub fn build_status_list(buf: &mut BytesMut, statuses: &[String]) {
    buf.put_u8(PacketTypeOut::StatusList.as_u8().wrapping_add(32));
    for (i, status) in statuses.iter().enumerate() {
        if i > 0 {
            buf.put_u8(b',');
        }
        buf.put_slice(status.as_bytes());
    }
    buf.put_u8(b'\n');
}

/// Build an RC chat packet (PLO_RC_CHAT)
///
/// # Purpose
/// Sends a chat message to the RC client.
///
/// # Packet Format
/// ```text
/// {79}{GSTRING message}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `message` - Chat message
///
/// # C++ Equivalence
/// Matches `CString() >> (char)PLO_RC_CHAT << message` in PlayerRC.cpp:224
pub fn build_rc_chat(buf: &mut BytesMut, message: &str) {
    // PLO_RC_CHAT is 79
    buf.put_u8(79u8.wrapping_add(32));
    write_gstring(buf, message);
    buf.put_u8(b'\n');
}

/// Build a showimg packet (PLO_SHOWIMG = 160)
///
/// # Purpose
/// Displays an overlay image on the client.
///
/// # Packet Format
/// ```text
/// {160}{index},{x},{y},{image},{r},{g},{b},{zoom},{mode},{params}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `index` - Image index (0-255)
/// * `x` - X position (pixels)
/// * `y` - Y position (pixels)
/// * `image` - Image filename
/// * `r` - Red colorization (0-255)
/// * `g` - Green colorization (0-255)
/// * `b` - Blue colorization (0-255)
/// * `zoom` - Zoom level (256 = 100%)
/// * `mode` - Mode flags (0x01=transparent, 0x02=parallax)
/// * `params` - Animation parameters
///
/// # C++ Equivalence
/// Matches showimg packet in Player.cpp
pub fn build_showimg(buf: &mut BytesMut, index: u8, x: f32, y: f32, image: &str,
                    r: u8, g: u8, b: u8, zoom: i16, mode: u8, params: u32) {
    buf.put_u8(160u8.wrapping_add(32));
    write_gstring(buf, &format!("{},{},{},{},{},{},{},{},{},{}",
        index, x, y, image, r, g, b, zoom, mode, params));
    buf.put_u8(b'\n');
}

/// Build a hideimg packet (PLO_HIDEIMG = 161)
///
/// # Purpose
/// Hides an overlay image.
///
/// # Packet Format
/// ```text
/// {161}{index}
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `index` - Image index to hide
///
/// # C++ Equivalence
/// Matches hideimg packet handling
pub fn build_hideimg(buf: &mut BytesMut, index: u8) {
    buf.put_u8(161u8.wrapping_add(32));
    write_gstring(buf, &index.to_string());
    buf.put_u8(b'\n');
}

/// Build a changeimg packet (PLO_CHANGEIMG = 162)
///
/// # Purpose
/// Changes properties of an existing overlay image.
///
/// # Packet Format
/// ```text
/// {162}{index},{x},{y},{r},{g},{b},{zoom},{mode}
/// ```
pub fn build_changeimg(buf: &mut BytesMut, index: u8, x: f32, y: f32,
                       r: u8, g: u8, b: u8, zoom: i16, mode: u8) {
    buf.put_u8(162u8.wrapping_add(32));
    write_gstring(buf, &format!("{},{},{},{},{},{},{},{}",
        index, x, y, r, g, b, zoom, mode));
    buf.put_u8(b'\n');
}

/// Build a changeimgvis packet (PLO_CHANGEIMGVIS = 163)
///
/// # Purpose
/// Changes visibility of an overlay image.
///
/// # Packet Format
/// ```text
/// {163}{index},{visible}
/// ```
pub fn build_changeimgvis(buf: &mut BytesMut, index: u8, visible: bool) {
    buf.put_u8(163u8.wrapping_add(32));
    write_gstring(buf, &format!("{},{}", index, if visible { 1 } else { 0 }));
    buf.put_u8(b'\n');
}

/// Build a flag set packet (PLO_FLAGSET = 18)
///
/// # Purpose
/// Sets a flag on the client.
///
/// # Packet Format
/// ```text
/// {18}{flag_name}={flag_value}
/// or
/// {18}{flag_name}  (for boolean true)
/// ```
///
/// # Arguments
/// * `buf` - Buffer to write the packet to
/// * `flag_name` - Name of the flag (e.g., "server.flag.name")
/// * `flag_value` - Value of the flag (empty string for boolean true)
///
/// # C++ Equivalence
/// Matches flag setting in PlayerClient::sendLogin()
pub fn build_flag_set(buf: &mut BytesMut, flag_name: &str, flag_value: &str) {
    buf.put_u8(18u8.wrapping_add(32));
    write_gstring(buf, flag_name);
    if !flag_value.is_empty() {
        buf.put_u8(b'=');
        buf.put_slice(flag_value.as_bytes());
    }
    buf.put_u8(b'\n');
}

/// Build a bigmap packet (PLO_BIGMAP = 153)
///
/// # Purpose
/// Sends bigmap data to the client.
///
/// # Packet Format
/// ```text
/// {153}{gmap_image}
/// ```
pub fn build_bigmap(buf: &mut BytesMut, gmap_image: &str) {
    buf.put_u8(153u8.wrapping_add(32));
    write_gstring(buf, gmap_image);
    buf.put_u8(b'\n');
}

/// Build a minimap packet (PLO_MINIMAP = 154)
///
/// # Purpose
/// Sends minimap data to the client.
///
/// # Packet Format
/// ```text
/// {154}{minimap_image}
/// ```
pub fn build_minimap(buf: &mut BytesMut, minimap_image: &str) {
    buf.put_u8(154u8.wrapping_add(32));
    write_gstring(buf, minimap_image);
    buf.put_u8(b'\n');
}

/// Build a chest packet (PLO_CHEST = 101)
///
/// # Purpose
/// Sends chest data to the client.
///
/// # Packet Format
/// ```text
/// {101}{x},{y},{item},{sign}
/// ```
pub fn build_chest(buf: &mut BytesMut, x: u8, y: u8, item: u8, sign: u8) {
    buf.put_u8(101u8.wrapping_add(32));
    write_gstring(buf, &format!("{},{},{},{}", x, y, item, sign));
    buf.put_u8(b'\n');
}

/// Build a sign packet (PLO_SIGN = 102)
///
/// # Purpose
/// Sends sign data to the client.
///
/// # Packet Format
/// ```text
/// {102}{x},{y},{encoded_text}
/// ```
pub fn build_sign(buf: &mut BytesMut, x: u8, y: u8, encoded_text: &str) {
    buf.put_u8(102u8.wrapping_add(32));
    write_gstring(buf, &format!("{},{}", x, y));
    buf.put_slice(encoded_text.as_bytes());
    buf.put_u8(b'\n');
}

/// Build a board modify packet (PLO_BOARDMODIFY = 48)
///
/// # Purpose
/// Modifies the board tiles.
///
/// # Packet Format
/// ```text
/// {48}{x},{y},{w},{h}{tiles_data}
/// ```
///
/// # C++ Equivalence
/// Matches board modification in Level.cpp
pub fn build_board_modify(buf: &mut BytesMut, x: u8, y: u8, w: u8, h: u8, tiles: &[u8]) {
    buf.put_u8(48u8.wrapping_add(32));
    write_gstring(buf, &format!("{},{},{},{}", x, y, w, h));
    buf.put_slice(tiles);
    buf.put_u8(b'\n');
}

/// Build an NPC weapon add packet (PLO_NPCWEAPONADD = 193)
///
/// # Purpose
/// Adds a weapon to the client's weapon list.
///
/// # Packet Format
/// ```text
/// {193}{weapon_name}
/// ```
pub fn build_npc_weapon_add(buf: &mut BytesMut, weapon_name: &str) {
    buf.put_u8(193u8.wrapping_add(32));
    write_gstring(buf, weapon_name);
    buf.put_u8(b'\n');
}

/// Build an NPC weapon delete packet (PLO_NPCWEAPONDEL = 27)
///
/// # Purpose
/// Removes a weapon from the client's weapon list.
///
/// # Packet Format
/// ```text
/// {27}{weapon_name}
/// ```
pub fn build_npc_weapon_del(buf: &mut BytesMut, weapon_name: &str) {
    buf.put_u8(27u8.wrapping_add(32));
    write_gstring(buf, weapon_name);
    buf.put_u8(b'\n');
}

/// Build a start message packet (PLO_STARTMESSAGE = 11)
///
/// # Purpose
/// Sends the server start message.
///
/// # Packet Format
/// ```text
/// {11}{message}
/// ```
pub fn build_start_message(buf: &mut BytesMut, message: &str) {
    buf.put_u8(11u8.wrapping_add(32));
    write_gstring(buf, message);
    buf.put_u8(b'\n');
}

/// Build a server text packet (PLO_SERVERTEXT = 155)
///
/// # Purpose
/// Sends server text/announcement.
///
/// # Packet Format
/// ```text
/// {155}{text}
/// ```
pub fn build_server_text(buf: &mut BytesMut, text: &str) {
    buf.put_u8(155u8.wrapping_add(32));
    write_gstring(buf, text);
    buf.put_u8(b'\n');
}

/// Build an RPG window packet (PLO_RPGWINDOW = 28)
///
/// # Purpose
/// Displays an RPG-style dialog window.
///
/// # Packet Format
/// ```text
/// {28}{message}
/// ```
pub fn build_rpg_window(buf: &mut BytesMut, message: &str) {
    buf.put_u8(28u8.wrapping_add(32));
    write_gstring(buf, message);
    buf.put_u8(b'\n');
}

/// Build a horse add packet (PLO_HORSEADD = 52)
///
/// # Purpose
/// Adds a horse to the level.
///
/// # Packet Format
/// ```text
/// {52}{horse_id},{x},{y},{horse_image}
/// ```
pub fn build_horse_add(buf: &mut BytesMut, horse_id: u8, x: u8, y: u8, horse_image: &str) {
    buf.put_u8(52u8.wrapping_add(32));
    write_gstring(buf, &format!("{},{},{},{}", horse_id, x, y, horse_image));
    buf.put_u8(b'\n');
}

/// Build a horse delete packet (PLO_HORSEDEL = 53)
///
/// # Purpose
/// Removes a horse from the level.
///
/// # Packet Format
/// ```text
/// {53}{horse_id}
/// ```
pub fn build_horse_del(buf: &mut BytesMut, horse_id: u8) {
    buf.put_u8(53u8.wrapping_add(32));
    write_gstring(buf, &horse_id.to_string());
    buf.put_u8(b'\n');
}

/// Build an explosion packet (PLO_EXPLOSION = 59)
///
/// # Purpose
/// Creates an explosion effect.
///
/// # Packet Format
/// ```text
/// {59}{x},{y}
/// ```
pub fn build_explosion(buf: &mut BytesMut, x: f32, y: f32) {
    buf.put_u8(59u8.wrapping_add(32));
    write_gstring(buf, &format!("{},{}", x, y));
    buf.put_u8(b'\n');
}

/// Build a bomb add packet (PLO_BOMBADD = 50)
///
/// # Purpose
/// Adds a bomb to the level.
///
/// # Packet Format
/// ```text
/// {50}{bomb_id},{x},{y},{power},{owner_id}
/// ```
pub fn build_bomb_add(buf: &mut BytesMut, bomb_id: u8, x: f32, y: f32, power: u8, owner_id: u32) {
    buf.put_u8(50u8.wrapping_add(32));
    write_gstring(buf, &format!("{},{},{},{},{}", bomb_id, x, y, power, owner_id));
    buf.put_u8(b'\n');
}

/// Build a bomb delete packet (PLO_BOMBDEL = 51)
///
/// # Purpose
/// Removes a bomb from the level.
///
/// # Packet Format
/// ```text
/// {51}{bomb_id}
/// ```
pub fn build_bomb_del(buf: &mut BytesMut, bomb_id: u8) {
    buf.put_u8(51u8.wrapping_add(32));
    write_gstring(buf, &bomb_id.to_string());
    buf.put_u8(b'\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level_name_packet() {
        let mut buf = BytesMut::new();
        build_level_name(&mut buf, "test.nw");

        // First byte should be GChar-encoded packet type (6 + 32 = 38)
        assert_eq!(buf[0], 38);

        // Should end with newline
        assert_eq!(buf[buf.len() - 1], b'\n');
    }

    #[test]
    fn test_raw_data_packet() {
        let data = vec![0u8; 8192]; // 64x64 tiles x 2 bytes
        let mut buf = BytesMut::new();
        build_raw_data(&mut buf, 8192, &data);

        // First byte should be packet type 100 (no GChar encoding for RAWDATA)
        assert_eq!(buf[0], 100);

        // Size should be 1 (type) + 4 (size) + 8192 (data)
        assert_eq!(buf.len(), 8197);
    }

    #[test]
    fn test_signature_packet() {
        let mut buf = BytesMut::new();
        build_signature(&mut buf, 73);

        // First byte should be GChar-encoded packet type (25 + 32 = 57)
        assert_eq!(buf[0], 57);

        // Signature should be 73 + 32 = 105 (GChar-encoded)
        assert_eq!(buf[1], 105);
    }

    #[test]
    fn test_chat_packet() {
        let mut buf = BytesMut::new();
        build_chat(&mut buf, "Hello, world!");

        // First byte should be GChar-encoded packet type (13 + 32 = 45)
        assert_eq!(buf[0], 45);

        // Should end with newline
        assert_eq!(buf[buf.len() - 1], b'\n');
    }
}
