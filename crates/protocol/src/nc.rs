//! NC (NPC Server) Protocol
//!
//! # Purpose
//! Implements the Graal Online NPC Server communication protocol.
//!
//! # C++ Equivalence
//! Matches `PlayerNC` and `PlayerNCPackets` from:
//! - PlayerNC.cpp - NC client implementation
//! - PlayerNCPackets.cpp - NC packet handling
//!
//! # NC Protocol Overview
//!
//! The NPC Server (NC) is a separate process that handles:
//! - NPC AI and behavior
//! - Weapon scripts
//! - Level NPCs
//! - Database NPCs
//!
//! ## Communication Flow
//! ```text
//! Game Server <--TCP--> NPC Server
//!     |
//!     v
//!   Clients
//! ```
//!
//! # Packet Types
//!
//! ## Server-to-NC (PLO_NC_*)
//! - PLO_NC_NPCADD = 200 - Add NPC to level
//! - PLO_NC_NPCDEL = 201 - Delete NPC from level
//! - PLO_NC_NPCRESET = 202 - Reset NPC
//! - PLO_NC_NPCPROPS = 203 - Update NPC properties
//! - PLO_NC_NPCSCRIPTGET = 204 - Get NPC script
//! - PLO_NC_NPCSCRIPTSET = 205 - Set NPC script
//! - PLO_NC_NPCWARP = 206 - Warp NPC
//! - PLO_NC_CLASSADD = 207 - Add NPC class
//! - PLO_NC_CLASSDEL = 208 - Delete NPC class
//! - PLO_NC_WEAPONADD = 209 - Add weapon
//! - PLO_NC_WEAPONDEL = 210 - Delete weapon
//! - PLO_NC_LEVELPLAYERS = 211 - Update players in level
//! - PLO_NC_PLAYERACTION = 212 - Player action on NPC
//! - PLO_NC_PLAYERCHAT = 213 - Player chat message
//! - PLO_NC_PLAYERLOGIN = 214 - Player logged in
//! - PLO_NC_PLAYERLOGOUT = 215 - Player logged out
//!
//! ## NC-to-Server (PLI_NC_*)
//! - PLI_NC_PACKET = 200 - Generic NC packet
//! - PLI_NC_NPCPROPS = 201 - NPC properties update
//! - PLI_NC_NPCWARP = 202 - NPC warp request
//! - PLI_NC_PLAYERWARP = 203 - Warp player
//! - PLI_NC_PLAYERPROPS = 204 - Update player props
//! - PLI_NC_SHOWIMG = 205 - Show image
//! - PLI_NC_HIDEIMG = 206 - Hide image
//! - PLI_NC_PLAYMIDI = 207 - Play MIDI
//! - PLI_NC_STOPMIDI = 208 - Stop MIDI
//! - PLI_NC_SETPLAYERPROPS = 209 - Set player properties
//! - PLI_NC_MESSAGERC = 210 - Message to RC
//! - PLI_NC_FLAGSET = 211 - Set flag
//! - PLI_NC_FLAGCLEAR = 212 - Clear flag
//! - PLI_NC_TRIGGERACTION = 213 - Trigger action
//! - PLI_NC_TIMEOUT = 214 - Script timeout
//! - PLI_NC_EFFECT = 215 - Play effect
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use gserver_protocol::nc::{NcPacket, NcHandler};
//!
//! // Create an NC packet
//! let packet = NcPacket::NpcAdd {
//!     id: "npc_123".to_string(),
//!     level: "test.nw".to_string(),
//!     x: 100,
//!     y: 100,
//!     image: "npc.png".to_string(),
//!     script: "".to_string(),
//! };
//! ```

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// NPC Server packet type (server-to-NC)
///
/// # C++ Equivalence
/// Matches PLO_NC_* packet types in IEnums.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NcPacketTypeOut {
    /// Add NPC to level
    NpcAdd = 200,

    /// Delete NPC from level
    NpcDel = 201,

    /// Reset NPC
    NpcReset = 202,

    /// Update NPC properties
    NpcProps = 203,

    /// Get NPC script
    NpcScriptGet = 204,

    /// Set NPC script
    NpcScriptSet = 205,

    /// Warp NPC
    NpcWarp = 206,

    /// Add NPC class
    ClassAdd = 207,

    /// Delete NPC class
    ClassDel = 208,

    /// Add weapon
    WeaponAdd = 209,

    /// Delete weapon
    WeaponDel = 210,

    /// Update players in level
    LevelPlayers = 211,

    /// Player action on NPC
    PlayerAction = 212,

    /// Player chat message
    PlayerChat = 213,

    /// Player logged in
    PlayerLogin = 214,

    /// Player logged out
    PlayerLogout = 215,
}

/// NPC Server packet type (NC-to-server)
///
/// # C++ Equivalence
/// Matches PLI_NC_* packet types in IEnums.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NcPacketTypeIn {
    /// Generic NC packet
    Packet = 200,

    /// NPC properties update
    NpcProps = 201,

    /// NPC warp request
    NpcWarp = 202,

    /// Warp player
    PlayerWarp = 203,

    /// Update player props
    PlayerProps = 204,

    /// Show image
    ShowImg = 205,

    /// Hide image
    HideImg = 206,

    /// Play MIDI
    PlayMidi = 207,

    /// Stop MIDI
    StopMidi = 208,

    /// Set player properties
    SetPlayerProps = 209,

    /// Message to RC
    MessageRc = 210,

    /// Set flag
    FlagSet = 211,

    /// Clear flag
    FlagClear = 212,

    /// Trigger action
    TriggerAction = 213,

    /// Script timeout
    Timeout = 214,

    /// Play effect
    Effect = 215,
}

impl NcPacketTypeIn {
    /// Parse from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            200 => Some(NcPacketTypeIn::Packet),
            201 => Some(NcPacketTypeIn::NpcProps),
            202 => Some(NcPacketTypeIn::NpcWarp),
            203 => Some(NcPacketTypeIn::PlayerWarp),
            204 => Some(NcPacketTypeIn::PlayerProps),
            205 => Some(NcPacketTypeIn::ShowImg),
            206 => Some(NcPacketTypeIn::HideImg),
            207 => Some(NcPacketTypeIn::PlayMidi),
            208 => Some(NcPacketTypeIn::StopMidi),
            209 => Some(NcPacketTypeIn::SetPlayerProps),
            210 => Some(NcPacketTypeIn::MessageRc),
            211 => Some(NcPacketTypeIn::FlagSet),
            212 => Some(NcPacketTypeIn::FlagClear),
            213 => Some(NcPacketTypeIn::TriggerAction),
            214 => Some(NcPacketTypeIn::Timeout),
            215 => Some(NcPacketTypeIn::Effect),
            _ => None,
        }
    }
}

/// NPC data
///
/// # C++ Equivalence
/// Matches TNPC class in NPC.h
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpcData {
    /// Unique NPC ID
    pub id: String,

    /// Level name
    pub level: String,

    /// X position (pixels)
    pub x: f32,

    /// Y position (pixels)
    pub y: f32,

    /// Image filename
    pub image: String,

    /// NPC script code
    pub script: String,

    /// NPC class/type
    pub class: String,

    /// NPC properties
    pub props: HashMap<String, String>,

    /// Is a database NPC (persistent)
    pub is_db_npc: bool,

    /// NPC sprite
    pub sprite: u32,

    /// NPC colors
    pub colors: String,

    /// NPC name (for display)
    pub name: String,

    /// NPC owner
    pub owner: String,

    /// NPC join position (for joining players)
    pub join_x: f32,

    /// NPC join Y position
    pub join_y: f32,
}

impl Default for NpcData {
    fn default() -> Self {
        Self {
            id: String::new(),
            level: String::new(),
            x: 0.0,
            y: 0.0,
            image: String::new(),
            script: String::new(),
            class: String::new(),
            props: HashMap::new(),
            is_db_npc: false,
            sprite: 2,
            colors: "2,0,10,4,18".to_string(),
            name: String::new(),
            owner: String::new(),
            join_x: 0.0,
            join_y: 0.0,
        }
    }
}

/// Level NPC reference
///
/// # C++ Equivalence
/// Matches level NPC references in TLevel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelNpc {
    /// NPC ID
    pub id: String,

    /// X position in level (tiles)
    pub x: f32,

    /// Y position in level (tiles)
    pub y: f32,
}

/// Player action on NPC
///
/// # C++ Equivalence
/// Matches player action events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NcPlayerAction {
    /// Player ID
    pub player_id: u16,

    /// NPC ID
    pub npc_id: String,

    /// Action type (click, touch, etc.)
    pub action: String,

    /// Action parameters
    pub params: HashMap<String, String>,
}

/// NPC Server packet (server-to-NC)
///
/// # C++ Equivalence
/// Matches packets sent to NPC server
#[derive(Debug, Clone)]
pub enum NcPacketOut {
    /// Add NPC to level
    NpcAdd(NpcData),

    /// Delete NPC from level
    NpcDel { npc_id: String },

    /// Reset NPC
    NpcReset { npc_id: String },

    /// Update NPC properties
    NpcProps { npc_id: String, props: HashMap<String, String> },

    /// Get NPC script
    NpcScriptGet { npc_id: String },

    /// Set NPC script
    NpcScriptSet { npc_id: String, script: String },

    /// Warp NPC
    NpcWarp { npc_id: String, x: f32, y: f32, level: Option<String> },

    /// Add NPC class
    ClassAdd { class_name: String, script: String },

    /// Delete NPC class
    ClassDel { class_name: String },

    /// Add weapon
    WeaponAdd {
        weapon_name: String,
        script: String,
        image: String,
    },

    /// Delete weapon
    WeaponDel { weapon_name: String },

    /// Update players in level
    LevelPlayers {
        level: String,
        players: Vec<NcPlayerData>,
    },

    /// Player action on NPC
    PlayerAction(NcPlayerAction),

    /// Player chat message
    PlayerChat { player_id: u16, message: String },

    /// Player logged in
    PlayerLogin {
        player_id: u16,
        account_name: String,
        level: String,
        x: f32,
        y: f32,
    },

    /// Player logged out
    PlayerLogout { player_id: u16 },
}

/// Player data for NC
///
/// # C++ Equivalence
/// Matches player data sent to NPC server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NcPlayerData {
    /// Player ID
    pub player_id: u16,

    /// Account name
    pub account_name: String,

    /// Nickname
    pub nick: String,

    /// Level name
    pub level: String,

    /// X position (pixels)
    pub x: f32,

    /// Y position (pixels)
    pub y: f32,

    /// Sprite type
    pub sprite: u32,

    /// Colors
    pub colors: String,

    /// Admin rights
    pub admin_rights: u32,
}

/// NPC Server packet (NC-to-server)
///
/// # C++ Equivalence
/// Matches packets received from NPC server
#[derive(Debug, Clone)]
pub enum NcPacketIn {
    /// NPC properties update
    NpcProps { npc_id: String, props: HashMap<String, String> },

    /// NPC warp request
    NpcWarp { npc_id: String, x: f32, y: f32 },

    /// Warp player
    PlayerWarp { player_id: u16, x: f32, y: f32, level: String },

    /// Update player props
    PlayerProps { player_id: u16, props: HashMap<String, String> },

    /// Show image
    ShowImg {
        player_id: u16,
        index: u8,
        x: f32,
        y: f32,
        image: String,
    },

    /// Hide image
    HideImg { player_id: u16, index: u8 },

    /// Play MIDI
    PlayMidi { player_id: u16, midi: String },

    /// Stop MIDI
    StopMidi { player_id: u16 },

    /// Set player properties
    SetPlayerProps { player_id: u16, props: HashMap<String, String> },

    /// Message to RC
    MessageRc { message: String },

    /// Set flag
    FlagSet {
        player_id: u16,
        flag: String,
        value: String,
    },

    /// Clear flag
    FlagClear { player_id: u16, flag: String },

    /// Trigger action
    TriggerAction {
        player_id: u16,
        action: String,
        params: HashMap<String, String>,
    },

    /// Script timeout
    Timeout { npc_id: String },

    /// Play effect
    Effect {
        x: f32,
        y: f32,
        effect: String,
    },
}

/// NPC Server handler
///
/// # Purpose
/// Handles communication with the NPC server
///
/// # C++ Equivalence
/// Matches TServer's NPC server communication
pub struct NcHandler {
    /// Connected to NPC server
    pub connected: bool,

    /// NPC server address
    pub address: String,

    /// NPCs managed by NC server
    pub npcs: HashMap<String, NpcData>,

    /// Level NPCs
    pub level_npcs: HashMap<String, Vec<LevelNpc>>,

    /// Players in each level
    pub level_players: HashMap<String, Vec<NcPlayerData>>,

    /// NPC classes
    pub classes: HashMap<String, String>,

    /// Weapons
    pub weapons: HashMap<String, String>,
}

impl NcHandler {
    /// Create a new NC handler
    pub fn new() -> Self {
        Self {
            connected: false,
            address: "127.0.0.1:14903".to_string(),
            npcs: HashMap::new(),
            level_npcs: HashMap::new(),
            level_players: HashMap::new(),
            classes: HashMap::new(),
            weapons: HashMap::new(),
        }
    }

    /// Connect to NPC server
    pub fn connect(&mut self, address: String) {
        self.address = address;
        self.connected = true;
    }

    /// Disconnect from NPC server
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    /// Add an NPC
    pub fn add_npc(&mut self, npc: NpcData) {
        let level = npc.level.clone();
        self.npcs.insert(npc.id.clone(), npc.clone());

        // Add to level NPCs
        self.level_npcs
            .entry(level)
            .or_insert_with(Vec::new)
            .push(LevelNpc {
                id: npc.id.clone(),
                x: npc.x / 16.0, // Convert to tiles
                y: npc.y / 16.0,
            });
    }

    /// Remove an NPC
    pub fn remove_npc(&mut self, npc_id: &str) -> bool {
        if let Some(npc) = self.npcs.remove(npc_id) {
            // Remove from level NPCs
            if let Some(npcs) = self.level_npcs.get_mut(&npc.level) {
                npcs.retain(|n| n.id != npc_id);
            }
            true
        } else {
            false
        }
    }

    /// Get an NPC
    pub fn get_npc(&self, npc_id: &str) -> Option<&NpcData> {
        self.npcs.get(npc_id)
    }

    /// Update player in level
    pub fn update_player(&mut self, player: NcPlayerData) {
        let level = player.level.clone();

        // Remove player from other levels
        for (_, players) in self.level_players.iter_mut() {
            players.retain(|p| p.player_id != player.player_id);
        }

        // Add to current level
        self.level_players
            .entry(level)
            .or_insert_with(Vec::new)
            .push(player);
    }

    /// Remove player
    pub fn remove_player(&mut self, player_id: u16) {
        for (_, players) in self.level_players.iter_mut() {
            players.retain(|p| p.player_id != player_id);
        }
    }

    /// Get players in level
    pub fn get_level_players(&self, level: &str) -> Vec<NcPlayerData> {
        self.level_players
            .get(level)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Add NPC class
    pub fn add_class(&mut self, name: String, script: String) {
        self.classes.insert(name, script);
    }

    /// Remove NPC class
    pub fn remove_class(&mut self, name: &str) -> bool {
        self.classes.remove(name).is_some()
    }

    /// Add weapon
    pub fn add_weapon(&mut self, name: String, script: String) {
        self.weapons.insert(name, script);
    }

    /// Remove weapon
    pub fn remove_weapon(&mut self, name: &str) -> bool {
        self.weapons.remove(name).is_some()
    }
}

impl Default for NcHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nc_packet_type_from_u8() {
        assert_eq!(NcPacketTypeIn::from_u8(200), Some(NcPacketTypeIn::Packet));
        assert_eq!(NcPacketTypeIn::from_u8(201), Some(NcPacketTypeIn::NpcProps));
        assert_eq!(NcPacketTypeIn::from_u8(255), None);
    }

    #[test]
    fn test_nc_handler_new() {
        let handler = NcHandler::new();
        assert!(!handler.connected);
        assert_eq!(handler.address, "127.0.0.1:14903");
    }

    #[test]
    fn test_nc_handler_connect_disconnect() {
        let mut handler = NcHandler::new();
        handler.connect("192.168.1.1:14903".to_string());
        assert!(handler.connected);
        assert_eq!(handler.address, "192.168.1.1:14903");

        handler.disconnect();
        assert!(!handler.connected);
    }

    #[test]
    fn test_nc_handler_add_remove_npc() {
        let mut handler = NcHandler::new();
        let npc = NpcData {
            id: "npc_123".to_string(),
            level: "test.nw".to_string(),
            x: 100.0,
            y: 100.0,
            ..Default::default()
        };

        handler.add_npc(npc);
        assert_eq!(handler.npcs.len(), 1);
        assert!(handler.get_npc("npc_123").is_some());

        handler.remove_npc("npc_123");
        assert_eq!(handler.npcs.len(), 0);
    }

    #[test]
    fn test_nc_player_data() {
        let player = NcPlayerData {
            player_id: 1,
            account_name: "test".to_string(),
            nick: "Test".to_string(),
            level: "test.nw".to_string(),
            x: 100.0,
            y: 100.0,
            sprite: 2,
            colors: "2,0,10,4,18".to_string(),
            admin_rights: 0,
        };

        assert_eq!(player.player_id, 1);
        assert_eq!(player.account_name, "test");
    }

    #[test]
    fn test_nc_handler_update_player() {
        let mut handler = NcHandler::new();
        let player = NcPlayerData {
            player_id: 1,
            account_name: "test".to_string(),
            nick: "Test".to_string(),
            level: "test.nw".to_string(),
            x: 100.0,
            y: 100.0,
            sprite: 2,
            colors: "2,0,10,4,18".to_string(),
            admin_rights: 0,
        };

        handler.update_player(player);
        let players = handler.get_level_players("test.nw");
        assert_eq!(players.len(), 1);
        assert_eq!(players[0].player_id, 1);
    }
}
