//! RC (Remote Control) Protocol
//!
//! # Purpose
//! Implements the Graal Online RC (Remote Control) protocol for server administration.
//!
//! # C++ Equivalence
//! Matches `PlayerRC` and `PlayerRCPackets` from:
//! - PlayerRC.cpp - RC command implementations
//! - PlayerRCPackets.cpp - RC packet handling
//!
//! # RC Protocol Overview
//!
//! RC is a text-based administrative protocol used by:
//! - GraalEditor (level editor)
//! - RC tools (remote administration)
//! - Staff tools (server management)
//!
//! # Packet Types
//!
//! ## Client-to-Server (PLI_RC_*)
//! - PLI_RC_SERVEROPTIONSGET = 100
//! - PLI_RC_SERVEROPTIONSSET = 101
//! - PLI_RC_PLAYERPROPSGET = 102
//! - PLI_RC_PLAYERPROPSSET = 103
//! - PLI_RC_PLAYERPROPSRESET = 104
//! - PLI_RC_DISCONNECTPLAYER = 105
//! - PLI_RC_WARPTO = 106
//! - PLI_RC_ACCOUNTADD = 107
//! - PLI_RC_ACCOUNTDEL = 108
//! - PLI_RC_ACCOUNTGET = 109
//! - PLI_RC_ACCOUNTSET = 110
//! - PLI_RC_ACCOUNTLISTGET = 111
//! - PLI_RC_FILEBROWSE = 112
//! - PLI_RC_FILEDELETE = 113
//! - PLI_RC_FILEUPLOAD = 114
//! - PLI_RC_FILEDOWNLOAD = 115
//! - PLI_RC_WEAPONADD = 116
//! - PLI_RC_WEAPONDEL = 117
//! - PLI_RC_FOLDERCONFIGGET = 118
//! - PLI_RC_FOLDERCONFIGSET = 119
//! - PLI_RC_NPCPROPSGET = 120
//! - PLI_RC_NPCPROPSSET = 121
//! - PLI_RC_NPCRESET = 122
//!
//! ## Server-to-Client (PLO_RC_*)
//! - PLO_RC_SERVEROPTIONS = 100
//! - PLO_RC_PLAYERPROPS = 101
//! - PLO_RC_ACCOUNTLIST = 102
//! - PLO_RC_ACCOUNT = 103
//! - PLO_RC_FILELIST = 104
//! - PLO_RC_FILEDATA = 105
//! - PLO_RC_WEAPONLIST = 106
//! - PLO_RC_ERROR = 107
//! - PLO_RC_FOLDERCONFIG = 108
//! - PLO_RC_NPCPROPS = 109
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use gserver_protocol::rc::{RcPacket, RcCommand};
//!
//! // Create an RC command
//! let cmd = RcCommand::GetServerOptions;
//!
//! // Serialize to packet
//! let packet = RcPacket::new(cmd);
//! ```

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// RC packet type (client-to-server)
///
/// # C++ Equivalence
/// Matches PLI_RC_* packet types in IEnums.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RcPacketTypeIn {
    /// Get server options
    ServerOptionsGet = 100,

    /// Set server options
    ServerOptionsSet = 101,

    /// Get player properties
    PlayerPropsGet = 102,

    /// Set player properties
    PlayerPropsSet = 103,

    /// Reset player properties
    PlayerPropsReset = 104,

    /// Disconnect a player
    DisconnectPlayer = 105,

    /// Warp to location
    Warpto = 106,

    /// Add account
    AccountAdd = 107,

    /// Delete account
    AccountDel = 108,

    /// Get account
    AccountGet = 109,

    /// Set account
    AccountSet = 110,

    /// Get account list
    AccountListGet = 111,

    /// Browse files
    FileBrowse = 112,

    /// Delete file
    FileDelete = 113,

    /// Upload file
    FileUpload = 114,

    /// Download file
    FileDownload = 115,

    /// Add weapon
    WeaponAdd = 116,

    /// Delete weapon
    WeaponDel = 117,

    /// Get folder config
    FolderConfigGet = 118,

    /// Set folder config
    FolderConfigSet = 119,

    /// Get NPC properties
    NpcPropsGet = 120,

    /// Set NPC properties
    NpcPropsSet = 121,

    /// Reset NPC
    NpcReset = 122,
}

impl RcPacketTypeIn {
    /// Parse from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            100 => Some(RcPacketTypeIn::ServerOptionsGet),
            101 => Some(RcPacketTypeIn::ServerOptionsSet),
            102 => Some(RcPacketTypeIn::PlayerPropsGet),
            103 => Some(RcPacketTypeIn::PlayerPropsSet),
            104 => Some(RcPacketTypeIn::PlayerPropsReset),
            105 => Some(RcPacketTypeIn::DisconnectPlayer),
            106 => Some(RcPacketTypeIn::Warpto),
            107 => Some(RcPacketTypeIn::AccountAdd),
            108 => Some(RcPacketTypeIn::AccountDel),
            109 => Some(RcPacketTypeIn::AccountGet),
            110 => Some(RcPacketTypeIn::AccountSet),
            111 => Some(RcPacketTypeIn::AccountListGet),
            112 => Some(RcPacketTypeIn::FileBrowse),
            113 => Some(RcPacketTypeIn::FileDelete),
            114 => Some(RcPacketTypeIn::FileUpload),
            115 => Some(RcPacketTypeIn::FileDownload),
            116 => Some(RcPacketTypeIn::WeaponAdd),
            117 => Some(RcPacketTypeIn::WeaponDel),
            118 => Some(RcPacketTypeIn::FolderConfigGet),
            119 => Some(RcPacketTypeIn::FolderConfigSet),
            120 => Some(RcPacketTypeIn::NpcPropsGet),
            121 => Some(RcPacketTypeIn::NpcPropsSet),
            122 => Some(RcPacketTypeIn::NpcReset),
            _ => None,
        }
    }
}

/// RC packet type (server-to-client)
///
/// # C++ Equivalence
/// Matches PLO_RC_* packet types in IEnums.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RcPacketTypeOut {
    /// Server options data
    ServerOptions = 100,

    /// Player properties data
    PlayerProps = 101,

    /// Account list
    AccountList = 102,

    /// Account data
    Account = 103,

    /// File list
    FileList = 104,

    /// File data
    FileData = 105,

    /// Weapon list
    WeaponList = 106,

    /// Error message
    Error = 107,

    /// Folder config data
    FolderConfig = 108,

    /// NPC properties data
    NpcProps = 109,
}

/// RC server options
///
/// # C++ Equivalence
/// Matches server options in TServer::serveroptions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RcServerOptions {
    /// Server name
    pub name: String,

    /// Server description
    pub description: String,

    /// Server language
    pub language: String,

    /// Maximum players
    pub max_players: u32,

    /// Server status (0 = local, 1 = online, etc.)
    pub status: u32,

    /// Only allow connections from localhost
    pub local_only: bool,

    /// Server URL
    pub url: String,

    /// Server IP
    pub ip: String,

    /// Server port
    pub port: u16,

    /// List server URL
    pub list_server_url: String,

    /// List server name
    pub list_server_name: String,

    /// Enable list server communication
    pub enable_list_server: bool,

    /// Nickname registration required
    pub nick_reg: bool,

    /// Player accounts required
    pub player_accounts: bool,

    /// Unlimited weapons
    pub unlimited_weapons: bool,

    /// Single player mode
    pub single_player: bool,

    /// Enable sparring
    pub enable_spar: bool,

    /// Enable PK (player killing)
    pub enable_pk: bool,

    /// Enable bombs
    pub enable_bombs: bool,

    /// Enable pushback
    pub enable_pushback: bool,

    /// Enable riding horses
    pub enable_horses: bool,

    /// NPC server address
    pub npc_server_addr: String,

    /// NPC server enabled
    pub npc_server_enabled: bool,

    /// Keep player bodies on death
    pub keep_bodies: bool,

    /// Team damage
    pub team_damage: bool,

    /// Enable gmap
    pub enable_gmap: bool,

    /// Enable folder rights
    pub enable_folder_rights: bool,

    /// Default rights
    pub default_rights: u32,

    /// Level rights
    pub level_rights: u32,

    /// Allow drop weapons
    pub allow_drop_weapons: bool,

    /// Allow nickname change
    pub allow_nick_change: bool,

    /// Allow multiple connections
    pub allow_multiple_connections: bool,
}

impl Default for RcServerOptions {
    fn default() -> Self {
        Self {
            name: "GServer".to_string(),
            description: "".to_string(),
            language: "English".to_string(),
            max_players: 128,
            status: 0,
            local_only: false,
            url: "".to_string(),
            ip: "".to_string(),
            port: 14902,
            list_server_url: "".to_string(),
            list_server_name: "".to_string(),
            enable_list_server: true,
            nick_reg: false,
            player_accounts: true,
            unlimited_weapons: false,
            single_player: false,
            enable_spar: true,
            enable_pk: true,
            enable_bombs: true,
            enable_pushback: true,
            enable_horses: true,
            npc_server_addr: "127.0.0.1:14903".to_string(),
            npc_server_enabled: false,
            keep_bodies: false,
            team_damage: false,
            enable_gmap: false,
            enable_folder_rights: true,
            default_rights: 0,
            level_rights: 0,
            allow_drop_weapons: true,
            allow_nick_change: true,
            allow_multiple_connections: true,
        }
    }
}

/// RC player properties request
///
/// # C++ Equivalence
/// Matches RC player property requests in PlayerRCPackets.cpp
#[derive(Debug, Clone)]
pub struct RcPlayerPropsRequest {
    /// Player ID to get properties for
    pub player_id: Option<u16>,

    /// Player name to get properties for
    pub player_name: Option<String>,
}

/// RC player properties data
///
/// # C++ Equivalence
/// Matches RC player property responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RcPlayerPropsData {
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

    /// Community name
    pub community_name: String,

    /// Status code
    pub status: u32,

    /// Language
    pub language: String,

    /// IP address
    pub ip: String,

    /// Is hidden/invisible
    pub hidden: bool,
}

/// RC account data
///
/// # C++ Equivalence
/// Matches account data in RC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RcAccountData {
    /// Account name
    pub account_name: String,

    /// Nickname
    pub nick: String,

    /// Password
    pub password: String,

    /// Community name
    pub community_name: String,

    /// Email
    pub email: String,

    /// Admin rights
    pub admin_rights: u32,

    /// IP address
    pub ip: String,

    /// Language
    pub language: String,

    /// Is banned
    pub banned: bool,

    /// Ban reason
    pub ban_reason: String,

    /// Account file text
    pub file_text: String,
}

/// RC file info
///
/// # C++ Equivalence
/// Matches file listing in RC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RcFileInfo {
    /// File name
    pub name: String,

    /// File size (bytes)
    pub size: u64,

    /// Is directory
    pub is_dir: bool,

    /// Modification time (unix timestamp)
    pub mod_time: u64,
}

/// RC file browse response
///
/// # C++ Equivalence
/// Matches file browsing in RC
#[derive(Debug, Clone)]
pub struct RcFileBrowseResponse {
    /// Current path
    pub path: String,

    /// Files in current directory
    pub files: Vec<RcFileInfo>,
}

/// RC folder config entry
///
/// # C++ Equivalence
/// Matches folder rights configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RcFolderConfig {
    /// Folder path pattern
    pub folder: String,

    /// Permissions (e.g., "rw", "r", "-")
    pub permissions: String,

    /// Can upload
    pub can_upload: bool,

    /// Can download
    pub can_download: bool,

    /// Can delete
    pub can_delete: bool,

    /// Can create folders
    pub can_create_folders: bool,
}

/// RC command response
///
/// # C++ Equivalence
/// Matches RC command responses
#[derive(Debug, Clone)]
pub enum RcResponse {
    /// Server options
    ServerOptions(RcServerOptions),

    /// Player properties
    PlayerProps(RcPlayerPropsData),

    /// Player props reset confirmation
    PlayerPropsReset { player_id: u16 },

    /// Player disconnected
    PlayerDisconnected { player_id: u16 },

    /// Warp confirmation
    Warped { player_id: u16 },

    /// Account list
    AccountList { accounts: Vec<String> },

    /// Account data
    Account(RcAccountData),

    /// Account added
    AccountAdded { account_name: String },

    /// Account deleted
    AccountDeleted { account_name: String },

    /// Account updated
    AccountUpdated { account_name: String },

    /// File browse result
    FileBrowse(RcFileBrowseResponse),

    /// File data
    FileData { file_name: String, data: Vec<u8> },

    /// File deleted
    FileDeleted { file_name: String },

    /// File uploaded
    FileUploaded { file_name: String },

    /// Weapon list
    WeaponList { weapons: Vec<String> },

    /// Weapon added
    WeaponAdded { weapon_name: String },

    /// Weapon deleted
    WeaponDeleted { weapon_name: String },

    /// Folder config
    FolderConfig { folders: Vec<RcFolderConfig> },

    /// NPC properties
    NpcProps { npc_id: String, props: HashMap<String, String> },

    /// NPC reset confirmation
    NpcReset { npc_id: String },

    /// Error message
    Error { message: String },
}

/// RC handler - processes RC commands
///
/// # Purpose
/// Handles RC protocol commands and generates responses
///
/// # C++ Equivalence
/// Matches PlayerRC command handlers
pub struct RcHandler {
    /// Server options
    pub server_options: RcServerOptions,

    /// Connected players (id -> name)
    pub players: HashMap<u16, String>,

    /// Accounts
    pub accounts: HashMap<String, RcAccountData>,

    /// Folder configurations
    pub folder_configs: Vec<RcFolderConfig>,
}

impl RcHandler {
    /// Create a new RC handler
    pub fn new() -> Self {
        Self {
            server_options: RcServerOptions::default(),
            players: HashMap::new(),
            accounts: HashMap::new(),
            folder_configs: Vec::new(),
        }
    }

    /// Handle an incoming RC packet
    pub fn handle_packet(&mut self, packet_type: RcPacketTypeIn, data: &[u8]) -> RcResponse {
        match packet_type {
            RcPacketTypeIn::ServerOptionsGet => {
                RcResponse::ServerOptions(self.server_options.clone())
            }
            RcPacketTypeIn::ServerOptionsSet => {
                // Parse and update server options from data
                RcResponse::Error { message: "ServerOptionsSet not yet implemented".to_string() }
            }
            RcPacketTypeIn::PlayerPropsGet => {
                // Parse player ID/name from data
                RcResponse::Error { message: "PlayerPropsGet not yet implemented".to_string() }
            }
            RcPacketTypeIn::PlayerPropsSet => {
                RcResponse::Error { message: "PlayerPropsSet not yet implemented".to_string() }
            }
            RcPacketTypeIn::PlayerPropsReset => {
                RcResponse::Error { message: "PlayerPropsReset not yet implemented".to_string() }
            }
            RcPacketTypeIn::DisconnectPlayer => {
                RcResponse::Error { message: "DisconnectPlayer not yet implemented".to_string() }
            }
            RcPacketTypeIn::Warpto => {
                RcResponse::Error { message: "Warpto not yet implemented".to_string() }
            }
            RcPacketTypeIn::AccountAdd => {
                RcResponse::Error { message: "AccountAdd not yet implemented".to_string() }
            }
            RcPacketTypeIn::AccountDel => {
                RcResponse::Error { message: "AccountDel not yet implemented".to_string() }
            }
            RcPacketTypeIn::AccountGet => {
                RcResponse::Error { message: "AccountGet not yet implemented".to_string() }
            }
            RcPacketTypeIn::AccountSet => {
                RcResponse::Error { message: "AccountSet not yet implemented".to_string() }
            }
            RcPacketTypeIn::AccountListGet => {
                RcResponse::AccountList {
                    accounts: self.accounts.keys().cloned().collect()
                }
            }
            RcPacketTypeIn::FileBrowse => {
                RcResponse::Error { message: "FileBrowse not yet implemented".to_string() }
            }
            RcPacketTypeIn::FileDelete => {
                RcResponse::Error { message: "FileDelete not yet implemented".to_string() }
            }
            RcPacketTypeIn::FileUpload => {
                RcResponse::Error { message: "FileUpload not yet implemented".to_string() }
            }
            RcPacketTypeIn::FileDownload => {
                RcResponse::Error { message: "FileDownload not yet implemented".to_string() }
            }
            RcPacketTypeIn::WeaponAdd => {
                RcResponse::Error { message: "WeaponAdd not yet implemented".to_string() }
            }
            RcPacketTypeIn::WeaponDel => {
                RcResponse::Error { message: "WeaponDel not yet implemented".to_string() }
            }
            RcPacketTypeIn::FolderConfigGet => {
                RcResponse::FolderConfig {
                    folders: self.folder_configs.clone()
                }
            }
            RcPacketTypeIn::FolderConfigSet => {
                RcResponse::Error { message: "FolderConfigSet not yet implemented".to_string() }
            }
            RcPacketTypeIn::NpcPropsGet => {
                RcResponse::Error { message: "NpcPropsGet not yet implemented".to_string() }
            }
            RcPacketTypeIn::NpcPropsSet => {
                RcResponse::Error { message: "NpcPropsSet not yet implemented".to_string() }
            }
            RcPacketTypeIn::NpcReset => {
                RcResponse::Error { message: "NpcReset not yet implemented".to_string() }
            }
        }
    }

    /// Set server options
    pub fn set_server_options(&mut self, options: RcServerOptions) {
        self.server_options = options;
    }

    /// Add a player to the player list
    pub fn add_player(&mut self, id: u16, name: String) {
        self.players.insert(id, name);
    }

    /// Remove a player from the player list
    pub fn remove_player(&mut self, id: u16) {
        self.players.remove(&id);
    }

    /// Add an account
    pub fn add_account(&mut self, account: RcAccountData) {
        self.accounts.insert(account.account_name.clone(), account);
    }

    /// Remove an account
    pub fn remove_account(&mut self, account_name: &str) -> bool {
        self.accounts.remove(account_name).is_some()
    }

    /// Get an account
    pub fn get_account(&self, account_name: &str) -> Option<&RcAccountData> {
        self.accounts.get(account_name)
    }
}

impl Default for RcHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc_packet_type_from_u8() {
        assert_eq!(RcPacketTypeIn::from_u8(100), Some(RcPacketTypeIn::ServerOptionsGet));
        assert_eq!(RcPacketTypeIn::from_u8(101), Some(RcPacketTypeIn::ServerOptionsSet));
        assert_eq!(RcPacketTypeIn::from_u8(255), None);
    }

    #[test]
    fn test_rc_handler_new() {
        let handler = RcHandler::new();
        assert_eq!(handler.server_options.name, "GServer");
        assert_eq!(handler.players.len(), 0);
    }

    #[test]
    fn test_rc_handler_player_add_remove() {
        let mut handler = RcHandler::new();
        handler.add_player(1, "TestPlayer".to_string());
        assert_eq!(handler.players.len(), 1);
        assert_eq!(handler.players.get(&1), Some(&"TestPlayer".to_string()));

        handler.remove_player(1);
        assert_eq!(handler.players.len(), 0);
    }

    #[test]
    fn test_rc_handler_account_list() {
        let mut handler = RcHandler::new();
        handler.add_account(RcAccountData {
            account_name: "test1".to_string(),
            nick: "Test1".to_string(),
            password: "pass".to_string(),
            community_name: "".to_string(),
            email: "".to_string(),
            admin_rights: 0,
            ip: "".to_string(),
            language: "English".to_string(),
            banned: false,
            ban_reason: "".to_string(),
            file_text: "".to_string(),
        });

        let response = handler.handle_packet(RcPacketTypeIn::AccountListGet, &[]);
        match response {
            RcResponse::AccountList { accounts } => {
                assert_eq!(accounts.len(), 1);
                assert_eq!(accounts[0], "test1");
            }
            _ => panic!("Expected AccountList response"),
        }
    }

    #[test]
    fn test_rc_server_options_default() {
        let options = RcServerOptions::default();
        assert_eq!(options.name, "GServer");
        assert_eq!(options.port, 14902);
        assert!(options.enable_list_server);
    }
}
