//! # Graal Protocol Packet Definitions
//!
//! This module contains all 160+ packet types used in the Graal protocol.
//!
//! ## Packet Organization
//!
//! Packets are organized into the following categories:
//! - **Client-to-Server (PLI_)**: Packets sent from the Graal client to the server
//! - **Server-to-Client (PLO_)**: Packets sent from the server to the Graal client
//! - **Server-to-ListServer (SVI_)**: Packets sent from the game server to the list server
//! - **ListServer-to-Server (SVO_)**: Packets sent from the list server to the game server
//!
//! ## Packet Naming Convention
//!
//! - `PLI_*` = Player-to-server Inbound
//! - `PLO_*` = Player-to-server Outbound
//! - `SVI_*` = Server-to-listserver Inbound
//! - `SVO_*` = Server-to-listserver Outbound
//!
//! ## Protocol Compatibility
//!
//! All packet structures maintain exact byte-level compatibility with the C++ implementation
//! in GS2Emu. Packet IDs correspond to the values in `IEnums.h`.
//!
//! ## Version-Specific Packets
//!
//! Some packets are marked as:
//! - **Deprecated**: No longer used in modern clients
//! - **Unhandled by X.XX**: Not processed by specific client versions
//! - **Experimental**: Purpose not fully understood
//!
//! See the [Graal Protocol](https://github.com/) documentation for more details.

// Re-export codecs
pub use super::codecs::*;

/// Packet type enumeration for all client-to-server packets
///
/// This enum represents all possible packet types that can be sent from
/// a Graal client to the server. Each variant corresponds to a specific
/// packet type defined in the Graal protocol.
///
/// # Packet IDs
///
/// Packet IDs are byte values (0-255) that identify the packet type.
/// Some IDs are unused or reserved for future use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketTypeIn {
    //=== Basic Movement & Warping ===//

    /// Player requests to warp to a different level
    ///
    /// # Packet Format
    /// ```text
    /// {0}{GINT5 modtime}{GSHORT x*2}{GSHORT y*2}{GSTRING level}
    /// ```
    ///
    /// # Fields
    /// - `modtime`: Level modification time (for caching)
    /// - `x`: X coordinate in pixels (divided by 2)
    /// - `y`: Y coordinate in pixels (divided by 2)
    /// - `level`: Target level name (e.g., "onlinestartlocal.nw")
    LevelWarp = 0,

    /// Player modifies the level board (tiles)
    ///
    /// Used when a player places or removes tiles in the level.
    /// Typically used for building/modifying levels.
    ///
    /// # Packet Format
    /// ```text
    /// {1}{GSHORT x}{GSHORT y}{GSHORT width}{GSHORT height}{TILE_DATA[]}
    /// ```
    BoardModify = 1,

    /// Player updates their own properties
    ///
    /// # Packet Format
    /// ```text
    /// {2}{GINT5 modtime}{PROPERTY_DATA}
    /// ```
    PlayerProps = 2,

    //=== NPC Interactions ===//

    /// Player updates NPC properties
    ///
    /// # Packet Format
    /// ```text
    /// {3}{GINT id}{GINT5 modtime}{PROPERTY_DATA}
    /// ```
    NpcProps = 3,

    /// Player places a bomb
    ///
    /// # Packet Format
    /// ```text
    /// {4}{GSHORT x}{GSHORT y}{GSHORT owner_x}{GSHORT owner_y}
    /// ```
    BombAdd = 4,

    /// Player removes a bomb
    BombDel = 5,

    //=== Communication ===//

    /// Player sends a message to all players on the server
    ///
    /// # Packet Format
    /// ```text
    /// {6}{GSTRING message}
    /// ```
    ToAll = 6,

    /// Player sends a private message to another player
    ///
    /// # Packet Format
    /// ```text
    /// {28}{GSTRING message}
    /// ```
    PrivateMessage = 28,

    //=== Items & Weapons ===//

    /// Player picks up an item
    ItemAdd = 12,

    /// Player drops/removes an item
    ItemDel = 13,

    /// Player claims a Pakker item
    ClaimPker = 14,

    //=== Horses ===//

    /// Player spawns a horse
    HorseAdd = 7,

    /// Player removes a horse
    HorseDel = 8,

    //=== Projectiles ===//

    /// Player fires an arrow
    ArrowAdd = 9,

    /// Player throws a carried object
    ThrowCarried = 11,

    //=== Enemies (Baddies) ===//

    /// Update baddy (enemy) properties
    BaddyProps = 15,

    /// Player hurts a baddy
    BaddyHurt = 16,

    /// Add a baddy to the level
    BaddyAdd = 17,

    //=== Flags ===//

    /// Set a player flag
    FlagSet = 18,

    /// Delete a player flag
    FlagDel = 19,

    //=== Chests & Signs ===//

    /// Player opens a chest
    OpenChest = 20,

    //=== NPC Management ===//

    /// Player places a new NPC
    PutNpc = 21,

    /// Player deletes an NPC
    NpcDel = 22,

    /// Player requests a file from the server
    WantFile = 23,

    /// Player shows an image (showimg command)
    ShowImg = 24,

    /// Player enters a level
    EnterLevel = 25,

    /// Player hurts another player
    HurtPlayer = 26,

    /// Player creates an explosion
    Explosion = 27,

    /// Delete an NPC weapon
    NpcWeaponDel = 29,

    /// Level warp with modification time
    LevelWarpMod = 30,

    /// Packet count acknowledgment
    PacketCount = 31,

    /// Player takes an item
    ItemTake = 32,

    /// Player adds a weapon
    WeaponAdd = 33,

    /// Player requests a file update
    UpdateFile = 34,

    /// Player requests adjacent level data (for maps)
    AdjacentLevel = 35,

    /// Player hits multiple objects
    HitObjects = 36,

    /// Player language setting
    Language = 37,

    /// Trigger an action
    TriggerAction = 38,

    /// Player requests map information
    MapInfo = 39,

    /// Player shoots a projectile
    Shoot = 40,

    /// Player requests a server warp (different from level warp)
    ServerWarp = 41,

    //=== Remote Control (RC) Packets ===//
    // These packets are sent by RC (Remote Control) connections

    /// Firespy (admin spectating)
    FireSpy = 10,

    /// RC: Send chat message
    RcChat = 79,

    /// Process list
    ProcessList = 80,

    /// Verify want send
    VerifyWantSend = 81,

    /// Tamper check
    TamperCheck = 95,

    //=== NPC Server (NC) Packets ===//
    // These packets are sent by NC (NPC Server) connections

    /// NC: Query NPC server status
    NpcServerQuery = 94,

    /// RC: Get server options
    RcServerOptionsGet = 51,

    /// RC: Set server options
    RcServerOptionsSet = 52,

    /// RC: Get folder configuration
    RcFolderConfigGet = 53,

    /// RC: Set folder configuration
    RcFolderConfigSet = 54,

    /// RC: Set respawn point
    RcRespawnSet = 55,

    /// RC: Set horse lifetime
    RcHorseLifeSet = 56,

    /// RC: Set AP increment
    RcApIncrementSet = 57,

    /// RC: Set baddy respawn
    RcBaddyRespawnSet = 58,

    /// RC: Get player properties
    RcPlayerPropsGet = 59,

    /// RC: Set player properties
    RcPlayerPropsSet = 60,

    /// RC: Disconnect a player
    RcDisconnectPlayer = 61,

    /// RC: Reload levels
    RcUpdateLevels = 62,

    /// RC: Send admin message
    RcAdminMessage = 63,

    /// RC: Send private admin message
    RcPrivAdminMessage = 64,

    /// RC: List all RC connections
    RcListRcs = 65,

    /// RC: Disconnect an RC connection
    RcDisconnectRc = 66,

    /// RC: Apply a reason/ban
    RcApplyReason = 67,

    /// RC: Get server flags
    RcServerFlagsGet = 68,

    /// RC: Set server flags
    RcServerFlagsSet = 69,

    /// RC: Add an account
    RcAccountAdd = 70,

    /// RC: Delete an account
    RcAccountDel = 71,

    /// RC: List all accounts
    RcAccountListGet = 72,

    /// RC: Get player properties by ID
    RcPlayerPropsGet2 = 73,

    /// RC: Get player properties by account name
    RcPlayerPropsGet3 = 74,

    /// RC: Reset player properties
    RcPlayerPropsReset = 75,

    /// RC: Set player properties (alternate)
    RcPlayerPropsSet2 = 76,

    /// RC: Get account information
    RcAccountGet = 77,

    /// RC: Set account information
    RcAccountSet = 78,

    /// RC: Warp a player
    RcWarpPlayer = 82,

    /// RC: Get player rights
    RcPlayerRightsGet = 83,

    /// RC: Set player rights
    RcPlayerRightsSet = 84,

    /// RC: Get player comments
    RcPlayerCommentsGet = 85,

    /// RC: Set player comments
    RcPlayerCommentsSet = 86,

    /// RC: Get player ban information
    RcPlayerBanGet = 87,

    /// RC: Set player ban
    RcPlayerBanSet = 88,

    /// RC: File browser - start browsing
    RcFileBrowserStart = 89,

    /// RC: File browser - change directory
    RcFileBrowserCd = 90,

    /// RC: File browser - end browsing
    RcFileBrowserEnd = 91,

    /// RC: File browser - download file
    RcFileBrowserDown = 92,

    /// RC: File browser - upload file
    RcFileBrowserUp = 93,

    //=== RC & NC File Browser Packets ===//

    /// RC: File browser - move file
    RcFileBrowserMove = 96,

    /// RC: File browser - delete file
    RcFileBrowserDelete = 97,

    /// RC: File browser - rename file
    RcFileBrowserRename = 98,

    /// NC: Get NPC by ID
    NcNpcGet = 103,

    /// NC: Delete NPC
    NcNpcDelete = 104,

    /// NC: Reset NPC
    NcNpcReset = 105,

    /// NC: Get NPC script
    NcNpcScriptGet = 106,

    /// NC: Warp NPC
    NcNpcWarp = 107,

    /// NC: Get NPC flags
    NcNpcFlagsGet = 108,

    /// NC: Set NPC script
    NcNpcScriptSet = 109,

    /// NC: Set NPC flags
    NcNpcFlagsSet = 110,

    /// NC: Add new NPC
    NcNpcAdd = 111,

    /// NC: Edit a class
    NcClassEdit = 112,

    /// NC: Add a class
    NcClassAdd = 113,

    /// NC: Get local NPCs
    NcLocalNpcsGet = 114,

    /// NC: Get weapon list
    NcWeaponListGet = 115,

    /// NC: Get weapon by name
    NcWeaponGet = 116,

    /// NC: Add weapon
    NcWeaponAdd = 117,

    /// NC: Delete weapon
    NcWeaponDelete = 118,

    /// NC: Delete class
    NcClassDelete = 119,

    //=== File Transfer ===//

    /// Request update of board tiles
    RequestUpdateBoard = 130,

    /// NC: Get level list
    NcLevelListGet = 150,

    /// NC: Set level list
    NcLevelListSet = 151,

    /// Request text from server
    RequestText = 152,

    /// Send text to server
    SendText = 154,

    /// RC: Start large file transfer
    RcLargeFileStart = 155,

    /// RC: End large file transfer
    RcLargeFileEnd = 156,

    /// Update gani animation
    UpdateGani = 157,

    /// Update script
    UpdateScript = 158,

    /// Request file from update package
    UpdatePackageRequestFile = 159,

    /// RC: Delete folder
    RcFolderDelete = 160,

    /// Update class
    UpdateClass = 161,

    /// Unknown packet (RC3 beta)
    RcUnknown162 = 162,
}

impl PacketTypeIn {
    /// Convert a byte to a packet type
    ///
    /// # Purpose
    /// Maps raw packet ID bytes to their corresponding PacketTypeIn enum values.
    /// This is the primary method for parsing incoming packets from clients.
    ///
    /// # Arguments
    /// * `value` - Raw packet type byte from the network
    ///
    /// # Returns
    /// - `Some(PacketTypeIn)` if the byte corresponds to a known packet type
    /// - `None` if the packet type is unknown
    ///
    /// # C++ Equivalence
    /// Matches packet type definitions in `/home/versa/Downloads/GServer-v2/dependencies/gs2lib/include/IEnums.h`
    ///
    /// # Example
    /// ```rust
    /// use gserver_protocol::PacketTypeIn;
    ///
    /// let packet_type = PacketTypeIn::from_u8(0);
    /// assert_eq!(packet_type, Some(PacketTypeIn::LevelWarp));
    ///
    /// let unknown = PacketTypeIn::from_u8(255);
    /// assert_eq!(unknown, None);
    /// ```
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            //=== Basic Movement & Warping ===//
            0 => Some(PacketTypeIn::LevelWarp),
            1 => Some(PacketTypeIn::BoardModify),
            2 => Some(PacketTypeIn::PlayerProps),
            3 => Some(PacketTypeIn::NpcProps),
            4 => Some(PacketTypeIn::BombAdd),
            5 => Some(PacketTypeIn::BombDel),
            //=== Communication & Movement ===//
            6 => Some(PacketTypeIn::ToAll),
            7 => Some(PacketTypeIn::HorseAdd),
            8 => Some(PacketTypeIn::HorseDel),
            9 => Some(PacketTypeIn::ArrowAdd),
            //=== Items & Projectiles ===//
            10 => Some(PacketTypeIn::FireSpy),
            11 => Some(PacketTypeIn::ThrowCarried),
            12 => Some(PacketTypeIn::ItemAdd),
            13 => Some(PacketTypeIn::ItemDel),
            14 => Some(PacketTypeIn::ClaimPker),
            //=== Enemies (Baddies) ===//
            15 => Some(PacketTypeIn::BaddyProps),
            16 => Some(PacketTypeIn::BaddyHurt),
            17 => Some(PacketTypeIn::BaddyAdd),
            //=== Flags ===//
            18 => Some(PacketTypeIn::FlagSet),
            19 => Some(PacketTypeIn::FlagDel),
            //=== Chests & NPCs ===//
            20 => Some(PacketTypeIn::OpenChest),
            21 => Some(PacketTypeIn::PutNpc),
            22 => Some(PacketTypeIn::NpcDel),
            23 => Some(PacketTypeIn::WantFile),
            24 => Some(PacketTypeIn::ShowImg),
            //=== Player Actions ===//
            25 => Some(PacketTypeIn::EnterLevel),
            26 => Some(PacketTypeIn::HurtPlayer),
            27 => Some(PacketTypeIn::Explosion),
            28 => Some(PacketTypeIn::PrivateMessage),
            29 => Some(PacketTypeIn::NpcWeaponDel),
            //=== More Warping & Items ===//
            30 => Some(PacketTypeIn::LevelWarpMod),
            31 => Some(PacketTypeIn::PacketCount),
            32 => Some(PacketTypeIn::ItemTake),
            33 => Some(PacketTypeIn::WeaponAdd),
            34 => Some(PacketTypeIn::UpdateFile),
            35 => Some(PacketTypeIn::AdjacentLevel),
            36 => Some(PacketTypeIn::HitObjects),
            //=== Language & Actions ===//
            37 => Some(PacketTypeIn::Language),
            38 => Some(PacketTypeIn::TriggerAction),
            39 => Some(PacketTypeIn::MapInfo),
            40 => Some(PacketTypeIn::Shoot),
            41 => Some(PacketTypeIn::ServerWarp),
            //=== RC Packets (51-95) ===//
            51 => Some(PacketTypeIn::RcServerOptionsGet),
            52 => Some(PacketTypeIn::RcServerOptionsSet),
            53 => Some(PacketTypeIn::RcFolderConfigGet),
            54 => Some(PacketTypeIn::RcFolderConfigSet),
            55 => Some(PacketTypeIn::RcRespawnSet),
            56 => Some(PacketTypeIn::RcHorseLifeSet),
            57 => Some(PacketTypeIn::RcApIncrementSet),
            58 => Some(PacketTypeIn::RcBaddyRespawnSet),
            59 => Some(PacketTypeIn::RcPlayerPropsGet),
            60 => Some(PacketTypeIn::RcPlayerPropsSet),
            61 => Some(PacketTypeIn::RcDisconnectPlayer),
            62 => Some(PacketTypeIn::RcUpdateLevels),
            63 => Some(PacketTypeIn::RcAdminMessage),
            64 => Some(PacketTypeIn::RcPrivAdminMessage),
            65 => Some(PacketTypeIn::RcListRcs),
            66 => Some(PacketTypeIn::RcDisconnectRc),
            67 => Some(PacketTypeIn::RcApplyReason),
            68 => Some(PacketTypeIn::RcServerFlagsGet),
            69 => Some(PacketTypeIn::RcServerFlagsSet),
            70 => Some(PacketTypeIn::RcAccountAdd),
            71 => Some(PacketTypeIn::RcAccountDel),
            72 => Some(PacketTypeIn::RcAccountListGet),
            73 => Some(PacketTypeIn::RcPlayerPropsGet2),
            74 => Some(PacketTypeIn::RcPlayerPropsGet3),
            75 => Some(PacketTypeIn::RcPlayerPropsReset),
            76 => Some(PacketTypeIn::RcPlayerPropsSet2),
            77 => Some(PacketTypeIn::RcAccountGet),
            78 => Some(PacketTypeIn::RcAccountSet),
            79 => Some(PacketTypeIn::RcChat),
            80 => Some(PacketTypeIn::ProcessList),
            81 => Some(PacketTypeIn::VerifyWantSend),
            82 => Some(PacketTypeIn::RcWarpPlayer),
            83 => Some(PacketTypeIn::RcPlayerRightsGet),
            84 => Some(PacketTypeIn::RcPlayerRightsSet),
            85 => Some(PacketTypeIn::RcPlayerCommentsGet),
            86 => Some(PacketTypeIn::RcPlayerCommentsSet),
            87 => Some(PacketTypeIn::RcPlayerBanGet),
            88 => Some(PacketTypeIn::RcPlayerBanSet),
            89 => Some(PacketTypeIn::RcFileBrowserStart),
            90 => Some(PacketTypeIn::RcFileBrowserCd),
            91 => Some(PacketTypeIn::RcFileBrowserEnd),
            92 => Some(PacketTypeIn::RcFileBrowserDown),
            93 => Some(PacketTypeIn::RcFileBrowserUp),
            94 => Some(PacketTypeIn::NpcServerQuery),
            95 => Some(PacketTypeIn::TamperCheck),
            //=== More RC & NC Packets (96-119) ===//
            96 => Some(PacketTypeIn::RcFileBrowserMove),
            97 => Some(PacketTypeIn::RcFileBrowserDelete),
            98 => Some(PacketTypeIn::RcFileBrowserRename),
            // 99-102: Reserved/unused
            103 => Some(PacketTypeIn::NcNpcGet),
            104 => Some(PacketTypeIn::NcNpcDelete),
            105 => Some(PacketTypeIn::NcNpcReset),
            106 => Some(PacketTypeIn::NcNpcScriptGet),
            107 => Some(PacketTypeIn::NcNpcWarp),
            108 => Some(PacketTypeIn::NcNpcFlagsGet),
            109 => Some(PacketTypeIn::NcNpcScriptSet),
            110 => Some(PacketTypeIn::NcNpcFlagsSet),
            111 => Some(PacketTypeIn::NcNpcAdd),
            112 => Some(PacketTypeIn::NcClassEdit),
            113 => Some(PacketTypeIn::NcClassAdd),
            114 => Some(PacketTypeIn::NcLocalNpcsGet),
            115 => Some(PacketTypeIn::NcWeaponListGet),
            116 => Some(PacketTypeIn::NcWeaponGet),
            117 => Some(PacketTypeIn::NcWeaponAdd),
            118 => Some(PacketTypeIn::NcWeaponDelete),
            119 => Some(PacketTypeIn::NcClassDelete),
            //=== Update & File Packets (130-162) ===//
            130 => Some(PacketTypeIn::RequestUpdateBoard),
            // 131-149: Reserved/unused
            150 => Some(PacketTypeIn::NcLevelListGet),
            151 => Some(PacketTypeIn::NcLevelListSet),
            152 => Some(PacketTypeIn::RequestText),
            // 153: Reserved
            154 => Some(PacketTypeIn::SendText),
            155 => Some(PacketTypeIn::RcLargeFileStart),
            156 => Some(PacketTypeIn::RcLargeFileEnd),
            157 => Some(PacketTypeIn::UpdateGani),
            158 => Some(PacketTypeIn::UpdateScript),
            159 => Some(PacketTypeIn::UpdatePackageRequestFile),
            160 => Some(PacketTypeIn::RcFolderDelete),
            161 => Some(PacketTypeIn::UpdateClass),
            162 => Some(PacketTypeIn::RcUnknown162),
            //=== Unknown/Reserved ===//
            _ => None, // Unknown packet type
        }
    }

    /// Convert packet type to its byte ID
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Packet type enumeration for all server-to-client packets
///
/// This enum represents all possible packet types that can be sent from
/// the server to a Graal client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketTypeOut {
    /// Send level board data (tiles)
    LevelBoard = 0,

    /// Send level link information
    LevelLink = 1,

    /// Send baddy (enemy) properties
    BaddyProps = 2,

    /// Send NPC properties
    NpcProps = 3,

    /// Send chest data
    LevelChest = 4,

    /// Send sign data
    LevelSign = 5,

    /// Send level name
    LevelName = 6,

    /// Send board modification
    BoardModify = 7,

    /// Send other player properties
    OtherPlayerProps = 8,

    /// Send player properties
    PlayerProps = 9,

    /// Player is leader (party leader)
    IsLeader = 10,

    /// Add bomb to level
    BombAdd = 11,

    /// Remove bomb from level
    BombDel = 12,

    /// Send message to all players
    ToAll = 13,

    /// Warp player to new location
    PlayerWarp = 14,

    /// Warp failed (couldn't find level, etc.)
    WarpFailed = 15,

    /// Disconnect message
    DiscMessage = 16,

    /// Add horse to level
    HorseAdd = 17,

    /// Remove horse from level
    HorseDel = 18,

    /// Add arrow to level
    ArrowAdd = 19,

    /// Firespy (admin spectating)
    Firespy = 20,

    /// Throw carried object
    ThrowCarried = 21,

    /// Add item to level
    ItemAdd = 22,

    /// Remove item from level
    ItemDel = 23,

    /// NPC moved (hidden/visible)
    NpcMoved = 24,

    /// Signature (for verification)
    Signature = 25,

    /// NPC action
    NpcAction = 26,

    /// Baddy hurt
    BaddyHurt = 27,

    /// Set flag
    FlagSet = 28,

    /// Delete NPC
    NpcDel = 29,

    /// File send failed
    FileSendFailed = 30,

    /// Delete flag
    FlagDel = 31,

    /// Show image (showimg command)
    ShowImg = 32,

    /// Add NPC weapon
    NpcWeaponAdd = 33,

    /// Delete NPC weapon
    NpcWeaponDel = 34,

    /// RC: Admin message
    RcAdminMessage = 35,

    /// Create explosion
    Explosion = 36,

    /// Send private message
    PrivateMessage = 37,

    /// Push player away
    PushAway = 38,

    /// Level modification time
    LevelModTime = 39,

    /// Hurt player
    HurtPlayer = 40,

    /// Start message
    StartMessage = 41,

    /// New world time
    NewWorldTime = 42,

    /// Default weapon
    DefaultWeapon = 43,

    /// Server has NPC server
    HasNpcServer = 44,

    /// File is up to date
    FileUpToDate = 45,

    /// Hit objects
    HitObjects = 46,

    /// Staff guilds
    StaffGuilds = 47,

    /// Trigger action
    TriggerAction = 48,

    /// Player warp (version 2)
    PlayerWarp2 = 49,

    /// Add player
    AddPlayer = 55,

    /// Delete player
    DelPlayer = 56,

    /// Unknown packet 60
    Unknown60 = 60,

    /// File transfer start
    LargeFileStart = 68,

    /// File transfer end
    LargeFileEnd = 69,

    /// Server text response
    ServerText = 82,

    /// Raw data
    RawData = 100,

    /// Board packet
    BoardPacket = 101,

    /// File data
    File = 102,

    /// Max upload file size
    RcMaxUploadFileSize = 103,

    /// NPC bytecode (compiled script)
    NpcBytecode = 131,

    /// Hide NPCs
    HideNpcs = 151,

    /// Say message (version 2)
    Say2 = 153,

    /// Freeze player
    FreezePlayer2 = 154,

    /// Unfreeze player
    UnfreezePlayer = 155,

    /// Set active level
    SetActiveLevel = 156,

    /// Move packet
    Move = 165,

    /// Unknown packet 168 - Login complete signal
    /// C++: PLO_UNKNOWN168 - "This seems to inform the client that they have logged in"
    Unknown168 = 168,

    /// Unknown packet 169
    Unknown169 = 169,

    /// Ghost mode
    GhostMode = 170,

    /// Big map
    BigMap = 171,

    /// Minimap
    Minimap = 172,

    /// Ghost text
    GhostText = 173,

    /// Ghost icon
    GhostIcon = 174,

    /// Full stop (freeze client)
    FullStop = 176,

    /// Full stop (version 2)
    FullStop2 = 177,

    /// Server warp
    ServerWarp = 178,

    /// RPG window
    RpgWindow = 179,

    /// Status list
    StatusList = 180,

    /// List processes
    ListProcesses = 182,

    /// Clear weapons
    ClearWeapons = 194,

    /// Move packet (version 2)
    Move2 = 189,

    /// Shoot (version 2)
    Shoot2 = 191,
}

impl PacketTypeOut {
    /// Convert a byte to a packet type
    ///
    /// # Purpose
    /// Maps raw packet ID bytes to their corresponding PacketTypeOut enum values.
    /// This is the primary method for parsing outgoing packet types.
    ///
    /// # Arguments
    /// * `value` - Raw packet type byte
    ///
    /// # Returns
    /// - `Some(PacketTypeOut)` if the byte corresponds to a known packet type
    /// - `None` if the packet type is unknown
    ///
    /// # C++ Equivalence
    /// Matches packet type definitions in `/home/versa/Downloads/GServer-v2/dependencies/gs2lib/include/IEnums.h`
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            //=== Level Packets (0-9) ===//
            0 => Some(PacketTypeOut::LevelBoard),
            1 => Some(PacketTypeOut::LevelLink),
            2 => Some(PacketTypeOut::BaddyProps),
            3 => Some(PacketTypeOut::NpcProps),
            4 => Some(PacketTypeOut::LevelChest),
            5 => Some(PacketTypeOut::LevelSign),
            6 => Some(PacketTypeOut::LevelName),
            7 => Some(PacketTypeOut::BoardModify),
            8 => Some(PacketTypeOut::OtherPlayerProps),
            9 => Some(PacketTypeOut::PlayerProps),
            //=== Player Actions (10-49) ===//
            10 => Some(PacketTypeOut::IsLeader),
            11 => Some(PacketTypeOut::BombAdd),
            12 => Some(PacketTypeOut::BombDel),
            13 => Some(PacketTypeOut::ToAll),
            14 => Some(PacketTypeOut::PlayerWarp),
            15 => Some(PacketTypeOut::WarpFailed),
            16 => Some(PacketTypeOut::DiscMessage),
            17 => Some(PacketTypeOut::HorseAdd),
            18 => Some(PacketTypeOut::HorseDel),
            19 => Some(PacketTypeOut::ArrowAdd),
            20 => Some(PacketTypeOut::Firespy),
            21 => Some(PacketTypeOut::ThrowCarried),
            22 => Some(PacketTypeOut::ItemAdd),
            23 => Some(PacketTypeOut::ItemDel),
            24 => Some(PacketTypeOut::NpcMoved),
            25 => Some(PacketTypeOut::Signature),
            26 => Some(PacketTypeOut::NpcAction),
            27 => Some(PacketTypeOut::BaddyHurt),
            28 => Some(PacketTypeOut::FlagSet),
            29 => Some(PacketTypeOut::NpcDel),
            30 => Some(PacketTypeOut::FileSendFailed),
            31 => Some(PacketTypeOut::FlagDel),
            32 => Some(PacketTypeOut::ShowImg),
            33 => Some(PacketTypeOut::NpcWeaponAdd),
            34 => Some(PacketTypeOut::NpcWeaponDel),
            35 => Some(PacketTypeOut::RcAdminMessage),
            36 => Some(PacketTypeOut::Explosion),
            37 => Some(PacketTypeOut::PrivateMessage),
            38 => Some(PacketTypeOut::PushAway),
            39 => Some(PacketTypeOut::LevelModTime),
            40 => Some(PacketTypeOut::HurtPlayer),
            41 => Some(PacketTypeOut::StartMessage),
            42 => Some(PacketTypeOut::NewWorldTime),
            43 => Some(PacketTypeOut::DefaultWeapon),
            44 => Some(PacketTypeOut::HasNpcServer),
            45 => Some(PacketTypeOut::FileUpToDate),
            46 => Some(PacketTypeOut::HitObjects),
            47 => Some(PacketTypeOut::StaffGuilds),
            48 => Some(PacketTypeOut::TriggerAction),
            49 => Some(PacketTypeOut::PlayerWarp2),
            //=== Player Management (55-60) ===//
            55 => Some(PacketTypeOut::AddPlayer),
            56 => Some(PacketTypeOut::DelPlayer),
            60 => Some(PacketTypeOut::Unknown60),
            //=== File Transfer (68-69, 100-103) ===//
            68 => Some(PacketTypeOut::LargeFileStart),
            69 => Some(PacketTypeOut::LargeFileEnd),
            82 => Some(PacketTypeOut::ServerText),
            100 => Some(PacketTypeOut::RawData),
            101 => Some(PacketTypeOut::BoardPacket),
            102 => Some(PacketTypeOut::File),
            103 => Some(PacketTypeOut::RcMaxUploadFileSize),
            //=== NPC Packets (131) ===//
            131 => Some(PacketTypeOut::NpcBytecode),
            //=== Extended Packets (151-156) ===//
            151 => Some(PacketTypeOut::HideNpcs),
            153 => Some(PacketTypeOut::Say2),
            154 => Some(PacketTypeOut::FreezePlayer2),
            155 => Some(PacketTypeOut::UnfreezePlayer),
            156 => Some(PacketTypeOut::SetActiveLevel),
            //=== Movement & Ghost (165, 168-182) ===//
            165 => Some(PacketTypeOut::Move),
            168 => Some(PacketTypeOut::Unknown168),
            169 => Some(PacketTypeOut::Unknown169),
            170 => Some(PacketTypeOut::GhostMode),
            171 => Some(PacketTypeOut::BigMap),
            172 => Some(PacketTypeOut::Minimap),
            173 => Some(PacketTypeOut::GhostText),
            174 => Some(PacketTypeOut::GhostIcon),
            176 => Some(PacketTypeOut::FullStop),
            177 => Some(PacketTypeOut::FullStop2),
            178 => Some(PacketTypeOut::ServerWarp),
            179 => Some(PacketTypeOut::RpgWindow),
            180 => Some(PacketTypeOut::StatusList),
            182 => Some(PacketTypeOut::ListProcesses),
            //=== More Packets (189, 191, 194) ===//
            189 => Some(PacketTypeOut::Move2),
            191 => Some(PacketTypeOut::Shoot2),
            194 => Some(PacketTypeOut::ClearWeapons),
            //=== Unknown ===//
            _ => None,
        }
    }

    /// Convert packet type to its byte ID
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}
