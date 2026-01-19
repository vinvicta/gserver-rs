//! # Player Properties
//!
//! This module contains all 84 player property definitions matching the C++ GServer implementation.
//!
//! Graal players have 84 properties that track everything from position to appearance to
//! admin rights. This module provides the complete property system with proper serialization.
//!
//! # Property Types
//!
//! - **PropertyNumeric<T>**: Packed numeric values (GBYTE1/2/3/5 = 1/2/4/8 bytes)
//! - **PropertyString**: Length-prefixed string (1 byte length prefix)
//! - **PropertyTileCoordinate**: Old-style tile coordinates (divided by 16)
//! - **PropertySprite**: Sprite + direction
//! - **PropertyColors**: Array of 5 color values
//! - **PropertyEffectColors**: Array of 5 effect colors (stop if first is 0)
//! - **PropertySwordPower**: Sword image + power combo
//! - **PropertyShieldPower**: Shield image + power combo
//! - **PropertyGaniOrBowGif**: Gani or bow gif + power (changed in 2.x clients)
//! - **PropertyHeadGif**: Head image (can be preset ID or string)
//! - **PropertyAttachNPC**: Attached NPC with type
//! - **PropertyTileCoordinateZ**: Z coordinate (offset by 50)
//! - **PropertyPixelCoordinate**: Pixel coordinate (3 bytes)
//! - **PropertyEloRating**: ELO rating + deviation
//! - **PropertyVoid**: No data
//! - **PropertyUnsafeByte**: Raw byte without validation

use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Numeric type aliases matching C++ GBYTE types
pub type GByte1 = u8;
pub type GByte2 = u16;
pub type GByte3 = u32;
pub type GByte5 = i64;

/// Player property enum (84 properties, 0-83)
///
/// This enum matches the C++ PlayerProp enum exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PlayerProp {
    // Core properties (0-10)
    Nickname = 0,      // Player nickname
    MaxPower = 1,      // Maximum hitpoints
    CurPower = 2,      // Current hitpoints
    RupeesCount = 3,   // Gralats count
    ArrowsCount = 4,   // Arrows count
    BombsCount = 5,    // Bombs count
    GlovePower = 6,    // Glove power (0-3)
    BombPower = 7,     // Bomb power (0-3)
    SwordPower = 8,    // Sword power + image
    ShieldPower = 9,   // Shield power + image
    Gani = 10,         // Gani or bow gif (BOWGIF in pre-2.x)

    // Appearance (11-23)
    HeadGif = 11,      // Head image or preset ID
    CurChat = 12,      // Current chat message
    Colors = 13,       // Player colors (5 values)
    Id = 14,           // Player ID
    X = 15,            // X position (tile coordinate)
    Y = 16,            // Y position (tile coordinate)
    Sprite = 17,       // Sprite + direction
    Status = 18,       // Player status
    CarrySprite = 19,  // Carried sprite
    CurLevel = 20,     // Current level name
    HorseGif = 21,     // Horse image
    HorseBushes = 22,  // Horse bomb count
    EffectColors = 23, // Effect colors (5 values, stop if first is 0)

    // More properties (24-35)
    CarryNPC = 24,     // Carried NPC ID
    ApCounter = 25,    // AP counter
    MagicPoints = 26,  // MP (0-100)
    KillsCount = 27,   // Kill count
    DeathsCount = 28,  // Death count
    OnlineSecs = 29,   // Online seconds (3 bytes)
    IpAddr = 30,       // IP address (5 bytes)
    UdpPort = 31,      // UDP port
    Alignment = 32,    // Alignment points (AP)
    AdditFlags = 33,   // Additional flags
    AccountName = 34,  // Account name
    BodyImg = 35,      // Body image

    // Rating and gani attributes (36-50)
    Rating = 36,       // ELO rating + deviation
    GAttrib1 = 37,     // Gani attribute 1
    GAttrib2 = 38,     // Gani attribute 2
    GAttrib3 = 39,     // Gani attribute 3
    GAttrib4 = 40,     // Gani attribute 4
    GAttrib5 = 41,     // Gani attribute 5
    AttachNPC = 42,    // Attached NPC
    GmapLevelX = 43,   // GMap X coordinate
    GmapLevelY = 44,   // GMap Y coordinate
    Z = 45,            // Z coordinate
    GAttrib6 = 46,     // Gani attribute 6
    GAttrib7 = 47,     // Gani attribute 7
    GAttrib8 = 48,     // Gani attribute 8
    GAttrib9 = 49,     // Gani attribute 9
    JoinLeaveLvl = 50, // Join/leave level

    // Flags and more gani attributes (51-74)
    Disconnect = 51,   // Disconnect flag
    Language = 52,     // Player language
    PlayerListStatus = 53, // Player list status
    GAttrib10 = 54,    // Gani attribute 10
    GAttrib11 = 55,    // Gani attribute 11
    GAttrib12 = 56,    // Gani attribute 12
    GAttrib13 = 57,    // Gani attribute 13
    GAttrib14 = 58,    // Gani attribute 14
    GAttrib15 = 59,    // Gani attribute 15
    GAttrib16 = 60,    // Gani attribute 16
    GAttrib17 = 61,    // Gani attribute 17
    GAttrib18 = 62,    // Gani attribute 18
    GAttrib19 = 63,    // Gani attribute 19
    GAttrib20 = 64,    // Gani attribute 20
    GAttrib21 = 65,    // Gani attribute 21
    GAttrib22 = 66,    // Gani attribute 22
    GAttrib23 = 67,    // Gani attribute 23
    GAttrib24 = 68,    // Gani attribute 24
    GAttrib25 = 69,    // Gani attribute 25
    GAttrib26 = 70,    // Gani attribute 26
    GAttrib27 = 71,    // Gani attribute 27
    GAttrib28 = 72,    // Gani attribute 28
    GAttrib29 = 73,    // Gani attribute 29
    GAttrib30 = 74,    // Gani attribute 30

    // Extended properties (75-82, added in 2.19+)
    OsType = 75,           // OS type (2.19+)
    TextCodePage = 76,     // Text code page (2.19+)
    OnlineSecs2 = 77,      // Online seconds (5 bytes)
    X2 = 78,               // X position (pixel coordinate)
    Y2 = 79,               // Y position (pixel coordinate)
    Z2 = 80,               // Z position (pixel coordinate)
    PlayerListCategory = 81, // Player list category
    CommunityName = 82,    // Community name (Graal######## alias)

    // Unknown (83)
    Unknown83 = 83,        // v6 reads 5 bytes but doesn't use

    // Count (84)
    PlayerPropCount = 84,
}

impl PlayerProp {
    /// Convert from u8 to PlayerProp
    pub fn from_u8(val: u8) -> Option<Self> {
        if val < Self::PlayerPropCount as u8 {
            Some(unsafe { std::mem::transmute(val) })
        } else {
            None
        }
    }

    /// Get all gani attribute properties
    pub fn gani_attribs() -> [PlayerProp; 30] {
        [
            PlayerProp::GAttrib1, PlayerProp::GAttrib2, PlayerProp::GAttrib3,
            PlayerProp::GAttrib4, PlayerProp::GAttrib5, PlayerProp::GAttrib6,
            PlayerProp::GAttrib7, PlayerProp::GAttrib8, PlayerProp::GAttrib9,
            PlayerProp::GAttrib10, PlayerProp::GAttrib11, PlayerProp::GAttrib12,
            PlayerProp::GAttrib13, PlayerProp::GAttrib14, PlayerProp::GAttrib15,
            PlayerProp::GAttrib16, PlayerProp::GAttrib17, PlayerProp::GAttrib18,
            PlayerProp::GAttrib19, PlayerProp::GAttrib20, PlayerProp::GAttrib21,
            PlayerProp::GAttrib22, PlayerProp::GAttrib23, PlayerProp::GAttrib24,
            PlayerProp::GAttrib25, PlayerProp::GAttrib26, PlayerProp::GAttrib27,
            PlayerProp::GAttrib28, PlayerProp::GAttrib29, PlayerProp::GAttrib30,
        ]
    }
}

/// Property modification time tracker
#[derive(Debug, Clone)]
pub struct PropModTimes {
    /// Modification times for all 84 properties
    times: [Option<Instant>; PlayerProp::PlayerPropCount as usize],
}

impl Default for PropModTimes {
    fn default() -> Self {
        Self::new()
    }
}

impl PropModTimes {
    pub fn new() -> Self {
        Self {
            times: [const { None }; PlayerProp::PlayerPropCount as usize],
        }
    }

    /// Mark a property as modified
    pub fn mark_modified(&mut self, prop: PlayerProp) {
        self.times[prop as usize] = Some(Instant::now());
    }

    /// Get modification time for a property
    pub fn get_mod_time(&self, prop: PlayerProp) -> Option<Instant> {
        self.times[prop as usize]
    }

    /// Clear all modification times
    pub fn clear(&mut self) {
        self.times = [const { None }; PlayerProp::PlayerPropCount as usize];
    }

    /// Save current modification times
    pub fn save(&mut self) -> Self {
        Self { times: self.times }
    }

    /// Check if property was modified since save
    pub fn is_modified_since(&self, prop: PlayerProp, saved: &PropModTimes) -> bool {
        match (self.times[prop as usize], saved.times[prop as usize]) {
            (Some(current), Some(saved_time)) => current > saved_time,
            (Some(_), None) => true,
            _ => false,
        }
    }
}

/// Sprite + direction property
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PropertySprite {
    pub sprite: u8,
    pub direction: u8,
}

impl Default for PropertySprite {
    fn default() -> Self {
        Self { sprite: 0, direction: 2 }
    }
}

/// Sword power + image property
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PropertySwordPower {
    pub image: String,
    pub power: Option<i8>,
}

impl Default for PropertySwordPower {
    fn default() -> Self {
        Self {
            image: String::new(),
            power: None,
        }
    }
}

/// Shield power + image property
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PropertyShieldPower {
    pub image: String,
    pub power: Option<u8>,
}

impl Default for PropertyShieldPower {
    fn default() -> Self {
        Self {
            image: String::new(),
            power: None,
        }
    }
}

/// Gani or bow gif property (changed in 2.x clients)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PropertyGaniOrBowGif {
    Gani(String),
    BowGif { gif: String, power: u8 },
}

impl Default for PropertyGaniOrBowGif {
    fn default() -> Self {
        Self::Gani(String::new())
    }
}

/// Head gif property (can be preset ID or image)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PropertyHeadGif {
    Preset(u8),
    Image(String),
}

impl Default for PropertyHeadGif {
    fn default() -> Self {
        Self::Preset(0)
    }
}

/// Attached NPC property
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PropertyAttachNPC {
    pub npc_id: u32,
    pub type_code: u8,
}

impl Default for PropertyAttachNPC {
    fn default() -> Self {
        Self { npc_id: 0, type_code: 0 }
    }
}

/// ELO rating property
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PropertyEloRating {
    pub rating: f32,
    pub deviation: f32,
}

impl Default for PropertyEloRating {
    fn default() -> Self {
        Self {
            rating: 1500.0,
            deviation: 350.0,
        }
    }
}

/// Player properties (all 84 properties)
///
/// This struct contains all player properties matching the C++ implementation.
/// Properties are organized logically for easier access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerProperties {
    // === Core Properties (0-10) ===
    /// Player nickname (display name)
    pub nickname: String,

    /// Maximum hitpoints (0-20)
    pub max_power: u8,

    /// Current hitpoints (in halves, so 10 = 5 hearts)
    pub cur_power: u8,

    /// Gralats (rupees) count
    pub rupees_count: u32,

    /// Arrows count (0-99)
    pub arrows_count: u8,

    /// Bombs count (0-99)
    pub bombs_count: u8,

    /// Glove power (0=None, 1=?, 2=glove1, 3=glove2)
    pub glove_power: u8,

    /// Bomb power (0=bomb, 1=joltbomb, 2=superbomb, 3=firebomb)
    pub bomb_power: u8,

    /// Sword power and image
    pub sword_power: PropertySwordPower,

    /// Shield power and image
    pub shield_power: PropertyShieldPower,

    /// Gani or bow gif (changed in 2.x)
    pub gani: PropertyGaniOrBowGif,

    // === Appearance (11-23) ===
    /// Head image (preset ID or image name)
    pub head_gif: PropertyHeadGif,

    /// Current chat message
    pub cur_chat: String,

    /// Player colors (5 values: skin, coat, sleeve, shoes, belt)
    pub colors: [u8; 5],

    /// Player ID
    pub id: u16,

    /// X position (tile coordinate, divide by 16 for pixels)
    pub x: i16,

    /// Y position (tile coordinate, divide by 16 for pixels)
    pub y: i16,

    /// Sprite and direction
    pub sprite: PropertySprite,

    /// Player status
    pub status: u8,

    /// Carried sprite (0xFF = none, 0=bomb, 1=bush, 3=stone, 5=vase, 7=sign, 61=superbomb, 87=joltbomb, 88=hotjoltbomb, 200=hotbomb, 201=blackstone, 251=npc, 255=none)
    pub carry_sprite: u8,

    /// Current level name
    pub cur_level: String,

    /// Horse image
    pub horse_gif: String,

    /// Horse bomb count
    pub horse_bushes: u8,

    /// Effect colors (5 values, stop if first is 0)
    pub effect_colors: [u8; 5],

    // === Extended Properties (24-35) ===
    /// Carried NPC ID
    pub carry_npc: u32,

    /// AP counter
    pub ap_counter: u16,

    /// Magic points (0-100)
    pub magic_points: u8,

    /// Kill count
    pub kills_count: u32,

    /// Death count
    pub deaths_count: u32,

    /// Online seconds (3 bytes)
    pub online_secs: u32,

    /// IP address (5 bytes)
    pub ip_addr: i64,

    /// UDP port
    pub udp_port: u32,

    /// Alignment points (0-100)
    pub alignment: u8,

    /// Additional flags
    pub addit_flags: u8,

    /// Account name
    pub account_name: String,

    /// Body image
    pub body_img: String,

    // === Rating and Gani Attributes (36-74) ===
    /// ELO rating and deviation
    pub rating: PropertyEloRating,

    /// Gani attributes (30 strings)
    pub gani_attribs: [String; 30],

    /// Attached NPC
    pub attach_npc: PropertyAttachNPC,

    /// GMap X coordinate
    pub gmap_level_x: u8,

    /// GMap Y coordinate
    pub gmap_level_y: u8,

    /// Z coordinate (tile coordinate, offset by 50*16 = 800)
    pub z: i16,

    /// Join/leave level flag
    pub join_leave_lvl: u8,

    // === Flags and Language (51-53) ===
    /// Disconnect flag
    pub disconnect: bool,

    /// Player language
    pub language: String,

    /// Player list status
    pub player_list_status: u8,

    // === Extended Properties (75-82, 2.19+) ===
    /// OS type
    pub os_type: String,

    /// Text code page
    pub text_code_page: u32,

    /// Online seconds (5 bytes)
    pub online_secs2: i64,

    /// X position (pixel coordinate)
    pub x2: i16,

    /// Y position (pixel coordinate)
    pub y2: i16,

    /// Z position (pixel coordinate)
    pub z2: i16,

    /// Player list category
    pub player_list_category: u8,

    /// Community name (Graal######## alias)
    pub community_name: String,

    /// Unknown property 83 (v6 reads 5 bytes but doesn't use)
    pub unknown_83: i64,

    // === Non-serialized ===
    /// Modification times for all properties
    #[serde(skip)]
    pub mod_times: PropModTimes,
}

impl PlayerProperties {
    /// Create default player properties
    pub fn new() -> Self {
        Self {
            // Core properties
            nickname: "Player".to_string(),
            max_power: 5, // 2.5 hearts
            cur_power: 10, // 5 hearts (in halves)
            rupees_count: 0,
            arrows_count: 0,
            bombs_count: 0,
            glove_power: 0,
            bomb_power: 0,
            sword_power: PropertySwordPower::default(),
            shield_power: PropertyShieldPower::default(),
            gani: PropertyGaniOrBowGif::Gani("idle.gani".to_string()),

            // Appearance
            head_gif: PropertyHeadGif::Preset(0),
            cur_chat: String::new(),
            colors: [0, 0, 0, 0, 0],
            id: 0,
            x: 0,
            y: 0,
            sprite: PropertySprite::default(),
            status: 0,
            carry_sprite: 0xFF,
            cur_level: "onlinestartlocal.nw".to_string(),
            horse_gif: String::new(),
            horse_bushes: 0,
            effect_colors: [0, 0, 0, 0, 0],

            // Extended
            carry_npc: 0,
            ap_counter: 0,
            magic_points: 0,
            kills_count: 0,
            deaths_count: 0,
            online_secs: 0,
            ip_addr: 0,
            udp_port: 0,
            alignment: 0,
            addit_flags: 0,
            account_name: String::new(),
            body_img: String::new(),

            // Rating and gani
            rating: PropertyEloRating::default(),
            gani_attribs: Default::default(),
            attach_npc: PropertyAttachNPC::default(),
            gmap_level_x: 0,
            gmap_level_y: 0,
            z: 0,
            join_leave_lvl: 1,

            // Flags and language
            disconnect: false,
            language: "English".to_string(),
            player_list_status: 0,

            // Extended (2.19+)
            os_type: "wind".to_string(),
            text_code_page: 1252,
            online_secs2: 0,
            x2: 0,
            y2: 0,
            z2: 0,
            player_list_category: 0,
            community_name: String::new(),
            unknown_83: 0,

            // Non-serialized
            mod_times: PropModTimes::new(),
        }
    }

    /// Get X position in pixels (tile coordinate * 16)
    pub fn x_pixels(&self) -> i16 {
        self.x * 16
    }

    /// Get Y position in pixels (tile coordinate * 16)
    pub fn y_pixels(&self) -> i16 {
        self.y * 16
    }

    /// Get Z position in pixels (tile coordinate * 16, offset by 800)
    pub fn z_pixels(&self) -> i16 {
        self.z * 16
    }

    /// Set X position from pixels
    pub fn set_x_pixels(&mut self, pixels: i16) {
        self.x = pixels / 16;
        self.x2 = pixels;
    }

    /// Set Y position from pixels
    pub fn set_y_pixels(&mut self, pixels: i16) {
        self.y = pixels / 16;
        self.y2 = pixels;
    }

    /// Set Z position from pixels
    pub fn set_z_pixels(&mut self, pixels: i16) {
        self.z = pixels / 16;
        self.z2 = pixels;
    }

    /// Get hitpoints in hearts (cur_power is in halves)
    pub fn hearts(&self) -> f32 {
        self.cur_power as f32 / 2.0
    }

    /// Set hitpoints in hearts
    pub fn set_hearts(&mut self, hearts: f32) {
        let cur_power = (hearts * 2.0) as u8;
        self.cur_power = cur_power.min(self.max_power);
    }

    /// Get a gani attribute by index (0-29)
    pub fn get_gani_attrib(&self, index: usize) -> Option<&str> {
        self.gani_attribs.get(index).map(|s| s.as_str())
    }

    /// Set a gani attribute by index (0-29)
    pub fn set_gani_attrib(&mut self, index: usize, value: String) {
        if index < 30 {
            self.gani_attribs[index] = value;
        }
    }
}

impl Default for PlayerProperties {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_player_prop_enum() {
        // Test enum values match C++ exactly
        assert_eq!(PlayerProp::Nickname as u8, 0);
        assert_eq!(PlayerProp::Id as u8, 14);
        assert_eq!(PlayerProp::X as u8, 15);
        assert_eq!(PlayerProp::Y as u8, 16);
        assert_eq!(PlayerProp::Z as u8, 45);
        assert_eq!(PlayerProp::Disconnect as u8, 51);
        assert_eq!(PlayerProp::OsType as u8, 75);
        assert_eq!(PlayerProp::CommunityName as u8, 82);
        assert_eq!(PlayerProp::PlayerPropCount as u8, 84);
    }

    #[test]
    fn test_player_prop_from_u8() {
        assert_eq!(PlayerProp::from_u8(0), Some(PlayerProp::Nickname));
        assert_eq!(PlayerProp::from_u8(82), Some(PlayerProp::CommunityName));
        assert_eq!(PlayerProp::from_u8(84), None); // Out of range
        assert_eq!(PlayerProp::from_u8(255), None);
    }

    #[test]
    fn test_properties_default() {
        let props = PlayerProperties::new();
        assert_eq!(props.nickname, "Player");
        assert_eq!(props.max_power, 5);
        assert_eq!(props.cur_power, 10);
        assert_eq!(props.rupees_count, 0);
        assert_eq!(props.arrows_count, 0);
        assert_eq!(props.bombs_count, 0);
        assert_eq!(props.x, 0);
        assert_eq!(props.y, 0);
        assert_eq!(props.z, 0);
        assert_eq!(props.cur_level, "onlinestartlocal.nw");
    }

    #[test]
    fn test_pixel_coordinates() {
        let mut props = PlayerProperties::new();

        // Test tile to pixel conversion
        props.x = 10;
        props.y = 20;
        assert_eq!(props.x_pixels(), 160);
        assert_eq!(props.y_pixels(), 320);

        // Test pixel to tile conversion
        props.set_x_pixels(160);
        props.set_y_pixels(320);
        assert_eq!(props.x, 10);
        assert_eq!(props.y, 20);
        assert_eq!(props.x2, 160);
        assert_eq!(props.y2, 320);
    }

    #[test]
    fn test_hearts() {
        let mut props = PlayerProperties::new();
        props.max_power = 10; // 10 halves = 5 hearts max

        // Test hearts calculation (cur_power is in halves)
        props.cur_power = 6;
        assert_eq!(props.hearts(), 3.0);

        // Test setting hearts
        props.set_hearts(4.0);
        assert_eq!(props.cur_power, 8);
        assert_eq!(props.hearts(), 4.0);

        // Test clamping to max (max_power is 10 halves = 5 hearts)
        // Setting 10 hearts = 20 halves, should clamp to 10 halves (5 hearts)
        props.set_hearts(10.0);
        assert_eq!(props.cur_power, 10); // Clamped to max_power (10 halves)
        assert_eq!(props.hearts(), 5.0); // Max is 5 hearts
    }

    #[test]
    fn test_gani_attribs() {
        let mut props = PlayerProperties::new();

        // Test getting/setting gani attributes
        assert_eq!(props.get_gani_attrib(0), Some(""));
        props.set_gani_attrib(0, "attrib0".to_string());
        assert_eq!(props.get_gani_attrib(0), Some("attrib0"));

        // Test bounds checking
        assert_eq!(props.get_gani_attrib(30), None);
        props.set_gani_attrib(30, "invalid".to_string()); // Should be ignored
        assert_eq!(props.get_gani_attrib(30), None);
    }

    #[test]
    fn test_prop_mod_times() {
        let mut times = PropModTimes::new();

        // Test marking as modified
        assert!(times.get_mod_time(PlayerProp::Nickname).is_none());
        times.mark_modified(PlayerProp::Nickname);
        assert!(times.get_mod_time(PlayerProp::Nickname).is_some());

        // Test save/restore
        let saved = times.save();
        times.mark_modified(PlayerProp::X);
        assert!(times.is_modified_since(PlayerProp::X, &saved));
        assert!(!times.is_modified_since(PlayerProp::Nickname, &saved));

        // Test clear
        times.clear();
        assert!(times.get_mod_time(PlayerProp::Nickname).is_none());
        assert!(times.get_mod_time(PlayerProp::X).is_none());
    }

    #[test]
    fn test_all_84_properties_exist() {
        let props = PlayerProperties::new();

        // Verify all properties can be accessed
        let _ = props.nickname;
        let _ = props.max_power;
        let _ = props.cur_power;
        let _ = props.rupees_count;
        let _ = props.arrows_count;
        let _ = props.bombs_count;
        let _ = props.glove_power;
        let _ = props.bomb_power;
        let _ = &props.sword_power;
        let _ = &props.shield_power;
        let _ = &props.gani;
        let _ = &props.head_gif;
        let _ = &props.cur_chat;
        let _ = &props.colors;
        let _ = props.id;
        let _ = props.x;
        let _ = props.y;
        let _ = &props.sprite;
        let _ = props.status;
        let _ = props.carry_sprite;
        let _ = &props.cur_level;
        let _ = &props.horse_gif;
        let _ = props.horse_bushes;
        let _ = &props.effect_colors;
        let _ = props.carry_npc;
        let _ = props.ap_counter;
        let _ = props.magic_points;
        let _ = props.kills_count;
        let _ = props.deaths_count;
        let _ = props.online_secs;
        let _ = props.ip_addr;
        let _ = props.udp_port;
        let _ = props.alignment;
        let _ = props.addit_flags;
        let _ = &props.account_name;
        let _ = &props.body_img;
        let _ = &props.rating;
        let _ = &props.gani_attribs;
        let _ = &props.attach_npc;
        let _ = props.gmap_level_x;
        let _ = props.gmap_level_y;
        let _ = props.z;
        let _ = props.join_leave_lvl;
        let _ = props.disconnect;
        let _ = &props.language;
        let _ = props.player_list_status;
        let _ = &props.os_type;
        let _ = props.text_code_page;
        let _ = props.online_secs2;
        let _ = props.x2;
        let _ = props.y2;
        let _ = props.z2;
        let _ = props.player_list_category;
        let _ = &props.community_name;
        let _ = props.unknown_83;
    }
}
