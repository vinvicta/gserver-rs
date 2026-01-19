//! Player account data structures

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;

/// Player flags/variables storage
///
/// # Purpose
/// Stores player-specific flags and variables used in scripting.
/// This is the Rust equivalent of GameVariableStore from the C++ codebase.
///
/// # C++ Equivalence
/// Matches `GameVariableStore` in ScriptContainers.h
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagStore {
    /// Stored flags as key-value pairs
    #[serde(flatten)]
    pub flags: HashMap<String, FlagValue>,
}

/// A flag value can be a string, number, or boolean
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlagValue {
    String(String),
    Number(f64),
    Boolean(bool),
}

impl FlagValue {
    /// Get as string (owned, for Number and Boolean variants)
    pub fn as_str(&self) -> Cow<str> {
        match self {
            FlagValue::String(s) => Cow::Borrowed(s),
            FlagValue::Number(n) => {
                // Convert number to string representation
                Cow::Owned(n.to_string())
            }
            FlagValue::Boolean(b) => Cow::Borrowed(if *b { "1" } else { "0" }),
        }
    }

    /// Get as number
    pub fn as_number(&self) -> f64 {
        match self {
            FlagValue::Number(n) => *n,
            FlagValue::String(s) => {
                s.parse().unwrap_or(0.0)
            }
            FlagValue::Boolean(b) => if *b { 1.0 } else { 0.0 },
        }
    }

    /// Get as boolean
    pub fn as_bool(&self) -> bool {
        match self {
            FlagValue::Boolean(b) => *b,
            FlagValue::String(s) => !s.is_empty(),
            FlagValue::Number(n) => *n != 0.0,
        }
    }

    /// Test if flag is set (for flag testing)
    pub fn is_set(&self) -> bool {
        match self {
            FlagValue::String(s) => !s.is_empty(),
            FlagValue::Number(n) => *n != 0.0,
            FlagValue::Boolean(b) => *b,
        }
    }
}

impl Default for FlagStore {
    fn default() -> Self {
        Self {
            flags: HashMap::new(),
        }
    }
}

impl FlagStore {
    /// Get a flag value
    pub fn get(&self, key: &str) -> Option<&FlagValue> {
        self.flags.get(key)
    }

    /// Set a flag value
    pub fn set(&mut self, key: String, value: FlagValue) {
        self.flags.insert(key, value);
    }

    /// Remove a flag
    pub fn remove(&mut self, key: &str) -> bool {
        self.flags.remove(key).is_some()
    }

    /// Check if a flag exists
    pub fn contains(&self, key: &str) -> bool {
        self.flags.contains_key(key)
    }

    /// Get all flags that start with a prefix
    pub fn get_prefix(&self, prefix: &str) -> Vec<(String, FlagValue)> {
        self.flags.iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// Player account data
///
/// # Purpose
/// Stores all player account information loaded from account files.
///
/// # File Format
/// Account files are stored in `accounts/ACCOUNTNAME.txt` with a simple text format:
/// ```text
/// GRACC001
/// NAME PlayerName
/// NICK PlayerNickname
/// LEVEL onlinestartlocal.nw
/// X 30.0
/// Y 30.5
/// MAXHP 3
/// HP 6.0
/// WEAPON bomb
/// WEAPON bow
/// FOLDERRIGHT rw accounts/*
/// ... (more fields)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Account name (login name)
    pub name: String,

    /// Display nickname
    pub nick: String,

    /// Community name
    pub community_name: String,

    /// Starting level
    pub level: String,

    /// X position (in pixels, divide by 16 for tiles)
    pub x: f32,

    /// Y position (in pixels, divide by 16 for tiles)
    pub y: f32,

    /// Z position
    pub z: f32,

    /// Maximum HP
    pub max_hp: f32,

    /// Current HP
    pub hp: f32,

    /// Current animation
    pub ani: String,

    /// Sprite type
    pub sprite: u32,

    /// Gralats (currency)
    pub gralats: u32,

    /// Arrow count
    pub arrows: u32,

    /// Bomb count
    pub bombs: u32,

    /// Glove power
    pub glove_power: u32,

    /// Sword power
    pub sword_power: u32,

    /// Shield power
    pub shield_power: u32,

    /// Bomb power
    pub bomb_power: u32,

    /// Bow power
    pub bow_power: u32,

    /// Bow
    pub bow: String,

    /// Head image
    pub head: String,

    /// Body image
    pub body: String,

    /// Sword image
    pub sword: String,

    /// Shield image
    pub shield: String,

    /// Colors (comma-separated)
    pub colors: String,

    /// Status code
    pub status: u32,

    /// Magic points
    pub mp: u32,

    /// Alignment points
    pub ap: i32,

    /// AP counter
    pub ap_counter: u32,

    /// Online time (seconds)
    pub onsecs: u32,

    /// IP address
    pub ip: String,

    /// Language
    pub language: String,

    /// Kill count
    pub kills: u32,

    /// Death count
    pub deaths: u32,

    /// Rating
    pub rating: f32,

    /// Rating deviation
    pub deviation: f32,

    /// Last spar time
    pub last_spar_time: u32,

    /// Banned flag
    pub banned: u32,

    /// Ban reason
    pub ban_reason: String,

    /// Ban length
    pub ban_length: String,

    /// Comments
    pub comments: String,

    /// Email
    pub email: String,

    /// Local rights (staff permissions)
    pub local_rights: u32,

    /// IP range
    pub ip_range: String,

    /// Load only flag
    pub load_only: u32,

    /// Weapons (weapon names from WEAPON entries)
    pub weapons: Vec<String>,

    /// Folder rights (FOLDERRIGHT entries, format: "rw accounts/*")
    pub folder_rights: Vec<String>,

    /// Last folder accessed
    pub last_folder: String,

    /// Gani attributes (30 animation strings)
    /// # C++ Equivalence
    /// Matches `std::array<std::string, 30> ganiAttributes` in Character.h
    /// These are animation attribute strings used in character scripting
    pub gani_attributes: [String; 30],

    /// Player flags/variables (this.*, server.*, clientr.*, etc.)
    /// # C++ Equivalence
    /// Matches `GameVariableStore variables` in Character.h
    /// Stored separately from extra to allow proper serialization
    #[serde(skip)]
    pub flags: FlagStore,

    /// Saved chests (level name -> list of (x, y) positions)
    /// # C++ Equivalence
    /// Matches `std::unordered_multimap<std::string, std::pair<int8_t, int8_t>> savedChests`
    pub saved_chests: HashMap<String, Vec<(i8, i8)>>,

    /// Additional custom properties
    #[serde(flatten)]
    pub extra: HashMap<String, String>,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            name: String::new(),
            nick: String::new(),
            community_name: String::new(),
            level: "onlinestartlocal.nw".to_string(),
            x: 30.0,
            y: 30.5,
            z: 0.0,
            max_hp: 3.0,
            hp: 6.0,
            ani: String::new(),
            sprite: 2,
            gralats: 0,
            arrows: 0,
            bombs: 0,
            glove_power: 0,
            sword_power: 1,
            shield_power: 1,
            bomb_power: 1,
            bow_power: 1,
            bow: String::new(),
            head: String::new(),
            body: String::new(),
            sword: String::new(),
            shield: String::new(),
            colors: "2,0,10,4,18".to_string(),
            status: 20,
            mp: 0,
            ap: 0,
            ap_counter: 0,
            onsecs: 0,
            ip: String::new(),
            language: "English".to_string(),
            kills: 0,
            deaths: 0,
            rating: 1500.0,
            deviation: 350.0,
            last_spar_time: 0,
            banned: 0,
            ban_reason: String::new(),
            ban_length: String::new(),
            comments: String::new(),
            email: String::new(),
            local_rights: 0,
            ip_range: String::new(),
            load_only: 0,
            weapons: Vec::new(),
            folder_rights: Vec::new(),
            last_folder: String::new(),
            gani_attributes: [
                String::new(), String::new(), String::new(), String::new(), String::new(),
                String::new(), String::new(), String::new(), String::new(), String::new(),
                String::new(), String::new(), String::new(), String::new(), String::new(),
                String::new(), String::new(), String::new(), String::new(), String::new(),
                String::new(), String::new(), String::new(), String::new(), String::new(),
                String::new(), String::new(), String::new(), String::new(), String::new(),
            ],
            flags: Default::default(),
            saved_chests: HashMap::new(),
            extra: HashMap::new(),
        }
    }
}

/// Player permissions (staff rights)
///
/// # Purpose
/// Bit flags for staff permissions.
///
/// # Example
/// ```rust
/// let rights = PLPERM_WARPTO | PLPERM_DISCONNECT;
/// assert!(player.has_permission(rights));
/// ```
pub type PlayerPermissions = u32;

/// Can warp to levels
pub const PLPERM_WARPTO: PlayerPermissions = 0x00001;

/// Can warp to players
pub const PLPERM_WARPTOPLAYER: PlayerPermissions = 0x00002;

/// Can summon players
pub const PLPERM_SUMMON: PlayerPermissions = 0x00004;

/// Can update levels
pub const PLPERM_UPDATELEVEL: PlayerPermissions = 0x00008;

/// Can disconnect players
pub const PLPERM_DISCONNECT: PlayerPermissions = 0x00010;

/// Can view player attributes
pub const PLPERM_VIEWATTRIBUTES: PlayerPermissions = 0x00020;

/// Can set player attributes
pub const PLPERM_SETATTRIBUTES: PlayerPermissions = 0x00040;

/// Can set own attributes
pub const PLPERM_SETSELFATTRIBUTES: PlayerPermissions = 0x00080;

/// Can reset player attributes
pub const PLPERM_RESETATTRIBUTES: PlayerPermissions = 0x00100;

/// Can send admin messages
pub const PLPERM_ADMINMSG: PlayerPermissions = 0x00200;

/// Can set rights
pub const PLPERM_SETRIGHTS: PlayerPermissions = 0x00400;

/// Can ban players
pub const PLPERM_BAN: PlayerPermissions = 0x00800;

/// Can set comments
pub const PLPERM_SETCOMMENTS: PlayerPermissions = 0x01000;

/// Can be invisible
pub const PLPERM_INVISIBLE: PlayerPermissions = 0x02000;

/// Can modify staff accounts
pub const PLPERM_MODIFYSTAFFACCOUNT: PlayerPermissions = 0x04000;

/// Can set server flags
pub const PLPERM_SETSERVERFLAGS: PlayerPermissions = 0x08000;

/// Can set server options
pub const PLPERM_SETSERVEROPTIONS: PlayerPermissions = 0x10000;

/// Can set folder options
pub const PLPERM_SETFOLDEROPTIONS: PlayerPermissions = 0x20000;

/// Can set folder rights
pub const PLPERM_SETFOLDERRIGHTS: PlayerPermissions = 0x40000;

/// Can control NPCs
pub const PLPERM_NPCCONTROL: PlayerPermissions = 0x80000;

/// All permissions
pub const PLPERM_ANYRIGHT: PlayerPermissions = 0xFFFFFF;

impl Account {
    /// Check if account has a specific permission
    #[inline]
    pub fn has_permission(&self, perm: PlayerPermissions) -> bool {
        (self.local_rights & perm) == perm
    }

    /// Check if account is staff (has any permissions)
    #[inline]
    pub fn is_staff(&self) -> bool {
        self.local_rights != 0
    }

    /// Check if account can use RC (Remote Control)
    #[inline]
    pub fn can_use_rc(&self) -> bool {
        self.is_staff() || self.local_rights & PLPERM_ANYRIGHT != 0
    }

    /// Get position in tiles (16 pixels = 1 tile)
    #[inline]
    pub fn get_tile_pos(&self) -> (f32, f32) {
        (self.x / 16.0, self.y / 16.0)
    }

    /// Check if account has a specific weapon
    ///
    /// # C++ Equivalence
    /// Matches `Account::hasWeapon()` in Account.cpp
    /// Weapon comparison is case-insensitive
    #[inline]
    pub fn has_weapon(&self, weapon: &str) -> bool {
        self.weapons.iter().any(|w| w.eq_ignore_ascii_case(weapon))
    }

    /// Add a weapon to the account
    ///
    /// # C++ Equivalence
    /// Matches the weapon loading from account files
    pub fn add_weapon(&mut self, weapon: String) {
        // Don't add duplicates
        if !self.has_weapon(&weapon) {
            self.weapons.push(weapon);
        }
    }

    /// Get folder rights for a specific path
    ///
    /// # C++ Equivalence
    /// Matches `FilePermissions::getPermission()` in the C++ code
    ///
    /// Returns the permission string (e.g., "rw", "r", "-") for the given path
    /// or None if no matching folder right is found
    pub fn get_folder_rights(&self, path: &str) -> Option<String> {
        for folder_right in &self.folder_rights {
            // Format: "rw accounts/*" or "r weapons/*"
            let parts: Vec<&str> = folder_right.splitn(2, ' ').collect();
            if parts.len() == 2 {
                let permission = parts[0];
                let pattern = parts[1];

                // Simple pattern matching (supports * wildcard)
                if self.matches_folder_pattern(path, pattern) {
                    return Some(permission.to_string());
                }
            }
        }
        None
    }

    /// Check if a path matches a folder pattern
    ///
    /// # Examples
    /// - "accounts/test.txt" matches "accounts/*"
    /// - "config/serveroptions.txt" matches "config/*"
    fn matches_folder_pattern(&self, path: &str, pattern: &str) -> bool {
        if pattern.ends_with("/*") {
            let prefix = &pattern[..pattern.len() - 2];
            path.starts_with(prefix) || path == prefix.trim_end_matches('/')
        } else if pattern.ends_with('*') {
            let prefix = &pattern[..pattern.len() - 1];
            path.starts_with(prefix)
        } else {
            path == pattern
        }
    }

    /// Check if player has opened a specific chest
    ///
    /// # C++ Equivalence
    /// Matches `Account::hasChest()` in the C++ code
    pub fn has_chest(&self, level: &str, x: i8, y: i8) -> bool {
        self.saved_chests.get(level)
            .map(|chests| chests.contains(&(x, y)))
            .unwrap_or(false)
    }

    /// Add a chest to the saved chests list
    ///
    /// # C++ Equivalence
    /// Matches chest opening behavior in PlayerClient::msgPLI_OPENCHEST
    pub fn add_chest(&mut self, level: &str, x: i8, y: i8) {
        self.saved_chests
            .entry(level.to_string())
            .or_insert_with(Vec::new)
            .push((x, y));
    }

    /// Get a gani attribute by index (0-29)
    ///
    /// # C++ Equivalence
    /// Matches accessing `Character::ganiAttributes[idx]`
    pub fn get_gani_attr(&self, index: usize) -> Option<&str> {
        self.gani_attributes.get(index).map(|s| s.as_str())
    }

    /// Set a gani attribute by index (0-29)
    ///
    /// # C++ Equivalence
    /// Matches setting `Character::ganiAttributes[idx]`
    pub fn set_gani_attr(&mut self, index: usize, value: String) {
        if index < 30 {
            self.gani_attributes[index] = value;
        }
    }

    /// Set a flag value
    ///
    /// # C++ Equivalence
    /// Matches `Player::setFlag()` behavior
    pub fn set_flag(&mut self, key: &str, value: FlagValue) {
        self.flags.set(key.to_string(), value);
    }

    /// Get a flag value
    pub fn get_flag(&self, key: &str) -> Option<&FlagValue> {
        self.flags.get(key)
    }

    /// Remove a flag
    pub fn remove_flag(&mut self, key: &str) -> bool {
        self.flags.remove(key)
    }

    /// Check if flag is set (for testing)
    pub fn has_flag(&self, key: &str) -> bool {
        self.flags.get(key).map(|v| v.is_set()).unwrap_or(false)
    }
}
