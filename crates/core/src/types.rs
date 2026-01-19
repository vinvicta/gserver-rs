//! Core type definitions

use serde::{Deserialize, Serialize};

/// Player ID (16-bit unsigned)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlayerID(pub u16);

impl PlayerID {
    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    pub fn get(&self) -> u16 {
        self.0
    }
}

impl From<u16> for PlayerID {
    fn from(id: u16) -> Self {
        Self(id)
    }
}

/// NPC ID (32-bit unsigned)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NPCID(pub u32);

impl NPCID {
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn get(&self) -> u32 {
        self.0
    }
}

impl From<u32> for NPCID {
    fn from(id: u32) -> Self {
        Self(id)
    }
}

/// Account name (String-based)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountName(pub String);

impl AccountName {
    pub fn new(name: String) -> Self {
        Self(name)
    }

    pub fn get(&self) -> &str {
        &self.0
    }
}

impl From<String> for AccountName {
    fn from(name: String) -> Self {
        Self(name)
    }
}

impl From<&str> for AccountName {
    fn from(name: &str) -> Self {
        Self(name.to_string())
    }
}

/// Server generation enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerGeneration {
    /// 1.x
    Original = 0,
    /// 2.x/3.x
    Classic = 1,
    /// 4.x to 5.007
    NewMain = 2,
    /// 5.1 and up
    Modern = 3,
}

impl ServerGeneration {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Original),
            1 => Some(Self::Classic),
            2 => Some(Self::NewMain),
            3 => Some(Self::Modern),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Original => "original",
            Self::Classic => "classic",
            Self::NewMain => "newmain",
            Self::Modern => "modern",
        }
    }
}

/// Socket type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    Player = 0,
    Server = 1,
}
