//! Level loading and management
//!
//! # Purpose
//! Loads and manages Graal Online level files in GLEVNW01 format.
//!
//! # File Format (GLEVNW01)
//! ```text
//! GLEVNW01
//! BOARD x y width layer base64data
//! CHEST x y item index
//! NPC image x y
//! SCRIPT
//! ...script code...
//! NPCEND
//! SIGN x y
//! ...sign text...
//! SIGNEND
//! BADDY x y type
//! ...verses...
//! BADDYEND
//! LINK x y level x y
//! HEIGHTS
//! ...heightmap data...
//! HEIGHTSEND
//! ```
//!
//! # C++ Equivalence
//! Matches `LevelLoader` in LevelLoader.cpp

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Level loading errors
#[derive(Debug, Error)]
pub enum LevelError {
    #[error("Invalid level magic: {0}")]
    InvalidMagic(String),

    #[error("Invalid board data: {0}")]
    InvalidBoardData(String),

    #[error("Invalid board format: {0}")]
    InvalidBoardFormat(String),

    #[error("Invalid NPC data: {0}")]
    InvalidNpcData(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Level data structure
///
/// # C++ Equivalence
/// Matches `Level` class in Level.h
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Level {
    /// Level name (filename without extension)
    pub name: String,

    /// Board tiles (64x64 = 4096 tiles, 2 bytes each = 8192 bytes)
    /// Stored as 16-bit tile indices
    pub tiles: Vec<u16>,

    /// Level width in tiles (always 64 for Graal levels)
    pub width: usize,

    /// Level height in tiles (always 64 for Graal levels)
    pub height: usize,

    /// Level modification time (Unix timestamp)
    pub mod_time: u64,

    /// Chests in the level
    pub chests: Vec<LevelChest>,

    /// NPCs in the level
    pub npcs: Vec<LevelNpc>,

    /// Signs in the level
    pub signs: Vec<LevelSign>,

    /// Baddies (enemies) in the level
    pub baddies: Vec<LevelBaddy>,

    /// Links (warps) in the level
    pub links: Vec<LevelLink>,

    /// Heightmap for gmap terrain generation
    /// 65x65 double-precision values
    pub heights: Option<Vec<f64>>,

    /// Additional metadata
    #[serde(flatten)]
    pub extra: HashMap<String, String>,
}

impl Level {
    /// Create a new empty level
    pub fn new(name: String) -> Self {
        Self {
            tiles: vec![0; 4096], // 64x64 empty tiles
            width: 64,
            height: 64,
            name,
            mod_time: 0,
            chests: Vec::new(),
            npcs: Vec::new(),
            signs: Vec::new(),
            baddies: Vec::new(),
            links: Vec::new(),
            heights: None,
            extra: HashMap::new(),
        }
    }

    /// Get tile at position (x, y)
    pub fn get_tile(&self, x: usize, y: usize) -> u16 {
        if x < self.width && y < self.height {
            self.tiles[y * self.width + x]
        } else {
            0
        }
    }

    /// Set tile at position (x, y)
    pub fn set_tile(&mut self, x: usize, y: usize, tile: u16) {
        if x < self.width && y < self.height {
            self.tiles[y * self.width + x] = tile;
        }
    }
}

impl Default for Level {
    fn default() -> Self {
        Self::new("unnamed".to_string())
    }
}

/// Chest object
///
/// # C++ Equivalence
/// Matches `LevelChest` in LevelChest.h
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelChest {
    /// X position (in tiles)
    pub x: u8,

    /// Y position (in tiles)
    pub y: u8,

    /// Item type in chest
    pub item: LevelItemType,

    /// Chest index/sign
    pub sign: u8,
}

/// NPC definition
///
/// # C++ Equivalence
/// Matches NPC data format from LevelLoader
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelNpc {
    /// Image filename
    pub image: String,

    /// X position (in tiles)
    pub x: u8,

    /// Y position (in tiles)
    pub y: u8,

    /// Script code
    pub script: String,

    /// NPC ID (assigned at runtime)
    pub id: Option<u32>,
}

/// Sign object
///
/// # C++ Equivalence
/// Matches `LevelSign` in LevelSign.h
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelSign {
    /// X position (in tiles)
    pub x: u8,

    /// Y position (in tiles)
    pub y: u8,

    /// Sign text (decoded)
    pub text: String,

    /// Raw encoded text (for transmission)
    pub encoded: Option<String>,
}

/// Baddy (enemy) types
///
/// # C++ Equivalence
/// Matches `BaddyType` enum in LevelBaddy.h
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BaddyType {
    GraySoldier = 0,
    BlueSoldier = 1,
    RedSoldier = 2,
    ShootingSoldier = 3,
    SwampSoldier = 4,
    Frog = 5,
    Octopus = 6,
    GoldenWarrior = 7,
    Lizardon = 8,
    Dragon = 9,
}

impl BaddyType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => BaddyType::GraySoldier,
            1 => BaddyType::BlueSoldier,
            2 => BaddyType::RedSoldier,
            3 => BaddyType::ShootingSoldier,
            4 => BaddyType::SwampSoldier,
            5 => BaddyType::Frog,
            6 => BaddyType::Octopus,
            7 => BaddyType::GoldenWarrior,
            8 => BaddyType::Lizardon,
            9 => BaddyType::Dragon,
            _ => BaddyType::GraySoldier,
        }
    }

    pub fn default_image(&self) -> &'static str {
        match self {
            BaddyType::GraySoldier => "baddygray.png",
            BaddyType::BlueSoldier => "baddyblue.png",
            BaddyType::RedSoldier => "baddyred.png",
            BaddyType::ShootingSoldier => "baddyblue.png",
            BaddyType::SwampSoldier => "baddygray.png",
            BaddyType::Frog => "baddyhare.png",
            BaddyType::Octopus => "baddyoctopus.png",
            BaddyType::GoldenWarrior => "baddygold.png",
            BaddyType::Lizardon => "baddylizardon.png",
            BaddyType::Dragon => "baddydragon.png",
        }
    }
}

/// Baddy (enemy) object
///
/// # C++ Equivalence
/// Matches `LevelBaddy` in LevelBaddy.h
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelBaddy {
    /// X position (in tiles)
    pub x: u8,

    /// Y position (in tiles)
    pub y: u8,

    /// Baddy type
    pub baddy_type: BaddyType,

    /// AI verses (behavior patterns)
    pub verses: Vec<String>,

    /// Power level
    pub power: u8,

    /// Custom image (overrides default)
    pub image: Option<String>,

    /// Baddy ID (assigned at runtime)
    pub id: Option<u8>,
}

/// Level link (warp)
///
/// # C++ Equivalence
/// Matches `LevelLink` in LevelLink.h
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelLink {
    /// BoundingBox x
    pub x: u8,

    /// BoundingBox y
    pub y: u8,

    /// BoundingBox width
    pub width: u8,

    /// BoundingBox height
    pub height: u8,

    /// Destination level name
    pub dest_level: String,

    /// Destination x ("playerx" or coordinate)
    pub dest_x: String,

    /// Destination y ("playery" or coordinate)
    pub dest_y: String,
}

impl LevelLink {
    /// Check if a position is within the link bounds
    pub fn contains(&self, x: u8, y: u8) -> bool {
        x >= self.x && x < self.x + self.width &&
        y >= self.y && y < self.y + self.height
    }
}

/// Level item types
///
/// # C++ Equivalence
/// Matches `LevelItemType` enum in LevelItem.h
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LevelItemType {
    Invalid = 0,
    GreenRupee = 1,
    BlueRupee = 2,
    RedRupee = 3,
    Bombs = 4,
    Darts = 5,
    Heart = 6,
    FullHeart = 7,
    Bomb = 8,
    Arrow = 9,
    Glove = 10,
    Mirror = 11,
}

impl LevelItemType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => LevelItemType::GreenRupee,
            2 => LevelItemType::BlueRupee,
            3 => LevelItemType::RedRupee,
            4 => LevelItemType::Bombs,
            5 => LevelItemType::Darts,
            6 => LevelItemType::Heart,
            7 => LevelItemType::FullHeart,
            8 => LevelItemType::Bomb,
            9 => LevelItemType::Arrow,
            10 => LevelItemType::Glove,
            11 => LevelItemType::Mirror,
            _ => LevelItemType::Invalid,
        }
    }

    /// Get player property string for this item
    /// # C++ Equivalence
    /// Matches `LevelItem::getItemPlayerProp()` in LevelItem.cpp
    pub fn get_player_prop(&self) -> &'static str {
        match self {
            LevelItemType::GreenRupee => "rupees1",
            LevelItemType::BlueRupee => "rupees2",
            LevelItemType::RedRupee => "rupees3",
            LevelItemType::Bombs => "databombs1",
            LevelItemType::Darts => "dataarrows1",
            LevelItemType::Heart => "hphearts",
            LevelItemType::FullHeart => "hpmpck",
            LevelItemType::Bomb => "databombs1",
            LevelItemType::Arrow => "dataarrows1",
            LevelItemType::Glove => "powerglove",
            LevelItemType::Mirror => "noguilds",
            LevelItemType::Invalid => "",
        }
    }
}

/// Level loader
///
/// # C++ Equivalence
/// Matches `LevelLoader` class in LevelLoader.cpp
pub struct LevelLoader;

impl LevelLoader {
    /// Load a level from GLEVNW01 format text
    ///
    /// # Arguments
    /// * `data` - The level file content as a string
    /// * `name` - The level name
    pub fn load_from_text(data: &str, name: String) -> Result<Level, LevelError> {
        let mut level = Level::new(name);
        let mut lines = data.lines().peekable();

        // Check magic header
        match lines.peek() {
            Some(&line) if line.trim() == "GLEVNW01" => {
                lines.next(); // Consume the magic line
            }
            Some(line) => return Err(LevelError::InvalidMagic(line.to_string())),
            None => return Err(LevelError::InvalidMagic("empty file".to_string())),
        }

        let mut current_npc: Option<LevelNpc> = None;
        let mut current_sign: Option<LevelSign> = None;
        let mut current_baddy: Option<LevelBaddy> = None;
        let mut in_heights = false;
        let mut height_data = String::new();

        while let Some(line) = lines.next() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Handle NPC sections
            if current_npc.is_some() {
                if line == "NPCEND" {
                    if let Some(npc) = current_npc.take() {
                        level.npcs.push(npc);
                    }
                } else {
                    // Accumulate script code
                    let npc = current_npc.as_mut().unwrap();
                    if !npc.script.is_empty() {
                        npc.script.push('\n');
                    }
                    npc.script.push_str(line);
                }
                continue;
            }

            // Handle SIGN sections
            if current_sign.is_some() {
                if line == "SIGNEND" {
                    if let Some(sign) = current_sign.take() {
                        level.signs.push(sign);
                    }
                } else {
                    let sign = current_sign.as_mut().unwrap();
                    if !sign.text.is_empty() {
                        sign.text.push('\n');
                    }
                    sign.text.push_str(line);
                }
                continue;
            }

            // Handle BADDY sections
            if current_baddy.is_some() {
                if line == "BADDYEND" {
                    if let Some(baddy) = current_baddy.take() {
                        level.baddies.push(baddy);
                    }
                } else {
                    let baddy = current_baddy.as_mut().unwrap();
                    baddy.verses.push(line.to_string());
                }
                continue;
            }

            // Handle HEIGHTS section
            if in_heights {
                if line == "HEIGHTSEND" {
                    in_heights = false;
                    // Parse height data (65x65 doubles, space-separated)
                    let heights: Result<Vec<f64>, _> = height_data
                        .split_whitespace()
                        .map(|s| s.parse::<f64>())
                        .collect();
                    if let Ok(h) = heights {
                        if h.len() == 65 * 65 {
                            level.heights = Some(h);
                        }
                    }
                    height_data.clear();
                } else {
                    height_data.push_str(line);
                    height_data.push(' ');
                }
                continue;
            }

            // Parse level elements
            if let Some(rest) = line.strip_prefix("BOARD ") {
                Self::parse_board(&mut level, rest)?;
            } else if let Some(rest) = line.strip_prefix("CHEST ") {
                Self::parse_chest(&mut level, rest)?;
            } else if let Some(rest) = line.strip_prefix("NPC ") {
                current_npc = Some(Self::parse_npc(rest)?);
            } else if let Some(rest) = line.strip_prefix("SIGN ") {
                current_sign = Some(Self::parse_sign(rest)?);
            } else if let Some(rest) = line.strip_prefix("BADDY ") {
                current_baddy = Some(Self::parse_baddy(rest)?);
            } else if let Some(rest) = line.strip_prefix("LINK ") {
                level.links.push(Self::parse_link(rest)?);
            } else if line == "HEIGHTS" {
                in_heights = true;
            }
        }

        // Handle any unclosed sections
        if let Some(npc) = current_npc {
            level.npcs.push(npc);
        }
        if let Some(sign) = current_sign {
            level.signs.push(sign);
        }
        if let Some(baddy) = current_baddy {
            level.baddies.push(baddy);
        }

        Ok(level)
    }

    /// Parse BOARD line
    /// Format: BOARD x y width layer base64data
    fn parse_board(level: &mut Level, rest: &str) -> Result<(), LevelError> {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() < 5 {
            return Err(LevelError::InvalidBoardFormat(
                "BOARD line requires at least 5 parts".to_string()
            ));
        }

        let _x: u8 = parts[0].parse()
            .map_err(|_| LevelError::InvalidBoardFormat("invalid x coordinate".to_string()))?;
        let _y: u8 = parts[1].parse()
            .map_err(|_| LevelError::InvalidBoardFormat("invalid y coordinate".to_string()))?;
        let _width: u8 = parts[2].parse()
            .map_err(|_| LevelError::InvalidBoardFormat("invalid width".to_string()))?;
        let _layer: u8 = parts[3].parse()
            .map_err(|_| LevelError::InvalidBoardFormat("invalid layer".to_string()))?;

        let base64_data = parts[4];

        // Decode base64 tiles
        // Each tile is 2 bytes, base64 encodes 3 bytes into 4 characters
        // So for 8192 bytes, we need ceil(8192 * 4/3) = 10923 chars (rounded to multiple of 4)
        let decoded = BASE64.decode(base64_data)
            .map_err(|e| LevelError::InvalidBoardData(format!("base64 decode failed: {}", e)))?;

        // Each pair of bytes forms one tile (little-endian u16)
        let mut tiles = vec![0u16; 4096];
        for i in 0..4096 {
            if i * 2 + 1 < decoded.len() {
                let lo = decoded[i * 2] as u16;
                let hi = decoded[i * 2 + 1] as u16;
                tiles[i] = lo | (hi << 8);
            }
        }

        level.tiles = tiles;
        Ok(())
    }

    /// Parse CHEST line
    /// Format: CHEST x y item index
    fn parse_chest(level: &mut Level, rest: &str) -> Result<(), LevelError> {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(LevelError::ParseError("CHEST line requires 4 parts".to_string()));
        }

        let x: u8 = parts[0].parse()
            .map_err(|_| LevelError::ParseError("invalid chest x".to_string()))?;
        let y: u8 = parts[1].parse()
            .map_err(|_| LevelError::ParseError("invalid chest y".to_string()))?;
        let item: u8 = parts[2].parse()
            .map_err(|_| LevelError::ParseError("invalid chest item".to_string()))?;
        let sign: u8 = parts[3].parse()
            .map_err(|_| LevelError::ParseError("invalid chest sign".to_string()))?;

        level.chests.push(LevelChest {
            x, y,
            item: LevelItemType::from_u8(item),
            sign,
        });

        Ok(())
    }

    /// Parse NPC line
    /// Format: NPC image x y
    fn parse_npc(rest: &str) -> Result<LevelNpc, LevelError> {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(LevelError::InvalidNpcData("NPC line requires 3 parts".to_string()));
        }

        let image = parts[0].to_string();
        let x: u8 = parts[1].parse()
            .map_err(|_| LevelError::InvalidNpcData("invalid npc x".to_string()))?;
        let y: u8 = parts[2].parse()
            .map_err(|_| LevelError::InvalidNpcData("invalid npc y".to_string()))?;

        Ok(LevelNpc {
            image, x, y,
            script: String::new(),
            id: None,
        })
    }

    /// Parse SIGN line
    /// Format: SIGN x y
    fn parse_sign(rest: &str) -> Result<LevelSign, LevelError> {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(LevelError::ParseError("SIGN line requires 2 parts".to_string()));
        }

        let x: u8 = parts[0].parse()
            .map_err(|_| LevelError::ParseError("invalid sign x".to_string()))?;
        let y: u8 = parts[1].parse()
            .map_err(|_| LevelError::ParseError("invalid sign y".to_string()))?;

        Ok(LevelSign {
            x, y,
            text: String::new(),
            encoded: None,
        })
    }

    /// Parse BADDY line
    /// Format: BADDY x y type
    fn parse_baddy(rest: &str) -> Result<LevelBaddy, LevelError> {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(LevelError::ParseError("BADDY line requires 3 parts".to_string()));
        }

        let x: u8 = parts[0].parse()
            .map_err(|_| LevelError::ParseError("invalid baddy x".to_string()))?;
        let y: u8 = parts[1].parse()
            .map_err(|_| LevelError::ParseError("invalid baddy y".to_string()))?;
        let baddy_type: u8 = parts[2].parse()
            .map_err(|_| LevelError::ParseError("invalid baddy type".to_string()))?;

        let baddy_type = BaddyType::from_u8(baddy_type);

        Ok(LevelBaddy {
            x, y, baddy_type,
            verses: Vec::new(),
            power: match baddy_type {
                BaddyType::GraySoldier => 2,
                BaddyType::BlueSoldier => 3,
                BaddyType::RedSoldier => 4,
                BaddyType::ShootingSoldier => 3,
                BaddyType::SwampSoldier => 2,
                BaddyType::Frog => 1,
                BaddyType::Octopus => 1,
                BaddyType::GoldenWarrior => 6,
                BaddyType::Lizardon => 12,
                BaddyType::Dragon => 8,
            },
            image: None,
            id: None,
        })
    }

    /// Parse LINK line
    /// Format: LINK x y w h level dest_x dest_y
    fn parse_link(rest: &str) -> Result<LevelLink, LevelError> {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() < 7 {
            return Err(LevelError::ParseError("LINK line requires 7 parts".to_string()));
        }

        let x: u8 = parts[0].parse()
            .map_err(|_| LevelError::ParseError("invalid link x".to_string()))?;
        let y: u8 = parts[1].parse()
            .map_err(|_| LevelError::ParseError("invalid link y".to_string()))?;
        let width: u8 = parts[2].parse()
            .map_err(|_| LevelError::ParseError("invalid link width".to_string()))?;
        let height: u8 = parts[3].parse()
            .map_err(|_| LevelError::ParseError("invalid link height".to_string()))?;

        Ok(LevelLink {
            x, y, width, height,
            dest_level: parts[4].to_string(),
            dest_x: parts[5].to_string(),
            dest_y: parts[6].to_string(),
        })
    }

    /// Load a level from a file
    pub fn load_from_file(path: &std::path::Path) -> Result<Level, LevelError> {
        let data = std::fs::read_to_string(path)?;
        let name = path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        Self::load_from_text(&data, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_simple_level() {
        let data = r#"GLEVNW01
BOARD 0 0 64 0 AA==
"#;

        let level = LevelLoader::load_from_text(data, "test".to_string()).unwrap();
        assert_eq!(level.name, "test");
        assert_eq!(level.width, 64);
        assert_eq!(level.height, 64);
        assert_eq!(level.tiles.len(), 4096);
    }

    #[test]
    fn test_parse_chest() {
        let data = r#"GLEVNW01
CHEST 10 20 1 0
"#;

        let level = LevelLoader::load_from_text(data, "test".to_string()).unwrap();
        assert_eq!(level.chests.len(), 1);
        assert_eq!(level.chests[0].x, 10);
        assert_eq!(level.chests[0].y, 20);
        assert!(matches!(level.chests[0].item, LevelItemType::GreenRupee));
    }

    #[test]
    fn test_parse_npc() {
        let data = r#"GLEVNW01
NPC test.png 5 5
SCRIPT
test code
NPCEND
"#;

        let level = LevelLoader::load_from_text(data, "test".to_string()).unwrap();
        assert_eq!(level.npcs.len(), 1);
        assert_eq!(level.npcs[0].image, "test.png");
        assert_eq!(level.npcs[0].x, 5);
        assert_eq!(level.npcs[0].y, 5);
        assert_eq!(level.npcs[0].script, "test code");
    }

    #[test]
    fn test_parse_sign() {
        let data = r#"GLEVNW01
SIGN 15 25
Hello World
SIGNEND
"#;

        let level = LevelLoader::load_from_text(data, "test".to_string()).unwrap();
        assert_eq!(level.signs.len(), 1);
        assert_eq!(level.signs[0].x, 15);
        assert_eq!(level.signs[0].y, 25);
        assert_eq!(level.signs[0].text, "Hello World");
    }

    #[test]
    fn test_parse_link() {
        let data = r#"GLEVNW01
LINK 0 63 1 64 onlinestartlocal.nw playerx playery
"#;

        let level = LevelLoader::load_from_text(data, "test".to_string()).unwrap();
        assert_eq!(level.links.len(), 1);
        assert_eq!(level.links[0].x, 0);
        assert_eq!(level.links[0].y, 63);
        assert_eq!(level.links[0].width, 1);
        assert_eq!(level.links[0].height, 64);
        assert_eq!(level.links[0].dest_level, "onlinestartlocal.nw");
        assert_eq!(level.links[0].dest_x, "playerx");
        assert_eq!(level.links[0].dest_y, "playery");
    }

    #[test]
    fn test_tile_operations() {
        let mut level = Level::new("test".to_string());

        assert_eq!(level.get_tile(10, 20), 0);

        level.set_tile(10, 20, 1234);
        assert_eq!(level.get_tile(10, 20), 1234);

        // Out of bounds returns 0
        assert_eq!(level.get_tile(100, 100), 0);
    }
}
