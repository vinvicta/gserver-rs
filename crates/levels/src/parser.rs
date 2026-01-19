//! Level file parser
//!
//! Parses Graal .nw level files.

use crate::level::{Level, LevelId, Link, Chest, Sign, Baddy, MapPosition};
use crate::tiles::{LevelTiles, EMPTY_TILE};
use crate::{Result, LevelError};
use std::path::Path;
use std::fs;
use std::io::Read;

/// Level file parser
pub struct LevelLoader;

impl LevelLoader {
    /// Load a level from a file
    pub fn load_file<P: AsRef<Path>>(path: P) -> Result<Level> {
        let path = path.as_ref();

        // Read file
        let mut file = fs::File::open(path)
            .map_err(|e| LevelError::NotFound(path.display().to_string()))?;

        let mut data = String::new();
        file.read_to_string(&mut data)?;

        // Get file modification time
        let metadata = file.metadata()?;
        let mod_time = metadata.modified()?.duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as u32;

        // Get level name from path
        let name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Parse the level
        Self::parse(&data, name, path.to_path_buf(), mod_time)
    }

    /// Parse level data from string
    pub fn parse(data: &str, name: String, file_path: std::path::PathBuf, mod_time: u32) -> Result<Level> {
        let lines: Vec<&str> = data.lines().collect();

        if lines.is_empty() {
            return Err(LevelError::InvalidFormat("Empty file".into()));
        }

        // Check magic header
        let magic = lines[0].trim();
        if magic != "GLEVNW01" {
            return Err(LevelError::UnsupportedVersion(magic.to_string()));
        }

        let id = Self::generate_level_id(&name);
        let mut level = Level::new(id, name);
        level.mod_time = mod_time;
        level.file_path = file_path.clone();

        // Parse the file
        let mut i = 1;
        while i < lines.len() {
            let line = lines[i].trim();

            if line.is_empty() {
                i += 1;
                continue;
            }

            // Parse based on command
            if let Some(rest) = line.strip_prefix("BOARD") {
                Self::parse_board(&mut level, rest)?;
            } else if let Some(rest) = line.strip_prefix("CHEST") {
                if let Ok(chest) = Self::parse_chest(rest) {
                    level.chests.push(chest);
                }
            } else if let Some(rest) = line.strip_prefix("LINK") {
                if let Ok(link) = Self::parse_link(rest) {
                    level.links.push(link);
                }
            } else if let Some(rest) = line.strip_prefix("SIGN") {
                let (sign, skip) = Self::parse_sign(rest, &lines[i..])?;
                level.signs.push(sign);
                i += skip;
            } else if let Some(rest) = line.strip_prefix("BADDY") {
                let (baddy, skip) = Self::parse_baddy(rest, &lines[i..])?;
                level.baddies.push(baddy);
                i += skip;
            } else if let Some(_rest) = line.strip_prefix("NPC") {
                // NPCs are handled separately in the full implementation
                // For now, skip to NPCEND
                while i < lines.len() && lines[i].trim() != "NPCEND" {
                    i += 1;
                }
            }

            i += 1;
        }

        level.set_state(crate::level::LevelState::Loaded);
        Ok(level)
    }

    /// Parse a BOARD line
    fn parse_board(level: &mut Level, line: &str) -> Result<()> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() != 5 {
            return Err(LevelError::ParseError {
                line: 0,
                message: format!("Invalid BOARD format: expected 5 parts, got {}", parts.len()),
            });
        }

        let x: u8 = parts[0].parse()
            .map_err(|_| LevelError::ParseError {
                line: 0,
                message: format!("Invalid x coordinate: {}", parts[0]),
            })?;

        let y: u8 = parts[1].parse()
            .map_err(|_| LevelError::ParseError {
                line: 0,
                message: format!("Invalid y coordinate: {}", parts[1]),
            })?;

        let width: u8 = parts[2].parse()
            .map_err(|_| LevelError::ParseError {
                line: 0,
                message: format!("Invalid width: {}", parts[2]),
            })?;

        let layer: u8 = parts[3].parse()
            .map_err(|_| LevelError::ParseError {
                line: 0,
                message: format!("Invalid layer: {}", parts[3]),
            })?;

        let data = parts[4];

        // Validate bounds
        if x >= 64 || y >= 64 || width == 0 || x + width > 64 {
            return Err(LevelError::ParseError {
                line: 0,
                message: format!("BOARD out of bounds: x={}, y={}, width={}", x, y, width),
            });
        }

        // Parse base64 tile data
        let tile_data = Self::parse_base64_tiles(data, width as usize)?;

        // Create layer if it doesn't exist
        if !level.tiles.read().has_layer(layer) {
            let mut tiles = level.tiles.write();
            tiles.set_layer(crate::tiles::TileLayer::new(layer));
        }

        // Apply tiles
        {
            let mut tiles = level.tiles.write();
            for (i, &tile) in tile_data.iter().enumerate() {
                let tile_x = x + i as u8;
                tiles.set_tile(tile_x, y, layer, tile);
            }
        }

        Ok(())
    }

    /// Parse base64-encoded tile data
    fn parse_base64_tiles(data: &str, count: usize) -> Result<Vec<u16>> {
        if data.len() < count * 2 {
            return Err(LevelError::TileError(
                format!("Not enough tile data: expected {}, got {}", count * 2, data.len())
            ));
        }

        let mut tiles = Vec::with_capacity(count);
        let chars: Vec<char> = data.chars().collect();

        for i in 0..count {
            let left = chars[i * 2];
            let top = chars[i * 2 + 1];

            let left_val = Self::get_base64_position(left);
            let top_val = Self::get_base64_position(top);

            // Combine: first char is high 6 bits, second char is low 6 bits
            let tile = (left_val << 6) | top_val;
            tiles.push(tile);
        }

        Ok(tiles)
    }

    /// Get base64 character value
    fn get_base64_position(c: char) -> u16 {
        if c >= 'a' && c <= 'z' {
            26 + (c as u16 - 'a' as u16)
        } else if c >= 'A' && c <= 'Z' {
            c as u16 - 'A' as u16
        } else if c >= '0' && c <= '9' {
            52 + (c as u16 - '0' as u16)
        } else if c == '+' {
            62
        } else if c == '/' {
            63
        } else {
            0
        }
    }

    /// Parse a CHEST line
    fn parse_chest(line: &str) -> Result<Chest> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() != 4 {
            return Err(LevelError::ParseError {
                line: 0,
                message: "Invalid CHEST format".into(),
            });
        }

        let x: u8 = parts[0].parse()
            .map_err(|_| LevelError::ParseError {
                line: 0,
                message: format!("Invalid chest x: {}", parts[0]),
            })?;

        let y: u8 = parts[1].parse()
            .map_err(|_| LevelError::ParseError {
                line: 0,
                message: format!("Invalid chest y: {}", parts[1]),
            })?;

        let item = parts[2].to_string();

        let sign_index: i8 = parts[3].parse()
            .map_err(|_| LevelError::ParseError {
                line: 0,
                message: format!("Invalid sign index: {}", parts[3]),
            })?;

        Ok(Chest { x, y, item, sign_index })
    }

    /// Parse a LINK line
    fn parse_link(line: &str) -> Result<Link> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 8 {
            return Err(LevelError::ParseError {
                line: 0,
                message: "Invalid LINK format".into(),
            });
        }

        let x: u8 = parts[0].parse()
            .map_err(|_| LevelError::ParseError {
                line: 0,
                message: format!("Invalid link x: {}", parts[0]),
            })?;

        let y: u8 = parts[1].parse()
            .map_err(|_| LevelError::ParseError {
                line: 0,
                message: format!("Invalid link y: {}", parts[1]),
            })?;

        let width: u8 = parts[2].parse()
            .map_err(|_| LevelError::ParseError {
                line: 0,
                message: format!("Invalid link width: {}", parts[2]),
            })?;

        let height: u8 = parts[3].parse()
            .map_err(|_| LevelError::ParseError {
                line: 0,
                message: format!("Invalid link height: {}", parts[3]),
            })?;

        let target_x: f32 = parts[4].parse()
            .map_err(|_| LevelError::ParseError {
                line: 0,
                message: format!("Invalid target x: {}", parts[4]),
            })?;

        let target_y: f32 = parts[5].parse()
            .map_err(|_| LevelError::ParseError {
                line: 0,
                message: format!("Invalid target y: {}", parts[5]),
            })?;

        // The rest is the level name (might have spaces)
        let target_level = parts[6..].join(" ");

        Ok(Link {
            x, y, width, height,
            target_level,
            target_x,
            target_y,
        })
    }

    /// Parse a SIGN (can span multiple lines until SIGNEND)
    fn parse_sign(line: &str, lines: &[&str]) -> Result<(Sign, usize)> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() != 2 {
            return Err(LevelError::ParseError {
                line: 0,
                message: "Invalid SIGN format".into(),
            });
        }

        let x: u8 = parts[0].parse()
            .map_err(|_| LevelError::ParseError {
                line: 0,
                message: format!("Invalid sign x: {}", parts[0]),
            })?;

        let y: u8 = parts[1].parse()
            .map_err(|_| LevelError::ParseError {
                line: 0,
                message: format!("Invalid sign y: {}", parts[1]),
            })?;

        // Collect text until SIGNEND
        let mut text = String::new();
        let mut skip = 1;

        for line in lines.iter().skip(1) {
            skip += 1;
            let trimmed = line.trim();
            if trimmed == "SIGNEND" {
                break;
            }
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(trimmed);
        }

        // Remove trailing newline
        text = text.trim_end().to_string();

        Ok((Sign { x, y, text }, skip))
    }

    /// Parse a BADDY (can span multiple lines until BADDYEND)
    fn parse_baddy(line: &str, lines: &[&str]) -> Result<(Baddy, usize)> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() != 3 {
            return Err(LevelError::ParseError {
                line: 0,
                message: "Invalid BADDY format".into(),
            });
        }

        let x: f32 = parts[0].parse()
            .map_err(|_| LevelError::ParseError {
                line: 0,
                message: format!("Invalid baddy x: {}", parts[0]),
            })?;

        let y: f32 = parts[1].parse()
            .map_err(|_| LevelError::ParseError {
                line: 0,
                message: format!("Invalid baddy y: {}", parts[1]),
            })?;

        let baddy_type = parts[2].to_string();

        // Collect verses until BADDYEND
        let mut verses = Vec::new();
        let mut skip = 1;

        for line in lines.iter().skip(1) {
            skip += 1;
            let trimmed = line.trim();
            if trimmed == "BADDYEND" {
                break;
            }
            verses.push(trimmed.to_string());
        }

        Ok((Baddy { x, y, baddy_type, verses }, skip))
    }

    /// Generate a unique level ID from name
    fn generate_level_id(name: &str) -> LevelId {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        hasher.finish() as LevelId
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_level() {
        let data = r#"GLEVNW01
BOARD 0 0 2 0 AAAA
BOARD 0 1 2 0 BBBB
CHEST 10 10 rupee 0
LINK 0 0 2 2 16.0 16.0 targetlevel.nw dummy.x dummy.y
SIGN 5 5
This is a test sign
SIGNEND
"#;

        let level = LevelLoader::parse(
            data,
            "test.nw".to_string(),
            std::path::PathBuf::from("test.nw"),
            0
        ).unwrap();

        assert_eq!(level.name, "test.nw");
        assert!(level.is_loaded());
        assert!(!level.chests.is_empty());
        assert!(!level.links.is_empty());
        assert!(!level.signs.is_empty());
    }

    #[test]
    fn test_parse_board_tiles() {
        let data = r#"GLEVNW01
BOARD 0 0 3 0 AAABAB
"#;

        let level = LevelLoader::parse(
            data,
            "test.nw".to_string(),
            std::path::PathBuf::from("test.nw"),
            0
        ).unwrap();

        // Check that tiles were set correctly
        // AAABAB = 3 tiles: AA=0, AB=1, AB=1
        assert_eq!(level.get_tile(0, 0, 0), 0);   // AA = 0
        assert_eq!(level.get_tile(1, 0, 0), 1);   // AB = 1
        assert_eq!(level.get_tile(2, 0, 0), 1);   // AB = 1
    }

    #[test]
    fn test_base64_parsing() {
        // 'A' in base64 position is 0
        assert_eq!(LevelLoader::get_base64_position('A'), 0);
        // 'Z' in base64 position is 25
        assert_eq!(LevelLoader::get_base64_position('Z'), 25);
        // 'a' in base64 position is 26
        assert_eq!(LevelLoader::get_base64_position('a'), 26);
        // '0' in base64 position is 52
        assert_eq!(LevelLoader::get_base64_position('0'), 52);
    }

    #[test]
    fn test_invalid_magic() {
        let data = "INVALID_MAGIC\nBOARD 0 0 64 0 AAAA\n";

        let result = LevelLoader::parse(
            data,
            "test.nw".to_string(),
            std::path::PathBuf::from("test.nw"),
            0
        );

        assert!(result.is_err());
    }
}
