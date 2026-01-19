//! Map system (gmap/bigmap)
//!
//! Handles world maps composed of multiple levels.

use crate::level::{Level, MapPosition};
use crate::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;

/// Map type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapType {
    /// gmap - Single map file
    GMap,
    /// bigmap - Multiple map files
    BigMap,
}

/// A Graal world map
///
/// Maps are grids of levels that form a continuous world.
#[derive(Debug, Clone)]
pub struct Map {
    /// Map name
    pub name: String,

    /// Map type
    pub map_type: MapType,

    /// Map width (in levels)
    pub width: u16,

    /// Map height (in levels)
    pub height: u16,

    /// Level names at each position
    pub levels: HashMap<(u16, u16), String>,

    /// Map file path
    pub file_path: PathBuf,

    /// Terrain generation data
    pub terrain: Option<TerrainData>,
}

/// Terrain generation data for procedural maps
#[derive(Debug, Clone)]
pub struct TerrainData {
    /// Level seeds for procedural generation
    pub level_seeds: Vec<u32>,

    /// Height deviation for terrain
    pub height_deviation: f64,

    /// Chaos factor for terrain
    pub chaos: f64,
}

/// Map file parser and loader
pub struct MapLoader;

impl MapLoader {
    /// Load a map from a .gmap file
    pub fn load_gmap<P: AsRef<Path>>(path: P) -> Result<Map> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)?;

        Self::parse_gmap(&content, path.to_path_buf())
    }

    /// Parse a .gmap file
    fn parse_gmap(content: &str, path: PathBuf) -> Result<Map> {
        let name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let mut width = 0;
        let mut height = 0;
        let mut levels = HashMap::new();
        let mut terrain = None;

        let mut current_row = 0u16;

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with("//") {
                continue;
            }

            // Parse width
            if let Some(rest) = line.strip_prefix("WIDTH ") {
                width = rest.parse()
                    .map_err(|_| crate::LevelError::ParseError {
                        line: 0,
                        message: format!("Invalid width: {}", rest),
                    })?;
                continue;
            }

            // Parse height
            if let Some(rest) = line.strip_prefix("HEIGHT ") {
                height = rest.parse()
                    .map_err(|_| crate::LevelError::ParseError {
                        line: 0,
                        message: format!("Invalid height: {}", rest),
                    })?;
                continue;
            }

            // Parse level data (format: "x,y levelname.nw")
            if line.contains(',') {
                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                if parts.len() == 2 {
                    let coords: Vec<&str> = parts[0].split(',').collect();
                    if coords.len() == 2 {
                        if let (Ok(x), Ok(y)) = (coords[0].parse::<u16>(), coords[1].parse::<u16>()) {
                            let level_name = parts[1].trim().to_string();
                            levels.insert((x, y), level_name);
                        }
                    }
                }
            }

            // Parse terrain data
            if let Some(_rest) = line.strip_prefix("TERRAIN ") {
                // For now, skip terrain parsing
                // Full implementation would parse level seeds, etc.
            }

            current_row += 1;
        }

        Ok(Map {
            name,
            map_type: MapType::GMap,
            width,
            height,
            levels,
            file_path: path,
            terrain,
        })
    }

    /// Load a bigmap (multiple .gmap files)
    pub fn load_bigmap<P: AsRef<Path>>(dir: P) -> Result<Map> {
        let dir = dir.as_ref();

        // Find all .gmap files in the directory
        let mut gmap_files = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("gmap") {
                gmap_files.push(path);
            }
        }

        if gmap_files.is_empty() {
            return Err(crate::LevelError::NotFound(
                "No .gmap files found in directory".into()
            ));
        }

        // For now, just load the first gmap file
        // Full implementation would merge multiple gmap files
        Self::load_gmap(&gmap_files[0])
    }
}

impl Map {
    /// Get the level name at a specific position
    pub fn get_level_at(&self, x: u16, y: u16) -> Option<&String> {
        self.levels.get(&(x, y))
    }

    /// Check if a position is valid on this map
    pub fn is_valid_position(&self, x: u16, y: u16) -> bool {
        x < self.width && y < self.height
    }

    /// Get the map position for a level name
    pub fn get_position(&self, level_name: &str) -> Option<MapPosition> {
        for (&(x, y), name) in &self.levels {
            if name == level_name {
                return Some(MapPosition { x, y });
            }
        }
        None
    }

    /// Get all level names
    pub fn level_names(&self) -> Vec<&String> {
        self.levels.values().collect()
    }

    /// Check if map has terrain data
    pub fn has_terrain(&self) -> bool {
        self.terrain.is_some()
    }

    /// Calculate neighbor coordinates
    pub fn get_neighbor(&self, x: u16, y: u16, direction: Direction) -> Option<(u16, u16)> {
        let (nx, ny) = match direction {
            Direction::North => (x, y.saturating_sub(1)),
            Direction::South => (x, y.saturating_add(1)),
            Direction::East => (x.saturating_add(1), y),
            Direction::West => (x.saturating_sub(1), y),
        };

        if self.is_valid_position(nx, ny) {
            Some((nx, ny))
        } else {
            None
        }
    }
}

/// Cardinal direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    North,
    South,
    East,
    West,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_parse_gmap() {
        let content = r#"// Test map
WIDTH 3
HEIGHT 3
0,0 level1.nw
1,0 level2.nw
0,1 level3.nw
"#;

        let temp_dir = TempDir::new().unwrap();
        let gmap_path = temp_dir.path().join("test.gmap");
        fs::write(&gmap_path, content).unwrap();

        let map = MapLoader::load_gmap(&gmap_path).unwrap();

        assert_eq!(map.width, 3);
        assert_eq!(map.height, 3);
        assert_eq!(map.get_level_at(0, 0), Some(&"level1.nw".to_string()));
        assert_eq!(map.get_level_at(1, 0), Some(&"level2.nw".to_string()));
        assert_eq!(map.get_level_at(0, 1), Some(&"level3.nw".to_string()));
    }

    #[test]
    fn test_map_validation() {
        let map = Map {
            name: "test".to_string(),
            map_type: MapType::GMap,
            width: 10,
            height: 10,
            levels: HashMap::new(),
            file_path: PathBuf::new(),
            terrain: None,
        };

        assert!(map.is_valid_position(0, 0));
        assert!(map.is_valid_position(9, 9));
        assert!(!map.is_valid_position(10, 0));
        assert!(!map.is_valid_position(0, 10));
    }

    #[test]
    fn test_map_neighbors() {
        let map = Map {
            name: "test".to_string(),
            map_type: MapType::GMap,
            width: 10,
            height: 10,
            levels: HashMap::new(),
            file_path: PathBuf::new(),
            terrain: None,
        };

        // Test neighbors
        assert_eq!(map.get_neighbor(5, 5, Direction::North), Some((5, 4)));
        assert_eq!(map.get_neighbor(5, 5, Direction::South), Some((5, 6)));
        assert_eq!(map.get_neighbor(5, 5, Direction::East), Some((6, 5)));
        assert_eq!(map.get_neighbor(5, 5, Direction::West), Some((4, 5)));

        // Test boundaries
        assert_eq!(map.get_neighbor(0, 0, Direction::North), Some((0, 0))); // Saturated
        assert_eq!(map.get_neighbor(9, 9, Direction::South), None); // Out of bounds
    }

    #[test]
    fn test_map_position_lookup() {
        let mut levels = HashMap::new();
        levels.insert((0, 0), "level1.nw".to_string());
        levels.insert((1, 0), "level2.nw".to_string());

        let map = Map {
            name: "test".to_string(),
            map_type: MapType::GMap,
            width: 10,
            height: 10,
            levels,
            file_path: PathBuf::new(),
            terrain: None,
        };

        assert_eq!(map.get_position("level1.nw"), Some(MapPosition { x: 0, y: 0 }));
        assert_eq!(map.get_position("level2.nw"), Some(MapPosition { x: 1, y: 0 }));
        assert_eq!(map.get_position("level3.nw"), None);
    }
}
