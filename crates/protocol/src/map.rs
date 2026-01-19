//! Map and GMap system
//!
//! # Purpose
//! Implements the Graal Online map system including BIGMAP and GMAP types.
//!
//! # C++ Equivalence
//! Matches `Map` class in Map.cpp and Map.h

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Map type
///
/// # C++ Equivalence
/// Matches `MapType` enum in Map.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MapType {
    /// Single level map (BIGMAP)
    BigMap = 0,

    /// Grid map with multiple levels (GMAP)
    Gmap = 1,
}

/// Map level position
///
/// # C++ Equivalence
/// Matches `Position<uint8_t>` in CommonTypes.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapLevelPosition {
    /// X position in grid (0-255)
    pub x: u8,

    /// Y position in grid (0-255)
    pub y: u8,
}

impl MapLevelPosition {
    /// Create a new position
    pub fn new(x: u8, y: u8) -> Self {
        Self { x, y }
    }
}

/// Map terrain data for gmap height generation
///
/// # C++ Equivalence
/// Matches `MapTerrain` in LevelTerrain.h
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapTerrain {
    /// Map-wide seed for terrain generation
    pub map_seed: u32,

    /// Base height offset
    pub height_base: f64,

    /// Even borders flag
    pub even_borders: bool,

    /// Height deviation for map
    pub height_deviation: f64,

    /// Map chaos (0.0 - 1.0)
    pub map_chaos: f64,

    /// Level height deviation
    pub level_height_deviation: f64,

    /// Level chaos (0.0 - 1.0)
    pub level_chaos: f64,

    /// Per-level seeds
    pub level_seeds: Vec<u32>,

    /// X-axis border tile heights
    pub grid_border_heights_x_axis: Vec<f64>,

    /// Y-axis border tile heights
    pub grid_border_heights_y_axis: Vec<f64>,
}

impl Default for MapTerrain {
    fn default() -> Self {
        Self {
            map_seed: 0,
            height_base: 0.0,
            even_borders: false,
            height_deviation: 65.0,
            map_chaos: 0.6,
            level_height_deviation: 4.0,
            level_chaos: 0.6,
            level_seeds: Vec::new(),
            grid_border_heights_x_axis: Vec::new(),
            grid_border_heights_y_axis: Vec::new(),
        }
    }
}

/// Map configuration
///
/// # C++ Equivalence
/// Matches `Map` class in Map.h
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GMap {
    /// Map type (BIGMAP or GMAP)
    pub map_type: MapType,

    /// Map image filename
    pub map_image: String,

    /// Minimap image filename
    pub minimap_image: String,

    /// Map dimensions (in grid units for gmap)
    pub width: u8,

    /// Map height (in grid units for gmap)
    pub height: u8,

    /// Keep all levels loaded (don't unload unused levels)
    pub keep_all_levels_loaded: bool,

    /// Level positions in the map
    /// For gmap: level name -> (x, y) position
    /// For bigmap: usually just one level
    pub levels: HashMap<String, MapLevelPosition>,

    /// Levels to keep in memory
    pub levels_to_keep_in_memory: Vec<String>,

    /// Terrain data for gmap height generation
    pub terrain: MapTerrain,

    /// Map filename
    pub filename: PathBuf,
}

impl GMap {
    /// Create a new empty gmap
    pub fn new_gmap(width: u8, height: u8) -> Self {
        Self {
            map_type: MapType::Gmap,
            map_image: String::new(),
            minimap_image: String::new(),
            width,
            height,
            keep_all_levels_loaded: false,
            levels: HashMap::new(),
            levels_to_keep_in_memory: Vec::new(),
            terrain: MapTerrain::default(),
            filename: PathBuf::new(),
        }
    }

    /// Create a new bigmap (single level)
    pub fn new_bigmap(level_name: String) -> Self {
        let mut levels = HashMap::new();
        levels.insert(level_name.clone(), MapLevelPosition::new(0, 0));

        Self {
            map_type: MapType::BigMap,
            map_image: String::new(),
            minimap_image: String::new(),
            width: 1,
            height: 1,
            keep_all_levels_loaded: false,
            levels,
            levels_to_keep_in_memory: Vec::new(),
            terrain: MapTerrain::default(),
            filename: PathBuf::new(),
        }
    }

    /// Add a level to the map
    pub fn add_level(&mut self, level_name: String, x: u8, y: u8) {
        self.levels.insert(level_name, MapLevelPosition::new(x, y));
    }

    /// Get the position of a level
    pub fn get_level_position(&self, level_name: &str) -> Option<MapLevelPosition> {
        self.levels.get(level_name).copied()
    }

    /// Get level at a specific grid position
    pub fn get_level_at(&self, x: u8, y: u8) -> Option<String> {
        for (level_name, pos) in &self.levels {
            if pos.x == x && pos.y == y {
                return Some(level_name.clone());
            }
        }
        None
    }

    /// Get all level names
    pub fn get_level_names(&self) -> Vec<String> {
        self.levels.keys().cloned().collect()
    }

    /// Check if this is a gmap
    pub fn is_gmap(&self) -> bool {
        self.map_type == MapType::Gmap
    }

    /// Check if this is a bigmap
    pub fn is_bigmap(&self) -> bool {
        self.map_type == MapType::BigMap
    }

    /// Get the number of levels in the map
    pub fn level_count(&self) -> usize {
        self.levels.len()
    }
}

impl Default for GMap {
    fn default() -> Self {
        Self::new_bigmap("onlinestartlocal.nw".to_string())
    }
}

/// Map loader
///
/// # Purpose
/// Loads map configuration from .gmap or .bigmap files
///
/// # File Format
/// GMAP file format:
/// ```text
/// GMAP001
/// NAME map_name
/// MAPIMAGE gmap.png
/// MINIMAP minimap.png
/// WIDTH width
/// HEIGHT height
/// LEVELS
/// level1.nw x y
/// level2.nw x y
/// ...
/// LEVELSEND
/// TERRAIN
/// ...terrain data...
/// TERRAINEND
/// ```
pub struct MapLoader;

impl MapLoader {
    /// Load a gmap from file content
    pub fn load_from_text(data: &str, filename: PathBuf) -> Result<GMap, String> {
        let lines: Vec<&str> = data.lines().collect();

        // Check magic header
        if !lines.iter().any(|l| *l == "GMAP001") {
            // Try bigmap format
            return Self::load_bigmap_from_text(data, filename);
        }

        let mut gmap = GMap::new_gmap(0, 0);
        gmap.filename = filename;

        let mut in_levels = false;
        let mut in_terrain = false;
        let mut level_lines = Vec::new();
        let mut terrain_lines = Vec::new();

        for line in lines {
            let line = line.trim();

            if in_levels {
                if line == "LEVELSEND" {
                    in_levels = false;
                    continue;
                }
                if !line.is_empty() {
                    level_lines.push(line.to_string());
                }
                continue;
            }

            if in_terrain {
                if line == "TERRAINEND" {
                    in_terrain = false;
                    Self::parse_terrain(&terrain_lines, &mut gmap.terrain);
                    continue;
                }
                if !line.is_empty() {
                    terrain_lines.push(line.to_string());
                }
                continue;
            }

            if line == "LEVELS" {
                in_levels = true;
                continue;
            }

            if line == "TERRAIN" {
                in_terrain = true;
                continue;
            }

            // Parse map-level properties
            if let Some(rest) = line.strip_prefix("NAME ") {
                // Map name (stored in map image or elsewhere)
                gmap.map_image = rest.to_string();
            } else if let Some(rest) = line.strip_prefix("MAPIMAGE ") {
                gmap.map_image = rest.to_string();
            } else if let Some(rest) = line.strip_prefix("MINIMAP ") {
                gmap.minimap_image = rest.to_string();
            } else if let Some(rest) = line.strip_prefix("WIDTH ") {
                gmap.width = rest.parse().unwrap_or(0);
            } else if let Some(rest) = line.strip_prefix("HEIGHT ") {
                gmap.height = rest.parse().unwrap_or(0);
            }
        }

        // Parse level lines
        for line in level_lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let level_name = parts[0].to_string();
                let x: u8 = parts[1].parse().unwrap_or(0);
                let y: u8 = parts[2].parse().unwrap_or(0);
                gmap.add_level(level_name, x, y);
            }
        }

        Ok(gmap)
    }

    /// Load a bigmap from file content
    fn load_bigmap_from_text(data: &str, filename: PathBuf) -> Result<GMap, String> {
        let lines: Vec<&str> = data.lines().collect();

        let mut level_name = "onlinestartlocal.nw".to_string();
        let mut map_image = String::new();
        let mut minimap_image = String::new();

        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if line.starts_with("LEVEL ") {
                level_name = line[6..].to_string();
            } else if line.starts_with("MAPIMAGE ") {
                map_image = line[9..].to_string();
            } else if line.starts_with("MINIMAP ") {
                minimap_image = line[8..].to_string();
            }
        }

        let mut gmap = GMap::new_bigmap(level_name);
        gmap.filename = filename;
        gmap.map_image = map_image;
        gmap.minimap_image = minimap_image;

        Ok(gmap)
    }

    /// Parse terrain data
    fn parse_terrain(lines: &[String], terrain: &mut MapTerrain) {
        // Basic terrain parsing
        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Some(rest) = line.strip_prefix("MAPSEED ") {
                terrain.map_seed = rest.parse().unwrap_or(0);
            } else if let Some(rest) = line.strip_prefix("HEIGHTBASE ") {
                terrain.height_base = rest.parse().unwrap_or(0.0);
            } else if let Some(rest) = line.strip_prefix("HEIGHTDEV ") {
                terrain.height_deviation = rest.parse().unwrap_or(65.0);
            } else if let Some(rest) = line.strip_prefix("MAPCHAOS ") {
                terrain.map_chaos = rest.parse().unwrap_or(0.6);
            }
        }
    }

    /// Load a map from a file
    pub fn load_from_file(path: &std::path::Path) -> Result<GMap, String> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read map file: {}", e))?;
        Self::load_from_text(&data, path.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_gmap() {
        let gmap = GMap::new_gmap(10, 10);
        assert_eq!(gmap.map_type, MapType::Gmap);
        assert_eq!(gmap.width, 10);
        assert_eq!(gmap.height, 10);
        assert!(gmap.levels.is_empty());
    }

    #[test]
    fn test_create_bigmap() {
        let gmap = GMap::new_bigmap("test.nw".to_string());
        assert_eq!(gmap.map_type, MapType::BigMap);
        assert_eq!(gmap.width, 1);
        assert_eq!(gmap.height, 1);
        assert_eq!(gmap.levels.len(), 1);
        assert_eq!(gmap.get_level_position("test.nw"), Some(MapLevelPosition::new(0, 0)));
    }

    #[test]
    fn test_add_level() {
        let mut gmap = GMap::new_gmap(5, 5);
        gmap.add_level("level1.nw".to_string(), 0, 0);
        gmap.add_level("level2.nw".to_string(), 1, 2);

        assert_eq!(gmap.level_count(), 2);
        assert_eq!(gmap.get_level_position("level1.nw"), Some(MapLevelPosition::new(0, 0)));
        assert_eq!(gmap.get_level_position("level2.nw"), Some(MapLevelPosition::new(1, 2)));
        assert_eq!(gmap.get_level_at(0, 0), Some("level1.nw".to_string()));
        assert_eq!(gmap.get_level_at(1, 2), Some("level2.nw".to_string()));
        assert_eq!(gmap.get_level_at(5, 5), None);
    }

    #[test]
    fn test_load_gmap_from_text() {
        let data = r#"GMAP001
NAME Test Map
MAPIMAGE testmap.png
WIDTH 5
HEIGHT 5
LEVELS
level1.nw 0 0
level2.nw 1 1
level3.nw 2 2
LEVELSEND
"#;

        let gmap = MapLoader::load_from_text(data, "test.gmap".into()).unwrap();
        assert_eq!(gmap.map_type, MapType::Gmap);
        assert_eq!(gmap.width, 5);
        assert_eq!(gmap.height, 5);
        assert_eq!(gmap.map_image, "Test Map"); // NAME is stored in map_image for now
        assert_eq!(gmap.level_count(), 3);
    }

    #[test]
    fn test_load_bigmap_from_text() {
        let data = r#"LEVEL onlinestartlocal.nw
MAPIMAGE bigmap.png
MINIMAP minimap.png
"#;

        let gmap = MapLoader::load_from_text(data, "test.bigmap".into()).unwrap();
        assert_eq!(gmap.map_type, MapType::BigMap);
        assert_eq!(gmap.levels.len(), 1);
        assert!(gmap.levels.contains_key("onlinestartlocal.nw"));
    }
}
