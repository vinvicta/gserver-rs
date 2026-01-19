//! Level structure and management
//!
//! Represents a single Graal level with tiles, NPCs, and other entities.

use crate::tiles::LevelTiles;
use crate::Result;
use gserver_core::PlayerID;
use std::path::PathBuf;
use std::sync::Arc;
use parking_lot::RwLock;

/// Unique level identifier
pub type LevelId = u32;

/// Level state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LevelState {
    /// Level is unloaded
    Unloaded,
    /// Level is being loaded
    Loading,
    /// Level is fully loaded and active
    Loaded,
    /// Level is being unloaded
    Unloading,
}

/// A single Graal level
///
/// Contains all data for a single level including tiles, NPCs, chests, etc.
#[derive(Debug, Clone)]
pub struct Level {
    /// Unique level ID
    pub id: LevelId,

    /// Level name (e.g., "onlinestartlocal.nw")
    pub name: String,

    /// File modification time (for caching)
    pub mod_time: u32,

    /// Level file path
    pub file_path: PathBuf,

    /// Tile data for all layers
    pub tiles: Arc<RwLock<LevelTiles>>,

    /// Current level state
    pub state: Arc<RwLock<LevelState>>,

    /// Players currently in this level
    pub players: Arc<RwLock<Vec<PlayerID>>>,

    /// NPCs in this level
    pub npcs: Arc<RwLock<Vec<NPCRef>>>,

    /// Chests in this level
    pub chests: Vec<Chest>,

    /// Links to other levels
    pub links: Vec<Link>,

    /// Signs in this level
    pub signs: Vec<Sign>,

    /// Baddies (enemies) in this level
    pub baddies: Vec<Baddy>,

    /// Map position if on a gmap
    pub map_position: Option<MapPosition>,

    /// Height overrides for terrain generation
    pub height_overrides: Option<Vec<f64>>,
}

/// Reference to an NPC
#[derive(Debug, Clone)]
pub struct NPCRef {
    /// NPC ID
    pub id: u32,

    /// NPC image
    pub image: String,

    /// X position (pixels)
    pub x: f32,

    /// Y position (pixels)
    pub y: f32,
}

/// A chest that contains items
#[derive(Debug, Clone)]
pub struct Chest {
    /// X position (tiles)
    pub x: u8,

    /// Y position (tiles)
    pub y: u8,

    /// Item type
    pub item: String,

    /// Sign index
    pub sign_index: i8,
}

/// A link to another level
#[derive(Debug, Clone)]
pub struct Link {
    /// X position (tiles)
    pub x: u8,

    /// Y position (tiles)
    pub y: u8,

    /// Width (tiles)
    pub width: u8,

    /// Height (tiles)
    pub height: u8,

    /// Target level name
    pub target_level: String,

    /// Target X position
    pub target_x: f32,

    /// Target Y position
    pub target_y: f32,
}

/// A sign with text
#[derive(Debug, Clone)]
pub struct Sign {
    /// X position (tiles)
    pub x: u8,

    /// Y position (tiles)
    pub y: u8,

    /// Sign text
    pub text: String,
}

/// An enemy (baddy)
#[derive(Debug, Clone)]
pub struct Baddy {
    /// X position (pixels)
    pub x: f32,

    /// Y position (pixels)
    pub y: f32,

    /// Baddy type
    pub baddy_type: String,

    /// Verses (AI behavior)
    pub verses: Vec<String>,
}

/// Position on a map
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapPosition {
    /// X coordinate on map (in levels)
    pub x: u16,

    /// Y coordinate on map (in levels)
    pub y: u16,
}

impl Level {
    /// Create a new empty level
    pub fn new(id: LevelId, name: String) -> Self {
        Self {
            id,
            name,
            mod_time: 0,
            file_path: PathBuf::new(),
            tiles: Arc::new(RwLock::new(LevelTiles::new())),
            state: Arc::new(RwLock::new(LevelState::Unloaded)),
            players: Arc::new(RwLock::new(Vec::new())),
            npcs: Arc::new(RwLock::new(Vec::new())),
            chests: Vec::new(),
            links: Vec::new(),
            signs: Vec::new(),
            baddies: Vec::new(),
            map_position: None,
            height_overrides: None,
        }
    }

    /// Create a default level with basic ground tiles
    ///
    /// # Purpose
    /// Creates a simple level filled with grass tiles for use when
    /// a level file cannot be found or for testing.
    ///
    /// # Arguments
    /// * `name` - Level name
    ///
    /// # Returns
    /// A new level with a 64x64 grass tile field
    ///
    /// # C++ Equivalence
    /// Similar to creating an empty level in the C++ server
    pub fn create_default(name: String) -> Self {
        use crate::tiles::{LevelTiles, TileLayer, BASE_LAYER};

        let id = Self::generate_level_id(&name);
        let mut tiles = LevelTiles::new();

        // Create base layer filled with grass (tile index 51 = grass.png)
        // Use a simple pattern: mostly grass with some variation
        let mut base_layer = TileLayer::new(BASE_LAYER);
        for y in 0..64u8 {
            for x in 0..64u8 {
                // Create a simple grass pattern with some variation
                // Grass tiles are typically in the 48-64 range
                let tile_idx = 48 + ((x + y) % 16) as u16;
                base_layer.set(x, y, tile_idx);
            }
        }

        tiles.set_layer(base_layer);

        Self {
            id,
            name,
            mod_time: 0,
            file_path: PathBuf::new(),
            tiles: Arc::new(RwLock::new(tiles)),
            state: Arc::new(RwLock::new(LevelState::Loaded)),
            players: Arc::new(RwLock::new(Vec::new())),
            npcs: Arc::new(RwLock::new(Vec::new())),
            chests: Vec::new(),
            links: Vec::new(),
            signs: Vec::new(),
            baddies: Vec::new(),
            map_position: None,
            height_overrides: None,
        }
    }

    /// Generate a unique level ID from name
    fn generate_level_id(name: &str) -> LevelId {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        hasher.finish() as LevelId
    }

    /// Get the level state
    pub fn get_state(&self) -> LevelState {
        *self.state.read()
    }

    /// Set the level state
    pub fn set_state(&self, state: LevelState) {
        *self.state.write() = state;
    }

    /// Add a player to this level
    pub fn add_player(&self, player_id: PlayerID) {
        let mut players = self.players.write();
        if !players.contains(&player_id) {
            players.push(player_id);
        }
    }

    /// Remove a player from this level
    pub fn remove_player(&self, player_id: PlayerID) {
        let mut players = self.players.write();
        players.retain(|&p| p != player_id);
    }

    /// Get the number of players in this level
    pub fn player_count(&self) -> usize {
        self.players.read().len()
    }

    /// Add an NPC to this level
    pub fn add_npc(&self, id: u32, image: String, x: f32, y: f32) {
        let mut npcs = self.npcs.write();
        npcs.push(NPCRef { id, image, x, y });
    }

    /// Remove an NPC from this level
    pub fn remove_npc(&self, id: u32) {
        let mut npcs = self.npcs.write();
        npcs.retain(|npc| npc.id != id);
    }

    /// Get tile at position from layer
    pub fn get_tile(&self, x: u8, y: u8, layer: u8) -> u16 {
        self.tiles.read().get_tile(x, y, layer)
    }

    /// Set tile at position in layer
    pub fn set_tile(&self, x: u8, y: u8, layer: u8, tile: u16) {
        self.tiles.write().set_tile(x, y, layer, tile);
    }

    /// Check if level is on a map
    pub fn is_on_map(&self) -> bool {
        self.map_position.is_some()
    }

    /// Check if level is loaded
    pub fn is_loaded(&self) -> bool {
        self.get_state() == LevelState::Loaded
    }

    /// Generate board packet data for this level
    ///
    /// # Purpose
    /// Generates the raw tile data to send to clients for level loading.
    ///
    /// # Returns
    /// Vector of bytes containing the board data
    ///
    /// # C++ Equivalence
    /// Matches `Level::getBoardPacket()` in Level.cpp
    pub fn get_board_data(&self) -> Vec<u8> {
        self.tiles.read().generate_board_data()
    }

    /// Generate layer packet data for additional layers
    ///
    /// # Purpose
    /// Generates tile data for layers beyond the base layer.
    ///
    /// # Arguments
    /// * `layer_id` - Layer ID to generate data for (1-15)
    ///
    /// # Returns
    /// Vector of tile data, or None if layer doesn't exist
    pub fn get_layer_data(&self, layer_id: u8) -> Option<Vec<u8>> {
        self.tiles.read().generate_layer_data(layer_id)
    }

    /// Get all layer IDs that have data
    pub fn get_layer_ids(&self) -> Vec<u8> {
        self.tiles.read().layer_ids().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level_creation() {
        let level = Level::new(1, "testlevel.nw".to_string());
        assert_eq!(level.id, 1);
        assert_eq!(level.name, "testlevel.nw");
        assert_eq!(level.get_state(), LevelState::Unloaded);
        assert_eq!(level.player_count(), 0);
        assert!(!level.is_on_map());
    }

    #[test]
    fn test_level_players() {
        let level = Level::new(1, "testlevel.nw".to_string());
        let player1 = PlayerID::new(1);
        let player2 = PlayerID::new(2);

        level.add_player(player1);
        assert_eq!(level.player_count(), 1);

        level.add_player(player2);
        assert_eq!(level.player_count(), 2);

        level.add_player(player1); // Duplicate, should not add
        assert_eq!(level.player_count(), 2);

        level.remove_player(player1);
        assert_eq!(level.player_count(), 1);
    }

    #[test]
    fn test_level_tiles() {
        let level = Level::new(1, "testlevel.nw".to_string());

        // Set and get tiles
        level.set_tile(10, 20, 0, 100);
        assert_eq!(level.get_tile(10, 20, 0), 100);

        level.set_tile(15, 25, 1, 200);
        assert_eq!(level.get_tile(15, 25, 1), 200);
    }

    #[test]
    fn test_level_state() {
        let level = Level::new(1, "testlevel.nw".to_string());

        assert_eq!(level.get_state(), LevelState::Unloaded);
        assert!(!level.is_loaded());

        level.set_state(LevelState::Loading);
        assert_eq!(level.get_state(), LevelState::Loading);

        level.set_state(LevelState::Loaded);
        assert!(level.is_loaded());
    }
}
