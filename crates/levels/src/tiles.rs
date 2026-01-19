//! Tile system for levels
//!
//! Graal levels use a 64x64 tile grid with support for multiple layers.
//! Each tile is represented by a 16-bit index.

use crate::error::{LevelError, Result};

/// Maximum number of tiles per level (64x64)
pub const MAX_TILE_COUNT: usize = 64 * 64;

/// Maximum number of tile layers
pub const MAX_LAYERS: u8 = 16;

/// Base layer (ground tiles)
pub const BASE_LAYER: u8 = 0;

/// Empty tile value (no tile)
pub const EMPTY_TILE: u16 = 0xFFFF;

/// A single tile with its index and optional attributes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tile {
    /// Tile index (0-4095, or 0xFFFF for empty)
    pub index: u16,

    /// Layer this tile belongs to
    pub layer: u8,
}

impl Tile {
    /// Create a new tile
    #[inline]
    pub fn new(index: u16, layer: u8) -> Self {
        Self { index, layer }
    }

    /// Create an empty tile
    #[inline]
    pub fn empty() -> Self {
        Self {
            index: EMPTY_TILE,
            layer: 0,
        }
    }

    /// Check if this tile is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.index == EMPTY_TILE
    }
}

/// A complete tile layer for a level
///
/// Contains 4096 tiles (64x64 grid) in row-major order.
#[derive(Debug, Clone)]
pub struct TileLayer {
    /// Layer ID (0-15)
    pub id: u8,

    /// Tile data (4096 tiles)
    tiles: Vec<u16>,
}

impl TileLayer {
    /// Create a new tile layer
    pub fn new(id: u8) -> Self {
        Self {
            id,
            tiles: vec![EMPTY_TILE; MAX_TILE_COUNT],
        }
    }

    /// Create a tile layer filled with a specific tile
    pub fn with_fill(id: u8, fill_tile: u16) -> Self {
        Self {
            id,
            tiles: vec![fill_tile; MAX_TILE_COUNT],
        }
    }

    /// Get tile at position (x, y)
    ///
    /// # Arguments
    /// * `x` - X coordinate (0-63)
    /// * `y` - Y coordinate (0-63)
    #[inline]
    pub fn get(&self, x: u8, y: u8) -> u16 {
        let index = (y as usize) * 64 + (x as usize);
        self.tiles[index]
    }

    /// Set tile at position (x, y)
    ///
    /// # Arguments
    /// * `x` - X coordinate (0-63)
    /// * `y` - Y coordinate (0-63)
    /// * `tile` - Tile index to set
    #[inline]
    pub fn set(&mut self, x: u8, y: u8, tile: u16) {
        let index = (y as usize) * 64 + (x as usize);
        self.tiles[index] = tile;
    }

    /// Get the raw tile data
    #[inline]
    pub fn data(&self) -> &[u16] {
        &self.tiles
    }

    /// Get mutable raw tile data
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u16] {
        &mut self.tiles
    }
}

/// Complete tile system for a level
///
/// Manages multiple tile layers for a single level.
#[derive(Debug, Clone)]
pub struct LevelTiles {
    /// All tile layers indexed by layer ID
    layers: Vec<Option<TileLayer>>,
}

impl LevelTiles {
    /// Create a new empty tile system
    pub fn new() -> Self {
        Self {
            layers: Vec::with_capacity(MAX_LAYERS as usize),
        }
    }

    /// Create with a base layer filled with a specific tile
    pub fn with_base_fill(fill_tile: u16) -> Self {
        let mut tiles = Self::new();
        tiles.layers.push(Some(TileLayer::with_fill(BASE_LAYER, fill_tile)));
        tiles
    }

    /// Get a tile layer by ID
    pub fn get_layer(&self, layer_id: u8) -> Option<&TileLayer> {
        self.layers.get(layer_id as usize)?.as_ref()
    }

    /// Get a mutable tile layer by ID
    pub fn get_layer_mut(&mut self, layer_id: u8) -> Option<&mut TileLayer> {
        self.layers.get_mut(layer_id as usize)?.as_mut()
    }

    /// Add or replace a tile layer
    pub fn set_layer(&mut self, layer: TileLayer) {
        let id = layer.id as usize;
        if self.layers.len() <= id {
            self.layers.resize_with(id + 1, || None);
        }
        self.layers[id] = Some(layer);
    }

    /// Get tile at position (x, y) from specific layer
    #[inline]
    pub fn get_tile(&self, x: u8, y: u8, layer_id: u8) -> u16 {
        self.get_layer(layer_id)
            .map(|layer| layer.get(x, y))
            .unwrap_or(EMPTY_TILE)
    }

    /// Set tile at position (x, y) in specific layer
    #[inline]
    pub fn set_tile(&mut self, x: u8, y: u8, layer_id: u8, tile: u16) {
        if self.get_layer(layer_id).is_none() {
            self.set_layer(TileLayer::new(layer_id));
        }
        if let Some(layer) = self.get_layer_mut(layer_id) {
            layer.set(x, y, tile);
        }
    }

    /// Check if a layer exists
    #[inline]
    pub fn has_layer(&self, layer_id: u8) -> bool {
        self.get_layer(layer_id).is_some()
    }

    /// Get all layer IDs that exist
    pub fn layer_ids(&self) -> impl Iterator<Item = u8> + '_ {
        self.layers
            .iter()
            .enumerate()
            .filter_map(|(id, layer)| layer.as_ref().map(|_| id as u8))
    }

    /// Generate board packet data for the base layer
    ///
    /// # Purpose
    /// Generates the raw tile data in the format expected by the Graal client.
    /// The board data is 64x64 tiles, each encoded as a 16-bit little-endian value.
    ///
    /// # Format
    /// ```text
    /// [tile(0,0)] [tile(1,0)] ... [tile(63,0)] [tile(0,1)] ... [tile(63,63)]
    /// ```
    ///
    /// Each tile is 2 bytes (little-endian u16), totaling 8192 bytes.
    ///
    /// # Returns
    /// Vector of 8192 bytes (64x64 tiles x 2 bytes)
    ///
    /// # C++ Equivalence
    /// Matches `Level::getBoardPacket()` in the C++ implementation
    pub fn generate_board_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(MAX_TILE_COUNT * 2);

        // Get base layer (layer 0), or use empty tiles if not present
        let base_layer = self.get_layer(BASE_LAYER);

        for y in 0..64u8 {
            for x in 0..64u8 {
                let tile_index = base_layer
                    .map(|layer| layer.get(x, y))
                    .unwrap_or(EMPTY_TILE);
                // Write as little-endian u16
                data.push((tile_index & 0xFF) as u8);
                data.push(((tile_index >> 8) & 0xFF) as u8);
            }
        }

        data
    }

    /// Generate layer packet data for additional layers
    ///
    /// # Purpose
    /// Generates tile data for layers beyond the base layer.
    /// These are sent separately to reduce bandwidth for levels with few layers.
    ///
    /// # Arguments
    /// * `layer_id` - Layer ID to generate data for (1-15)
    ///
    /// # Returns
    /// Vector of tile data, or None if layer doesn't exist
    ///
    /// # C++ Equivalence
    /// Matches `Level::getLayerPacket()` in the C++ implementation
    pub fn generate_layer_data(&self, layer_id: u8) -> Option<Vec<u8>> {
        let layer = self.get_layer(layer_id)?;
        let mut data = Vec::with_capacity(MAX_TILE_COUNT * 2 + 3);

        // Layer header: {GCHAR layer_id}
        data.push(layer_id + 32); // GChar encode

        // Tile data
        for y in 0..64u8 {
            for x in 0..64u8 {
                let tile_index = layer.get(x, y);
                // Write as little-endian u16
                data.push((tile_index & 0xFF) as u8);
                data.push(((tile_index >> 8) & 0xFF) as u8);
            }
        }

        Some(data)
    }
}

impl Default for LevelTiles {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tile_creation() {
        let tile = Tile::new(100, 0);
        assert_eq!(tile.index, 100);
        assert_eq!(tile.layer, 0);
        assert!(!tile.is_empty());

        let empty = Tile::empty();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_tile_layer() {
        let mut layer = TileLayer::new(0);
        assert_eq!(layer.get(10, 20), EMPTY_TILE);

        layer.set(10, 20, 100);
        assert_eq!(layer.get(10, 20), 100);
        assert_eq!(layer.data().len(), MAX_TILE_COUNT);
    }

    #[test]
    fn test_level_tiles() {
        let mut tiles = LevelTiles::with_base_fill(50);

        // Base layer should be filled
        assert_eq!(tiles.get_tile(0, 0, 0), 50);
        assert_eq!(tiles.get_tile(63, 63, 0), 50);

        // Set a different tile
        tiles.set_tile(10, 10, 0, 100);
        assert_eq!(tiles.get_tile(10, 10, 0), 100);
        assert_eq!(tiles.get_tile(11, 10, 0), 50); // Unchanged

        // Add a new layer
        tiles.set_tile(5, 5, 1, 200);
        assert_eq!(tiles.get_tile(5, 5, 1), 200);
        assert!(tiles.has_layer(1));
    }

    #[test]
    fn test_tile_boundaries() {
        let mut layer = TileLayer::new(0);

        // Test boundaries
        layer.set(0, 0, 1);
        layer.set(63, 63, 2);
        assert_eq!(layer.get(0, 0), 1);
        assert_eq!(layer.get(63, 63), 2);

        // Test middle
        layer.set(32, 32, 3);
        assert_eq!(layer.get(32, 32), 3);
    }
}
