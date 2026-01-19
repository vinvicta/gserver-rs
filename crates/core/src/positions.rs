//! Position types for game objects

use serde::{Deserialize, Serialize};

/// Tile-based position (for tiles, NPCs, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TilePosition {
    pub x: i32,
    pub y: i32,
}

impl TilePosition {
    pub const fn new(x: i32, y: i32) -> Self {
        Self { x, y }
    }

    /// Convert tile position to pixel position (1 tile = 16 pixels)
    pub const fn to_pixels(self) -> PixelPosition {
        PixelPosition {
            x: self.x as f32 * 16.0,
            y: self.y as f32 * 16.0,
        }
    }
}

/// Pixel-based position (for smooth movement)
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PixelPosition {
    pub x: f32,
    pub y: f32,
}

impl PixelPosition {
    pub const fn new(x: f32, y: f32) -> Self {
        Self { x, y }
    }

    /// Convert pixel position to tile position
    pub fn to_tiles(self) -> TilePosition {
        TilePosition {
            x: (self.x / 16.0).floor() as i32,
            y: (self.y / 16.0).floor() as i32,
        }
    }

    /// Calculate distance to another position
    pub fn distance_to(self, other: PixelPosition) -> f32 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        (dx * dx + dy * dy).sqrt()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tile_to_pixel_conversion() {
        let tile_pos = TilePosition::new(2, 3);
        let pixel_pos = tile_pos.to_pixels();
        assert_eq!(pixel_pos.x, 32.0);
        assert_eq!(pixel_pos.y, 48.0);
    }

    #[test]
    fn test_pixel_to_tile_conversion() {
        let pixel_pos = PixelPosition::new(32.0, 48.0);
        let tile_pos = pixel_pos.to_tiles();
        assert_eq!(tile_pos.x, 2);
        assert_eq!(tile_pos.y, 3);
    }

    #[test]
    fn test_distance_calculation() {
        let pos1 = PixelPosition::new(0.0, 0.0);
        let pos2 = PixelPosition::new(3.0, 4.0);
        let dist = pos1.distance_to(pos2);
        assert!((dist - 5.0).abs() < 0.001);
    }
}
