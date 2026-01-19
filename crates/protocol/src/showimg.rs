//! ShowImg - Dynamic image overlay system
//!
//! # Purpose
//! Displays overlay images on characters (players/NPCs) with various
//! customization options including position, colorization, zoom, and animation.
//!
//! # C++ Equivalence
//! Matches `ShowImg` struct in ShowImg.h
//!
//! # Packet Types
//! - PLO_SHOWIMG (160) - Send/show an image
//! - PLO_HIDEIMG (161) - Hide an image
//! - PLO_CHANGEIMG (162) - Change image properties
//! - PLO_CHANGEIMGVIS (163) - Change image visibility

use serde::{Deserialize, Serialize};

/// Image overlay data
///
/// # C++ Equivalence
/// Matches `ShowImg` in ShowImg.h
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShowImg {
    /// Image index (0-255, used to identify the image)
    pub index: u8,

    /// X position (in pixels relative to character)
    pub x: f32,

    /// Y position (in pixels relative to character)
    pub y: f32,

    /// Z position (layer depth)
    pub z: f32,

    /// Image filename
    pub image: String,

    /// Script code (for clickable images)
    pub code: String,

    /// Red colorization (0-255)
    pub red: u8,

    /// Green colorization (0-255)
    pub green: u8,

    /// Blue colorization (0-255)
    pub blue: u8,

    /// Zoom level (256 = 100%, 512 = 200%, etc.)
    pub zoom: i16,

    /// Mode flags
    /// - 0x01: transparent
    /// - 0x02: parallax
    pub mode: u8,

    /// Animation parameters
    pub params: u32,

    /// Sprite sheet part (for sprites)
    pub part: u16,

    /// Animation name (.gani file)
    pub gani: String,

    /// Visibility flag
    pub visible: bool,
}

impl Default for ShowImg {
    fn default() -> Self {
        Self {
            index: 0,
            x: 0.0,
            y: 0.0,
            z: 0.0,
            image: String::new(),
            code: String::new(),
            red: 0,
            green: 0,
            blue: 0,
            zoom: 256,  // 100%
            mode: 0,
            params: 0,
            part: 0,
            gani: String::new(),
            visible: true,
        }
    }
}

impl ShowImg {
    /// Create a new static image overlay
    pub fn new(index: u8, x: f32, y: f32, image: String) -> Self {
        Self {
            index,
            x,
            y,
            image,
            ..Default::default()
        }
    }

    /// Create a new image with colorization
    pub fn with_color(mut self, r: u8, g: u8, b: u8) -> Self {
        self.red = r;
        self.green = g;
        self.blue = b;
        self
    }

    /// Create a new image with zoom
    pub fn with_zoom(mut self, zoom: i16) -> Self {
        self.zoom = zoom;
        self
    }

    /// Create a new image with transparency mode
    pub fn with_transparent(mut self, transparent: bool) -> Self {
        if transparent {
            self.mode |= 0x01;
        } else {
            self.mode &= !0x01;
        }
        self
    }

    /// Create a new image with parallax mode
    pub fn with_parallax(mut self, parallax: bool) -> Self {
        if parallax {
            self.mode |= 0x02;
        } else {
            self.mode &= !0x02;
        }
        self
    }

    /// Create a new image with animation
    pub fn with_animation(mut self, gani: String, params: u32) -> Self {
        self.gani = gani;
        self.params = params;
        self
    }

    /// Create a new image with sprite part
    pub fn with_part(mut self, part: u16) -> Self {
        self.part = part;
        self
    }

    /// Create a new image with script code
    pub fn with_code(mut self, code: String) -> Self {
        self.code = code;
        self
    }

    /// Set visibility
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Check if transparent mode is set
    pub fn is_transparent(&self) -> bool {
        (self.mode & 0x01) != 0
    }

    /// Check if parallax mode is set
    pub fn is_parallax(&self) -> bool {
        (self.mode & 0x02) != 0
    }

    /// Get zoom as a percentage (1.0 = 100%)
    pub fn zoom_percent(&self) -> f32 {
        self.zoom as f32 / 256.0
    }

    /// Set zoom as a percentage (1.0 = 100%)
    pub fn set_zoom_percent(&mut self, percent: f32) {
        self.zoom = (percent * 256.0) as i16;
    }

    /// Get the effective color as RGB tuple
    pub fn color_rgb(&self) -> (u8, u8, u8) {
        (self.red, self.green, self.blue)
    }
}

/// Collection of showimg overlays
///
/// # C++ Equivalence
/// Matches `std::vector<ShowImg> Character::images`
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShowImgCollection {
    /// List of overlay images
    pub images: Vec<ShowImg>,
}

impl ShowImgCollection {
    /// Create a new empty collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an image to the collection
    pub fn add(&mut self, img: ShowImg) {
        // Remove existing image with same index
        self.images.retain(|i| i.index != img.index);
        self.images.push(img);
    }

    /// Remove an image by index
    pub fn remove(&mut self, index: u8) -> bool {
        let original_len = self.images.len();
        self.images.retain(|i| i.index != index);
        self.images.len() < original_len
    }

    /// Get an image by index
    pub fn get(&self, index: u8) -> Option<&ShowImg> {
        self.images.iter().find(|i| i.index == index)
    }

    /// Get a mutable reference to an image by index
    pub fn get_mut(&mut self, index: u8) -> Option<&mut ShowImg> {
        self.images.iter_mut().find(|i| i.index == index)
    }

    /// Clear all images
    pub fn clear(&mut self) {
        self.images.clear();
    }

    /// Get the number of images
    pub fn len(&self) -> usize {
        self.images.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.images.is_empty()
    }

    /// Iterate over all images
    pub fn iter(&self) -> impl Iterator<Item = &ShowImg> {
        self.images.iter()
    }

    /// Get all visible images
    pub fn visible(&self) -> impl Iterator<Item = &ShowImg> {
        self.images.iter().filter(|i| i.visible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_showimg_default() {
        let img = ShowImg::default();
        assert_eq!(img.index, 0);
        assert_eq!(img.x, 0.0);
        assert_eq!(img.y, 0.0);
        assert_eq!(img.zoom, 256);
        assert!(img.visible);
    }

    #[test]
    fn test_showimg_builder() {
        let img = ShowImg::new(5, 100.0, 200.0, "test.png".to_string())
            .with_color(255, 128, 64)
            .with_zoom(512)
            .with_transparent(true);

        assert_eq!(img.index, 5);
        assert_eq!(img.x, 100.0);
        assert_eq!(img.y, 200.0);
        assert_eq!(img.image, "test.png");
        assert_eq!(img.color_rgb(), (255, 128, 64));
        assert_eq!(img.zoom, 512);
        assert!(img.is_transparent());
    }

    #[test]
    fn test_showimg_collection() {
        let mut collection = ShowImgCollection::new();

        let img1 = ShowImg::new(1, 10.0, 20.0, "img1.png".to_string());
        let img2 = ShowImg::new(2, 30.0, 40.0, "img2.png".to_string());

        collection.add(img1.clone());
        collection.add(img2.clone());

        assert_eq!(collection.len(), 2);
        assert!(collection.get(1).is_some());
        assert!(collection.get(2).is_some());

        // Test replacement
        let img1_new = ShowImg::new(1, 50.0, 60.0, "img1_new.png".to_string());
        collection.add(img1_new);
        assert_eq!(collection.len(), 2); // Still 2, not 3
        assert_eq!(collection.get(1).unwrap().image, "img1_new.png");

        // Test removal
        collection.remove(1);
        assert_eq!(collection.len(), 1);
        assert!(collection.get(1).is_none());
        assert!(collection.get(2).is_some());
    }

    #[test]
    fn test_zoom_percent() {
        let mut img = ShowImg::default();
        assert_eq!(img.zoom_percent(), 1.0); // 100%

        img.set_zoom_percent(2.0); // 200%
        assert_eq!(img.zoom, 512);
        assert_eq!(img.zoom_percent(), 2.0);
    }
}
