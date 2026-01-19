//! # GServer Levels System
//!
//! This crate handles level loading, parsing, and management for Graal Online.
//!
//! ## Features
//! - .nw level file format parser (GLEVNW01)
//! - Multi-layer tile system (base + additional layers)
//! - Board changes and modifications
//! - Level caching and lazy loading
//! - Spatial indexing for queries
//! - gmap/bigmap support
//!
//! ## Level Format
//!
//! Levels are stored in text-based .nw files with the following structure:
//! - **Magic header**: "GLEVNW01"
//! - **BOARD lines**: Tile data for each row
//! - **CHEST/LINK/NPC/SIGN/BADDY**: Game objects
//! - **HEIGHTS**: Terrain height data

pub mod error;
pub mod level;
pub mod tiles;
pub mod parser;
pub mod cache;
pub mod map;
pub mod manager;

pub use error::{LevelError, Result};
pub use level::{Level, LevelId, MapPosition};
pub use tiles::{Tile, TileLayer, LevelTiles, MAX_TILE_COUNT};
pub use parser::LevelLoader;
pub use cache::LevelCache;
pub use map::{Map, MapType};
pub use manager::{LevelManager, SimpleLevelProvider};
