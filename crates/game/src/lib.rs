//! # GServer Game Logic Layer
//!
//! This crate contains all game logic for the GServer.
//!
//! ## Modules
//!
//! - `player` - Player management and state
//! - `manager` - Player collection management
//! - `properties` - Player property definitions
//! - `handlers` - Packet handlers for game logic
//! - `account` - Player account management

pub mod player;
pub mod manager;
pub mod properties;
pub mod handlers;
pub mod account;

// Re-export commonly used types
pub use player::{Player, PlayerType, PlayerState};
pub use manager::PlayerManager;
pub use properties::PlayerProperties;
pub use account::{Account, AccountManager};
