//! # Player Management
//!
//! This module handles player state and lifecycle.

use crate::properties::PlayerProperties;
use gserver_core::PlayerID;
use parking_lot::Mutex;
use std::sync::Arc;

/// Player account type
///
/// # Purpose
/// Determines what kind of connection this is and what permissions it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlayerType {
    /// Regular player connected via Graal client
    Player,

    /// Remote Control (admin) connection
    Rc,

    /// NPC Server connection
    Nc,
}

/// Player state during login/gameplay
///
/// # Purpose
/// Tracks where the player is in the connection lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlayerState {
    /// Connection just established
    Connecting,

    /// Login packet received, validating credentials
    LoggingIn,

    /// Successfully logged in and playing
    InGame,
}

/// Individual player
///
/// # Purpose
/// Manages a single player's state and connection.
///
/// # Thread Safety
/// Internally synchronized with `Mutex` for safe sharing across tasks.
pub struct Player {
    /// Unique player ID
    pub id: PlayerID,

    /// Player account type
    pub player_type: PlayerType,

    /// Current player state
    pub state: PlayerState,

    /// Player properties (nickname, position, etc.)
    pub properties: Arc<Mutex<PlayerProperties>>,
}

impl Player {
    /// Create a new player
    ///
    /// # Arguments
    /// * `id` - Unique player identifier
    /// * `player_type` - Type of player account
    #[inline]
    pub fn new(id: PlayerID, player_type: PlayerType) -> Self {
        tracing::debug!("Creating player {}: type={:?}", id.get(), player_type);

        Self {
            id,
            player_type,
            state: PlayerState::Connecting,
            properties: Arc::new(Mutex::new(PlayerProperties::new())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_player_creation() {
        let player = Player::new(PlayerID::new(1), PlayerType::Player);
        assert_eq!(player.id.get(), 1);
        assert_eq!(player.player_type, PlayerType::Player);
        assert_eq!(player.state, PlayerState::Connecting);
    }
}
