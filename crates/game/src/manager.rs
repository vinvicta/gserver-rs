//! # Player Manager
//!
//! This module manages the collection of all connected players.

use crate::player::Player;
use gserver_core::PlayerID;
use std::sync::Arc;

/// Player Manager
///
/// # Purpose
/// Tracks all connected players and provides lookup/management functions.
///
/// # Thread Safety
/// All operations are thread-safe using DashMap for concurrent access.
pub struct PlayerManager {
    /// All players
    /// Key: PlayerID, Value: Player handle
    players: Arc<dashmap::DashMap<PlayerID, Arc<Player>>>,
}

impl PlayerManager {
    /// Create a new player manager
    ///
    /// # Returns
    /// An empty manager ready to track players
    #[inline]
    pub fn new() -> Self {
        tracing::debug!("Creating PlayerManager");

        Self {
            players: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Add a player to the manager
    ///
    /// # Arguments
    /// * `player` - The player to add
    #[inline]
    pub fn add_player(&self, player: Arc<Player>) {
        tracing::debug!("Adding player {}", player.id.get());
        self.players.insert(player.id, player);
    }

    /// Remove a player from the manager
    ///
    /// # Arguments
    /// * `id` - The player ID to remove
    #[inline]
    pub fn remove_player(&self, id: PlayerID) {
        tracing::debug!("Removing player {}", id.get());
        self.players.remove(&id);
    }

    /// Get a player by ID
    ///
    /// # Arguments
    /// * `id` - The player ID to look up
    ///
    /// # Returns
    /// `Some(player)` if found, `None` otherwise
    #[inline]
    pub fn get_player(&self, id: PlayerID) -> Option<Arc<Player>> {
        self.players.get(&id).map(|entry| entry.clone())
    }

    /// Get the number of players
    ///
    /// # Returns
    /// The current number of players in the manager
    #[inline]
    pub fn player_count(&self) -> usize {
        self.players.len()
    }
}

impl Default for PlayerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::player::PlayerType;

    #[test]
    fn test_manager_creation() {
        let manager = PlayerManager::new();
        assert_eq!(manager.player_count(), 0);
    }

    #[test]
    fn test_add_remove_player() {
        let manager = PlayerManager::new();
        let player = Arc::new(Player::new(PlayerID::new(1), PlayerType::Player));

        manager.add_player(player.clone());
        assert_eq!(manager.player_count(), 1);

        manager.remove_player(player.id);
        assert_eq!(manager.player_count(), 0);
    }

    #[test]
    fn test_get_player() {
        let manager = PlayerManager::new();
        let player = Arc::new(Player::new(PlayerID::new(1), PlayerType::Player));

        manager.add_player(player.clone());

        let found = manager.get_player(player.id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, player.id);

        let not_found = manager.get_player(PlayerID::new(999));
        assert!(not_found.is_none());
    }
}
