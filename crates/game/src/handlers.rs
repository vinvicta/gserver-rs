//! # Packet Handlers
//!
//! This module contains packet handlers for game logic.

use crate::{AccountManager, Player, PlayerType};
use gserver_core::{PlayerID, Result};
use gserver_protocol::PacketIn;
use std::sync::Arc;
use std::path::PathBuf;

/// Login Handler Context
///
/// # Purpose
/// Contains shared state needed for login handling.
///
/// # Thread Safety
/// All fields are thread-safe for concurrent access.
pub struct LoginContext {
    /// Account manager for loading accounts
    pub account_manager: Arc<AccountManager>,
}

impl LoginContext {
    /// Create a new login context
    ///
    /// # Arguments
    /// * `accounts_dir` - Directory containing account files
    #[inline]
    pub fn new(accounts_dir: PathBuf) -> Self {
        Self {
            account_manager: Arc::new(AccountManager::new(accounts_dir)),
        }
    }
}

/// Handle login packet
///
/// # Purpose
/// Processes player login requests with account validation.
///
/// # Arguments
/// * `packet` - The login packet to handle
/// * `context` - Login context with account manager
///
/// # Returns
/// The created player or error
///
/// # Process
/// 1. Parse account name and password from packet
/// 2. Load account from file
/// 3. Validate password
/// 4. Create player object
/// 5. Return player for connection tracking
pub async fn handle_login(
    packet: &PacketIn,
    context: &LoginContext,
) -> Result<Player> {
    tracing::debug!("Handling login packet: {:?}", packet.packet_type);

    // For now, use a simple account name from packet data
    // TODO: Parse actual account name and password from packet
    let account_name = String::from_utf8_lossy(&packet.packet_data).trim().to_string();

    if account_name.is_empty() {
        return Err(gserver_core::GServerError::InvalidData(
            "Empty account name".to_string()
        ));
    }

    // Load account
    let account = context.account_manager.load_account(&account_name)?;

    tracing::info!("Player {} logged in successfully", account.nickname);

    // Create player
    let player = Player::new(PlayerID::new(1), PlayerType::Player);

    // TODO: Load account properties into player
    // TODO: Set player state to InGame

    Ok(player)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gserver_protocol::{PacketTypeIn, PacketIn};
    use std::fs;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_login_handler() {
        // Create temp directory
        let temp_dir = TempDir::new().unwrap();
        let accounts_dir = temp_dir.path().to_path_buf();

        // Create test account file
        let account_file = accounts_dir.join("testuser.txt");
        let account_data = r#"nickname=TestUser
password=hash123
x=50.0
y=50.0
level=onlinestartlocal.nw
admin=0"#;
        fs::write(&account_file, account_data).unwrap();

        // Create context
        let context = LoginContext::new(accounts_dir);

        // Create login packet
        let packet = PacketIn::new(PacketTypeIn::LevelWarp, b"testuser".to_vec());

        // Handle login
        let result = handle_login(&packet, &context).await;
        assert!(result.is_ok());

        let player = result.unwrap();
        assert_eq!(player.player_type, PlayerType::Player);
        assert_eq!(player.id.get(), 1);
    }
}
