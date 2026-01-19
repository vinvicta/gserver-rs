//! # Player Accounts
//!
//! This module handles loading and managing player accounts from flat files.
//!
//! # Account File Format
//!
//! Graal accounts are stored in plain text files with the format:
//! ```text
//! account.txt
//! nickname=PlayerName
//! password=hashedpassword
//! x=30.5
//! y=30.5
//! level=onlinestartlocal.nw
//! admin=0
//! ...
//! ```

use gserver_core::Result;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Player account
///
/// # Purpose
/// Stores all account data loaded from account files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Account name (username)
    pub account_name: String,

    /// Display nickname
    pub nickname: String,

    /// Password hash (stored, not plain text)
    pub password_hash: String,

    /// X position in pixels
    pub x: f32,

    /// Y position in pixels
    pub y: f32,

    /// Current level name
    pub level: String,

    /// Admin rights (0 = none, 1 = trial, 2 = full)
    pub admin: u8,

    /// Additional custom properties
    #[serde(flatten)]
    pub extra: HashMap<String, String>,
}

impl Account {
    /// Create a new account with default values
    ///
    /// # Arguments
    /// * `account_name` - The account username
    #[inline]
    pub fn new(account_name: String) -> Self {
        Self {
            account_name: account_name.clone(),
            nickname: account_name,
            password_hash: String::new(),
            x: 30.0,
            y: 30.0,
            level: "onlinestartlocal.nw".to_string(),
            admin: 0,
            extra: HashMap::new(),
        }
    }

    /// Get a property value by name
    #[inline]
    pub fn get(&self, name: &str) -> Option<&String> {
        self.extra.get(name)
    }

    /// Set a property value
    #[inline]
    pub fn set(&mut self, name: String, value: String) {
        self.extra.insert(name, value);
    }

    /// Parse account from key=value format
    ///
    /// # Arguments
    /// * `data` - String data in key=value format (one per line)
    ///
    /// # Returns
    /// Parsed account or error
    pub fn parse_from_text(account_name: String, data: &str) -> Result<Self> {
        let mut account = Self::new(account_name);

        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                match key {
                    "nickname" => account.nickname = value.to_string(),
                    "password" => account.password_hash = value.to_string(),
                    "x" => account.x = value.parse().unwrap_or(30.0),
                    "y" => account.y = value.parse().unwrap_or(30.0),
                    "level" => account.level = value.to_string(),
                    "admin" => account.admin = value.parse().unwrap_or(0),
                    _ => {
                        account.extra.insert(key.to_string(), value.to_string());
                    }
                }
            }
        }

        Ok(account)
    }
}

/// Account Manager
///
/// # Purpose
/// Manages loading and caching of player accounts from files.
///
/// # Thread Safety
/// All operations are thread-safe.
pub struct AccountManager {
    /// Base directory for accounts
    accounts_dir: PathBuf,

    /// Account cache
    /// Key: account name, Value: Account data
    cache: Arc<Mutex<HashMap<String, Account>>>,
}

impl AccountManager {
    /// Create a new account manager
    ///
    /// # Arguments
    /// * `accounts_dir` - Base directory containing account files
    #[inline]
    pub fn new(accounts_dir: PathBuf) -> Self {
        tracing::debug!("Creating AccountManager with dir: {:?}", accounts_dir);

        Self {
            accounts_dir,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Load an account from file
    ///
    /// # Arguments
    /// * `account_name` - The account name to load
    ///
    /// # Returns
    /// The account if found, error otherwise
    pub fn load_account(&self, account_name: &str) -> Result<Account> {
        // Check cache first
        {
            let cache = self.cache.lock();
            if let Some(account) = cache.get(account_name) {
                tracing::debug!("Account {} found in cache", account_name);
                return Ok(account.clone());
            }
        }

        // Build file path
        let account_path = self.accounts_dir.join(format!("{}.txt", account_name));

        // Read file
        let data = fs::read_to_string(&account_path).map_err(|e| {
            gserver_core::GServerError::NotFound(format!("Account file {:?}: {}", account_path, e))
        })?;

        // Parse account
        let account = Account::parse_from_text(account_name.to_string(), &data)?;

        // Cache it
        {
            let mut cache = self.cache.lock();
            cache.insert(account_name.to_string(), account.clone());
        }

        tracing::info!("Loaded account {} from file", account_name);
        Ok(account)
    }

    /// Save an account to file
    ///
    /// # Arguments
    /// * `account` - The account to save
    pub fn save_account(&self, account: &Account) -> Result<()> {
        let account_path = self.accounts_dir.join(format!("{}.txt", account.account_name));

        // Build file content
        let mut content = String::new();
        content.push_str(&format!("nickname={}\n", account.nickname));
        content.push_str(&format!("password={}\n", account.password_hash));
        content.push_str(&format!("x={}\n", account.x));
        content.push_str(&format!("y={}\n", account.y));
        content.push_str(&format!("level={}\n", account.level));
        content.push_str(&format!("admin={}\n", account.admin));

        for (key, value) in &account.extra {
            content.push_str(&format!("{}={}\n", key, value));
        }

        // Write file
        fs::write(&account_path, content).map_err(|e| {
            gserver_core::GServerError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to write account file: {}", e),
            ))
        })?;

        // Update cache
        {
            let mut cache = self.cache.lock();
            cache.insert(account.account_name.clone(), account.clone());
        }

        tracing::info!("Saved account {} to file", account.account_name);
        Ok(())
    }

    /// Check if an account exists
    ///
    /// # Arguments
    /// * `account_name` - The account name to check
    #[inline]
    pub fn account_exists(&self, account_name: &str) -> bool {
        let account_path = self.accounts_dir.join(format!("{}.txt", account_name));
        account_path.exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_creation() {
        let account = Account::new("testuser".to_string());
        assert_eq!(account.account_name, "testuser");
        assert_eq!(account.nickname, "testuser");
        assert_eq!(account.x, 30.0);
        assert_eq!(account.y, 30.0);
        assert_eq!(account.level, "onlinestartlocal.nw");
        assert_eq!(account.admin, 0);
    }

    #[test]
    fn test_account_properties() {
        let mut account = Account::new("testuser".to_string());
        account.set("custom".to_string(), "value".to_string());

        assert_eq!(account.get("custom"), Some(&"value".to_string()));
        assert_eq!(account.get("nonexistent"), None);
    }

    #[test]
    fn test_account_parse() {
        let data = r#"
nickname=TestPlayer
password=hash123
x=50.5
y=100.0
level=testlevel.nw
admin=1
customprop=value
"#;

        let account = Account::parse_from_text("testuser".to_string(), data).unwrap();

        assert_eq!(account.account_name, "testuser");
        assert_eq!(account.nickname, "TestPlayer");
        assert_eq!(account.password_hash, "hash123");
        assert_eq!(account.x, 50.5);
        assert_eq!(account.y, 100.0);
        assert_eq!(account.level, "testlevel.nw");
        assert_eq!(account.admin, 1);
        assert_eq!(account.get("customprop"), Some(&"value".to_string()));
    }

    #[test]
    fn test_account_parse_empty_lines() {
        let data = "nickname=Test\n\nx=50\n# Comment\ny=100";

        let account = Account::parse_from_text("test".to_string(), data).unwrap();

        assert_eq!(account.nickname, "Test");
        assert_eq!(account.x, 50.0);
        assert_eq!(account.y, 100.0);
    }

    #[test]
    fn test_account_manager_creation() {
        let dir = std::path::PathBuf::from("/tmp/test_accounts");
        let manager = AccountManager::new(dir);
        assert_eq!(manager.accounts_dir, std::path::PathBuf::from("/tmp/test_accounts"));
    }
}
