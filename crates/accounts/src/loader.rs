//! Account file loading

use super::{account::Account, error::{AccountError, Result}};
use std::path::{Path, PathBuf};
use std::fs;
use tracing::{debug, warn};

/// Account file loader
///
/// # Purpose
/// Loads and parses player account files from disk.
///
/// # File Format
/// Accounts are stored as text files in `accounts/ACCOUNTNAME.txt`:
/// ```text
/// GRACC001
/// NAME PlayerName
/// NICK PlayerNickname
/// LEVEL onlinestartlocal.nw
/// X 30.0
/// Y 30.5
/// ... (more fields)
/// ```
pub struct AccountLoader {
    /// Base directory for accounts
    accounts_dir: PathBuf,
}

impl AccountLoader {
    /// Create a new account loader
    ///
    /// # Arguments
    /// * `server_dir` - Server directory (contains `accounts/` subdirectory)
    pub fn new(server_dir: &Path) -> Self {
        Self {
            accounts_dir: server_dir.join("accounts"),
        }
    }

    /// Load an account by name
    ///
    /// # Arguments
    /// * `account_name` - Account name (case-insensitive, will be searched for)
    ///
    /// # Returns
    /// The loaded account, or a default account if not found
    ///
    /// # Behavior
    /// 1. Searches for `accounts/ACCOUNTNAME.txt` (case-insensitive)
    /// 2. If not found, uses `accounts/defaultaccount.txt`
    /// 3. Parses the account file
    /// 4. Returns the account data
    pub fn load(&self, account_name: &str) -> Result<Account> {
        debug!("Loading account: {}", account_name);

        // Try to find account file (case-insensitive)
        let account_path = self.find_account_file(account_name)?;

        // Load and parse the file
        let account = self.parse_account_file(&account_path)?;

        debug!("Loaded account: {} from {:?}", account.name, account_path);
        Ok(account)
    }

    /// Find account file (case-insensitive search)
    fn find_account_file(&self, account_name: &str) -> Result<PathBuf> {
        // First, try exact match
        let exact_path = self.accounts_dir.join(format!("{}.txt", account_name));
        if exact_path.exists() {
            return Ok(exact_path);
        }

        // Case-insensitive search
        if let Ok(entries) = fs::read_dir(&self.accounts_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("txt") {
                    let filename = path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("");

                    if filename.eq_ignore_ascii_case(account_name) {
                        return Ok(path);
                    }
                }
            }
        }

        // Fall back to default account
        let default_path = self.accounts_dir.join("defaultaccount.txt");
        if default_path.exists() {
            debug!("Account '{}' not found, using default account", account_name);
            return Ok(default_path);
        }

        Err(AccountError::NotFound(account_name.to_string()))
    }

    /// Parse account file
    fn parse_account_file(&self, path: &Path) -> Result<Account> {
        let content = fs::read_to_string(path)?;

        // Check magic header
        let first_line = content.lines().next()
            .ok_or_else(|| AccountError::InvalidFormat("Empty file".to_string()))?;

        if first_line.trim() != "GRACC001" {
            return Err(AccountError::InvalidFormat(
                format!("Invalid magic header: {}", first_line)
            ));
        }

        let mut account = Account::default();
        account.name = path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Parse each line
        for line in content.lines().skip(1) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Split on first space
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            if parts.len() != 2 {
                continue;
            }

            let key = parts[0].trim();
            let value = parts[1].trim();

            self.parse_account_field(&mut account, key, value);
        }

        // Set nick from name if not present
        if account.nick.is_empty() {
            account.nick = account.name.clone();
        }

        Ok(account)
    }

    /// Parse a single account field
    fn parse_account_field(&self, account: &mut Account, key: &str, value: &str) {
        match key {
            "NAME" => account.name = value.to_string(),
            "NICK" => account.nick = value.to_string(),
            "COMMUNITYNAME" => account.community_name = value.to_string(),
            "LEVEL" => account.level = value.to_string(),
            "X" => account.x = value.parse().unwrap_or(account.x),
            "Y" => account.y = value.parse().unwrap_or(account.y),
            "Z" => account.z = value.parse().unwrap_or(account.z),
            "MAXHP" => account.max_hp = value.parse().unwrap_or(account.max_hp),
            "HP" => account.hp = value.parse().unwrap_or(account.hp),
            "ANI" => account.ani = value.to_string(),
            "SPRITE" => account.sprite = value.parse().unwrap_or(account.sprite),
            "GRALATS" => account.gralats = value.parse().unwrap_or(account.gralats),
            "ARROWS" => account.arrows = value.parse().unwrap_or(account.arrows),
            "BOMBS" => account.bombs = value.parse().unwrap_or(account.bombs),
            "GLOVEP" => account.glove_power = value.parse().unwrap_or(account.glove_power),
            "SWORDP" => account.sword_power = value.parse().unwrap_or(account.sword_power),
            "SHIELDP" => account.shield_power = value.parse().unwrap_or(account.shield_power),
            "BOMBP" => account.bomb_power = value.parse().unwrap_or(account.bomb_power),
            "BOWP" => account.bow_power = value.parse().unwrap_or(account.bow_power),
            "BOW" => account.bow = value.to_string(),
            "HEAD" => account.head = value.to_string(),
            "BODY" => account.body = value.to_string(),
            "SWORD" => account.sword = value.to_string(),
            "SHIELD" => account.shield = value.to_string(),
            "COLORS" => account.colors = value.to_string(),
            "STATUS" => account.status = value.parse().unwrap_or(account.status),
            "MP" => account.mp = value.parse().unwrap_or(account.mp),
            "AP" => account.ap = value.parse().unwrap_or(account.ap),
            "APCOUNTER" => account.ap_counter = value.parse().unwrap_or(account.ap_counter),
            "ONSECS" => account.onsecs = value.parse().unwrap_or(account.onsecs),
            "IP" => account.ip = value.to_string(),
            "LANGUAGE" => account.language = value.to_string(),
            "KILLS" => account.kills = value.parse().unwrap_or(account.kills),
            "DEATHS" => account.deaths = value.parse().unwrap_or(account.deaths),
            "RATING" => account.rating = value.parse().unwrap_or(account.rating),
            "DEVIATION" => account.deviation = value.parse().unwrap_or(account.deviation),
            "LASTSPARTIME" => account.last_spar_time = value.parse().unwrap_or(account.last_spar_time),
            "BANNED" => account.banned = value.parse().unwrap_or(account.banned),
            "BANREASON" => account.ban_reason = value.to_string(),
            "BANLENGTH" => account.ban_length = value.to_string(),
            "COMMENTS" => account.comments = value.to_string(),
            "EMAIL" => account.email = value.to_string(),
            "LOCALRIGHTS" => account.local_rights = value.parse().unwrap_or(account.local_rights),
            "IPRANGE" => account.ip_range = value.to_string(),
            "LOADONLY" => account.load_only = value.parse().unwrap_or(account.load_only),
            "WEAPON" => {
                // Weapons can appear multiple times, collect them all
                account.add_weapon(value.to_string());
            }
            "FOLDERRIGHT" => {
                // Folder rights can appear multiple times, collect them all
                // Format: "rw accounts/*" or "r weapons/*"
                account.folder_rights.push(value.to_string());
            }
            "LASTFOLDER" => {
                account.last_folder = value.to_string();
            }
            _ => {
                // Store unknown fields in extra map
                account.extra.insert(key.to_string(), value.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;

    #[test]
    fn test_parse_default_account() {
        let temp_dir = tempfile::tempdir().unwrap();
        let accounts_dir = temp_dir.path().join("accounts");
        fs::create_dir_all(&accounts_dir).unwrap();

        // Create a test account file
        let account_path = accounts_dir.join("testplayer.txt");
        let account_content = r#"GRACC001
NAME TestPlayer
NICK Test
LEVEL onlinestartlocal.nw
X 30.0
Y 30.5
MAXHP 3
HP 6.0
LOCALRIGHTS 65535
"#;
        File::create(&account_path).unwrap()
            .write_all(account_content.as_bytes()).unwrap();

        // Load the account
        let loader = AccountLoader::new(temp_dir.path());
        let account = loader.load("testplayer").unwrap();

        assert_eq!(account.name, "TestPlayer");
        assert_eq!(account.nick, "Test");
        assert_eq!(account.level, "onlinestartlocal.nw");
        assert_eq!(account.x, 30.0);
        assert_eq!(account.y, 30.5);
        assert_eq!(account.max_hp, 3.0);
        assert_eq!(account.hp, 6.0);
        assert_eq!(account.local_rights, 65535);
        assert!(account.is_staff());
        assert!(account.has_permission(PLPERM_WARPTO));
    }

    #[test]
    fn test_default_account_fallback() {
        let temp_dir = tempfile::tempdir().unwrap();
        let accounts_dir = temp_dir.path().join("accounts");
        fs::create_dir_all(&accounts_dir).unwrap();

        // Create default account
        let default_path = accounts_dir.join("defaultaccount.txt");
        let default_content = r#"GRACC001
NAME DefaultPlayer
NICK Default
LOCALRIGHTS 0
"#;
        File::create(&default_path).unwrap()
            .write_all(default_content.as_bytes()).unwrap();

        // Try to load non-existent account
        let loader = AccountLoader::new(temp_dir.path());
        let account = loader.load("nonexistent").unwrap();

        assert_eq!(account.nick, "Default");
        assert!(!account.is_staff());
    }
}
