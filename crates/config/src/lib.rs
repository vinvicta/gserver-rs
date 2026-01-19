//! GServer Configuration Management
//!
//! Loads server configuration from all config files, just like the C++ version.

use std::collections::HashSet;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;

/// Complete server configuration from all config files
///
/// This mirrors the C++ server's configuration system exactly.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    // ========== From serveroptions.txt ==========
    // Network configuration
    /// Server name (from "name" option)
    pub name: String,
    /// Server description (from "description" option)
    pub description: String,
    /// Server URL (from "url" option)
    pub url: String,
    /// Server language (from "language" option)
    pub language: String,
    /// Server IP address (from "serverip" option)
    pub server_ip: String,
    /// Server port (from "serverport" option, default: 14802)
    pub server_port: u16,
    /// Server interface (from "serverinterface" option)
    pub server_interface: String,
    /// Local IP (from "localip" option)
    pub local_ip: String,
    /// UPnP enabled (from "upnp" option)
    pub upnp: bool,
    /// Maximum players (from "maxplayers" option)
    pub max_players: usize,
    /// List server IP (from "listip" option)
    pub list_ip: String,
    /// List server port (from "listport" option)
    pub list_port: u16,

    // Server type
    /// Only staff allowed (from "onlystaff" option)
    pub only_staff: bool,
    /// Server generation (from "generation" option)
    pub generation: ServerGeneration,
    /// Staff accounts (from "staff" option)
    pub staff_accounts: Vec<String>,
    /// Staff guilds (from "staffguilds" option)
    pub staff_guilds: Vec<String>,

    // Game settings
    /// Default weapons (from "defaultweapons" option)
    pub default_weapons: bool,
    /// Bush items (from "bushitems" option)
    pub bush_items: bool,
    /// Vases drop items (from "vasesdrop" option)
    pub vases_drop: bool,
    /// Baddy items (from "baddyitems" option)
    pub baddy_items: bool,
    /// No explosions (from "noexplosions" option)
    pub no_explosions: bool,
    /// Healing swords allowed (from "healswords" option)
    pub heal_swords: bool,

    // Limits
    /// Heart limit (from "heartlimit" option)
    pub heart_limit: u8,
    /// Sword limit (from "swordlimit" option)
    pub sword_limit: u8,
    /// Shield limit (from "shieldlimit" option)
    pub shield_limit: u8,

    // Script settings
    /// GS2 default (from "gs2default" option)
    pub gs2_default: bool,
    /// PutNPC enabled (from "putnpcenabled" option)
    pub putnpc_enabled: bool,
    /// Serverside (from "serverside" option)
    pub serverside: bool,
    /// Save levels (from "savelevels" option)
    pub save_levels: bool,

    // Path
    /// Server folder path
    pub server_folder: String,

    // ========== From adminconfig.txt ==========
    /// ServerHQ password (from "hq_password" option)
    pub hq_password: String,
    /// ServerHQ level (from "hq_level" option: 3=Gold, 2=Silver, 1=Bronze, 0=Hidden)
    pub hq_level: u8,
    /// NPC-Server IP (from "ns_ip" option)
    pub ns_ip: String,

    // ========== From allowedversions.txt ==========
    /// Allowed client versions per generation
    pub allowed_versions: AllowedVersions,

    // ========== From ipbans.txt ==========
    /// List of banned IP addresses
    pub ip_bans: HashSet<String>,

    // ========== From rules.txt ==========
    /// Word filter (banned words)
    pub word_filter: HashSet<String>,

    // ========== From servermessage.html ==========
    /// Server welcome message (HTML)
    pub server_message: String,

    // ========== From foldersconfig.txt ==========
    /// Folder configuration
    pub folder_config: FolderConfig,

    // ========== From serverflags.txt ==========
    /// Server flags (one per line)
    pub server_flags: Vec<String>,

    // ========== From defaultaccount.txt ==========
    /// Default account settings
    pub default_account: DefaultAccount,
}

/// Folder configuration from foldersconfig.txt
#[derive(Debug, Clone)]
pub struct FolderConfig {
    /// Folder entries (type, pattern)
    pub entries: Vec<(FolderType, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FolderType {
    Head,
    Body,
    Sword,
    Shield,
    File,
    Level,
}

/// Default account settings from defaultaccount.txt
#[derive(Debug, Clone)]
pub struct DefaultAccount {
    /// Account name
    pub name: String,
    /// Display nickname
    pub nickname: String,
    /// Starting level
    pub level: String,
    /// Starting X position
    pub x: f64,
    /// Starting Y position
    pub y: f64,
    /// Starting Z position
    pub z: f64,
    /// Max hearts
    pub max_hp: f64,
    /// Current hearts
    pub hp: f64,
    /// Gralats (rupees)
    pub rupees: u32,
    /// Default gani
    pub ani: String,
    /// Arrows count
    pub arrows: u32,
    /// Bombs count
    pub bombs: u32,
    /// Glove power
    pub glove_power: u8,
    /// Shield power
    pub shield_power: u8,
    /// Sword power
    pub sword_power: u8,
    /// Bow power
    pub bow_power: u8,
    /// Bow type
    pub bow: String,
    /// Head sprite
    pub head: String,
    /// Body sprite
    pub body: String,
    /// Sword sprite
    pub sword: String,
    /// Shield sprite
    pub shield: String,
    /// Colors
    pub colors: Vec<u8>,
    /// Sprite type
    pub sprite: u8,
    /// Status (player list icon)
    pub status: u8,
    /// Magic points
    pub mp: u32,
    /// Action points
    pub ap: u32,
    /// AP counter
    pub ap_counter: u32,
    /// Language
    pub language: String,
    /// Kills
    pub kills: u32,
    /// Deaths
    pub deaths: u32,
    /// Rating
    pub rating: f64,
    /// Deviation
    pub deviation: f64,
    /// Default weapons
    pub weapons: Vec<String>,
}

impl Default for FolderConfig {
    fn default() -> Self {
        Self {
            entries: vec![
                (FolderType::Head, "heads/*".into()),
                (FolderType::Body, "bodies/*.png".into()),
                (FolderType::Sword, "swords/*".into()),
                (FolderType::Shield, "shields/*".into()),
                (FolderType::File, "ganis/*.gani".into()),
                (FolderType::File, "hats/*.png".into()),
                (FolderType::File, "images/*.png".into()),
                (FolderType::File, "images/*.gif".into()),
                (FolderType::File, "images/*.mng".into()),
                (FolderType::File, "sounds/*.mid".into()),
                (FolderType::File, "sounds/*.mp3".into()),
                (FolderType::File, "sounds/*.wav".into()),
                (FolderType::File, "*.gani".into()),
                (FolderType::File, "*.gif".into()),
                (FolderType::File, "*.mng".into()),
                (FolderType::File, "*.png".into()),
                (FolderType::File, "*.mid".into()),
                (FolderType::File, "*.mp3".into()),
                (FolderType::File, "*.wav".into()),
                (FolderType::File, "*.txt".into()),
                (FolderType::File, "*.gmap".into()),
                (FolderType::Level, "*.graal".into()),
                (FolderType::Level, "*.nw".into()),
                (FolderType::Level, "*.gmap".into()),
                (FolderType::File, "levels/*.gmap".into()),
                (FolderType::Level, "levels/*.nw".into()),
                (FolderType::Level, "levels/*.graal".into()),
                (FolderType::Level, "levels/*.gmap".into()),
                (FolderType::File, "global/*".into()),
            ],
        }
    }
}

impl Default for DefaultAccount {
    fn default() -> Self {
        Self {
            name: "default".into(),
            nickname: "default".into(),
            level: "onlinestartlocal.nw".into(),
            x: 30.0,
            y: 30.5,
            z: 0.0,
            max_hp: 3.0,
            hp: 3.0,
            rupees: 0,
            ani: "idle".into(),
            arrows: 10,
            bombs: 5,
            glove_power: 1,
            shield_power: 1,
            sword_power: 1,
            bow_power: 1,
            bow: String::new(),
            head: "head0.png".into(),
            body: "body.png".into(),
            sword: "sword1.png".into(),
            shield: "shield1.png".into(),
            colors: vec![2, 0, 10, 4, 18],
            sprite: 2,
            status: 20,
            mp: 0,
            ap: 50,
            ap_counter: 60,
            language: "English".into(),
            kills: 0,
            deaths: 0,
            rating: 1500.0,
            deviation: 350.0,
            weapons: vec!["bomb".into(), "bow".into(), "-gr_movement".into()],
        }
    }
}

/// Allowed client versions for each generation
#[derive(Debug, Clone)]
pub struct AllowedVersions {
    /// Original generation (1.x)
    pub original: Option<String>,
    /// Classic generation (2.x/3.x)
    pub classic: Option<(String, String)>, // (min, max)
    /// NewMain generation (4.x to 5.007)
    pub newmain: Option<String>,
    /// Modern generation (5.1+)
    pub modern: Option<(String, String)>, // (min, max)
}

impl Default for AllowedVersions {
    fn default() -> Self {
        Self {
            original: Some("GNW13110".into()),
            classic: Some(("GNW03014".into(), "GNW28015".into())),
            newmain: Some("G3D22067".into()),
            modern: Some(("G3D14097".into(), "G3D0511C".into())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ServerGeneration {
    Original, // 1.x
    Classic,  // 2.x/3.x
    NewMain,  // 4.x to 5.007
    Modern,   // 5.1+
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            name: "My Server".into(),
            description: "My Server".into(),
            url: "http://www.graal.in/".into(),
            language: "English".into(),
            server_ip: "AUTO".into(),
            server_port: 14802, // C++ default!
            server_interface: "AUTO".into(),
            local_ip: "AUTO".into(),
            upnp: true,
            max_players: 128,
            list_ip: "listserver.graal.in".into(),
            list_port: 14900,
            only_staff: false,
            generation: ServerGeneration::Classic,
            staff_accounts: vec![],
            staff_guilds: vec![],
            default_weapons: true,
            bush_items: true,
            vases_drop: true,
            baddy_items: false,
            no_explosions: false,
            heal_swords: false,
            heart_limit: 3,
            sword_limit: 3,
            shield_limit: 3,
            gs2_default: false,
            putnpc_enabled: true,
            serverside: false,
            save_levels: false,
            server_folder: "servers/default".into(),

            // adminconfig.txt defaults
            hq_password: String::new(),
            hq_level: 1, // Bronze
            ns_ip: "AUTO".into(),

            // allowedversions.txt defaults
            allowed_versions: AllowedVersions::default(),

            // ipbans.txt defaults
            ip_bans: HashSet::new(),

            // rules.txt defaults
            word_filter: HashSet::new(),

            // servermessage.html defaults
            server_message: String::new(),

            // foldersconfig.txt defaults
            folder_config: FolderConfig::default(),

            // serverflags.txt defaults
            server_flags: vec![],

            // defaultaccount.txt defaults
            default_account: DefaultAccount::default(),
        }
    }
}

impl ServerConfig {
    /// Load configuration from serveroptions.txt
    ///
    /// This mimics the C++ server's config loading exactly.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config = Self::parse(&content)?;
        Ok(config)
    }

    /// Load configuration from default server path
    ///
    /// This loads ALL config files that the C++ server loads at startup,
    /// ensuring 1:1 parity with the original implementation.
    ///
    /// Directory structure:
    /// - ./gserver (executable)
    /// - ./servers/default/config/ (config files)
    /// - ./servers/default/serverflags.txt (server flags)
    /// - ./servers/default/accounts/ (account files)
    pub fn load_default() -> Result<Self, Box<dyn std::error::Error>> {
        let base_path = "servers/default";

        // Load serveroptions.txt (required)
        let mut config = Self::load_from_file(&format!("{}/config/serveroptions.txt", base_path))?;

        // Load adminconfig.txt (optional)
        if let Ok(content) = fs::read_to_string(&format!("{}/config/adminconfig.txt", base_path)) {
            config.parse_adminconfig(&content);
        }

        // Load allowedversions.txt (optional)
        if let Ok(content) = fs::read_to_string(&format!("{}/config/allowedversions.txt", base_path)) {
            config.parse_allowedversions(&content);
        }

        // Load ipbans.txt (optional)
        if let Ok(content) = fs::read_to_string(&format!("{}/config/ipbans.txt", base_path)) {
            config.parse_ipbans(&content);
        }

        // Load rules.txt (optional)
        if let Ok(content) = fs::read_to_string(&format!("{}/config/rules.txt", base_path)) {
            config.parse_wordfilter(&content);
        }

        // Load servermessage.html (optional)
        if let Ok(content) = fs::read_to_string(&format!("{}/config/servermessage.html", base_path)) {
            config.server_message = content;
        }

        // Load foldersconfig.txt (optional)
        if let Ok(content) = fs::read_to_string(&format!("{}/config/foldersconfig.txt", base_path)) {
            config.parse_foldersconfig(&content);
        }

        // Load serverflags.txt (NOTE: in root dir, NOT config/!)
        if let Ok(content) = fs::read_to_string(&format!("{}/serverflags.txt", base_path)) {
            config.parse_serverflags(&content);
        }

        // Load defaultaccount.txt (optional)
        if let Ok(content) = fs::read_to_string(&format!("{}/accounts/defaultaccount.txt", base_path)) {
            config.parse_defaultaccount(&content);
        }

        Ok(config)
    }

    /// Parse serveroptions.txt content
    fn parse(content: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config = Self::default();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse key=value
            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].trim();
                let value = line[eq_pos + 1..].trim();

                config.parse_option(key, value);
            }
        }

        Ok(config)
    }

    fn parse_option(&mut self, key: &str, value: &str) {
        match key {
            "name" => self.name = value.into(),
            "description" => self.description = value.into(),
            "url" => self.url = value.into(),
            "language" => self.language = value.into(),
            "serverip" => self.server_ip = value.into(),
            "serverport" => {
                self.server_port = value.parse().unwrap_or(14802);
            }
            "serverinterface" => self.server_interface = value.into(),
            "localip" => self.local_ip = value.into(),
            "upnp" => {
                self.upnp = value.parse().unwrap_or(true);
            }
            "maxplayers" => {
                self.max_players = value.parse().unwrap_or(128);
            }
            "listip" => self.list_ip = value.into(),
            "listport" => {
                self.list_port = value.parse().unwrap_or(14900);
            }
            "onlystaff" => {
                self.only_staff = value.parse().unwrap_or(false);
            }
            "generation" => {
                self.generation = match value.to_lowercase().as_str() {
                    "original" => ServerGeneration::Original,
                    "classic" => ServerGeneration::Classic,
                    "newmain" => ServerGeneration::NewMain,
                    "modern" => ServerGeneration::Modern,
                    _ => ServerGeneration::Classic,
                };
            }
            "staff" => {
                // Parse staff accounts: (Manager),account1,account2,...
                self.staff_accounts = value
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty() && !s.starts_with('(') && !s.ends_with(')'))
                    .collect();
            }
            "staffguilds" => {
                self.staff_guilds = value
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
            }
            "defaultweapons" => {
                self.default_weapons = value.parse().unwrap_or(true);
            }
            "bushitems" => {
                self.bush_items = value.parse().unwrap_or(true);
            }
            "vasesdrop" => {
                self.vases_drop = value.parse().unwrap_or(true);
            }
            "baddyitems" => {
                self.baddy_items = value.parse().unwrap_or(false);
            }
            "noexplosions" => {
                self.no_explosions = value.parse().unwrap_or(false);
            }
            "healswords" => {
                self.heal_swords = value.parse().unwrap_or(false);
            }
            "heartlimit" => {
                self.heart_limit = value.parse().unwrap_or(3);
            }
            "swordlimit" => {
                self.sword_limit = value.parse().unwrap_or(3);
            }
            "shieldlimit" => {
                self.shield_limit = value.parse().unwrap_or(3);
            }
            "gs2default" => {
                self.gs2_default = value.parse().unwrap_or(false);
            }
            "putnpcenabled" => {
                self.putnpc_enabled = value.parse().unwrap_or(true);
            }
            "serverside" => {
                self.serverside = value.parse().unwrap_or(false);
            }
            "savelevels" => {
                self.save_levels = value.parse().unwrap_or(false);
            }
            _ => {
                // tracing::debug!("Unknown config option: {} = {}", key, value);
            }
        }
    }

    /// Parse adminconfig.txt
    fn parse_adminconfig(&mut self, content: &str) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].trim();
                let value = line[eq_pos + 1..].trim();

                match key {
                    "hq_password" => self.hq_password = value.into(),
                    "hq_level" => self.hq_level = value.parse().unwrap_or(1),
                    "ns_ip" => self.ns_ip = value.into(),
                    _ => {}
                }
            }
        }
    }

    /// Parse allowedversions.txt
    fn parse_allowedversions(&mut self, content: &str) {
        let mut versions = AllowedVersions::default();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }

            // Parse: generation = version
            if let Some(eq_pos) = line.find('=') {
                let gen = line[..eq_pos].trim();
                let ver = line[eq_pos + 1..].trim();

                match gen {
                    "original" => versions.original = Some(ver.into()),
                    "newmain" => versions.newmain = Some(ver.into()),
                    "classic" => {
                        if let Some(colon_pos) = ver.find(':') {
                            let min = ver[..colon_pos].trim();
                            let max = ver[colon_pos + 1..].trim();
                            versions.classic = Some((min.into(), max.into()));
                        }
                    }
                    "modern" => {
                        if let Some(colon_pos) = ver.find(':') {
                            let min = ver[..colon_pos].trim();
                            let max = ver[colon_pos + 1..].trim();
                            versions.modern = Some((min.into(), max.into()));
                        }
                    }
                    _ => {}
                }
            }
        }

        self.allowed_versions = versions;
    }

    /// Parse ipbans.txt
    fn parse_ipbans(&mut self, content: &str) {
        self.ip_bans = content
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
            .map(|line| line.trim().to_string())
            .collect();
    }

    /// Parse rules.txt (word filter)
    fn parse_wordfilter(&mut self, content: &str) {
        self.word_filter = content
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
            .map(|line| line.trim().to_lowercase())
            .collect();
    }

    /// Parse foldersconfig.txt
    fn parse_foldersconfig(&mut self, content: &str) {
        let mut entries = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Format: type pattern
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let folder_type = match parts[0] {
                    "head" => FolderType::Head,
                    "body" => FolderType::Body,
                    "sword" => FolderType::Sword,
                    "shield" => FolderType::Shield,
                    "file" => FolderType::File,
                    "level" => FolderType::Level,
                    _ => continue,
                };
                entries.push((folder_type, parts[1].into()));
            }
        }

        if !entries.is_empty() {
            self.folder_config.entries = entries;
        }
    }

    /// Parse serverflags.txt (one flag per line)
    fn parse_serverflags(&mut self, content: &str) {
        self.server_flags = content
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
            .map(|line| line.trim().into())
            .collect();
    }

    /// Parse defaultaccount.txt
    fn parse_defaultaccount(&mut self, content: &str) {
        let mut account = self.default_account.clone();
        let mut weapons = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Skip the GRACC001 line (account type)
            if line.starts_with("GRACC") {
                continue;
            }

            // Parse: KEY value
            if let Some(space_pos) = line.find(' ') {
                let key = line[..space_pos].trim();
                let value = line[space_pos + 1..].trim();

                match key {
                    "NAME" => account.name = value.into(),
                    "NICK" => account.nickname = value.into(),
                    "LEVEL" => account.level = value.into(),
                    "X" => account.x = value.parse().unwrap_or(30.0),
                    "Y" => account.y = value.parse().unwrap_or(30.5),
                    "Z" => account.z = value.parse().unwrap_or(0.0),
                    "MAXHP" => account.max_hp = value.parse().unwrap_or(3.0),
                    "HP" => account.hp = value.parse().unwrap_or(3.0),
                    "RUPEES" => account.rupees = value.parse().unwrap_or(0),
                    "ANI" => account.ani = value.into(),
                    "ARROWS" => account.arrows = value.parse().unwrap_or(10),
                    "BOMBS" => account.bombs = value.parse().unwrap_or(5),
                    "GLOVEP" => account.glove_power = value.parse().unwrap_or(1),
                    "SHIELDP" => account.shield_power = value.parse().unwrap_or(1),
                    "SWORDP" => account.sword_power = value.parse().unwrap_or(1),
                    "BOWP" => account.bow_power = value.parse().unwrap_or(1),
                    "BOW" => account.bow = value.into(),
                    "HEAD" => account.head = value.into(),
                    "BODY" => account.body = value.into(),
                    "SWORD" => account.sword = value.into(),
                    "SHIELD" => account.shield = value.into(),
                    "COLORS" => {
                        account.colors = value
                            .split(',')
                            .filter_map(|s| s.trim().parse().ok())
                            .collect();
                    }
                    "SPRITE" => account.sprite = value.parse().unwrap_or(2),
                    "STATUS" => account.status = value.parse().unwrap_or(20),
                    "MP" => account.mp = value.parse().unwrap_or(0),
                    "AP" => account.ap = value.parse().unwrap_or(50),
                    "APCOUNTER" => account.ap_counter = value.parse().unwrap_or(60),
                    "LANGUAGE" => account.language = value.into(),
                    "KILLS" => account.kills = value.parse().unwrap_or(0),
                    "DEATHS" => account.deaths = value.parse().unwrap_or(0),
                    "RATING" => account.rating = value.parse().unwrap_or(1500.0),
                    "DEVIATION" => account.deviation = value.parse().unwrap_or(350.0),
                    "WEAPON" => weapons.push(value.into()),
                    _ => {}
                }
            }
        }

        account.weapons = weapons;
        self.default_account = account;
    }

    /// Get the bind address for the TCP listener
    pub fn bind_address(&self) -> SocketAddr {
        let ip = if self.server_interface == "AUTO" {
            "0.0.0.0"
        } else {
            &self.server_interface
        };

        format!("{}:{}", ip, self.server_port)
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:14802".parse().unwrap())
    }

    /// Display configuration summary
    pub fn display(&self) {
        tracing::info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        tracing::info!("📋 Server Configuration (1:1 C++ Parity):");
        tracing::info!("");
        tracing::info!("  [config/serveroptions.txt]");
        tracing::info!("    Name: {}", self.name);
        tracing::info!("    Description: {}", self.description);
        tracing::info!("    URL: {}", self.url);
        tracing::info!("    Bind: {} (port {})", self.bind_address(), self.server_port);
        tracing::info!("    Max Players: {}", self.max_players);
        tracing::info!("    Generation: {:?}", self.generation);
        tracing::info!("    Staff Accounts: {}", self.staff_accounts.len());
        tracing::info!("    Only Staff: {}", self.only_staff);
        tracing::info!("    Default Weapons: {}", self.default_weapons);
        tracing::info!("");
        tracing::info!("  [config/adminconfig.txt]");
        tracing::info!("    HQ Level: {} (0=Hidden, 1=Bronze, 2=Silver, 3=Gold)", self.hq_level);
        tracing::info!("    NS IP: {}", self.ns_ip);
        tracing::info!("");
        tracing::info!("  [config/allowedversions.txt]");
        if let Some(ref ver) = self.allowed_versions.original {
            tracing::info!("    Original: {}", ver);
        }
        if let Some((ref min, ref max)) = self.allowed_versions.classic {
            tracing::info!("    Classic: {} - {}", min, max);
        }
        if let Some(ref ver) = self.allowed_versions.newmain {
            tracing::info!("    NewMain: {}", ver);
        }
        if let Some((ref min, ref max)) = self.allowed_versions.modern {
            tracing::info!("    Modern: {} - {}", min, max);
        }
        tracing::info!("");
        tracing::info!("  [config/ipbans.txt]");
        tracing::info!("    Banned IPs: {}", self.ip_bans.len());
        tracing::info!("");
        tracing::info!("  [config/rules.txt]");
        tracing::info!("    Filtered words: {}", self.word_filter.len());
        tracing::info!("");
        tracing::info!("  [config/servermessage.html]");
        if self.server_message.is_empty() {
            tracing::info!("    (empty - using default)");
        } else {
            tracing::info!("    {} bytes", self.server_message.len());
        }
        tracing::info!("");
        tracing::info!("  [config/foldersconfig.txt]");
        tracing::info!("    Folder entries: {}", self.folder_config.entries.len());
        tracing::info!("");
        tracing::info!("  [serverflags.txt]");
        tracing::info!("    Server flags: {}", self.server_flags.len());
        tracing::info!("");
        tracing::info!("  [accounts/defaultaccount.txt]");
        tracing::info!("    Account: {}", self.default_account.name);
        tracing::info!("    Nick: {}", self.default_account.nickname);
        tracing::info!("    Start: {} @ ({}, {})", self.default_account.level, self.default_account.x, self.default_account.y);
        tracing::info!("    HP: {}/{}", self.default_account.hp, self.default_account.max_hp);
        tracing::info!("    Weapons: {}", self.default_account.weapons.len());
        tracing::info!("");
        tracing::info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.server_port, 14802);
        assert_eq!(config.name, "My Server");
        assert_eq!(config.max_players, 128);
    }

    #[test]
    fn test_parse_simple_config() {
        let config_text = r#"
name = Test Server
serverport = 9999
maxplayers = 50
"#;
        let config = ServerConfig::parse(config_text).unwrap();
        assert_eq!(config.name, "Test Server");
        assert_eq!(config.server_port, 9999);
        assert_eq!(config.max_players, 50);
    }
}
