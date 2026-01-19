//! GS1 Scripting Engine
//!
//! # Purpose
//! Implements the Graal Online GS1 scripting language for NPCs, weapons, and level scripts.
//!
//! # C++ Equivalence
//! Matches `TScript` and `GS1Commands` from:
//! - ScriptFormats/Script.h
//! - ScriptFormats/TScript.cpp
//! - ScriptFormats/GS1Commands.cpp
//!
//! # Script Format
//!
//! GS1 scripts are text-based with one command per line:
//! ```text
//! //#name
//! if (playerchars) {
//!   message Hello!;
//! }
//! ```
//!
//! # Variables
//!
//! - `this.*` - NPC/weapon instance variables
//! - `player.*` - Player who triggered the script
//! - `server.*` - Server global variables
//! - `client.*` - Client variables (sent to client)
//! - `clientr.*` - Client variables (not sent)
//! - `triggerplayer.*` - Player who triggered action
//!
//! # Triggers
//!
//! - `onCreated()` - When NPC/weapon is created
//! - `onAction[...]()` - Player action (click, touch, etc.)
//! - `onPlayerEnters()` - Player enters level
//! - `onPlayerLeaves()` - Player leaves level
//! - `onPlayerChats()` - Player sends message

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::Mutex;

/// GS1 variable prefix types
///
/// # C++ Equivalence
/// Matches variable prefix handling in TScript.cpp
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VarPrefix {
    /// NPC/Weapon instance variables
    This,

    /// Player who triggered the script
    Player,

    /// Server global variables
    Server,

    /// Client variables (sent to client)
    Client,

    /// Client variables (not sent to client)
    ClientR,

    /// Player who triggered action (for onAction scripts)
    TriggerPlayer,
}

impl VarPrefix {
    /// Parse variable prefix from string
    ///
    /// # Examples
    /// ```rust
    /// assert_eq!(VarPrefix::from_str("player.x"), Some(VarPrefix::Player));
    /// assert_eq!(VarPrefix::from_str("this.name"), Some(VarPrefix::This));
    /// assert_eq!(VarPrefix::from_str("unknown.x"), None);
    /// ```
    pub fn from_str(s: &str) -> Option<Self> {
        let prefix = s.split('.').next()?;
        match prefix {
            "this" => Some(VarPrefix::This),
            "player" => Some(VarPrefix::Player),
            "server" => Some(VarPrefix::Server),
            "client" => Some(VarPrefix::Client),
            "clientr" => Some(VarPrefix::ClientR),
            "triggerplayer" => Some(VarPrefix::TriggerPlayer),
            _ => None,
        }
    }

    /// Get the prefix string
    pub fn as_str(&self) -> &'static str {
        match self {
            VarPrefix::This => "this",
            VarPrefix::Player => "player",
            VarPrefix::Server => "server",
            VarPrefix::Client => "client",
            VarPrefix::ClientR => "clientr",
            VarPrefix::TriggerPlayer => "triggerplayer",
        }
    }
}

/// A GS1 script variable value
///
/// # C++ Equivalence
/// Matches variable storage in GameVariableStore
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptValue {
    String(String),
    Number(f64),
    Boolean(bool),
    Null,
}

impl ScriptValue {
    /// Create from string (auto-detect type)
    pub fn from_string(s: &str) -> Self {
        if s.is_empty() {
            return ScriptValue::Null;
        }

        // Try boolean
        match s.to_lowercase().as_str() {
            "true" | "1" => return ScriptValue::Boolean(true),
            "false" | "0" => return ScriptValue::Boolean(false),
            _ => {}
        }

        // Try number
        if let Ok(n) = s.parse::<f64>() {
            return ScriptValue::Number(n);
        }

        // Default to string
        ScriptValue::String(s.to_string())
    }

    /// Convert to string representation
    pub fn to_string(&self) -> String {
        match self {
            ScriptValue::String(s) => s.clone(),
            ScriptValue::Number(n) => n.to_string(),
            ScriptValue::Boolean(b) => if *b { "1" } else { "0" }.to_string(),
            ScriptValue::Null => String::new(),
        }
    }

    /// Get as number
    pub fn as_number(&self) -> f64 {
        match self {
            ScriptValue::Number(n) => *n,
            ScriptValue::String(s) => s.parse().unwrap_or(0.0),
            ScriptValue::Boolean(b) => if *b { 1.0 } else { 0.0 },
            ScriptValue::Null => 0.0,
        }
    }

    /// Get as boolean
    pub fn as_bool(&self) -> bool {
        match self {
            ScriptValue::Boolean(b) => *b,
            ScriptValue::String(s) => !s.is_empty() && s != "0",
            ScriptValue::Number(n) => *n != 0.0,
            ScriptValue::Null => false,
        }
    }

    /// Check if value is "true" for GS1 conditional purposes
    ///
    /// # C++ Equivalence
    /// Matches truthiness check in TScript::ifCondition()
    pub fn is_true(&self) -> bool {
        match self {
            ScriptValue::String(s) => !s.is_empty(),
            ScriptValue::Number(n) => *n != 0.0,
            ScriptValue::Boolean(b) => *b,
            ScriptValue::Null => false,
        }
    }
}

impl From<String> for ScriptValue {
    fn from(s: String) -> Self {
        ScriptValue::String(s)
    }
}

impl From<f64> for ScriptValue {
    fn from(n: f64) -> Self {
        ScriptValue::Number(n)
    }
}

impl From<bool> for ScriptValue {
    fn from(b: bool) -> Self {
        ScriptValue::Boolean(b)
    }
}

impl Default for ScriptValue {
    fn default() -> Self {
        ScriptValue::Null
    }
}

/// Script variable store
///
/// # Purpose
/// Stores script variables with their prefixes
///
/// # C++ Equivalence
/// Matches `GameVariableStore` in ScriptContainers.h
#[derive(Debug, Clone, Default)]
pub struct ScriptVars {
    /// Storage for all variables (prefix.name -> value)
    vars: HashMap<String, ScriptValue>,
}

impl ScriptVars {
    /// Create a new variable store
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a variable value
    ///
    /// # Arguments
    /// * `key` - Variable key (e.g., "player.x", "this.name")
    pub fn get(&self, key: &str) -> Option<&ScriptValue> {
        self.vars.get(key)
    }

    /// Set a variable value
    pub fn set(&mut self, key: String, value: ScriptValue) {
        self.vars.insert(key, value);
    }

    /// Remove a variable
    pub fn remove(&mut self, key: &str) -> bool {
        self.vars.remove(key).is_some()
    }

    /// Check if a variable exists
    pub fn contains(&self, key: &str) -> bool {
        self.vars.contains_key(key)
    }

    /// Get all variables with a prefix
    pub fn get_prefix(&self, prefix: &str) -> Vec<(String, ScriptValue)> {
        self.vars.iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Clear all variables
    pub fn clear(&mut self) {
        self.vars.clear();
    }
}

/// GS1 Script command
///
/// # Purpose
/// Represents a single script command with its arguments
///
/// # C++ Equivalence
/// Matches command parsing in TScript::runCode()
#[derive(Debug, Clone, PartialEq)]
pub struct ScriptCommand {
    /// Command name (e.g., "message", "warpto")
    pub name: String,

    /// Raw arguments string
    pub args: String,

    /// Parsed arguments (split by spaces, respecting quotes)
    pub parsed_args: Vec<String>,
}

impl ScriptCommand {
    /// Parse a command from a line
    ///
    /// # Examples
    /// ```rust
    /// let cmd = ScriptCommand::parse("message Hello, world!");
    /// assert_eq!(cmd.name, "message");
    /// assert_eq!(cmd.args, "Hello, world!");
    /// ```
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            return None;
        }

        // Split command name and arguments
        let space_pos = line.find(' ')?;
        let name = line[..space_pos].to_lowercase();
        let args = if line.len() > space_pos + 1 {
            line[space_pos + 1..].to_string()
        } else {
            String::new()
        };

        // Parse arguments (respect quotes)
        let parsed_args = Self::parse_args(&args);

        Some(ScriptCommand {
            name,
            args,
            parsed_args,
        })
    }

    /// Parse arguments respecting quoted strings
    fn parse_args(args: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut escape_next = false;

        for ch in args.chars() {
            if escape_next {
                current.push(ch);
                escape_next = false;
                continue;
            }

            match ch {
                '\\' => {
                    escape_next = true;
                    current.push(ch);
                }
                '"' => {
                    in_quotes = !in_quotes;
                    current.push(ch);
                }
                ' ' | '\t' if !in_quotes => {
                    if !current.is_empty() {
                        result.push(current.clone());
                        current.clear();
                    }
                }
                _ => {
                    current.push(ch);
                }
            }
        }

        if !current.is_empty() {
            result.push(current);
        }

        // Remove quotes from arguments
        result.into_iter()
            .map(|s| {
                if s.starts_with('"') && s.ends_with('"') && s.len() > 1 {
                    s[1..s.len()-1].to_string()
                } else {
                    s
                }
            })
            .collect()
    }

    /// Get argument at index (or default if not found)
    pub fn get_arg(&self, index: usize) -> Option<&str> {
        self.parsed_args.get(index).map(|s| s.as_str())
    }

    /// Get argument at index or return default
    pub fn get_arg_or(&self, index: usize, default: &str) -> String {
        self.get_arg(index)
            .unwrap_or(default)
            .to_string()
    }
}

/// GS1 Script trigger types
///
/// # C++ Equivalence
/// Matches trigger types in TScript.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptTrigger {
    /// NPC/Weapon created
    Created,

    /// Player action (click, touch, etc.)
    Action,

    /// Player enters level
    PlayerEnters,

    /// Player leaves level
    PlayerLeaves,

    /// Player chats
    PlayerChats,

    /// Player joined (server-wide)
    PlayerJoins,

    /// Player detached (left server)
    PlayerDetaches,

    /// Timeout occurred
    Timeout,

    /// Initial check (before created)
    InitialCheck,
}

impl ScriptTrigger {
    /// Parse trigger from script name
    ///
    /// # Examples
    /// ```rust
    /// assert_eq!(ScriptTrigger::from_name("onCreated"), Some(ScriptTrigger::Created));
    /// assert_eq!(ScriptTrigger::from_name("onActionTest"), Some(ScriptTrigger::Action));
    /// ```
    pub fn from_name(name: &str) -> Option<Self> {
        if name == "onCreated" {
            Some(ScriptTrigger::Created)
        } else if name.starts_with("onAction") {
            Some(ScriptTrigger::Action)
        } else if name == "onPlayerEnters" {
            Some(ScriptTrigger::PlayerEnters)
        } else if name == "onPlayerLeaves" {
            Some(ScriptTrigger::PlayerLeaves)
        } else if name == "onPlayerChats" {
            Some(ScriptTrigger::PlayerChats)
        } else if name == "onPlayerJoins" {
            Some(ScriptTrigger::PlayerJoins)
        } else if name == "onPlayerDetaches" {
            Some(ScriptTrigger::PlayerDetaches)
        } else if name == "onTimeout" {
            Some(ScriptTrigger::Timeout)
        } else if name == "onInitialCheck" {
            Some(ScriptTrigger::InitialCheck)
        } else {
            None
        }
    }
}

/// A compiled GS1 script
///
/// # Purpose
/// Stores a parsed GS1 script with all its triggers
///
/// # C++ Equivalence
/// Matches `TScript` class in ScriptFormats/Script.h
#[derive(Debug, Clone)]
pub struct Script {
    /// Script name (e.g., from //#name comment)
    pub name: String,

    /// Script triggers (trigger_type -> commands)
    pub triggers: HashMap<ScriptTrigger, Vec<ScriptCommand>>,

    /// Action code (for onAction[...] triggers)
    pub action_codes: Vec<String>,

    /// Script variables (this.* prefix)
    pub vars: ScriptVars,
}

impl Script {
    /// Create a new empty script
    pub fn new() -> Self {
        Self {
            name: String::new(),
            triggers: HashMap::new(),
            action_codes: Vec::new(),
            vars: ScriptVars::new(),
        }
    }

    /// Parse a GS1 script from text
    ///
    /// # Arguments
    /// * `text` - Script text
    ///
    /// # Examples
    /// ```rust
    /// let script = Script::parse(r#"
    ///     //#name MyScript
    ///     if (created) {
    ///       message Hello!;
    ///     }
    /// "#);
    /// ```
    pub fn parse(text: &str) -> Self {
        let mut script = Self::new();
        let mut current_trigger: Option<ScriptTrigger> = None;
        let mut current_commands: Vec<ScriptCommand> = Vec::new();
        let mut in_if_block = false;

        for line in text.lines() {
            let line = line.trim();

            // Skip empty lines and comments (except //#name)
            if line.is_empty() || (line.starts_with("//") && !line.starts_with("//#")) {
                continue;
            }

            // Parse //#name
            if line.starts_with("//#name") {
                script.name = line[7..].trim().to_string();
                continue;
            }

            // Parse trigger blocks
            if line.starts_with("if (") {
                // Extract condition between "if (" and ")" (and handle trailing "{")
                // Format: "if (created) {" or "if (created)" -> "created"
                let rest = line[4..].trim(); // Remove "if "
                let rest = rest.strip_prefix('(').unwrap_or(rest);
                // Find the closing ')'
                let end_paren = rest.find(')').unwrap_or(rest.len());
                let mut condition = rest[..end_paren].trim();

                // Also remove trailing '{' if present
                if let Some(pos) = condition.find('{') {
                    condition = &condition[..pos];
                }
                let condition = condition.trim();

                // Map old-style conditions to triggers
                current_trigger = if condition == "created" {
                    Some(ScriptTrigger::Created)
                } else if condition.starts_with("playersays") {
                    Some(ScriptTrigger::PlayerChats)
                } else if condition.starts_with("playerenters") {
                    Some(ScriptTrigger::PlayerEnters)
                } else if condition.starts_with("playerleaves") {
                    Some(ScriptTrigger::PlayerLeaves)
                } else if condition.starts_with("action") {
                    // Extract action code: action[...] or action2[...]
                    if let Some(start) = condition.find('[') {
                        if let Some(end) = condition.find(']') {
                            let code = condition[start + 1..end].to_string();
                            script.action_codes.push(code);
                        }
                    }
                    Some(ScriptTrigger::Action)
                } else {
                    // Unknown condition, treat as general if
                    current_trigger
                };

                in_if_block = true;
                continue;
            }

            // End of if block
            if line == "}" {
                if let Some(trigger) = current_trigger {
                    if !current_commands.is_empty() {
                        script.triggers.insert(trigger, current_commands.clone());
                    } else {
                        // Still insert empty trigger for scripts with no commands
                        script.triggers.insert(trigger, Vec::new());
                    }
                }
                current_commands.clear();
                in_if_block = false;
                current_trigger = None;
                continue;
            }

            // Parse command
            if in_if_block {
                if let Some(cmd) = ScriptCommand::parse(line) {
                    current_commands.push(cmd);
                }
            }
        }

        script
    }

    /// Get commands for a trigger
    pub fn get_commands(&self, trigger: ScriptTrigger) -> Option<&[ScriptCommand]> {
        self.triggers.get(&trigger).map(|v| v.as_slice())
    }

    /// Check if script has a trigger
    pub fn has_trigger(&self, trigger: ScriptTrigger) -> bool {
        self.triggers.contains_key(&trigger)
    }
}

impl Default for Script {
    fn default() -> Self {
        Self::new()
    }
}

/// GS1 Script execution context
///
/// # Purpose
/// Provides context for executing GS1 scripts
///
/// # C++ Equivalence
/// Matches script execution context in TScript::runCode()
pub struct ScriptContext {
    /// Script being executed
    pub script: Script,

    /// Player variables (player.*, triggerplayer.*)
    pub player_vars: Arc<Mutex<ScriptVars>>,

    /// Server variables (server.*)
    pub server_vars: Arc<Mutex<ScriptVars>>,

    /// Client variables (client.*, clientr.*)
    pub client_vars: Arc<Mutex<ScriptVars>>,

    /// Current NPC/Weapon id
    pub entity_id: Option<String>,

    /// Current level name
    pub level_name: String,

    /// Output messages (for testing/debugging)
    pub messages: Arc<Mutex<Vec<String>>>,
}

impl ScriptContext {
    /// Create a new script context
    pub fn new(script: Script) -> Self {
        Self {
            script,
            player_vars: Arc::new(Mutex::new(ScriptVars::new())),
            server_vars: Arc::new(Mutex::new(ScriptVars::new())),
            client_vars: Arc::new(Mutex::new(ScriptVars::new())),
            entity_id: None,
            level_name: String::new(),
            messages: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Execute a trigger's commands
    pub fn execute_trigger(&mut self, trigger: ScriptTrigger) -> Result<(), String> {
        let commands: Vec<ScriptCommand> = self.script.get_commands(trigger)
            .map(|cmds| cmds.to_vec())
            .unwrap_or_default();
        for cmd in commands {
            self.execute_command(&cmd)?;
        }
        Ok(())
    }

    /// Execute a single command
    fn execute_command(&mut self, cmd: &ScriptCommand) -> Result<(), String> {
        match cmd.name.as_str() {
            "message" => self.cmd_message(cmd),
            "say" => self.cmd_say(cmd),
            "say2" => self.cmd_say2(cmd),
            "set" | "setstring" => self.cmd_set(cmd),
            "unset" => self.cmd_unset(cmd),
            "hide" => self.cmd_hide(cmd),
            "show" => self.cmd_show(cmd),
            "destroy" => self.cmd_destroy(cmd),
            "warpto" => self.cmd_warpto(cmd),
            "serverwarp" => self.cmd_serverwarp(cmd),
            "move" => self.cmd_move(cmd),
            _ => {
                // Log unknown command but don't fail
                tracing::debug!("Unknown GS1 command: {} with args: {}", cmd.name, cmd.args);
                Ok(())
            }
        }
    }

    /// message command - Display a message to the player
    fn cmd_message(&mut self, cmd: &ScriptCommand) -> Result<(), String> {
        let msg = cmd.args.clone();
        self.messages.lock().push(msg.clone());
        tracing::debug!("GS1: message {}", msg);
        Ok(())
    }

    /// say command - Make the NPC say something
    fn cmd_say(&mut self, cmd: &ScriptCommand) -> Result<(), String> {
        let msg = cmd.args.clone();
        self.messages.lock().push(format!("say: {}", msg));
        tracing::debug!("GS1: say {}", msg);
        Ok(())
    }

    /// say2 command - Make NPC say with timeout
    fn cmd_say2(&mut self, cmd: &ScriptCommand) -> Result<(), String> {
        let msg = cmd.args.clone();
        self.messages.lock().push(format!("say2: {}", msg));
        tracing::debug!("GS1: say2 {}", msg);
        Ok(())
    }

    /// set/setstring command - Set a variable
    fn cmd_set(&mut self, cmd: &ScriptCommand) -> Result<(), String> {
        // Format: set variable value
        // Or: setstring variable value
        let parts: Vec<&str> = cmd.parsed_args.iter().map(|s| s.as_str()).collect();
        if parts.len() >= 2 {
            let var_name = parts[0].to_string();
            let value = if parts.len() > 2 {
                parts[2..].join(" ")
            } else {
                parts.get(1).unwrap_or(&"").to_string()
            };

            // Determine variable store based on prefix
            if let Some(prefix) = VarPrefix::from_str(&var_name) {
                let value = ScriptValue::from_string(&value);
                match prefix {
                    VarPrefix::Player => {
                        self.player_vars.lock().set(var_name, value);
                    }
                    VarPrefix::Server => {
                        self.server_vars.lock().set(var_name, value);
                    }
                    VarPrefix::Client | VarPrefix::ClientR => {
                        self.client_vars.lock().set(var_name, value);
                    }
                    VarPrefix::This => {
                        self.script.vars.set(var_name, value);
                    }
                    VarPrefix::TriggerPlayer => {
                        // Same as player vars in this context
                        self.player_vars.lock().set(var_name, value);
                    }
                }
            }
        }
        Ok(())
    }

    /// unset command - Unset a variable
    fn cmd_unset(&mut self, cmd: &ScriptCommand) -> Result<(), String> {
        let var_name = cmd.get_arg(0).unwrap_or("");
        // Remove from all stores (simple approach)
        self.player_vars.lock().remove(var_name);
        self.server_vars.lock().remove(var_name);
        self.client_vars.lock().remove(var_name);
        self.script.vars.remove(var_name);
        Ok(())
    }

    /// hide command - Hide the NPC
    fn cmd_hide(&mut self, _cmd: &ScriptCommand) -> Result<(), String> {
        self.messages.lock().push("hide".to_string());
        tracing::debug!("GS1: hide");
        Ok(())
    }

    /// show command - Show the NPC
    fn cmd_show(&mut self, _cmd: &ScriptCommand) -> Result<(), String> {
        self.messages.lock().push("show".to_string());
        tracing::debug!("GS1: show");
        Ok(())
    }

    /// destroy command - Destroy the NPC
    fn cmd_destroy(&mut self, _cmd: &ScriptCommand) -> Result<(), String> {
        self.messages.lock().push("destroy".to_string());
        tracing::debug!("GS1: destroy");
        Ok(())
    }

    /// warpto command - Warp player to level
    fn cmd_warpto(&mut self, cmd: &ScriptCommand) -> Result<(), String> {
        let level = cmd.get_arg(0).unwrap_or("");
        let x = cmd.get_arg(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let y = cmd.get_arg(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        self.messages.lock().push(format!("warpto {} {} {}", level, x, y));
        tracing::debug!("GS1: warpto {} {} {}", level, x, y);
        Ok(())
    }

    /// serverwarp command - Warp player to another server
    fn cmd_serverwarp(&mut self, cmd: &ScriptCommand) -> Result<(), String> {
        let server = cmd.get_arg(0).unwrap_or("");
        let level = cmd.get_arg(1).unwrap_or("");
        self.messages.lock().push(format!("serverwarp {} {}", server, level));
        tracing::debug!("GS1: serverwarp {} {}", server, level);
        Ok(())
    }

    /// move command - Move the NPC
    fn cmd_move(&mut self, cmd: &ScriptCommand) -> Result<(), String> {
        let x = cmd.get_arg(0).and_then(|s| s.parse().ok()).unwrap_or(0);
        let y = cmd.get_arg(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        self.messages.lock().push(format!("move {} {}", x, y));
        tracing::debug!("GS1: move {} {}", x, y);
        Ok(())
    }
}

/// GS1 Commands registry
///
/// # Purpose
/// Provides access to all GS1 commands
///
/// # C++ Equivalence
/// Matches GS1Commands.cpp
pub struct GS1Commands;

impl GS1Commands {
    /// Get all supported command names
    pub fn all_commands() -> &'static [&'static str] {
        &[
            // Movement
            "move", "warpto", "serverwarp", "setlevel", "setlevel2",
            // Player
            "setplayerprop", "setplayerdir", "freezeplayer2", "unfreezeplayer",
            // Items
            "take", "take2", "addweapon", "removeweapon", "removeitem",
            // NPCs
            "putnpc", "putnpc2", "callnpc", "hide", "show", "destroy",
            // Visual
            "showimg", "hideimg", "showani", "showcharacter", "showtext",
            // Weapons
            "shoot", "shootarrow", "shootfireball", "shootfireblast", "shootnuke",
            // Bombs
            "putbomb", "putexplosion", "putexplosion2", "removebomb", "explodebomb",
            // Horses
            "puthorse", "removehorse", "takehorse",
            // Level
            "updateboard", "updateboard2", "updateterrain", "lay", "lay2",
            // Flags
            "set", "unset",
            // Messaging
            "message", "say", "say2", "sendpm", "sendrpgmessage",
            // Guild
            "addguildmember", "removeguildmember", "removeguild",
            // String ops
            "setstring", "addstring", "insertstring", "deletestring", "replacestring", "tokenize",
            // NPC control
            "canbecarried", "cannotbecarried", "canbepushed", "cannotbepushed",
            // Image control
            "changeimgcolors", "changeimgmode", "changeimgpart", "changeimgvis", "changeimgzoom",
            // Time
            "timeout", "settimer", "stoptimer",
            // Position
            "setposition", "setx", "sety", "setz",
            // NPC properties
            "setshape", "setimg", "setcolor", "setcolorspec",
            // Audio
            "play", "playlooped", "stopmidi",
            // Other
            "enableparticles", "disableparticles", "attr",
        ]
    }

    /// Check if a command is supported
    pub fn is_supported(command: &str) -> bool {
        Self::all_commands().contains(&command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_var_prefix_parse() {
        assert_eq!(VarPrefix::from_str("player.x"), Some(VarPrefix::Player));
        assert_eq!(VarPrefix::from_str("this.name"), Some(VarPrefix::This));
        assert_eq!(VarPrefix::from_str("server.flag"), Some(VarPrefix::Server));
        assert_eq!(VarPrefix::from_str("clientr.var"), Some(VarPrefix::ClientR));
        assert_eq!(VarPrefix::from_str("unknown.x"), None);
    }

    #[test]
    fn test_script_value() {
        assert_eq!(ScriptValue::from_string("123").as_number(), 123.0);
        assert_eq!(ScriptValue::from_string("true").as_bool(), true);
        assert!(ScriptValue::from_string("hello").is_true());
        assert!(!ScriptValue::from_string("").is_true());
        assert!(!ScriptValue::from_string("0").is_true());
    }

    #[test]
    fn test_script_command_parse() {
        let cmd = ScriptCommand::parse("message Hello, world!").unwrap();
        assert_eq!(cmd.name, "message");
        assert_eq!(cmd.args, "Hello, world!");
        assert_eq!(cmd.parsed_args, vec!["Hello,", "world!"]);

        let cmd2 = ScriptCommand::parse("set player.x 50").unwrap();
        assert_eq!(cmd2.name, "set");
        assert_eq!(cmd2.get_arg(0), Some("player.x"));
        assert_eq!(cmd2.get_arg(1), Some("50"));
    }

    #[test]
    fn test_script_parse() {
        let script = Script::parse(
            r#"
            //#name TestScript
            if (created) {
              message Hello!;
              set this.x 50;
            }
            "#
        );

        assert_eq!(script.name, "TestScript");
        assert!(script.has_trigger(ScriptTrigger::Created));
    }

    #[test]
    fn test_script_context() {
        let script = Script::parse(
            r#"
            if (created) {
              message Test;
            }
            "#
        );

        let mut ctx = ScriptContext::new(script);
        ctx.execute_trigger(ScriptTrigger::Created).unwrap();

        assert_eq!(ctx.messages.lock().len(), 1);
        // Message includes the semicolon as that's part of the GS1 syntax
        assert_eq!(ctx.messages.lock()[0], "Test;");
    }
}
