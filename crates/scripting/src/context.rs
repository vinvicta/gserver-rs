//! Script execution context
//!
//! Provides shared state for script execution including
//! global variables, player references, and level data.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use gserver_core::PlayerID;

/// Script execution context
#[derive(Debug, Clone)]
pub struct ScriptContext {
    /// Global variables
    globals: Arc<RwLock<HashMap<String, String>>>,
    
    /// Current player (if any)
    player: Option<PlayerID>,
    
    /// Current level (if any)
    level: Option<String>,
}

impl ScriptContext {
    /// Create a new empty context
    pub fn new() -> Self {
        Self {
            globals: Arc::new(RwLock::new(HashMap::new())),
            player: None,
            level: None,
        }
    }
    
    /// Get a global variable
    pub fn get_global(&self, name: &str) -> Option<String> {
        self.globals.read().ok()?.get(name).cloned()
    }
    
    /// Set a global variable
    pub fn set_global(&self, name: String, value: String) {
        if let Ok(mut globals) = self.globals.write() {
            globals.insert(name, value);
        }
    }
    
    /// Get the current player
    pub fn player(&self) -> Option<PlayerID> {
        self.player
    }
    
    /// Set the current player
    pub fn set_player(&mut self, player: PlayerID) {
        self.player = Some(player);
    }
    
    /// Get the current level
    pub fn level(&self) -> Option<&str> {
        self.level.as_deref()
    }
    
    /// Set the current level
    pub fn set_level(&mut self, level: String) {
        self.level = Some(level);
    }
}

impl Default for ScriptContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_context_globals() {
        let ctx = ScriptContext::new();
        
        assert!(ctx.get_global("test").is_none());
        
        ctx.set_global("test".to_string(), "value".to_string());
        assert_eq!(ctx.get_global("test"), Some("value".to_string()));
    }
}
