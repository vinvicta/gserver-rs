//! Level manager for runtime level handling
//!
//! Provides a simple interface for loading and managing levels during gameplay.

use crate::cache::LevelCache;
use crate::level::Level;
use crate::Result;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Level manager
///
/// Provides a high-level interface for level loading and management.
pub struct LevelManager {
    /// Level cache for loaded levels
    cache: LevelCache,

    /// Default level directory
    levels_dir: PathBuf,
}

impl LevelManager {
    /// Create a new level manager
    ///
    /// # Arguments
    /// * `levels_dir` - Directory containing level files
    pub fn new<P: Into<PathBuf>>(levels_dir: P) -> Self {
        let levels_dir = levels_dir.into();
        let cache = LevelCache::with_defaults(&levels_dir);

        Self {
            cache,
            levels_dir,
        }
    }

    /// Get or load a level by name
    ///
    /// # Purpose
    /// Retrieves a level from cache or loads it from disk.
    /// If the level doesn't exist, returns a default level.
    ///
    /// # Arguments
    /// * `name` - Level name (e.g., "onlinestartlocal.nw")
    ///
    /// # Returns
    /// The loaded or cached level
    ///
    /// # Example
    /// ```rust,no_run
    /// use gserver_levels::LevelManager;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = LevelManager::new("world/indoor");
    /// let level = manager.get_level("onlinestartlocal.nw").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_level(&self, name: &str) -> Result<Arc<Level>> {
        // Try to load from cache/disk
        match self.cache.get(name).await {
            Ok(level) => Ok(level),
            Err(_) => {
                // Level not found, return a default level
                tracing::warn!("Level '{}' not found, using default level", name);
                Ok(Arc::new(Level::create_default(name.to_string())))
            }
        }
    }

    /// Get the levels directory
    pub fn levels_dir(&self) -> &PathBuf {
        &self.levels_dir
    }

    /// Get cache statistics
    pub fn stats(&self) -> crate::cache::CacheStats {
        self.cache.stats()
    }

    /// Clear the level cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Preload levels into cache
    pub async fn preload(&self, level_names: &[&str]) -> Result<()> {
        self.cache.preload(level_names).await
    }
}

/// Simple level provider for testing
///
/// This provides a non-async interface for level loading in tests.
pub struct SimpleLevelProvider {
    levels: std::collections::HashMap<String, Arc<Level>>,
}

impl SimpleLevelProvider {
    /// Create a new simple level provider
    pub fn new() -> Self {
        Self {
            levels: std::collections::HashMap::new(),
        }
    }

    /// Get or create a level
    pub fn get_level(&mut self, name: &str) -> Arc<Level> {
        if !self.levels.contains_key(name) {
            self.levels.insert(
                name.to_string(),
                Arc::new(Level::create_default(name.to_string())),
            );
        }
        self.levels.get(name).unwrap().clone()
    }

    /// Add a level to the provider
    pub fn add_level(&mut self, level: Level) {
        self.levels.insert(level.name.clone(), Arc::new(level));
    }
}

impl Default for SimpleLevelProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current time as seconds since UNIX epoch
///
/// # Purpose
/// Utility function for getting timestamps
pub fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_level_manager_default_level() {
        // Create a manager with an empty directory
        let temp_dir = tempfile::TempDir::unwrap();
        let manager = LevelManager::new(temp_dir.path());

        // Request a level that doesn't exist
        let level = manager.get_level("nonexistent.nw").await.unwrap();

        // Should get a default level
        assert_eq!(level.name, "nonexistent.nw");
        assert!(level.is_loaded());
    }

    #[test]
    fn test_simple_level_provider() {
        let mut provider = SimpleLevelProvider::new();

        // Get a level - should create default
        let level1 = provider.get_level("test.nw");
        assert_eq!(level1.name, "test.nw");

        // Get same level - should return cached
        let level2 = provider.get_level("test.nw");
        assert!(Arc::ptr_eq(&level1, &level2));

        // Get different level - should create new
        let level3 = provider.get_level("other.nw");
        assert_eq!(level3.name, "other.nw");
        assert!(!Arc::ptr_eq(&level1, &level3));
    }

    #[test]
    fn test_current_time() {
        let t = current_time();
        assert!(t > 0);
    }
}
