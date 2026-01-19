//! Level cache system
//!
//! Provides caching and lazy loading for levels to improve performance.

use crate::level::{Level, LevelId};
use crate::parser::LevelLoader;
use crate::Result;
use dashmap::DashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of levels to keep in cache
    pub max_levels: usize,

    /// Maximum memory usage in bytes (approximately)
    pub max_memory_bytes: usize,

    /// Cache TTL in seconds (0 = no expiration)
    pub ttl_seconds: u64,

    /// Whether to enable automatic cache cleanup
    pub auto_cleanup: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_levels: 100,
            max_memory_bytes: 100 * 1024 * 1024, // 100 MB
            ttl_seconds: 0,
            auto_cleanup: true,
        }
    }
}

/// Cache entry with metadata
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The cached level
    level: Arc<Level>,

    /// Timestamp when this entry was last accessed
    last_accessed: u64,

    /// Timestamp when this entry was loaded
    loaded_at: u64,

    /// Approximate size in bytes
    size_bytes: usize,
}

/// Level cache with LRU eviction
pub struct LevelCache {
    /// Cached levels indexed by level name
    cache: DashMap<String, CacheEntry>,

    /// Path to levels directory
    levels_dir: PathBuf,

    /// Cache configuration
    config: CacheConfig,

    /// Current memory usage
    memory_usage: std::sync::atomic::AtomicUsize,
}

impl LevelCache {
    /// Create a new level cache
    pub fn new<P: AsRef<Path>>(levels_dir: P, config: CacheConfig) -> Self {
        Self {
            cache: DashMap::new(),
            levels_dir: levels_dir.as_ref().to_path_buf(),
            config,
            memory_usage: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Create a new level cache with default config
    pub fn with_defaults<P: AsRef<Path>>(levels_dir: P) -> Self {
        Self::new(levels_dir, CacheConfig::default())
    }

    /// Get a level from cache or load it
    ///
    /// This is the primary method for accessing levels.
    pub async fn get(&self, level_name: &str) -> Result<Arc<Level>> {
        // Check cache first
        if let Some(entry) = self.cache.get(level_name) {
            // Clone the Arc to return
            // Note: We don't update last_accessed here to avoid locking issues
            return Ok(Arc::clone(&entry.level));
        }

        // Load from disk
        self.load_level(level_name).await
    }

    /// Load a level from disk and cache it
    async fn load_level(&self, level_name: &str) -> Result<Arc<Level>> {
        // Build path to level file
        let level_path = self.levels_dir.join(level_name);

        // Load the level
        let level = LevelLoader::load_file(&level_path)?;

        // Calculate approximate size
        let size_bytes = Self::estimate_size(&level);

        // Check if we need to make space
        if self.config.auto_cleanup {
            self.cleanup_if_needed().await;
        }

        // Create cache entry
        let now = Self::current_time();
        let entry = CacheEntry {
            level: Arc::new(level),
            last_accessed: now,
            loaded_at: now,
            size_bytes,
        };

        // Add to cache
        let level_arc = Arc::clone(&entry.level);
        self.cache.insert(level_name.to_string(), entry);
        self.memory_usage.fetch_add(size_bytes, std::sync::atomic::Ordering::Relaxed);

        Ok(level_arc)
    }

    /// Reload a level from disk (refresh cache)
    pub async fn reload(&self, level_name: &str) -> Result<Arc<Level>> {
        // Remove from cache
        self.remove(level_name);

        // Reload
        self.load_level(level_name).await
    }

    /// Remove a level from cache
    pub fn remove(&self, level_name: &str) {
        if let Some((_, entry)) = self.cache.remove(level_name) {
            self.memory_usage.fetch_sub(entry.size_bytes, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Clear all cached levels
    pub fn clear(&self) {
        self.cache.clear();
        self.memory_usage.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let mut total_memory = 0;
        let mut oldest_access = u64::MAX;
        let mut newest_access = 0;

        for entry in self.cache.iter() {
            total_memory += entry.size_bytes;
            oldest_access = oldest_access.min(entry.last_accessed);
            newest_access = newest_access.max(entry.last_accessed);
        }

        CacheStats {
            num_levels: self.cache.len(),
            total_memory_bytes: total_memory,
            oldest_access_secs: oldest_access,
            newest_access_secs: newest_access,
        }
    }

    /// Cleanup old/unused levels if needed
    async fn cleanup_if_needed(&self) {
        let current_count = self.cache.len();
        let current_memory = self.memory_usage.load(std::sync::atomic::Ordering::Relaxed);

        // Check if we need cleanup
        let needs_cleanup = current_count >= self.config.max_levels
            || current_memory >= self.config.max_memory_bytes;

        if !needs_cleanup {
            return;
        }

        // Collect entries to remove
        let mut entries: Vec<_> = self.cache.iter()
            .map(|entry| {
                (
                    entry.level.name.clone(),
                    entry.last_accessed,
                    entry.size_bytes,
                )
            })
            .collect();

        // Sort by last accessed (oldest first)
        entries.sort_by_key(|&(_, accessed, _)| accessed);

        // Remove oldest entries until we're under limits
        let mut removed_memory = 0;
        for (name, _, size) in entries {
            let current_count = self.cache.len();
            let current_memory = self.memory_usage.load(std::sync::atomic::Ordering::Relaxed);

            if current_count < self.config.max_levels
                && current_memory + removed_memory < self.config.max_memory_bytes
            {
                break;
            }

            self.remove(&name);
            removed_memory += size;
        }
    }

    /// Check if a cache entry has expired
    fn is_expired(&self, entry: &CacheEntry) -> bool {
        if self.config.ttl_seconds == 0 {
            return false;
        }

        let now = Self::current_time();
        now.saturating_sub(entry.loaded_at) > self.config.ttl_seconds
    }

    /// Get current time as seconds since UNIX epoch
    fn current_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Estimate memory size of a level
    fn estimate_size(level: &Level) -> usize {
        // Base size
        let mut size = std::mem::size_of::<Level>();

        // Add tiles size (approximate)
        let tiles = level.tiles.read();
        for layer_id in tiles.layer_ids() {
            if let Some(layer) = tiles.get_layer(layer_id) {
                size += layer.data().len() * 2; // Each tile is 2 bytes
            }
        }

        // Add entities
        size += level.chests.len() * std::mem::size_of::<crate::level::Chest>();
        size += level.links.len() * std::mem::size_of::<crate::level::Link>();
        size += level.signs.len() * std::mem::size_of::<crate::level::Sign>();
        size += level.baddies.len() * std::mem::size_of::<crate::level::Baddy>();

        size
    }

    /// Preload levels into cache
    pub async fn preload(&self, level_names: &[&str]) -> Result<()> {
        for name in level_names {
            self.get(name).await?;
        }
        Ok(())
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of levels in cache
    pub num_levels: usize,

    /// Total memory usage in bytes
    pub total_memory_bytes: usize,

    /// Oldest access time (seconds since epoch)
    pub oldest_access_secs: u64,

    /// Newest access time (seconds since epoch)
    pub newest_access_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_cache_miss() {
        let temp_dir = TempDir::new().unwrap();
        let levels_dir = temp_dir.path();

        // Create a test level file
        let level_path = levels_dir.join("test.nw");
        let level_data = r#"GLEVNW01
BOARD 0 0 2 0 AAAA
"#;
        std::fs::write(&level_path, level_data).unwrap();

        let cache = LevelCache::new(levels_dir, CacheConfig {
            auto_cleanup: false,
            ..Default::default()
        });
        let level = cache.get("test.nw").await.unwrap();

        assert_eq!(level.name, "test.nw");
        assert!(level.is_loaded());
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let temp_dir = TempDir::new().unwrap();
        let levels_dir = temp_dir.path();

        // Create a test level file
        let level_path = levels_dir.join("test.nw");
        let level_data = r#"GLEVNW01
BOARD 0 0 2 0 AAAA
"#;
        std::fs::write(&level_path, level_data).unwrap();

        let cache = LevelCache::new(levels_dir, CacheConfig {
            auto_cleanup: false,
            ..Default::default()
        });

        // First access - cache miss
        let level1 = cache.get("test.nw").await.unwrap();

        // Second access - cache hit
        let level2 = cache.get("test.nw").await.unwrap();

        // Should be the same Arc pointer
        assert!(Arc::ptr_eq(&level1, &level2));
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let temp_dir = TempDir::new().unwrap();
        let levels_dir = temp_dir.path();

        // Create test level files
        for i in 0..3 {
            let level_path = levels_dir.join(format!("test{}.nw", i));
            let level_data = format!(r#"GLEVNW01
BOARD 0 0 64 0 {}
"#, "A".repeat(128));
            std::fs::write(&level_path, level_data).unwrap();
        }

        let cache = LevelCache::new(levels_dir, CacheConfig {
            auto_cleanup: false,
            ..Default::default()
        });

        // Load levels
        cache.get("test0.nw").await.unwrap();
        cache.get("test1.nw").await.unwrap();

        let stats = cache.stats();
        assert_eq!(stats.num_levels, 2);
        assert!(stats.total_memory_bytes > 0);
    }

    #[tokio::test]
    async fn test_cache_reload() {
        let temp_dir = TempDir::new().unwrap();
        let levels_dir = temp_dir.path();

        // Create a test level file
        let level_path = levels_dir.join("test.nw");
        let level_data = r#"GLEVNW01
BOARD 0 0 2 0 AAAA
"#;
        std::fs::write(&level_path, level_data).unwrap();

        let cache = LevelCache::new(levels_dir, CacheConfig {
            auto_cleanup: false,
            ..Default::default()
        });

        // Load level
        let level1 = cache.get("test.nw").await.unwrap();

        // Reload level
        let level2 = cache.reload("test.nw").await.unwrap();

        assert_eq!(level1.name, level2.name);
        assert_eq!(level1.id, level2.id);
    }
}
