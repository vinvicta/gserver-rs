//! # Server Configuration
//!
//! Configuration options for the GServer networking layer.
//!
//! # Example
//!
//! ```rust
//! use gserver_network::ServerConfig;
//! use std::time::Duration;
//!
//! let config = ServerConfig {
//!     bind_address: "0.0.0.0:14902".parse().unwrap(),
//!     max_connections: 1000,
//!     connection_timeout: Duration::from_secs(60),
//!     read_timeout: Duration::from_secs(30),
//!     write_timeout: Duration::from_secs(10),
//!     ..Default::default()
//! };
//! ```

use std::net::SocketAddr;
use std::time::Duration;

/// Server configuration options
///
/// # Purpose
/// Defines all configurable parameters for the GServer networking layer.
///
/// # Default Values
///
/// The defaults are chosen for a typical Graal server:
/// - Port 14902 (standard Graal server port)
/// - 1000 max connections (suitable for most servers)
/// - 60-second connection timeout
/// - Compression enabled (zlib, level 6)
///
/// # Fields
///
/// - `bind_address`: Address and port to listen on
/// - `max_connections`: Maximum concurrent connections
/// - `connection_timeout`: How long to wait before closing idle connections
/// - `read_timeout`: How long to wait for packet data
/// - `write_timeout`: How long to wait for write operations
/// - `enable_compression`: Whether to compress outbound packets
/// - `compression_level`: Compression level (0-9, higher = more compression but slower)
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Server directory path (contains accounts/, levels/, etc.)
    ///
    /// # Default
    /// `"servers/default"`
    ///
    /// # Notes
    /// - This is where the server looks for accounts, levels, scripts, etc.
    /// - Relative paths are resolved from the current working directory
    pub server_dir: String,

    /// Address and port to bind the TCP listener to
    ///
    /// # Default
    /// `0.0.0.0:14902` (all interfaces, standard Graal port)
    ///
    /// # Examples
    /// - `0.0.0.0:14902` - Listen on all interfaces
    /// - `127.0.0.1:14902` - Listen only on localhost
    /// - `192.168.1.100:14902` - Listen on specific IP
    pub bind_address: SocketAddr,

    /// Maximum number of concurrent connections allowed
    ///
    /// # Purpose
    /// Prevents resource exhaustion and DoS attacks
    ///
    /// # Default
    /// 1000 connections
    ///
    /// # Recommended Values
    /// - Small server: 100-500
    /// - Medium server: 500-1000
    /// - Large server: 1000-5000
    pub max_connections: usize,

    /// Connection timeout - idle connections are closed after this duration
    ///
    /// # Purpose
    /// Prevents zombie connections from consuming resources
    ///
    /// # Default
    /// 60 seconds
    ///
    /// # Notes
    /// - Players can be disconnected for being idle too long
    /// - Consider player activity when setting this
    /// - Some clients have heartbeat packets to stay connected
    pub connection_timeout: Duration,

    /// Read timeout - time to wait for packet data
    ///
    /// # Purpose
    /// Prevents connections from hanging on slow/missing packets
    ///
    /// # Default
    /// 30 seconds
    ///
    /// # Notes
    /// - If a partial packet is received, we wait this long for the rest
    /// - Should be less than connection_timeout
    pub read_timeout: Duration,

    /// Write timeout - time to wait for write operations to complete
    ///
    /// # Purpose
    /// Prevents hangs on slow/unresponsive clients
    ///
    /// # Default
    /// 10 seconds
    ///
    /// # Notes
    /// - Applies to each individual write() call
    /// - Large packets may take multiple write() calls
    pub write_timeout: Duration,

    /// Whether to enable packet compression
    ///
    /// # Purpose
    /// Reduces bandwidth usage for large packets (level data, files, etc.)
    ///
    /// # Default
    /// `true` (enabled)
    ///
    /// # Notes
    /// - Uses zlib compression
    /// - Only packets larger than threshold are compressed
    /// - Small packets are sent uncompressed to avoid overhead
    pub enable_compression: bool,

    /// Compression level (0-9)
    ///
    /// # Purpose
    /// Controls the tradeoff between CPU usage and compression ratio
    ///
    /// # Default
    /// 6 (good balance)
    ///
    /// # Values
    /// - 0: No compression (fastest)
    /// - 1-3: Fast compression, lower ratio
    /// - 4-6: Medium compression, medium ratio (recommended)
    /// - 7-9: Maximum compression, slower
    pub compression_level: u32,

    /// Minimum packet size before compression is applied
    ///
    /// # Purpose
    /// Avoid compressing small packets (compression overhead > savings)
    ///
    /// # Default
    /// 256 bytes
    ///
    /// # Notes
    /// - Packets smaller than this are sent uncompressed
    /// - Typical chat packets (~50 bytes) won't be compressed
    /// - Level data (>10KB) will always be compressed
    pub compression_threshold: usize,

    /// Size of the read buffer for each connection
    ///
    /// # Purpose
    /// Controls memory usage vs throughput tradeoff
    ///
    /// # Default
    /// 8192 bytes (8KB)
    ///
    /// # Recommended Values
    /// - 4096: Lower memory usage, slightly more syscalls
    /// - 8192: Good balance (default)
    /// - 16384: Higher throughput, more memory
    /// - 65536: Maximum throughput, high memory usage
    pub read_buffer_size: usize,

    /// Size of the write buffer for each connection
    ///
    /// # Purpose
    /// Buffers outbound data to reduce syscall overhead
    ///
    /// # Default
    /// 8192 bytes (8KB)
    ///
    /// # Notes
    /// - Larger buffers = fewer write() syscalls
    /// - But consume more memory per connection
    pub write_buffer_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server_dir: "servers/default".to_string(),
            bind_address: "0.0.0.0:14902".parse().unwrap(),
            max_connections: 1000,
            connection_timeout: Duration::from_secs(60),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(10),
            enable_compression: true,
            compression_level: 6,
            compression_threshold: 256,
            read_buffer_size: 8192,
            write_buffer_size: 8192,
        }
    }
}

impl ServerConfig {
    /// Validate the configuration
    ///
    /// # Returns
    /// `Ok(())` if configuration is valid, `Err(String)` otherwise
    ///
    /// # Checks
    /// - `max_connections` must be > 0
    /// - `connection_timeout` must be > `read_timeout`
    /// - `compression_level` must be 0-9
    /// - Buffer sizes must be power of 2 and >= 1024
    pub fn validate(&self) -> Result<(), String> {
        if self.max_connections == 0 {
            return Err("max_connections must be > 0".to_string());
        }

        if self.connection_timeout <= self.read_timeout {
            return Err("connection_timeout must be > read_timeout".to_string());
        }

        if self.compression_level > 9 {
            return Err("compression_level must be 0-9".to_string());
        }

        if self.read_buffer_size < 1024 {
            return Err("read_buffer_size must be >= 1024".to_string());
        }

        if self.write_buffer_size < 1024 {
            return Err("write_buffer_size must be >= 1024".to_string());
        }

        // Check if buffer sizes are power of 2 (optional, but good practice)
        if !self.read_buffer_size.is_power_of_two() {
            tracing::warn!("read_buffer_size is not a power of 2, this may reduce performance");
        }

        if !self.write_buffer_size.is_power_of_two() {
            tracing::warn!("write_buffer_size is not a power of 2, this may reduce performance");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.bind_address.port(), 14902);
        assert_eq!(config.max_connections, 1000);
        assert_eq!(config.enable_compression, true);
        assert_eq!(config.compression_level, 6);
    }

    #[test]
    fn test_config_validation() {
        let config = ServerConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_max_connections() {
        let mut config = ServerConfig::default();
        config.max_connections = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_compression_level() {
        let mut config = ServerConfig::default();
        config.compression_level = 10;
        assert!(config.validate().is_err());
    }
}
