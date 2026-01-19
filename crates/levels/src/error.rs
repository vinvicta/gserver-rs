//! Error types for the levels crate

use gserver_core::GServerError;
use std::path::PathBuf;

/// Level-specific error types
#[derive(Debug, thiserror::Error)]
pub enum LevelError {
    /// File I/O error
    #[error("File error: {0}")]
    FileError(#[from] std::io::Error),

    /// Invalid level file format
    #[error("Invalid level format: {0}")]
    InvalidFormat(String),

    /// Invalid level version
    #[error("Unsupported level version: {0}")]
    UnsupportedVersion(String),

    /// Parse error
    #[error("Parse error at line {line}: {message}")]
    ParseError { line: usize, message: String },

    /// Tile data error
    #[error("Tile error: {0}")]
    TileError(String),

    /// Level not found
    #[error("Level not found: {0}")]
    NotFound(String),

    /// Cache error
    #[error("Cache error: {0}")]
    CacheError(String),

    /// Time error
    #[error("Time error: {0}")]
    TimeError(String),
}

// Additional From implementations
impl From<std::time::SystemTimeError> for LevelError {
    fn from(err: std::time::SystemTimeError) -> Self {
        LevelError::TimeError(err.to_string())
    }
}

impl From<LevelError> for GServerError {
    fn from(err: LevelError) -> Self {
        GServerError::InvalidData(err.to_string())
    }
}

/// Result type for level operations
pub type Result<T> = std::result::Result<T, LevelError>;
