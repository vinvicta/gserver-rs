//! Core error types for GServer

#[derive(thiserror::Error, Debug)]
pub enum GServerError {
    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Script error: {0}")]
    Script(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Compression error: {0}")]
    Compression(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),
}

pub type Result<T> = std::result::Result<T, GServerError>;
