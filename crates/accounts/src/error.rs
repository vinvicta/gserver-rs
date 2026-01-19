//! Account-related errors

use thiserror::Error;

/// Account-related errors
#[derive(Error, Debug)]
pub enum AccountError {
    #[error("Account not found: {0}")]
    NotFound(String),

    #[error("Invalid account file format: {0}")]
    InvalidFormat(String),

    #[error("Invalid account data: {0}")]
    InvalidData(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Account file corrupted: {0}")]
    Corrupted(String),
}

pub type Result<T> = std::result::Result<T, AccountError>;
