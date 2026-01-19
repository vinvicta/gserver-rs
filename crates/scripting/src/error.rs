//! Error types for the scripting crate

use gserver_core::GServerError;

/// Script-specific error types
#[derive(Debug, thiserror::Error)]
pub enum ScriptError {
    /// Parse error
    #[error("Parse error at line {line}: {message}")]
    ParseError { line: usize, message: String },

    /// Runtime error
    #[error("Runtime error: {0}")]
    RuntimeError(String),

    /// Variable not found
    #[error("Variable not found: {0}")]
    VariableNotFound(String),

    /// Invalid function call
    #[error("Invalid function call: {0}")]
    InvalidFunctionCall(String),

    /// Stack overflow
    #[error("Stack overflow")]
    StackOverflow,

    /// Timeout
    #[error("Script timeout")]
    Timeout,
}

impl From<ScriptError> for GServerError {
    fn from(err: ScriptError) -> Self {
        GServerError::InvalidData(err.to_string())
    }
}

/// Result type for scripting operations
pub type Result<T> = std::result::Result<T, ScriptError>;
