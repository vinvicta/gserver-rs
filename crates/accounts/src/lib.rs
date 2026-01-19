//! # GServer Account Management
//!
//! This crate handles player account loading and management.
//!
//! ## Features
//!
//! - Account file loading from disk
//! - Staff rights validation
//! - Player permissions
//! - Default account fallback
//!
//! ## Usage
//!
//! ```rust,no_run
//! use gserver_accounts::AccountLoader;
//! use std::path::Path;
//!
//! let loader = AccountLoader::new(Path::new("servers/default"));
//! let account = loader.load("playername").unwrap();
//!
//! if account.is_staff() {
//!     println!("{} is staff with rights: {}", account.name, account.local_rights);
//! }
//! ```

mod account;
mod error;
mod loader;

pub use account::{
    Account, PlayerPermissions,
    PLPERM_WARPTO, PLPERM_DISCONNECT, PLPERM_ANYRIGHT, PLPERM_INVISIBLE
};
pub use error::{AccountError, Result};
pub use loader::AccountLoader;
