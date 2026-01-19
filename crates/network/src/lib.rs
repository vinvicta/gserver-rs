//! # GServer Networking Layer
//!
//! This crate provides Tokio-based async networking for the GServer.
//!
//! ## Modules
//!
//! - [`config`] - Server configuration options
//! - [`connection`] - Individual connection management
//! - [`handlers`] - Packet handler registry
//! - [`server`] - Main server implementation
//! - [`listserver`] - ListServer client implementation

pub mod config;
pub mod connection;
pub mod handlers;
pub mod server;
pub mod listserver;

// Re-export commonly used items
pub use config::ServerConfig;
pub use connection::{PlayerConnection, ConnectionState};
pub use handlers::HandlerRegistry;
pub use server::GServer;
pub use listserver::{ListServerClient, ListServerConfig, spawn_listserver_client};
