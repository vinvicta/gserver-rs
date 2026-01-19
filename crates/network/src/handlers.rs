//! # Packet Handler System
//!
//! This module provides type-safe packet routing and handling.
//!
//! # Architecture
//!
//! ## Handler Registry
//!
//! The handler registry maintains a mapping from packet types to handler functions.
//!
//! # Performance
//!
//! - O(1) packet dispatch via direct HashMap lookup
//! - No dynamic dispatch (uses concrete types)
//! - Handler functions are `Arc` wrapped for sharing
//!
//! # Thread Safety
//!
//! Handlers can be called from multiple connection tasks concurrently.
//! State must be protected with appropriate synchronization (`Mutex`, `RwLock`, etc.).
//!
//! # Example
//!
//! ```no_run
//! use gserver_network::HandlerRegistry;
//! use gserver_protocol::{PacketIn, PacketTypeIn};
//! use gserver_core::Result;
//!
//! // Create handler registry
//! let mut registry = HandlerRegistry::new();
//!
//! // Register a handler function
//! registry.register_function(PacketTypeIn::ToAll, |packet| async move {
//!     println!("ToAll packet received");
//!     Ok(())
//! });
//! ```

use gserver_core::Result;
use gserver_protocol::{PacketIn, PacketTypeIn};
use std::collections::HashMap;
use std::sync::Arc;
use std::pin::Pin;
use std::future::Future;

/// Type for packet handler functions
///
/// # Purpose
/// Async function that handles a packet and returns a Result.
///
/// # Type Parameters
/// - `'static` - The future cannot borrow any data from its environment
/// - `Send` - The future must be safe to send between threads
/// - `Result<()>` - Returns success or error
pub type HandlerFunction = Arc<dyn Fn(&PacketIn) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

/// Registry of packet handlers
///
/// # Purpose
/// Maintains a mapping from packet types to handler functions.
/// Provides O(1) lookup and dispatch.
///
/// # Thread Safety
/// The registry is thread-safe and can be shared across connection tasks.
///
/// # Example
///
/// ```no_run
/// use gserver_network::HandlerRegistry;
/// use gserver_protocol::PacketTypeIn;
///
/// let mut registry = HandlerRegistry::new();
///
/// // Register a handler function
/// registry.register_function(PacketTypeIn::LevelWarp, |packet| async move {
///     println!("Handling level warp");
///     Ok(())
/// });
/// ```
pub struct HandlerRegistry {
    /// Map from packet type to handler function
    handlers: HashMap<PacketTypeIn, HandlerFunction>,
}

impl HandlerRegistry {
    /// Create a new handler registry
    ///
    /// # Returns
    /// An empty registry ready for handler registration
    #[inline]
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a function-based handler
    ///
    /// # Arguments
    /// * `packet_type` - The packet type to handle
    /// * `handler` - Function to call for packets of this type
    ///
    /// # Example
    ///
    /// ```no_run
    /// registry.register_function(PacketTypeIn::LevelWarp, |packet| async move {
    ///     println!("Level warp packet!");
    ///     Ok(())
    /// });
    /// ```
    pub fn register_function<F, Fut>(&mut self, packet_type: PacketTypeIn, handler: F)
    where
        F: Fn(&PacketIn) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let handler = Arc::new(move |packet: &PacketIn| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
            Box::pin(handler(packet))
        });

        tracing::debug!("Registered handler for packet type: {:?}", packet_type);
        self.handlers.insert(packet_type, handler);
    }

    /// Dispatch a packet to its registered handler
    ///
    /// # Arguments
    /// * `packet` - The packet to dispatch
    ///
    /// # Returns
    /// - `Ok(())` - Packet handled successfully
    /// - `Err(e)` - Handler error or no handler registered
    ///
    /// # Errors
    /// Returns an error if:
    /// - No handler is registered for this packet type
    /// - The handler itself returns an error
    pub async fn dispatch(&self, packet: &PacketIn) -> Result<()> {
        let handler = self.handlers.get(&packet.packet_type)
            .ok_or_else(|| {
                gserver_core::GServerError::Protocol(format!(
                    "No handler registered for packet type: {:?}",
                    packet.packet_type
                ))
            })?;

        handler(packet).await
    }

    /// Check if a handler is registered for a packet type
    ///
    /// # Arguments
    /// * `packet_type` - The packet type to check
    ///
    /// # Returns
    /// `true` if a handler is registered, `false` otherwise
    pub fn has_handler(&self, packet_type: PacketTypeIn) -> bool {
        self.handlers.contains_key(&packet_type)
    }

    /// Get the number of registered handlers
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_registry_register() {
        let mut registry = HandlerRegistry::new();

        registry.register_function(PacketTypeIn::ToAll, |packet| async move {
            println!("ToAll packet received");
            Ok(())
        });

        assert!(registry.has_handler(PacketTypeIn::ToAll));
        assert_eq!(registry.handler_count(), 1);
    }

    #[tokio::test]
    async fn test_registry_dispatch() {
        let mut registry = HandlerRegistry::new();

        registry.register_function(PacketTypeIn::ToAll, |packet| async move {
            println!("Handling packet");
            Ok(())
        });

        let packet = PacketIn::new(PacketTypeIn::ToAll, vec![]);
        let result = registry.dispatch(&packet).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_registry_no_handler() {
        let registry = HandlerRegistry::new();
        let packet = PacketIn::new(PacketTypeIn::ToAll, vec![]);

        let result = registry.dispatch(&packet).await;
        assert!(result.is_err());
    }
}
