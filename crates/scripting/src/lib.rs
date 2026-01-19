//! # GServer Scripting System
//!
//! This crate handles GS1 and GS2 scripting for Graal Online.
//!
//! ## Features
//! - GS1 interpreter (event-driven scripting)
//! - GS2 compiler and bytecode VM
//! - 200+ built-in functions
//! - Variable scoping and events
//!
//! ## Script Types
//!
//! ### GS1
//! - Simple, line-based scripting
//! - Event-driven (timeout, playerenter, etc.)
//! - Text-based commands
//!
//! ### GS2
//! - Compiled bytecode
//! - Stack-based VM
//! - Classes and objects

pub mod error;
pub mod gs1;
pub mod gs2;
pub mod context;
pub mod builtins;

pub use error::{ScriptError, Result};
pub use gs1::{GS1Script, GS1Interpreter, EventType};
pub use gs2::{Parser as GS2Parser, Compiler as GS2Compiler, VM as GS2VM};
pub use context::ScriptContext;
