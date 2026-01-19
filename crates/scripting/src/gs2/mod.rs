//! GS2 Scripting System
//!
//! GS2 is Graal's compiled scripting language.
//! It features a bytecode VM and class-based objects.

pub mod lexer;
pub mod ast;
pub mod parser;
pub mod bytecode;
pub mod compiler;
pub mod vm;

pub use lexer::{Lexer, Token};
pub use ast::*;
pub use parser::Parser;
pub use bytecode::{Chunk, OpCode, Value};
pub use compiler::Compiler;
pub use vm::VM;
