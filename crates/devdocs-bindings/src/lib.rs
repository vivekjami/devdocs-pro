//! DevDocs Pro Language Bindings
//!
//! This crate will contain FFI bindings for Python, Node.js, Go, etc.
//! Implementation will be added in later phases.

pub mod nodejs;
pub mod python;

pub use devdocs_core::*;
pub use devdocs_middleware::*;
