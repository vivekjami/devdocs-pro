//! DevDocs Pro Core Library
//! 
//! This crate contains the core data structures and utilities
//! for the DevDocs Pro API documentation system.

pub mod config;
pub mod models;
pub mod utils;
pub mod errors;
pub mod body_capture;

pub use config::Config;
pub use models::*;
pub use errors::DevDocsError;
pub use body_capture::*;
