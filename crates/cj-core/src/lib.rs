//! cj-core: shared types, traits, errors, and parser registry for the cj project.
//!
//! This crate defines the contracts that all other cj crates depend on:
//!
//! - **types**: `ParseOutput`, `ParserInfo`, `Platform`, `Tag`
//! - **error**: `ParseError` (parser-level), `CjError` (application-level)
//! - **traits**: `Parser`, `StreamingParser`
//! - **registry**: `ParserEntry`, `all_parsers()`, `find_parser()`, `find_magic_parser()`

pub mod error;
pub mod registry;
pub mod traits;
pub mod types;

// Re-export the most commonly used items for ergonomic imports.
pub use error::{CjError, ParseError};
pub use registry::{ParserEntry, all_parsers, find_magic_parser, find_parser};
pub use traits::{Parser, StreamingParser};
pub use types::{ParseOutput, ParserInfo, Platform, Tag};
