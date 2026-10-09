// ============================================================================
// DeMoD Communications Framework - Identity & Billing Service (library half)
// ============================================================================
// Everything that is not HTML lives here so that `cargo test --lib` can run it
// without the askama template (templates/index.html is not in the repository).
// src/main.rs holds the template, the HTML handlers and the process wiring.
// ============================================================================

pub mod api;
pub mod billing;
pub mod db;
pub mod gate;
pub mod limiter;
pub mod security;
pub mod state;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
