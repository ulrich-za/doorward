//! # doorward
//!
//! Headless sign-in for Rust web apps. doorward is the doorkeeper: it answers
//! "who is this request, and may they?" and leaves every screen to the app.
//!
//! This release contains the first piece, [`password`]: Argon2id password
//! hashing sized to the machine it runs on. Passkeys, sessions and the rest of
//! sign-in follow in later releases.
//!
//! ## Features
//!
//! - `serde` (default): save and load a [`password::HashPolicy`] as JSON.
//! - `tokio` (default): limit concurrent password checks and run them on
//!   blocking threads ([`password::Hasher::verify_async`]).
//! - `detect-memory` (default): read the machine's memory on systems other
//!   than Linux through the `sysinfo` crate. Linux is read directly.
//!
//! doorward contains no `unsafe` code.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod clock;
mod error;
pub mod password;

pub use error::{Error, ErrorCode};
