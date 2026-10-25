//! # doorward
//!
//! Headless sign-in for Rust web apps. doorward is the doorkeeper: it answers
//! "who is this request, and may they?" and leaves every screen to the app.
//!
//! - [`password`]: Argon2id hashing sized to the machine.
//! - [`Doorward`]: users, password sign-in, sessions bound to the address
//!   they were made on, recent-sign-in checks before sensitive actions,
//!   per-visitor rate limits with remembered browsers, and a security log.
//! - Passkeys (feature `passkeys`), per address.
//! - axum route guards and ready-made JSON endpoints (feature `axum`).
//! - Storage behind the [`store::Store`] trait: [`store::MemoryStore`] here,
//!   SQLite and Postgres in the `doorward-sqlite` and `doorward-postgres`
//!   crates.
//!
//! ```no_run
//! use doorward::{Address, Doorward, NewUser, RequestInfo};
//! use doorward::store::MemoryStore;
//!
//! # async fn demo(headers: http::HeaderMap) -> Result<(), doorward::Error> {
//! let dw = Doorward::builder(MemoryStore::new())
//!     .address(Address::new("https://pc.lan:8040")?)
//!     .app_name("pingrail")
//!     .build()
//!     .await?;
//! dw.create_user(NewUser {
//!     username: "admin".into(),
//!     password: Some("a long passphrase".to_string().into()),
//!     ..Default::default()
//! })
//! .await?;
//!
//! // In a request handler:
//! let req = RequestInfo { peer: "192.168.1.20".parse().unwrap(), method: &http::Method::POST, host: None, headers: &headers };
//! let visit = dw.visit(&req)?;
//! let signed_in = dw.sign_in_password(&visit, "admin", "a long passphrase", false).await?;
//! // send signed_in.cookies as Set-Cookie headers
//! # Ok(()) }
//! ```
//!
//! ## Features
//!
//! - `detect-memory` (default): read the machine's memory on systems other
//!   than Linux through `sysinfo` (Linux is read directly).
//! - `passkeys`: passkey sign-in through webauthn-rs, which uses OpenSSL.
//! - `vendored-openssl`: build OpenSSL into the program (`passkeys` too).
//! - `axum`: extractors, route guards and JSON endpoints for axum 0.8.
//! - `test-util`: the store conformance suite and a software passkey
//!   authenticator for the app's own tests.
//!
//! doorward contains no `unsafe` code.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod address;
mod clock;
mod doorward;
mod error;
mod limits;
mod model;
mod net;
pub mod password;
pub mod store;
mod token;
mod username;

#[cfg(feature = "passkeys")]
pub mod passkey;

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "test-util")]
pub mod testing;

pub use address::{Address, SessionLengths, Via};
pub use clock::{Clock, ManualClock, SystemClock};
pub use doorward::{AddressInfo, Builder, DeviceCookie, Doorward, RequestInfo, Visit};
pub use error::{Error, ErrorCode};
pub use limits::Limits;
pub use model::{NewUser, PasswordRules, SecurityEvent, Session, SessionInfo, SetCookie, SignInMethod, SignedIn, User};
pub use net::IpNet;
pub use username::{MAX_ROLE_CHARS, MAX_USERNAME_CHARS, Username};
pub use uuid::Uuid;
pub use zeroize::Zeroizing;
