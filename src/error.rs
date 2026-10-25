//! Errors, each with a stable code the app turns into its own wording.

/// Something doorward refused or couldn't do.
///
/// The `Display` text is for logs. Show users your own wording, chosen by
/// [`Error::code`], so each app controls its tone and languages.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Not enough free memory, or too many checks waiting, to hash a password
    /// right now. Ask the user to try again shortly.
    #[error("too busy to check a password right now")]
    Busy,
    /// The password is longer than [`MAX_PASSWORD_BYTES`](crate::password::MAX_PASSWORD_BYTES).
    #[error("password is too long")]
    PasswordTooLong,
    /// A hash policy outside doorward's limits was given.
    #[error("hash policy is outside doorward's limits")]
    InvalidHashPolicy,
    /// The machine can't spare even the minimum memory for one check.
    #[error("not enough memory for password hashing")]
    NotEnoughMemory,
    /// The operating system's random number generator failed.
    #[error("the system's random number generator failed")]
    Random,
    /// Password hashing failed for another reason.
    #[error("password hashing failed")]
    Hashing,
}

/// A stable, machine-readable reason for an [`Error`], for apps to map to
/// their own messages and HTTP statuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// See [`Error::Busy`].
    Busy,
    /// See [`Error::PasswordTooLong`].
    PasswordTooLong,
    /// Something went wrong inside the server; details are in the log.
    Internal,
}

impl ErrorCode {
    /// The code as a short snake_case string, such as `"busy"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Busy => "busy",
            ErrorCode::PasswordTooLong => "password_too_long",
            ErrorCode::Internal => "internal",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error {
    /// The stable code for this error.
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Busy => ErrorCode::Busy,
            Error::PasswordTooLong => ErrorCode::PasswordTooLong,
            Error::InvalidHashPolicy | Error::NotEnoughMemory | Error::Random | Error::Hashing => ErrorCode::Internal,
        }
    }
}
