//! Errors, each with a stable code the app turns into its own wording.

use std::time::Duration;

use crate::store::StoreError;

/// Something doorward refused or couldn't do.
///
/// The `Display` text is for logs. Show users your own wording, chosen by
/// [`Error::code`], so each app controls its tone and languages. Messages never
/// contain passwords, tokens or cookies.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Not enough free memory, or too many checks waiting, to hash a password
    /// right now. Ask the user to try again shortly.
    #[error("too busy to check a password right now")]
    Busy,
    /// The password is longer than allowed.
    #[error("password is too long")]
    PasswordTooLong,
    /// The new password is shorter than the app's minimum.
    #[error("password is too short")]
    PasswordTooShort,
    /// The new password is one of the most common, contains the username, or
    /// contains one of the app's refused words.
    #[error("password is too easy to guess")]
    PasswordTooCommon,
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
    /// Wrong username or password (deliberately not saying which).
    #[error("wrong username or password")]
    InvalidCredentials,
    /// The passkey isn't one this server knows, or its check failed.
    #[error("passkey not recognised")]
    PasskeyNotRecognised,
    /// Too many attempts from this visitor; try again after `retry_after`.
    #[error("too many attempts; retry after {retry_after:?}")]
    TooManyAttempts {
        /// How long to wait before trying again.
        retry_after: Duration,
    },
    /// The request carries no valid session.
    #[error("not signed in")]
    NotSignedIn,
    /// The action needs a sign-in from the last few minutes.
    #[error("a recent sign-in is needed")]
    NeedsRecentSignIn,
    /// The user lacks the role the action needs.
    #[error("forbidden")]
    Forbidden,
    /// A browser request from another site was refused.
    #[error("cross-origin request refused")]
    CrossOrigin,
    /// The request was sent to an address that isn't on the app's list, or
    /// claimed a proxied address without coming through the trusted proxy.
    #[error("address not allowed")]
    AddressNotAllowed,
    /// Passwords are turned off at this address.
    #[error("passwords are turned off at this address")]
    PasswordsDisabledHere,
    /// Passkeys are turned off at this address.
    #[error("passkeys are turned off at this address")]
    PasskeysUnavailableHere,
    /// The passkey request is unknown, expired, already used, or for another
    /// address or session.
    #[error("passkey request expired")]
    CeremonyExpired,
    /// The username is empty, too long, or has characters that aren't allowed.
    #[error("username not allowed")]
    UsernameInvalid,
    /// The username, or one that looks the same, is taken.
    #[error("username taken")]
    UsernameTaken,
    /// A role name isn't allowed.
    #[error("role name not allowed")]
    RoleInvalid,
    /// The account is disabled.
    #[error("account disabled")]
    AccountDisabled,
    /// Removing this passkey would leave the user unable to sign in at an
    /// address that has passwords turned off.
    #[error("last passkey for an address without passwords")]
    LastPasskey,
    /// The user has the most passkeys allowed.
    #[error("too many passkeys")]
    TooManyPasskeys,
    /// This passkey is already registered (to this or another account).
    #[error("passkey already registered")]
    PasskeyAlreadyAdded,
    /// The new passkey failed verification.
    #[error("passkey registration rejected")]
    PasskeyRejected,
    /// No such user, session or passkey (or not the caller's).
    #[error("not found")]
    NotFound,
    /// The request was malformed.
    #[error("bad request")]
    BadRequest,
    /// The configuration given to the builder is wrong.
    #[error("configuration: {0}")]
    Config(String),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] StoreError),
}

/// A stable, machine-readable reason for an [`Error`], for apps to map to
/// their own messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// See [`Error::Busy`].
    Busy,
    /// See [`Error::PasswordTooLong`].
    PasswordTooLong,
    /// See [`Error::PasswordTooShort`].
    PasswordTooShort,
    /// See [`Error::PasswordTooCommon`].
    PasswordTooCommon,
    /// See [`Error::InvalidCredentials`].
    InvalidCredentials,
    /// See [`Error::PasskeyNotRecognised`].
    PasskeyNotRecognised,
    /// See [`Error::TooManyAttempts`].
    TooManyAttempts,
    /// See [`Error::NotSignedIn`].
    NotSignedIn,
    /// See [`Error::NeedsRecentSignIn`].
    NeedsRecentSignIn,
    /// See [`Error::Forbidden`].
    Forbidden,
    /// See [`Error::CrossOrigin`].
    CrossOrigin,
    /// See [`Error::AddressNotAllowed`].
    AddressNotAllowed,
    /// See [`Error::PasswordsDisabledHere`].
    PasswordsDisabledHere,
    /// See [`Error::PasskeysUnavailableHere`].
    PasskeysUnavailableHere,
    /// See [`Error::CeremonyExpired`].
    CeremonyExpired,
    /// See [`Error::UsernameInvalid`].
    UsernameInvalid,
    /// See [`Error::UsernameTaken`].
    UsernameTaken,
    /// See [`Error::RoleInvalid`].
    RoleInvalid,
    /// See [`Error::AccountDisabled`].
    AccountDisabled,
    /// See [`Error::LastPasskey`].
    LastPasskey,
    /// See [`Error::TooManyPasskeys`].
    TooManyPasskeys,
    /// See [`Error::PasskeyAlreadyAdded`].
    PasskeyAlreadyAdded,
    /// See [`Error::PasskeyRejected`].
    PasskeyRejected,
    /// See [`Error::NotFound`].
    NotFound,
    /// See [`Error::BadRequest`].
    BadRequest,
    /// Something went wrong inside the server; details are in the log.
    Internal,
}

impl ErrorCode {
    /// The code as a short snake_case string, such as `"too_many_attempts"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Busy => "busy",
            ErrorCode::PasswordTooLong => "password_too_long",
            ErrorCode::PasswordTooShort => "password_too_short",
            ErrorCode::PasswordTooCommon => "password_too_common",
            ErrorCode::InvalidCredentials => "invalid_credentials",
            ErrorCode::PasskeyNotRecognised => "passkey_not_recognised",
            ErrorCode::TooManyAttempts => "too_many_attempts",
            ErrorCode::NotSignedIn => "not_signed_in",
            ErrorCode::NeedsRecentSignIn => "needs_recent_sign_in",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::CrossOrigin => "cross_origin",
            ErrorCode::AddressNotAllowed => "address_not_allowed",
            ErrorCode::PasswordsDisabledHere => "passwords_disabled_here",
            ErrorCode::PasskeysUnavailableHere => "passkeys_unavailable_here",
            ErrorCode::CeremonyExpired => "ceremony_expired",
            ErrorCode::UsernameInvalid => "username_invalid",
            ErrorCode::UsernameTaken => "username_taken",
            ErrorCode::RoleInvalid => "role_invalid",
            ErrorCode::AccountDisabled => "account_disabled",
            ErrorCode::LastPasskey => "last_passkey",
            ErrorCode::TooManyPasskeys => "too_many_passkeys",
            ErrorCode::PasskeyAlreadyAdded => "passkey_already_added",
            ErrorCode::PasskeyRejected => "passkey_rejected",
            ErrorCode::NotFound => "not_found",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Internal => "internal",
        }
    }

    /// The HTTP status that fits this code.
    pub const fn http_status(self) -> u16 {
        match self {
            ErrorCode::InvalidCredentials | ErrorCode::PasskeyNotRecognised | ErrorCode::NotSignedIn => 401,
            ErrorCode::NeedsRecentSignIn
            | ErrorCode::Forbidden
            | ErrorCode::CrossOrigin
            | ErrorCode::AddressNotAllowed
            | ErrorCode::PasswordsDisabledHere
            | ErrorCode::PasskeysUnavailableHere
            | ErrorCode::AccountDisabled => 403,
            ErrorCode::NotFound => 404,
            ErrorCode::UsernameTaken
            | ErrorCode::LastPasskey
            | ErrorCode::TooManyPasskeys
            | ErrorCode::PasskeyAlreadyAdded => 409,
            ErrorCode::TooManyAttempts => 429,
            ErrorCode::Busy => 503,
            ErrorCode::Internal => 500,
            ErrorCode::PasswordTooLong
            | ErrorCode::PasswordTooShort
            | ErrorCode::PasswordTooCommon
            | ErrorCode::CeremonyExpired
            | ErrorCode::UsernameInvalid
            | ErrorCode::RoleInvalid
            | ErrorCode::PasskeyRejected
            | ErrorCode::BadRequest => 400,
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
            Error::PasswordTooShort => ErrorCode::PasswordTooShort,
            Error::PasswordTooCommon => ErrorCode::PasswordTooCommon,
            Error::InvalidCredentials => ErrorCode::InvalidCredentials,
            Error::PasskeyNotRecognised => ErrorCode::PasskeyNotRecognised,
            Error::TooManyAttempts { .. } => ErrorCode::TooManyAttempts,
            Error::NotSignedIn => ErrorCode::NotSignedIn,
            Error::NeedsRecentSignIn => ErrorCode::NeedsRecentSignIn,
            Error::Forbidden => ErrorCode::Forbidden,
            Error::CrossOrigin => ErrorCode::CrossOrigin,
            Error::AddressNotAllowed => ErrorCode::AddressNotAllowed,
            Error::PasswordsDisabledHere => ErrorCode::PasswordsDisabledHere,
            Error::PasskeysUnavailableHere => ErrorCode::PasskeysUnavailableHere,
            Error::CeremonyExpired => ErrorCode::CeremonyExpired,
            Error::UsernameInvalid => ErrorCode::UsernameInvalid,
            Error::UsernameTaken => ErrorCode::UsernameTaken,
            Error::RoleInvalid => ErrorCode::RoleInvalid,
            Error::AccountDisabled => ErrorCode::AccountDisabled,
            Error::LastPasskey => ErrorCode::LastPasskey,
            Error::TooManyPasskeys => ErrorCode::TooManyPasskeys,
            Error::PasskeyAlreadyAdded => ErrorCode::PasskeyAlreadyAdded,
            Error::PasskeyRejected => ErrorCode::PasskeyRejected,
            Error::NotFound => ErrorCode::NotFound,
            Error::BadRequest => ErrorCode::BadRequest,
            Error::InvalidHashPolicy
            | Error::NotEnoughMemory
            | Error::Random
            | Error::Hashing
            | Error::Config(_)
            | Error::Store(_) => ErrorCode::Internal,
        }
    }

    /// How long to wait before retrying, for [`Error::TooManyAttempts`].
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Error::TooManyAttempts { retry_after } => Some(*retry_after),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_distinct_snake_case_and_have_statuses() {
        let all = [
            ErrorCode::Busy,
            ErrorCode::PasswordTooLong,
            ErrorCode::PasswordTooShort,
            ErrorCode::PasswordTooCommon,
            ErrorCode::InvalidCredentials,
            ErrorCode::PasskeyNotRecognised,
            ErrorCode::TooManyAttempts,
            ErrorCode::NotSignedIn,
            ErrorCode::NeedsRecentSignIn,
            ErrorCode::Forbidden,
            ErrorCode::CrossOrigin,
            ErrorCode::AddressNotAllowed,
            ErrorCode::PasswordsDisabledHere,
            ErrorCode::PasskeysUnavailableHere,
            ErrorCode::CeremonyExpired,
            ErrorCode::UsernameInvalid,
            ErrorCode::UsernameTaken,
            ErrorCode::RoleInvalid,
            ErrorCode::AccountDisabled,
            ErrorCode::LastPasskey,
            ErrorCode::TooManyPasskeys,
            ErrorCode::PasskeyAlreadyAdded,
            ErrorCode::PasskeyRejected,
            ErrorCode::NotFound,
            ErrorCode::BadRequest,
            ErrorCode::Internal,
        ];
        let mut seen = std::collections::HashSet::new();
        for c in all {
            assert!(seen.insert(c.as_str()), "{c} twice");
            assert!(c.as_str().bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
            assert!((400..600).contains(&c.http_status()));
        }
    }

    #[test]
    fn internal_details_stay_internal() {
        let e = Error::Store(StoreError::Backend("disk I/O error at /var/lib/x".into()));
        assert_eq!(e.code(), ErrorCode::Internal);
        let e = Error::TooManyAttempts { retry_after: Duration::from_secs(3) };
        assert_eq!(e.retry_after(), Some(Duration::from_secs(3)));
    }
}
