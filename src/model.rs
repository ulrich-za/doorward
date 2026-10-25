//! What doorward hands back to the app: users, sessions, cookies to set and
//! security log lines.

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::store::{EventRecord, SessionRecord, UserRecord};

/// A user account.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct User {
    /// Random and permanent.
    pub id: Uuid,
    /// The name as written (normalised).
    pub username: String,
    /// A name to show.
    pub display_name: String,
    /// The app's roles for this user, sorted.
    pub roles: Vec<String>,
    /// Disabled accounts can't sign in.
    pub active: bool,
    /// When the account was made (ms since the Unix epoch).
    pub created_ms: i64,
}

impl User {
    /// Does the user have this role?
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

impl From<UserRecord> for User {
    fn from(u: UserRecord) -> User {
        User {
            id: u.id,
            username: u.username,
            display_name: u.display_name,
            roles: u.roles,
            active: u.active,
            created_ms: u.created_ms,
        }
    }
}

/// How a session was signed in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignInMethod {
    /// With a password.
    Password,
    /// With a passkey.
    Passkey,
}

impl SignInMethod {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SignInMethod::Password => "password",
            SignInMethod::Passkey => "passkey",
        }
    }

    pub(crate) fn parse(s: &str) -> SignInMethod {
        if s == "passkey" { SignInMethod::Passkey } else { SignInMethod::Password }
    }
}

/// The session a request belongs to, with its user.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Session {
    /// The session's public id (not its cookie).
    pub id: Uuid,
    /// Whose session it is.
    pub user: User,
    /// The origin it belongs to.
    pub address: String,
    /// How it was signed in.
    pub method: SignInMethod,
    /// When it began.
    pub created_ms: i64,
    /// The last time the user proved who they are.
    pub auth_ms: i64,
    /// When it ends if not used again.
    pub expires_ms: i64,
    /// Whether the cookie outlives the browser.
    pub persistent: bool,
}

impl Session {
    pub(crate) fn from_parts(r: &SessionRecord, user: User) -> Session {
        Session {
            id: r.id,
            user,
            address: r.address.clone(),
            method: SignInMethod::parse(&r.method),
            created_ms: r.created_ms,
            auth_ms: r.auth_ms,
            expires_ms: r.expires_ms(),
            persistent: r.persistent,
        }
    }
}

/// One of a user's sessions, for a "where you're signed in" list.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SessionInfo {
    /// Its public id, for ending it.
    pub id: Uuid,
    /// The origin it belongs to.
    pub address: String,
    /// How it was signed in.
    pub method: SignInMethod,
    /// When it began.
    pub created_ms: i64,
    /// Its last request.
    pub last_seen_ms: i64,
    /// When it ends if not used again.
    pub expires_ms: i64,
    /// The visitor's address at its last request.
    pub ip: Option<String>,
    /// The browser it was signed in from.
    pub user_agent: Option<String>,
    /// The session making this request.
    pub current: bool,
}

impl SessionInfo {
    pub(crate) fn from_record(r: &SessionRecord, current: Uuid) -> SessionInfo {
        SessionInfo {
            id: r.id,
            address: r.address.clone(),
            method: SignInMethod::parse(&r.method),
            created_ms: r.created_ms,
            last_seen_ms: r.last_seen_ms,
            expires_ms: r.expires_ms(),
            ip: r.ip.clone(),
            user_agent: r.user_agent.clone(),
            current: r.id == current,
        }
    }
}

/// A line of a user's security log.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SecurityEvent {
    /// When it happened.
    pub at_ms: i64,
    /// What happened, such as `"sign_in"`.
    pub kind: String,
    /// The origin it happened on.
    pub address: Option<String>,
    /// The visitor's address.
    pub ip: Option<String>,
    /// Detail as JSON text, if any.
    pub detail: Option<String>,
}

impl From<EventRecord> for SecurityEvent {
    fn from(e: EventRecord) -> SecurityEvent {
        SecurityEvent { at_ms: e.at_ms, kind: e.kind, address: e.address, ip: e.ip, detail: e.detail }
    }
}

/// A `Set-Cookie` header value for the app to send with its response.
#[derive(Clone, PartialEq, Eq)]
pub struct SetCookie(pub(crate) Zeroizing<String>);

impl SetCookie {
    /// The header value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn set(name: &str, value: &str, max_age_secs: Option<i64>) -> SetCookie {
        let mut s = format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Strict");
        if let Some(age) = max_age_secs {
            s.push_str(&format!("; Max-Age={}", age.max(1)));
        }
        SetCookie(Zeroizing::new(s))
    }

    pub(crate) fn clear(name: &str) -> SetCookie {
        SetCookie(Zeroizing::new(format!("{name}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")))
    }
}

impl std::fmt::Debug for SetCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the cookie's value.
        let name = self.0.split('=').next().unwrap_or("");
        write!(f, "SetCookie({name}=…)")
    }
}

/// A successful sign-in: the new session, and the cookies to set.
#[derive(Debug)]
#[must_use = "the cookies must be sent to the browser"]
pub struct SignedIn {
    /// The new session.
    pub session: Session,
    /// `Set-Cookie` values to add to the response.
    pub cookies: Vec<SetCookie>,
}

/// Rules for new passwords.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordRules {
    /// Fewest characters. NIST SP 800-63B asks for at least 15 when a password
    /// is the only way to sign in, and 8 when it is paired with another factor.
    pub min_chars: usize,
    /// Most characters (never more than 1 KiB of UTF-8 in any case).
    pub max_chars: usize,
    /// Refuse the 5,000 most common passwords of 8 or more characters
    /// (OWASP ASVS 6.2.4 asks for at least the top 3,000).
    pub refuse_common: bool,
}

impl Default for PasswordRules {
    fn default() -> PasswordRules {
        PasswordRules { min_chars: 8, max_chars: 256, refuse_common: true }
    }
}

/// A new account for [`Doorward::create_user`](crate::Doorward::create_user).
/// Its `Debug` output leaves the password out.
#[derive(Clone, Default)]
pub struct NewUser {
    /// The username (checked by [`Username::parse`](crate::Username::parse)).
    pub username: String,
    /// A name to show (defaults to the username).
    pub display_name: Option<String>,
    /// The app's roles.
    pub roles: Vec<String>,
    /// A first password, if the account should have one.
    pub password: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for NewUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewUser")
            .field("username", &self.username)
            .field("display_name", &self.display_name)
            .field("roles", &self.roles)
            .field("has_password", &self.password.is_some())
            .finish()
    }
}
