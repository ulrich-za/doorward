//! axum integration (feature `axum`): extractors, route guards and ready-made
//! JSON endpoints.
//!
//! Put a [`Doorward`] in the router's state (directly, or in a state struct
//! with `FromRef`), and serve with the peer address available: either
//! `into_make_service_with_connect_info::<SocketAddr>()`, or by inserting a
//! [`Peer`] extension from your own server loop.
//!
//! ```no_run
//! use axum::{Router, routing::get};
//! use doorward::axum::{Authenticated, routes};
//! use doorward::Doorward;
//!
//! async fn dashboard(me: Authenticated) -> String {
//!     format!("hello {}", me.session.user.display_name)
//! }
//!
//! fn app(dw: Doorward) -> Router {
//!     Router::new()
//!         .route("/api/dashboard", get(dashboard))
//!         .nest("/auth", routes())
//!         .with_state(dw)
//! }
//! ```
//!
//! Every endpoint answers JSON and `Cache-Control: no-store`. Errors are
//! `{"error": "<code>"}` with the status from [`ErrorCode::http_status`]
//! (and `retry_after` seconds plus a `Retry-After` header when rate-limited).

use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRef, FromRequestParts, Path, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::doorward::{AddressInfo, Doorward, RequestInfo, Visit};
use crate::error::{Error, ErrorCode};
use crate::model::{SecurityEvent, Session, SessionInfo, SetCookie, SignInMethod, SignedIn, User};

/// The connection's peer address, for servers that don't use axum's
/// `ConnectInfo` (insert it as a request extension).
#[derive(Clone, Copy, Debug)]
pub struct Peer(pub IpAddr);

/// An error as an HTTP response.
#[derive(Debug)]
pub struct AuthError {
    error: Error,
    clear_cookie: Option<SetCookie>,
}

impl From<Error> for AuthError {
    fn from(error: Error) -> AuthError {
        AuthError { error, clear_cookie: None }
    }
}

impl AuthError {
    /// The error inside.
    pub fn error(&self) -> &Error {
        &self.error
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let code = self.error.code();
        if code == ErrorCode::Internal {
            tracing::error!(target: "doorward", "request failed: {}", self.error);
        }
        let status = StatusCode::from_u16(code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let retry = self.error.retry_after().map(|d| d.as_secs_f64().ceil().max(1.0) as u64);
        let body = match retry {
            Some(s) => serde_json::json!({ "error": code.as_str(), "retry_after": s }),
            None => serde_json::json!({ "error": code.as_str() }),
        };
        let mut resp = (status, Json(body)).into_response();
        let h = resp.headers_mut();
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if let Some(s) = retry {
            h.insert(header::RETRY_AFTER, HeaderValue::from(s));
        }
        if let Some(c) = self.clear_cookie
            && let Ok(v) = HeaderValue::from_str(c.as_str())
        {
            h.append(header::SET_COOKIE, v);
        }
        resp
    }
}

fn peer_of(parts: &Parts) -> Option<IpAddr> {
    if let Some(p) = parts.extensions.get::<Peer>() {
        return Some(p.0);
    }
    parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip())
}

/// Build the [`Visit`] for a request.
pub fn visit_of(dw: &Doorward, parts: &Parts) -> Result<Visit, Error> {
    let Some(peer) = peer_of(parts) else {
        tracing::error!(
            target: "doorward",
            "no peer address: serve with into_make_service_with_connect_info::<SocketAddr>() or insert doorward::axum::Peer"
        );
        return Err(Error::Config("no peer address on the request".into()));
    };
    let authority = parts.uri.authority().map(|a| a.as_str());
    let host = if parts.headers.contains_key(header::HOST) { None } else { authority };
    dw.visit(&RequestInfo { peer, method: &parts.method, host, headers: &parts.headers })
}

/// The request as doorward sees it (which address, who, which cookies).
#[derive(Clone, Debug)]
pub struct Visitor(pub Visit);

impl<S> FromRequestParts<S> for Visitor
where
    Doorward: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let Some(v) = parts.extensions.get::<Visitor>() {
            return Ok(v.clone());
        }
        let dw = Doorward::from_ref(state);
        let v = Visitor(visit_of(&dw, parts)?);
        parts.extensions.insert(v.clone());
        Ok(v)
    }
}

/// A signed-in request: refuses with 401 `not_signed_in` otherwise, and with
/// 403 `cross_origin` for a write from another site.
#[derive(Clone, Debug)]
pub struct Authenticated {
    /// The request.
    pub visit: Visit,
    /// Its session and user.
    pub session: Session,
}

impl Authenticated {
    /// Refuse with 403 `forbidden` unless the user has `role`.
    pub fn require_role(&self, role: &str) -> Result<(), AuthError> {
        if self.session.user.has_role(role) { Ok(()) } else { Err(Error::Forbidden.into()) }
    }
}

impl<S> FromRequestParts<S> for Authenticated
where
    Doorward: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let Some(a) = parts.extensions.get::<Authenticated>() {
            return Ok(a.clone());
        }
        let dw = Doorward::from_ref(state);
        let Visitor(visit) = Visitor::from_request_parts(parts, state).await?;
        match dw.authenticate(&visit).await? {
            Some(session) => {
                let a = Authenticated { visit, session };
                parts.extensions.insert(a.clone());
                Ok(a)
            }
            None => Err(AuthError {
                error: Error::NotSignedIn,
                clear_cookie: visit.has_session_cookie().then(|| dw.clear_session_cookie()),
            }),
        }
    }
}

/// A signed-in request whose user proved who they are recently (403
/// `needs_recent_sign_in` otherwise). Use it for sensitive actions.
#[derive(Clone, Debug)]
pub struct Recent(pub Authenticated);

impl<S> FromRequestParts<S> for Recent
where
    Doorward: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let a = Authenticated::from_request_parts(parts, state).await?;
        Doorward::from_ref(state).require_recent(&a.session)?;
        Ok(Recent(a))
    }
}

/// Middleware: only signed-in requests reach the routes behind it.
///
/// ```ignore
/// .route_layer(axum::middleware::from_fn_with_state(dw.clone(), doorward::axum::require_signed_in))
/// ```
pub async fn require_signed_in(State(dw): State<Doorward>, req: Request, next: Next) -> Response {
    let (mut parts, body) = req.into_parts();
    match Authenticated::from_request_parts(&mut parts, &dw).await {
        Ok(_) => next.run(Request::from_parts(parts, body)).await,
        Err(e) => e.into_response(),
    }
}

/// Middleware: only signed-in users with the role reach the routes behind it.
///
/// ```ignore
/// .route_layer(axum::middleware::from_fn_with_state((dw.clone(), "admin"), doorward::axum::require_role))
/// ```
pub async fn require_role(State((dw, role)): State<(Doorward, &'static str)>, req: Request, next: Next) -> Response {
    let (mut parts, body) = req.into_parts();
    match Authenticated::from_request_parts(&mut parts, &dw).await {
        Ok(a) if a.session.user.has_role(role) => next.run(Request::from_parts(parts, body)).await,
        Ok(_) => AuthError::from(Error::Forbidden).into_response(),
        Err(e) => e.into_response(),
    }
}

// ----- JSON endpoints -----------------------------------------------------------

/// What `GET /session` answers.
#[derive(Debug, Serialize)]
pub struct SessionView {
    /// Signed in at all.
    pub signed_in: bool,
    /// What this address offers (for the sign-in page).
    pub address: AddressInfo,
    /// The user, when signed in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,
    /// How the session was signed in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<SignInMethod>,
    /// Milliseconds left in which sensitive actions need no confirmation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_left_ms: Option<u64>,
    /// When the session ends if not used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_ms: Option<i64>,
}

fn session_view(dw: &Doorward, v: &Visit, s: Option<&Session>) -> SessionView {
    SessionView {
        signed_in: s.is_some(),
        address: dw.address_info(v),
        user: s.map(|s| s.user.clone()),
        method: s.map(|s| s.method),
        recent_left_ms: s.map(|s| dw.recent_left(s).as_millis().min(u64::MAX as u128) as u64),
        expires_ms: s.map(|s| s.expires_ms),
    }
}

fn no_store(mut r: Response) -> Response {
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn with_cookies(mut r: Response, cookies: &[SetCookie]) -> Response {
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c.as_str()) {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    no_store(r)
}

fn signed_in_response(dw: &Doorward, v: &Visit, s: SignedIn) -> Response {
    with_cookies(Json(session_view(dw, v, Some(&s.session))).into_response(), &s.cookies)
}

/// `POST /sign-in` body.
#[derive(Deserialize)]
pub struct PasswordSignIn {
    /// The username.
    pub username: String,
    /// The password.
    pub password: Zeroizing<String>,
    /// "Keep me signed in".
    #[serde(default)]
    pub remember: bool,
}

/// `POST /confirm` body.
#[derive(Deserialize)]
pub struct Confirm {
    /// The current password.
    pub password: Zeroizing<String>,
}

/// `POST /password` body.
#[derive(Deserialize)]
pub struct NewPassword {
    /// The current password (required when the user has one).
    #[serde(default)]
    pub current_password: Option<Zeroizing<String>>,
    /// The new password.
    pub new_password: Zeroizing<String>,
}

/// The JSON endpoints, to nest under a prefix such as `/auth`:
///
/// | Method | Path | |
/// |---|---|---|
/// | GET | `/session` | Signed in? Who? What this address offers |
/// | POST | `/sign-in` | `{username, password, remember}` |
/// | POST | `/sign-out` | |
/// | POST | `/confirm` | `{password}`: counts as a recent sign-in |
/// | POST | `/password` | `{current_password, new_password}` (no current password for a passkey-only user, who needs a recent sign-in instead) |
/// | GET | `/sessions` | Where you're signed in |
/// | DELETE | `/sessions/{id}` | End one |
/// | POST | `/sessions/end-others` | Sign out everywhere else |
/// | GET | `/events` | Your recent security log |
///
/// With the `passkeys` feature, also: `POST /passkey/sign-in/start`,
/// `POST /passkey/sign-in/finish` (`{ceremony, credential, remember}`),
/// `POST /passkey/confirm/start`, `POST /passkey/confirm/finish`,
/// `GET /passkeys`, `POST /passkeys/register/start` (`{label}`),
/// `POST /passkeys/register/finish` (`{ceremony, credential}`),
/// `PATCH /passkeys/{id}` (`{label}`) and `DELETE /passkeys/{id}`.
pub fn routes<S>() -> Router<S>
where
    Doorward: FromRef<S>,
    S: Clone + Send + Sync + 'static,
{
    let r = Router::new()
        .route("/session", get(get_session))
        .route("/sign-in", post(sign_in))
        .route("/sign-out", post(sign_out))
        .route("/confirm", post(confirm))
        .route("/password", post(change_password))
        .route("/sessions", get(list_sessions))
        .route("/sessions/{id}", delete(end_session))
        .route("/sessions/end-others", post(end_others))
        .route("/events", get(events));
    #[cfg(feature = "passkeys")]
    let r = r
        .route("/passkey/sign-in/start", post(passkeys::sign_in_start))
        .route("/passkey/sign-in/finish", post(passkeys::sign_in_finish))
        .route("/passkey/confirm/start", post(passkeys::confirm_start))
        .route("/passkey/confirm/finish", post(passkeys::confirm_finish))
        .route("/passkeys", get(passkeys::list))
        .route("/passkeys/register/start", post(passkeys::register_start))
        .route("/passkeys/register/finish", post(passkeys::register_finish))
        .route("/passkeys/{id}", axum::routing::patch(passkeys::rename).delete(passkeys::remove));
    r.layer(DefaultBodyLimit::max(64 * 1024))
}

async fn get_session<S>(State(state): State<S>, Visitor(v): Visitor) -> Result<Response, AuthError>
where
    Doorward: FromRef<S>,
{
    let dw = Doorward::from_ref(&state);
    let s = dw.authenticate(&v).await?;
    let mut resp = no_store(Json(session_view(&dw, &v, s.as_ref())).into_response());
    if s.is_none()
        && v.has_session_cookie()
        && let Ok(c) = HeaderValue::from_str(dw.clear_session_cookie().as_str())
    {
        resp.headers_mut().append(header::SET_COOKIE, c);
    }
    Ok(resp)
}

async fn sign_in<S>(
    State(state): State<S>,
    Visitor(v): Visitor,
    Json(b): Json<PasswordSignIn>,
) -> Result<Response, AuthError>
where
    Doorward: FromRef<S>,
{
    let dw = Doorward::from_ref(&state);
    let s = dw.sign_in_password(&v, &b.username, &b.password, b.remember).await?;
    Ok(signed_in_response(&dw, &v, s))
}

async fn sign_out<S>(State(state): State<S>, Visitor(v): Visitor) -> Result<Response, AuthError>
where
    Doorward: FromRef<S>,
{
    let dw = Doorward::from_ref(&state);
    let c = dw.sign_out(&v).await?;
    Ok(with_cookies(StatusCode::NO_CONTENT.into_response(), &[c]))
}

async fn confirm<S>(State(state): State<S>, Visitor(v): Visitor, Json(b): Json<Confirm>) -> Result<Response, AuthError>
where
    Doorward: FromRef<S>,
{
    let dw = Doorward::from_ref(&state);
    let s = dw.confirm_password(&v, &b.password).await?;
    Ok(signed_in_response(&dw, &v, s))
}

async fn change_password<S>(
    State(state): State<S>,
    Visitor(v): Visitor,
    Json(b): Json<NewPassword>,
) -> Result<Response, AuthError>
where
    Doorward: FromRef<S>,
{
    let dw = Doorward::from_ref(&state);
    let s = dw.change_password(&v, b.current_password.as_deref().map(|p| p.as_str()), &b.new_password).await?;
    Ok(signed_in_response(&dw, &v, s))
}

async fn list_sessions<S>(State(state): State<S>, me: Authenticated) -> Result<Json<Vec<SessionInfo>>, AuthError>
where
    Doorward: FromRef<S>,
{
    Ok(Json(Doorward::from_ref(&state).sessions(&me.session).await?))
}

async fn end_session<S>(State(state): State<S>, me: Authenticated, Path(id): Path<Uuid>) -> Result<Response, AuthError>
where
    Doorward: FromRef<S>,
{
    let dw = Doorward::from_ref(&state);
    dw.end_session(&me.visit, &me.session, id).await?;
    let cookies = if id == me.session.id { vec![dw.clear_session_cookie()] } else { vec![] };
    Ok(with_cookies(StatusCode::NO_CONTENT.into_response(), &cookies))
}

async fn end_others<S>(State(state): State<S>, me: Authenticated) -> Result<Json<serde_json::Value>, AuthError>
where
    Doorward: FromRef<S>,
{
    let n = Doorward::from_ref(&state).end_other_sessions(&me.visit, &me.session).await?;
    Ok(Json(serde_json::json!({ "ended": n })))
}

async fn events<S>(State(state): State<S>, me: Authenticated) -> Result<Json<Vec<SecurityEvent>>, AuthError>
where
    Doorward: FromRef<S>,
{
    Ok(Json(Doorward::from_ref(&state).events(&me.session, 50).await?))
}

#[cfg(feature = "passkeys")]
mod passkeys {
    use super::*;
    use crate::passkey::{PasskeyInfo, PublicKeyCredential, RegisterPublicKeyCredential};

    #[derive(Deserialize)]
    pub struct Finish {
        ceremony: String,
        credential: PublicKeyCredential,
        #[serde(default)]
        remember: bool,
    }

    #[derive(Deserialize)]
    pub struct RegisterFinish {
        ceremony: String,
        credential: RegisterPublicKeyCredential,
    }

    #[derive(Deserialize)]
    pub struct Label {
        #[serde(default)]
        label: String,
    }

    pub async fn sign_in_start<S>(State(state): State<S>, Visitor(v): Visitor) -> Result<Response, AuthError>
    where
        Doorward: FromRef<S>,
    {
        let c = Doorward::from_ref(&state).passkey_sign_in_start(&v).await?;
        Ok(no_store(Json(c).into_response()))
    }

    pub async fn sign_in_finish<S>(
        State(state): State<S>,
        Visitor(v): Visitor,
        Json(b): Json<Finish>,
    ) -> Result<Response, AuthError>
    where
        Doorward: FromRef<S>,
    {
        let dw = Doorward::from_ref(&state);
        let s = dw.passkey_sign_in_finish(&v, &b.ceremony, &b.credential, b.remember).await?;
        Ok(signed_in_response(&dw, &v, s))
    }

    pub async fn confirm_start<S>(State(state): State<S>, Visitor(v): Visitor) -> Result<Response, AuthError>
    where
        Doorward: FromRef<S>,
    {
        let c = Doorward::from_ref(&state).passkey_confirm_start(&v).await?;
        Ok(no_store(Json(c).into_response()))
    }

    pub async fn confirm_finish<S>(
        State(state): State<S>,
        Visitor(v): Visitor,
        Json(b): Json<Finish>,
    ) -> Result<Response, AuthError>
    where
        Doorward: FromRef<S>,
    {
        let dw = Doorward::from_ref(&state);
        let s = dw.passkey_confirm_finish(&v, &b.ceremony, &b.credential).await?;
        Ok(signed_in_response(&dw, &v, s))
    }

    pub async fn list<S>(State(state): State<S>, me: Authenticated) -> Result<Json<Vec<PasskeyInfo>>, AuthError>
    where
        Doorward: FromRef<S>,
    {
        Ok(Json(Doorward::from_ref(&state).passkeys(&me.visit, &me.session).await?))
    }

    pub async fn register_start<S>(
        State(state): State<S>,
        Visitor(v): Visitor,
        Json(b): Json<Label>,
    ) -> Result<Response, AuthError>
    where
        Doorward: FromRef<S>,
    {
        let c = Doorward::from_ref(&state).passkey_register_start(&v, &b.label).await?;
        Ok(no_store(Json(c).into_response()))
    }

    pub async fn register_finish<S>(
        State(state): State<S>,
        Visitor(v): Visitor,
        Json(b): Json<RegisterFinish>,
    ) -> Result<Json<PasskeyInfo>, AuthError>
    where
        Doorward: FromRef<S>,
    {
        Ok(Json(Doorward::from_ref(&state).passkey_register_finish(&v, &b.ceremony, &b.credential).await?))
    }

    pub async fn rename<S>(
        State(state): State<S>,
        me: Authenticated,
        Path(id): Path<Uuid>,
        Json(b): Json<Label>,
    ) -> Result<StatusCode, AuthError>
    where
        Doorward: FromRef<S>,
    {
        Doorward::from_ref(&state).rename_passkey(&me.visit, &me.session, id, &b.label).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    pub async fn remove<S>(
        State(state): State<S>,
        me: Authenticated,
        Path(id): Path<Uuid>,
    ) -> Result<StatusCode, AuthError>
    where
        Doorward: FromRef<S>,
    {
        Doorward::from_ref(&state).remove_passkey(&me.visit, &me.session, id).await?;
        Ok(StatusCode::NO_CONTENT)
    }
}
