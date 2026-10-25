//! The axum layer over HTTP: endpoints, guards, status codes and headers.

#![cfg(feature = "axum")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use axum::Router;
use axum::body::Body;
use axum::routing::get;
use common::*;
use doorward::Doorward;
use doorward::axum::{Authenticated, Peer, Recent, routes};
use http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::net::IpAddr;
use std::time::Duration;
use tower::ServiceExt;

async fn secret(me: Authenticated) -> String {
    format!("hello {}", me.session.user.username)
}

async fn sensitive(Recent(me): Recent) -> String {
    format!("recent {}", me.session.user.username)
}

fn app(dw: &Doorward) -> Router {
    let admin = Router::new()
        .route("/api/admin", get(|| async { "admin area" }))
        .route_layer(axum::middleware::from_fn_with_state((dw.clone(), "admin"), doorward::axum::require_role));
    Router::new()
        .route("/api/secret", get(secret))
        .route("/api/sensitive", get(sensitive))
        .merge(admin)
        .nest("/auth", routes())
        .with_state(dw.clone())
}

struct Client {
    app: Router,
    host: String,
    origin: String,
    ip: IpAddr,
    jar: std::collections::BTreeMap<String, String>,
}

struct Resp {
    status: StatusCode,
    headers: http::HeaderMap,
    body: Value,
    text: String,
}

impl Client {
    fn new(dw: &Doorward) -> Client {
        Client {
            app: app(dw),
            host: "pc.lan:8040".into(),
            origin: LAN.into(),
            ip: "192.168.1.20".parse().unwrap(),
            jar: Default::default(),
        }
    }

    async fn send(&mut self, method: &str, path: &str, body: Option<Value>) -> Resp {
        self.send_raw(method, path, body.map(|b| ("application/json", b.to_string())), true).await
    }

    async fn send_raw(&mut self, method: &str, path: &str, body: Option<(&str, String)>, with_peer: bool) -> Resp {
        let mut b = Request::builder().method(method).uri(path).header(header::HOST, &self.host);
        if method != "GET" {
            b = b.header(header::ORIGIN, &self.origin);
        }
        if !self.jar.is_empty() {
            let c: Vec<String> = self.jar.iter().map(|(k, v)| format!("{k}={v}")).collect();
            b = b.header(header::COOKIE, c.join("; "));
        }
        if with_peer {
            b = b.extension(Peer(self.ip));
        }
        let req = match body {
            Some((ct, s)) => b.header(header::CONTENT_TYPE, ct).body(Body::from(s)).unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        for c in headers.get_all(header::SET_COOKIE) {
            let s = c.to_str().unwrap();
            let (kv, _) = s.split_once(';').unwrap();
            let (k, v) = kv.split_once('=').unwrap();
            if v.is_empty() || s.contains("Max-Age=0") {
                self.jar.remove(k);
            } else {
                self.jar.insert(k.into(), v.into());
            }
        }
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&bytes).to_string();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Resp { status, headers, body, text }
    }
}

#[tokio::test]
async fn sign_in_over_http() {
    let e = env().await;
    e.user("admin", Some("correct horse battery")).await;
    let mut c = Client::new(&e.dw);

    let r = c.send("GET", "/auth/session", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["signed_in"], false);
    assert_eq!(r.body["address"], json!({"origin": LAN, "passwords": true, "passkeys": true, "remember": true}));
    assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");

    let r = c.send("GET", "/api/secret", None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.body, json!({"error": "not_signed_in"}));

    let r = c.send("POST", "/auth/sign-in", Some(json!({"username": "admin", "password": "wrong"}))).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::UNAUTHORIZED, Some("invalid_credentials")));

    let r = c
        .send(
            "POST",
            "/auth/sign-in",
            Some(json!({"username": "admin", "password": "correct horse battery", "remember": true})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    assert_eq!(r.body["signed_in"], true);
    assert_eq!(r.body["user"]["username"], "admin");
    assert_eq!(r.body["method"], "password");
    assert_eq!(r.headers.get_all(header::SET_COOKIE).iter().count(), 2);
    assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");
    assert!(!r.text.contains(&c.jar["__Host-doorward"]), "the token is only in the cookie");

    let r = c.send("GET", "/api/secret", None).await;
    assert_eq!((r.status, r.text.as_str()), (StatusCode::OK, "hello admin"));
    let r = c.send("GET", "/auth/sessions", None).await;
    assert_eq!(r.body.as_array().unwrap().len(), 1);
    assert_eq!(r.body[0]["current"], true);
    let r = c.send("GET", "/auth/events", None).await;
    assert!(r.body.as_array().unwrap().iter().any(|e| e["kind"] == "sign_in"));

    let r = c.send("POST", "/auth/sign-out", None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(!c.jar.contains_key("__Host-doorward"));
    assert_eq!(c.send("GET", "/api/secret", None).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_stale_cookie_is_cleared() {
    let e = env().await;
    let mut c = Client::new(&e.dw);
    c.jar.insert("__Host-doorward".into(), "A".repeat(43));
    let r = c.send("GET", "/api/secret", None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.headers[header::SET_COOKIE].to_str().unwrap().contains("Max-Age=0"));
    assert!(!c.jar.contains_key("__Host-doorward"));
}

#[tokio::test]
async fn refusals_have_the_right_status_and_headers() {
    let e = env_with(|b| b.limits(doorward::Limits { visitor_burst: 2, ..Default::default() })).await;
    e.user("admin", Some("correct horse battery")).await;
    let mut c = Client::new(&e.dw);
    for _ in 0..2 {
        c.send("POST", "/auth/sign-in", Some(json!({"username": "admin", "password": "x"}))).await;
    }
    let r = c.send("POST", "/auth/sign-in", Some(json!({"username": "admin", "password": "x"}))).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.body["error"], "too_many_attempts");
    assert_eq!(r.headers[header::RETRY_AFTER], "3");
    assert_eq!(r.body["retry_after"], 3);

    // A form post (what a cross-site page could send without CORS) is refused.
    let mut c = Client::new(&e.dw);
    let r = c
        .send_raw(
            "POST",
            "/auth/sign-in",
            Some(("application/x-www-form-urlencoded", "username=admin&password=x".into())),
            true,
        )
        .await;
    assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    // An unknown host.
    let mut c = Client::new(&e.dw);
    c.host = "evil.example".into();
    let r = c.send("GET", "/auth/session", None).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::FORBIDDEN, Some("address_not_allowed")));
    // A server that forgot to provide the peer address.
    let mut c = Client::new(&e.dw);
    let r = c.send_raw("GET", "/auth/session", None, false).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::INTERNAL_SERVER_ERROR, Some("internal")));
    assert!(!r.text.contains("peer"), "no internals in the response");
    // Oversized bodies.
    let mut c = Client::new(&e.dw);
    let huge = json!({"username": "admin", "password": "x".repeat(100_000)});
    let r = c.send("POST", "/auth/sign-in", Some(huge)).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn cross_site_writes_are_refused() {
    let e = env().await;
    e.user("admin", Some("correct horse battery")).await;
    let mut c = Client::new(&e.dw);
    c.send("POST", "/auth/sign-in", Some(json!({"username": "admin", "password": "correct horse battery"}))).await;
    c.origin = "https://evil.example".into();
    let r = c.send("POST", "/auth/password", Some(json!({"new_password": "hijacked password"}))).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::FORBIDDEN, Some("cross_origin")));
    let r = c.send("POST", "/auth/sessions/end-others", None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn roles_and_recent_sign_in() {
    let e = env().await;
    let admin = e.user("admin", Some("correct horse battery")).await;
    e.dw.set_roles(admin.id, &["admin".into()]).await.unwrap();
    e.user("tech", Some("a tech's password")).await;
    let mut a = Client::new(&e.dw);
    a.send("POST", "/auth/sign-in", Some(json!({"username": "admin", "password": "correct horse battery"}))).await;
    let mut t = Client::new(&e.dw);
    t.send("POST", "/auth/sign-in", Some(json!({"username": "tech", "password": "a tech's password"}))).await;
    assert_eq!(a.send("GET", "/api/admin", None).await.status, StatusCode::OK);
    let r = t.send("GET", "/api/admin", None).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::FORBIDDEN, Some("forbidden")));
    let mut nobody = Client::new(&e.dw);
    assert_eq!(nobody.send("GET", "/api/admin", None).await.status, StatusCode::UNAUTHORIZED);

    assert_eq!(a.send("GET", "/api/sensitive", None).await.status, StatusCode::OK);
    e.clock.advance(Duration::from_secs(11 * 60));
    let r = a.send("GET", "/api/sensitive", None).await;
    assert_eq!((r.status, r.body["error"].as_str()), (StatusCode::FORBIDDEN, Some("needs_recent_sign_in")));
    let r = a.send("POST", "/auth/confirm", Some(json!({"password": "correct horse battery"}))).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body["recent_left_ms"].as_u64().unwrap() > 590_000);
    assert_eq!(a.send("GET", "/api/sensitive", None).await.status, StatusCode::OK);
    let r = a.send("POST", "/auth/password", Some(json!({"new_password": "short"}))).await;
    assert_eq!(r.body["error"], "password_too_short");
    let r = a.send("POST", "/auth/password", Some(json!({"new_password": "a much longer password"}))).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
}

#[cfg(all(feature = "passkeys", feature = "test-util"))]
#[tokio::test]
async fn passkeys_over_http() {
    use doorward::testing::TestAuthenticator;
    let e = env().await;
    e.user("admin", Some("correct horse battery")).await;
    let mut c = Client::new(&e.dw);
    c.send("POST", "/auth/sign-in", Some(json!({"username": "admin", "password": "correct horse battery"}))).await;
    let mut device = TestAuthenticator::new();
    let r = c.send("POST", "/auth/passkeys/register/start", Some(json!({"label": "Phone"}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    let answer = device.register(LAN, &r.body["options"]).unwrap();
    let r = c
        .send(
            "POST",
            "/auth/passkeys/register/finish",
            Some(json!({"ceremony": r.body["ceremony"], "credential": answer})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    let id = r.body["id"].as_str().unwrap().to_string();
    let r = c.send("PATCH", &format!("/auth/passkeys/{id}"), Some(json!({"label": "Work phone"}))).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = c.send("GET", "/auth/passkeys", None).await;
    assert_eq!(r.body[0]["label"], "Work phone");
    assert_eq!(r.body[0]["here"], true);

    let mut fresh = Client::new(&e.dw);
    let r = fresh.send("POST", "/auth/passkey/sign-in/start", None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    let answer = device.sign_in(LAN, &r.body["options"]).unwrap();
    let r = fresh
        .send(
            "POST",
            "/auth/passkey/sign-in/finish",
            Some(json!({"ceremony": r.body["ceremony"], "credential": answer})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    assert_eq!(r.body["method"], "passkey");
    assert_eq!(fresh.send("GET", "/api/secret", None).await.text, "hello admin");

    let r = fresh.send("POST", "/auth/passkey/sign-in/finish", Some(json!({"ceremony": "nope", "credential": device.sign_in(LAN, &json!({"publicKey": {"rpId": "pc.lan", "challenge": "AAAA"}})).unwrap()}))).await;
    assert_eq!(r.body["error"], "ceremony_expired");
    let r = c.send("DELETE", &format!("/auth/passkeys/{id}"), None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
}
