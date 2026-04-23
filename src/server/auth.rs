// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 IONOS SE
// Author: Roman Penyaev <r.peniaev@gmail.com>

use axum::{
    body::Body,
    extract::Extension,
    http::{header, HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine;
use cookie::Cookie;
use std::sync::Arc;

use argon2::{password_hash::PasswordVerifier, Argon2, PasswordHash};
use ring::hmac;

use crate::master_password::MasterAuth;

const SESSION_COOKIE: &str = "master_session";

pub async fn master_auth_middleware(
    Extension(master): Extension<Arc<MasterAuth>>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    // Allow the login endpoint to proceed without auth
    let path = request.uri().path();
    if path == "/login" {
        return next.run(request).await;
    }

    // Cookie-based session
    let cookie_ok = request
        .headers()
        .get(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .map(|cookie_str| {
            let mut ok = false;
            for c in cookie::Cookie::split_parse(cookie_str).flatten() {
                if c.name() == SESSION_COOKIE {
                    ok = validate_session(&master, c.value());
                    break;
                }
            }
            ok
        })
        .unwrap_or(false);

    if cookie_ok {
        return next.run(request).await;
    }

    let authorized = verify_master_from_header(request.headers(), &master);

    if authorized {
        // Issue a session cookie for subsequent requests
        let session = issue_session(&master);
        let cookie = Cookie::build((SESSION_COOKIE, session))
            .path("/")
            .http_only(true)
            .same_site(cookie::SameSite::Lax)
            .build();

        let mut resp = next.run(request).await.into_response();
        resp.headers_mut()
            .append(header::SET_COOKIE, cookie.to_string().parse().unwrap());
        resp
    } else {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::WWW_AUTHENTICATE,
            "Basic realm=\"SnpGuard Management\"".parse().unwrap(),
        );
        // Redirect GET requests to the login page
        if request.method() == axum::http::Method::GET {
            return Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header(header::LOCATION, "/login")
                .body(Body::empty())
                .unwrap();
        }

        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                header::WWW_AUTHENTICATE,
                "Basic realm=\"SnpGuard Management\"",
            )
            .body(Body::from("Unauthorized - enter master password"))
            .unwrap()
    }
}

/// Verify master password using HTTP Basic Authorization header.
pub fn verify_master_from_header(headers: &HeaderMap, master: &MasterAuth) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Basic "))
        .and_then(|encoded| {
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .ok()
        })
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .and_then(|credentials| {
            credentials
                .split_once(':')
                .map(|x| x.1)
                .map(|pw| pw.to_owned())
        })
        .map(|supplied_password| verify_password(master, &supplied_password))
        .unwrap_or(false)
}

pub fn verify_password(master: &MasterAuth, supplied_password: &str) -> bool {
    if let Ok(parsed_hash) = PasswordHash::new(&master.hash) {
        let argon2 = Argon2::default();
        argon2
            .verify_password(supplied_password.as_bytes(), &parsed_hash)
            .is_ok()
    } else {
        false
    }
}

pub fn issue_session(master: &MasterAuth) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, master.hash.as_bytes());
    let tag = hmac::sign(&key, b"master-session");
    base64::engine::general_purpose::STANDARD.encode(tag.as_ref())
}

pub fn clear_session_cookie() -> String {
    Cookie::build((SESSION_COOKIE, ""))
        .path("/")
        .http_only(true)
        .same_site(cookie::SameSite::Lax)
        .max_age(cookie::time::Duration::seconds(0))
        .build()
        .to_string()
}

fn validate_session(master: &MasterAuth, val: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, master.hash.as_bytes());
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(val) {
        hmac::verify(&key, b"master-session", &bytes).is_ok()
    } else {
        false
    }
}
