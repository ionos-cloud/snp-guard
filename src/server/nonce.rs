// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 IONOS SE
// Author: Roman Penyaev <r.peniaev@gmail.com>

use rand::RngCore;
use ring::hmac;
use std::time::{SystemTime, UNIX_EPOCH};

pub const NONCE_SIZE: usize = 64;
const TS_SIZE: usize = 8;
const RND_SIZE: usize = 32;
const MAC_SIZE: usize = 24; // truncated HMAC-SHA256
const MAX_SKEW_SECS: u64 = 60; // 60s timeout

#[derive(Debug, thiserror::Error)]
pub enum NonceError {
    #[error("nonce length invalid")]
    InvalidLength,
    #[error("nonce MAC invalid")]
    InvalidMac,
    #[error("nonce timestamp invalid or expired")]
    InvalidTimestamp,
    #[error("system time error")]
    Time,
}

/// Generate a 64-byte stateless nonce: ts(8) | rnd(32) | mac(24)
pub fn generate_nonce(secret: &[u8]) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];

    // timestamp seconds
    let ts = current_unix_time().expect("time failed");
    nonce[..TS_SIZE].copy_from_slice(&ts.to_be_bytes());

    // random payload
    rand::thread_rng().fill_bytes(&mut nonce[TS_SIZE..TS_SIZE + RND_SIZE]);

    // mac
    let mac = compute_mac(secret, &nonce[..TS_SIZE + RND_SIZE]);
    nonce[TS_SIZE + RND_SIZE..].copy_from_slice(&mac);

    nonce
}

/// Verify that the received nonce is not expired
pub fn verify_nonce(secret: &[u8], nonce: &[u8]) -> Result<(), NonceError> {
    if nonce.len() != NONCE_SIZE {
        return Err(NonceError::InvalidLength);
    }

    let ts_bytes = &nonce[..TS_SIZE];
    let payload = &nonce[..TS_SIZE + RND_SIZE];
    let mac_recv = &nonce[TS_SIZE + RND_SIZE..];

    let mac_expected = compute_mac(secret, payload);
    if !constant_time_eq(mac_recv, &mac_expected) {
        return Err(NonceError::InvalidMac);
    }

    let ts = u64::from_be_bytes(ts_bytes.try_into().unwrap());
    let now = current_unix_time().map_err(|_| NonceError::Time)?;

    // Reject future timestamps and stale nonces
    if ts > now || now - ts > MAX_SKEW_SECS {
        return Err(NonceError::InvalidTimestamp);
    }

    Ok(())
}

fn compute_mac(secret: &[u8], data: &[u8]) -> [u8; MAC_SIZE] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, data);
    let mut mac = [0u8; MAC_SIZE];
    mac.copy_from_slice(&tag.as_ref()[..MAC_SIZE]);
    mac
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn current_unix_time() -> Result<u64, ()> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ())
}
