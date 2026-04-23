// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 IONOS SE
// Author: Roman Penyaev <r.peniaev@gmail.com>

use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use once_cell::sync::Lazy;
use rand::{rngs::OsRng, Rng};
use std::fs;
use std::io::Write;
use std::path::Path;

const WORDLIST: &str = include_str!("../../assets/diceware/eff_large_wordlist.txt");

static WORDS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    WORDLIST
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            parts.next()?;
            parts.next()
        })
        .collect()
});

#[derive(Clone)]
pub struct MasterAuth {
    pub hash: String,
}

pub fn load_or_create_master_password(
    path: &Path,
) -> Result<MasterAuth, Box<dyn std::error::Error>> {
    if path.exists() {
        let hash = fs::read_to_string(path)?.trim().to_string();
        if hash.is_empty() {
            return Err("Existing master password hash file is empty".into());
        }
        return Ok(MasterAuth { hash });
    }

    // Generate a human-readable, high-entropy passphrase
    let password = generate_memorable_password();

    // Hash with Argon2id
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Failed to hash master password: {e}"))?
        .to_string();

    // Persist hash only
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    let mut file = fs::File::create(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(hash.as_bytes())?;

    // Show the password once to the operator
    println!("==================================================");
    println!("SnpGuard master password (store this securely):");
    println!("{}", password);
    println!("(This password is shown only once and not stored in plaintext.)");
    println!("==================================================");

    Ok(MasterAuth { hash })
}

fn generate_memorable_password() -> String {
    let mut rng = OsRng;
    let count = 6;
    let mut words = Vec::with_capacity(count);
    for _ in 0..count {
        let idx = rng.gen_range(0..WORDS.len());
        words.push(WORDS[idx]);
    }
    words.join("-")
}
