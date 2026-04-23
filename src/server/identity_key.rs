// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 IONOS SE
// Author: Roman Penyaev <r.peniaev@gmail.com>

use anyhow::{anyhow, Result};
use pem::{EncodeConfig, Pem};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Server identity key: a stable Ed25519 signing keypair.
///
/// The public key is exposed via /public/info so operators can bake it into
/// the guest initrd.  The server uses the private key to sign artifacts
/// returned to the guest, allowing the guest to verify their origin without
/// a network round-trip.
pub struct IdentityKey {
    // key_pair is used by sign(); not yet called but will be in the renew response path
    #[allow(dead_code)]
    key_pair: Ed25519KeyPair,
    public_key_bytes: [u8; 32],
}

impl IdentityKey {
    /// Load from disk if both files exist, otherwise generate a new keypair and persist it.
    ///
    /// Private key is stored as PKCS#8 DER wrapped in a PEM "PRIVATE KEY" block.
    /// Public key is stored as raw 32 bytes wrapped in a PEM "PUBLIC KEY" block
    /// (same non-standard PEM convention used by the ingestion key).
    pub fn load_or_create(priv_path: &Path, pub_path: &Path) -> Result<Self> {
        if priv_path.exists() && pub_path.exists() {
            let priv_pem = fs::read_to_string(priv_path)?;
            let priv_pem_parsed = pem::parse(priv_pem)?;
            if priv_pem_parsed.tag() != "PRIVATE KEY" {
                return Err(anyhow!("Invalid identity private key PEM tag"));
            }
            // Stored as PKCS#8 DER
            let key_pair = Ed25519KeyPair::from_pkcs8(priv_pem_parsed.contents())
                .map_err(|e| anyhow!("Failed to load Ed25519 key pair: {}", e))?;
            let public_key_bytes: [u8; 32] = key_pair
                .public_key()
                .as_ref()
                .try_into()
                .map_err(|_| anyhow!("Unexpected Ed25519 public key length"))?;
            Ok(IdentityKey {
                key_pair,
                public_key_bytes,
            })
        } else {
            let rng = ring::rand::SystemRandom::new();
            let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng)
                .map_err(|_| anyhow!("Failed to generate Ed25519 key pair"))?;
            let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref())
                .map_err(|e| anyhow!("Failed to reload generated key pair: {}", e))?;
            let public_key_bytes: [u8; 32] = key_pair
                .public_key()
                .as_ref()
                .try_into()
                .map_err(|_| anyhow!("Unexpected Ed25519 public key length"))?;

            // Persist private key
            if let Some(parent) = priv_path.parent() {
                fs::create_dir_all(parent)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
                }
            }
            let priv_pem = Pem::new("PRIVATE KEY", pkcs8_doc.as_ref().to_vec());
            let priv_pem_str = pem::encode_config(
                &priv_pem,
                EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
            );
            let mut file = fs::File::create(priv_path)?;
            file.write_all(priv_pem_str.as_bytes())?;
            file.sync_all()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(priv_path, fs::Permissions::from_mode(0o400))?;
            }

            // Persist public key
            let pub_pem = Pem::new("PUBLIC KEY", public_key_bytes.to_vec());
            let pub_pem_str = pem::encode_config(
                &pub_pem,
                EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
            );
            fs::write(pub_path, pub_pem_str)?;

            println!("==================================================");
            println!("SnpGuard identity keys generated at:");
            println!("  Private: {}", priv_path.display());
            println!("  Public:  {}", pub_path.display());
            println!("(This Ed25519 keypair is used to sign artifacts sent to guests)");
            println!("==================================================");

            Ok(IdentityKey {
                key_pair,
                public_key_bytes,
            })
        }
    }

    /// Sign `message` with the Ed25519 private key.  Returns a 64-byte signature.
    #[allow(dead_code)]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key_pair.sign(message).as_ref().to_vec()
    }

    /// Return the public key as a PEM string (raw 32 bytes, "PUBLIC KEY" tag).
    pub fn get_public_key_pem(&self) -> Result<String> {
        let pub_pem = Pem::new("PUBLIC KEY", self.public_key_bytes.to_vec());
        let s = pem::encode_config(
            &pub_pem,
            EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
        );
        Ok(s)
    }

    /// Return the raw 32-byte Ed25519 public key.
    #[allow(dead_code)]
    pub fn get_public_key_bytes(&self) -> [u8; 32] {
        self.public_key_bytes
    }
}
