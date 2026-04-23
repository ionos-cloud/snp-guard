// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 IONOS SE
// Author: Roman Penyaev <r.peniaev@gmail.com>

use anyhow::{anyhow, Result};
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{Kem, X25519HkdfSha256},
    Deserializable, OpModeR, OpModeS, Serializable,
};
use pem::{EncodeConfig, Pem};
use rand::rngs::OsRng;
use std::fs;
use std::io::Write;
use std::path::Path;

pub struct IngestionKeys {
    pub private_key: <X25519HkdfSha256 as Kem>::PrivateKey,
    pub public_key: <X25519HkdfSha256 as Kem>::PublicKey,
}

impl IngestionKeys {
    pub fn load_or_create(priv_path: &Path, pub_path: &Path) -> Result<Self> {
        if priv_path.exists() && pub_path.exists() {
            // Load existing keys (non-standard PEM format - raw 32-byte keys wrapped in PEM)
            let priv_pem = fs::read_to_string(priv_path)?;
            let pub_pem = fs::read_to_string(pub_path)?;

            let priv_pem_parsed = pem::parse(priv_pem)?;
            let pub_pem_parsed = pem::parse(pub_pem)?;

            if priv_pem_parsed.tag() != "PRIVATE KEY" {
                return Err(anyhow!("Invalid private key PEM tag"));
            }
            if pub_pem_parsed.tag() != "PUBLIC KEY" {
                return Err(anyhow!("Invalid public key PEM tag"));
            }

            let private_bytes: [u8; 32] = priv_pem_parsed
                .contents()
                .try_into()
                .map_err(|_| anyhow!("Invalid private key length"))?;
            let public_bytes: [u8; 32] = pub_pem_parsed
                .contents()
                .try_into()
                .map_err(|_| anyhow!("Invalid public key length"))?;

            let private_key = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&private_bytes)
                .map_err(|e| anyhow!("Failed to create private key: {}", e))?;
            let public_key = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&public_bytes)
                .map_err(|e| anyhow!("Failed to create public key: {}", e))?;

            Ok(IngestionKeys {
                private_key,
                public_key,
            })
        } else {
            // Generate new keys
            let mut rng = OsRng;
            let (private_key, public_key) = <X25519HkdfSha256 as Kem>::gen_keypair(&mut rng);
            let private_bytes = private_key.to_bytes();
            let public_bytes = public_key.to_bytes();

            // Ensure parent directory exists
            if let Some(parent) = priv_path.parent() {
                fs::create_dir_all(parent)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
                }
            }

            // Save private key
            // Note: This is NOT standard PKCS#8 format. It's a simple PEM wrapper around raw bytes.
            // Standard tools like openssl may not recognize this format.
            let priv_pem = Pem::new("PRIVATE KEY", private_bytes.to_vec());
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

            println!("Ingestion private key saved: {:?}", priv_path);

            // Save public key
            // Note: This is NOT standard PKCS#8 format. It's a simple PEM wrapper around raw bytes.
            // Standard tools like openssl may not recognize this format.
            let pub_pem = Pem::new("PUBLIC KEY", public_bytes.to_vec());
            let pub_pem_str = pem::encode_config(
                &pub_pem,
                EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
            );
            fs::write(pub_path, pub_pem_str)?;

            println!("Ingestion public key saved: {:?}", pub_path);

            println!("==================================================");
            println!("SnpGuard ingestion keys generated at:");
            println!("  Private: {}", priv_path.display());
            println!("  Public:  {}", pub_path.display());
            println!("(These keys are used for encrypting unsealing private keys)");
            println!("==================================================");

            Ok(IngestionKeys {
                private_key,
                public_key,
            })
        }
    }

    pub fn get_public_key_pem(&self) -> Result<String> {
        let public_bytes = self.public_key.to_bytes();
        // Note: This is NOT standard PKCS#8 format. It's a simple PEM wrapper around raw bytes.
        let pub_pem = Pem::new("PUBLIC KEY", public_bytes.to_vec());
        let pub_pem_str = pem::encode_config(
            &pub_pem,
            EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
        );
        Ok(pub_pem_str)
    }

    #[allow(dead_code)]
    pub fn get_public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes().into()
    }

    #[allow(dead_code)]
    pub fn get_private_key_bytes(&self) -> [u8; 32] {
        self.private_key.to_bytes().into()
    }

    /// Encrypt plaintext using HPKE with the ingestion public key
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut rng = OsRng;
        let (encapped_key, mut sender_ctx) =
            hpke::setup_sender::<AesGcm256, HkdfSha256, X25519HkdfSha256, _>(
                &OpModeS::Base,
                &self.public_key,
                &[],
                &mut rng,
            )
            .map_err(|e| anyhow!("HPKE setup failed: {}", e))?;

        let ciphertext = sender_ctx
            .seal(plaintext, &[])
            .map_err(|e| anyhow!("HPKE seal failed: {}", e))?;

        let encapped_bytes = encapped_key.to_bytes();
        let mut db_blob = Vec::with_capacity(encapped_bytes.len() + ciphertext.len());
        db_blob.extend_from_slice(&encapped_bytes);
        db_blob.extend_from_slice(&ciphertext);

        Ok(db_blob)
    }

    /// Decrypt ciphertext using HPKE with the ingestion private key
    pub fn decrypt(&self, db_blob: &[u8]) -> Result<Vec<u8>> {
        if db_blob.len() < 32 {
            return Err(anyhow!("Blob too short"));
        }

        let (encapped_bytes, ciphertext) = db_blob.split_at(32);

        let encapped_key = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(encapped_bytes)
            .map_err(|e| anyhow!("Failed to create encapped key: {}", e))?;

        let mut receiver_ctx = hpke::setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &self.private_key,
            &encapped_key,
            &[],
        )
        .map_err(|e| anyhow!("HPKE setup receiver failed: {}", e))?;

        let plaintext = receiver_ctx
            .open(ciphertext, &[])
            .map_err(|e| anyhow!("HPKE open failed: {}", e))?;

        Ok(plaintext)
    }
}

/// Encrypt plaintext using a public key (for client-side encryption)
pub fn encrypt_with_public_key(public_key_pem: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    // Parse non-standard PEM format - raw 32-byte key wrapped in PEM
    let pub_pem_parsed = pem::parse(public_key_pem)?;
    if pub_pem_parsed.tag() != "PUBLIC KEY" {
        return Err(anyhow!("Invalid public key PEM tag"));
    }

    let public_bytes: [u8; 32] = pub_pem_parsed
        .contents()
        .try_into()
        .map_err(|_| anyhow!("Invalid public key length"))?;

    let server_pub = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&public_bytes)
        .map_err(|e| anyhow!("Failed to create public key: {}", e))?;

    let mut rng = OsRng;
    let (encapped_key, mut sender_ctx) = hpke::setup_sender::<
        AesGcm256,
        HkdfSha256,
        X25519HkdfSha256,
        _,
    >(&OpModeS::Base, &server_pub, &[], &mut rng)
    .map_err(|e| anyhow!("HPKE setup failed: {}", e))?;

    let ciphertext = sender_ctx
        .seal(plaintext, &[])
        .map_err(|e| anyhow!("HPKE seal failed: {}", e))?;

    let encapped_bytes = encapped_key.to_bytes();
    let mut db_blob = Vec::with_capacity(encapped_bytes.len() + ciphertext.len());
    db_blob.extend_from_slice(&encapped_bytes);
    db_blob.extend_from_slice(&ciphertext);

    Ok(db_blob)
}
