// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 IONOS SE
// Author: Roman Penyaev <r.peniaev@gmail.com>

use anyhow::{anyhow, Context, Result};
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{Kem, X25519HkdfSha256},
    Deserializable, OpModeR, OpModeS, Serializable,
};
use pem::{EncodeConfig, Pem};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;

/// Generates an X25519 keypair and saves as standard PEM files.
pub fn generate_keys(priv_path: &Path, pub_path: &Path) -> Result<()> {
    let mut rng = OsRng;
    // Generate Keypair using HPKE's KEM
    let (priv_key, pub_key) = <X25519HkdfSha256 as Kem>::gen_keypair(&mut rng);
    let priv_bytes = priv_key.to_bytes();
    let pub_bytes = pub_key.to_bytes();

    // Write Private Key
    // Note: This is NOT standard PKCS#8 format. It's a simple PEM wrapper around raw bytes.
    // Standard tools like openssl may not recognize this format.
    let priv_pem = Pem::new("PRIVATE KEY", priv_bytes.to_vec());
    let priv_pem_str = pem::encode_config(
        &priv_pem,
        EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    );

    fs::write(priv_path, priv_pem_str.as_bytes())
        .with_context(|| format!("Failed to write private key to {:?}", priv_path))?;

    // Set permissions (read-only for owner)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(priv_path)?.permissions();
        perms.set_mode(0o400);
        fs::set_permissions(priv_path, perms)?;
    }

    // Write Public Key
    // Note: This is NOT standard PKCS#8 format. It's a simple PEM wrapper around raw bytes.
    // Standard tools like openssl may not recognize this format.
    let pub_pem = Pem::new("PUBLIC KEY", pub_bytes.to_vec());
    let pub_pem_str = pem::encode_config(
        &pub_pem,
        EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    );

    fs::write(pub_path, pub_pem_str.as_bytes())
        .with_context(|| format!("Failed to write public key to {:?}", pub_path))?;

    println!(
        "Keys generated:\n  Private: {:?}\n  Public:  {:?}",
        priv_path, pub_path
    );
    Ok(())
}

/// Encrypts a file using HPKE (X25519 + AES-GCM-256)
pub fn encrypt_file(pub_key_path: &Path, data_path: &Path, out_path: &Path) -> Result<()> {
    let mut rng = OsRng;

    // Load Data
    let plaintext = fs::read(data_path)
        .with_context(|| format!("Failed to read data file: {:?}", data_path))?;

    let pub_pem_str = fs::read_to_string(pub_key_path)
        .with_context(|| format!("Failed to read public key: {:?}", pub_key_path))?;

    // Parse Public Key (non-standard PEM format - raw 32-byte key wrapped in PEM)
    let pub_pem = pem::parse(&pub_pem_str).map_err(|e| anyhow!("Invalid PEM format: {}", e))?;

    if pub_pem.tag() != "PUBLIC KEY" {
        return Err(anyhow!("Expected PUBLIC KEY, got {}", pub_pem.tag()));
    }

    let pub_bytes: [u8; 32] = pub_pem
        .contents()
        .try_into()
        .map_err(|_| anyhow!("Invalid public key length (expected 32 bytes)"))?;

    // Convert to HPKE-compatible key type
    let hpke_key = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&pub_bytes)
        .map_err(|e| anyhow!("Key conversion failed: {}", e))?;

    // Encrypt (HPKE)
    let (encapped_key, mut sender_ctx) = hpke::setup_sender::<
        AesGcm256,
        HkdfSha256,
        X25519HkdfSha256,
        _,
    >(&OpModeS::Base, &hpke_key, &[], &mut rng)
    .map_err(|e| anyhow!("HPKE setup failed: {}", e))?;

    let ciphertext = sender_ctx
        .seal(&plaintext, &[])
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    // Serialize: [ Encapped_Key (32b) || Ciphertext ]
    let mut output = encapped_key.to_bytes().to_vec();
    output.extend_from_slice(&ciphertext);

    fs::write(out_path, &output)
        .with_context(|| format!("Failed to write output to {:?}", out_path))?;

    println!("Encrypted {} bytes to {:?}", plaintext.len(), out_path);
    Ok(())
}

/// Decrypts a file using HPKE (X25519 + AES-GCM-256)
pub fn decrypt_file(priv_key_path: &Path, enc_data_path: &Path, out_path: &Path) -> Result<()> {
    // Load encrypted blob
    let enc_blob = fs::read(enc_data_path)
        .with_context(|| format!("Failed to read encrypted data file: {:?}", enc_data_path))?;

    if enc_blob.len() < 32 {
        return Err(anyhow!(
            "Encrypted blob too short (expected at least 32 bytes for encapped key)"
        ));
    }

    // Split Blob: [ Encapped_Key (32 bytes) || Ciphertext ]
    let (encapped_bytes, ciphertext) = enc_blob.split_at(32);

    // Load and Parse Private Key (non-standard PEM format - raw 32-byte key wrapped in PEM)
    let priv_pem_str = fs::read_to_string(priv_key_path)
        .with_context(|| format!("Failed to read private key: {:?}", priv_key_path))?;

    let priv_pem = pem::parse(&priv_pem_str).map_err(|e| anyhow!("Invalid PEM format: {}", e))?;

    if priv_pem.tag() != "PRIVATE KEY" {
        return Err(anyhow!("Expected PRIVATE KEY, got {}", priv_pem.tag()));
    }

    let priv_bytes: [u8; 32] = priv_pem
        .contents()
        .try_into()
        .map_err(|_| anyhow!("Invalid private key length (expected 32 bytes)"))?;

    // Convert to HPKE-compatible key type
    let hpke_priv = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&priv_bytes)
        .map_err(|e| anyhow!("Key conversion failed: {}", e))?;

    // Parse Encapped Key
    let encapped_key = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(encapped_bytes)
        .map_err(|e| anyhow!("Invalid encapped key: {}", e))?;

    // Decrypt (HPKE Open)
    let mut receiver_ctx = hpke::setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &hpke_priv,
        &encapped_key,
        &[],
    )
    .map_err(|e| anyhow!("HPKE setup failed: {}", e))?;

    let plaintext = receiver_ctx
        .open(ciphertext, &[])
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;

    // Write Plaintext
    fs::write(out_path, &plaintext)
        .with_context(|| format!("Failed to write output to {:?}", out_path))?;

    println!("Decrypted {} bytes to {:?}", plaintext.len(), out_path);
    Ok(())
}
