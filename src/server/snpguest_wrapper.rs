// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 IONOS SE
// Author: Roman Penyaev <r.peniaev@gmail.com>

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use openssl::ec::EcKey;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Locate the snpguest binary.
///
/// In Docker/installed deployments snpguest is placed alongside the server
/// binary (e.g. both in /usr/local/bin/).  In local dev builds it lives in
/// the snpguest workspace member output directory.
fn find_snpguest() -> Result<PathBuf> {
    let exe_dir = std::env::current_exe()?
        .parent()
        .ok_or_else(|| anyhow!("Cannot get executable directory"))?
        .to_path_buf();

    // Installed/Docker: snpguest is a sibling of the server binary.
    let sibling = exe_dir.join("snpguest");
    if sibling.exists() {
        return Ok(sibling);
    }

    // Local dev: snpguest is built with MUSL target (matches Makefile build-snpguest).
    Ok(exe_dir.join("../../snpguest/target/x86_64-unknown-linux-musl/release/snpguest"))
}

/// Wraps 'snpguest generate measurement' then 'snpguest generate id-block'
#[allow(clippy::too_many_arguments)]
pub fn generate_measurement_and_block(
    ovmf: &Path,
    kernel: &Path,
    initrd: &Path,
    params: &str,
    vcpus: u32,
    vcpu_type: &str,
    policy: u64,
    id_key: &Path,
    auth_key: &Path,
    output_dir: &Path,
    image_id: &[u8],
) -> Result<String> {
    validate_ec_key(id_key)?;
    validate_ec_key(auth_key)?;

    // Calculate Measurement
    let snpguest_path = find_snpguest()?;

    let output = Command::new(&snpguest_path)
        .arg("generate")
        .arg("measurement")
        .arg("--ovmf")
        .arg(ovmf)
        .arg("--kernel")
        .arg(kernel)
        .arg("--append")
        .arg(params)
        .arg("--initrd")
        .arg(initrd)
        .arg("--vcpus")
        .arg(vcpus.to_string())
        .arg("--vcpu-type")
        .arg(vcpu_type)
        .output()
        .context("Failed to execute snpguest generate measurement")?;

    if !output.status.success() {
        return Err(anyhow!(
            "snpguest measurement failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let measurement = String::from_utf8(output.stdout)?.trim().to_string();

    // Validate image_id is exactly 16 bytes
    if image_id.len() != 16 {
        return Err(anyhow!("image_id must be a 16-bytes long"));
    }

    // Generate ID-Block and Auth-Block with image-id
    let status = Command::new(&snpguest_path)
        .arg("--quiet")
        .arg("generate")
        .arg("id-block")
        .arg(id_key)
        .arg(auth_key)
        .arg(&measurement)
        .arg("--image-id")
        .arg(hex::encode(image_id))
        .arg("--policy")
        .arg(policy.to_string())
        .arg("--id-file")
        .arg(output_dir.join("id-block.bin"))
        .arg("--auth-file")
        .arg(output_dir.join("id-auth.bin"))
        .status()?;

    if !status.success() {
        return Err(anyhow!("Failed to generate id-block"));
    }

    // Decode Base64 outputs to binary
    decode_base64_file(&output_dir.join("id-block.bin"))?;
    decode_base64_file(&output_dir.join("id-auth.bin"))?;

    Ok(measurement)
}

fn decode_base64_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let content = std::fs::read(path)?;
    let content_str = String::from_utf8(content)?.replace('\n', "");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&content_str)
        .context("Failed to decode base64 block")?;
    std::fs::write(path, decoded)?;
    Ok(())
}

pub fn get_key_digest(key_path: &Path) -> Result<Vec<u8>> {
    validate_ec_key(key_path)?;

    let snpguest_path = find_snpguest()?;

    let output = Command::new(&snpguest_path)
        .arg("generate")
        .arg("key-digest")
        .arg(key_path)
        .output()?;

    if !output.status.success() {
        return Err(anyhow!(
            "Failed to get key digest: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8(output.stdout)?.trim().to_string();
    // Try to extract the first hex-looking token
    let hex_token = stdout
        .split_whitespace()
        .find(|tok| tok.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| anyhow!("Failed to parse key digest from output: {}", stdout))?;

    let bytes = hex::decode(hex_token)
        .map_err(|e| anyhow!("Failed to decode key digest '{}': {}", hex_token, e))?;
    Ok(bytes)
}

fn validate_ec_key(path: &Path) -> Result<()> {
    let pem =
        std::fs::read(path).with_context(|| format!("Failed to read key: {}", path.display()))?;
    EcKey::private_key_from_pem(&pem).with_context(|| {
        format!(
            "Invalid EC private key PEM (expecting secp384r1) at {}",
            path.display()
        )
    })?;
    Ok(())
}

pub fn verify_report_signature(report_path: &Path) -> Result<()> {
    let snpguest_path = find_snpguest()?;

    // Create temporary directory for certificates
    let temp_dir = tempfile::TempDir::new().context("Failed to create temporary directory")?;
    let certs_dir = temp_dir.path();

    // Fetch CA
    let status = Command::new(&snpguest_path)
        .arg("fetch")
        .arg("ca")
        .arg("pem")
        .arg(certs_dir)
        .arg("-r")
        .arg(report_path)
        .status()?;
    if !status.success() {
        return Err(anyhow!("Failed to fetch CA certificates"));
    }

    // Fetch VCEK (Needs report to identify chip)
    let status = Command::new(&snpguest_path)
        .arg("fetch")
        .arg("vcek")
        .arg("pem")
        .arg(certs_dir)
        .arg(report_path)
        .status()?;
    if !status.success() {
        return Err(anyhow!("Failed to fetch VCEK certificate"));
    }

    // Verify Certs
    let status = Command::new(&snpguest_path)
        .arg("verify")
        .arg("certs")
        .arg(certs_dir)
        .status()?;
    if !status.success() {
        return Err(anyhow!("Failed to verify certificate chain"));
    }

    // Verify Attestation
    let status = Command::new(&snpguest_path)
        .arg("verify")
        .arg("attestation")
        .arg(certs_dir)
        .arg(report_path)
        .status()?;
    if !status.success() {
        return Err(anyhow!("Failed to verify attestation report signature"));
    }

    // Temp directory will be automatically cleaned up when dropped
    Ok(())
}
