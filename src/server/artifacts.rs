// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 IONOS SE
// Author: Roman Penyaev <r.peniaev@gmail.com>

use anyhow::{anyhow, bail, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Generate artifact archive (squashfs or tar.gz) from artifact directory.
/// Removes stale files before generation to ensure fresh content.
/// Returns the path to the generated artifact file.
pub fn generate_artifact(artifact_dir: &Path, filename: &str) -> Result<PathBuf> {
    // Extract just the filename component to prevent path traversal
    let filename = Path::new(filename)
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| anyhow!("Invalid filename"))?;

    let path = artifact_dir.join(filename);

    // Always regenerate archives to reflect the latest artifacts
    if filename.ends_with(".squashfs") {
        let def_path = artifact_dir.join("squash.def");
        std::fs::write(
            &def_path,
            "/ d 755 0 0\nlaunch-config.json m 444 0 0\nfirmware-code.fd m 444 0 0\nvmlinuz m 444 0 0\ninitrd.img m 444 0 0\nkernel-params.txt m 444 0 0\nid-block.bin m 444 0 0\nid-auth.bin m 444 0 0\n",
        )
        .map_err(|e| anyhow!("Failed to write squash.def: {}", e))?;

        // Remove stale file first to avoid reusing old content
        let _ = std::fs::remove_file(&path);

        Command::new("mksquashfs")
            .arg(artifact_dir)
            .arg(&path)
            .arg("-noappend")
            .arg("-all-root")
            .arg("-pf")
            .arg(&def_path)
            .arg("-wildcards")
            .arg("-e") // exclude
            .arg("squash.def")
            .status()
            .map_err(|e| anyhow!("Failed to create squashfs: {}", e))?;
    } else if filename.ends_with(".tar.gz") {
        // Remove stale file first to ensure updated contents
        let _ = std::fs::remove_file(&path);

        Command::new("tar")
            .arg("-czf")
            .arg(&path)
            .arg("-C")
            .arg(artifact_dir)
            .arg("--transform=s|^|/|")
            .arg("launch-config.json")
            .arg("firmware-code.fd")
            .arg("vmlinuz")
            .arg("initrd.img")
            .arg("kernel-params.txt")
            .arg("id-block.bin")
            .arg("id-auth.bin")
            .status()
            .map_err(|e| anyhow!("Failed to create tarball: {}", e))?;
    } else {
        bail!("Unknown artifact '{}' format is requested", filename);
    }

    Ok(path)
}
