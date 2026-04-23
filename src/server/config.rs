// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 IONOS SE
// Author: Roman Penyaev <r.peniaev@gmail.com>

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DataPaths {
    pub data_dir: PathBuf,
    pub tls_dir: PathBuf,
    pub auth_dir: PathBuf,
    pub db_dir: PathBuf,
    pub artifacts_dir: PathBuf,
    pub attestations_dir: PathBuf,
    pub artifacts_tmp_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub ca_cert: PathBuf,
    pub master_password_hash: PathBuf,
    pub ingestion_key: PathBuf,
    pub ingestion_pub: PathBuf,
    pub identity_key: PathBuf,
    pub identity_pub: PathBuf,
    pub db_file: PathBuf,
}

impl DataPaths {
    pub fn new<P: AsRef<Path>>(data_dir: P) -> std::io::Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        let tls_dir = data_dir.join("tls");
        let auth_dir = data_dir.join("auth");
        let db_dir = data_dir.join("db");
        let artifacts_dir = data_dir.join("artifacts");
        let attestations_dir = artifacts_dir.join("attestations");
        let artifacts_tmp_dir = artifacts_dir.join("tmp");
        let logs_dir = data_dir.join("logs");

        Ok(Self {
            data_dir: data_dir.clone(),
            tls_cert: tls_dir.join("server.crt"),
            tls_key: tls_dir.join("server.key"),
            ca_cert: tls_dir.join("ca.pem"),
            master_password_hash: auth_dir.join("master.pw.hash"),
            ingestion_key: auth_dir.join("ingestion.key"),
            ingestion_pub: auth_dir.join("ingestion.pub"),
            identity_key: auth_dir.join("identity.key"),
            identity_pub: auth_dir.join("identity.pub"),
            db_file: db_dir.join("snpguard.sqlite"),
            tls_dir,
            auth_dir,
            db_dir,
            artifacts_dir,
            attestations_dir,
            artifacts_tmp_dir,
            logs_dir,
        })
    }

    pub fn ensure(&self) -> std::io::Result<()> {
        // Secrets: 0700
        for dir in [
            &self.data_dir,
            &self.tls_dir,
            &self.auth_dir,
            &self.db_dir,
            &self.artifacts_dir,
            &self.attestations_dir,
            &self.artifacts_tmp_dir,
        ] {
            create_dir_secure(dir, 0o700)?;
        }

        // Logs can be readable by group
        create_dir_secure(&self.logs_dir, 0o750)?;

        // Optional: create empty DB file so path exists; TLS files are created later by generator
        if !self.db_file.exists() {
            touch_if_missing(&self.db_file, 0o600)?;
        }
        Ok(())
    }
}

fn create_dir_secure(path: &Path, mode: u32) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

fn touch_if_missing(path: &Path, mode: u32) -> std::io::Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    fs::write(path, [])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}
