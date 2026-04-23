// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 IONOS SE
// Author: Roman Penyaev <r.peniaev@gmail.com>

use std::fs;
use std::io;
use std::path::Path;

/// Whether a kernel has SEV-SNP guest support available.
#[derive(Debug, PartialEq, Eq)]
pub enum SevGuestSupport {
    /// CONFIG_SEV_GUEST=y -- driver is compiled directly into the kernel.
    SupportedBuiltIn,
    /// CONFIG_SEV_GUEST=m and sev-guest.ko (or a compressed variant) was found.
    SupportedModule,
    /// CONFIG_SEV_GUEST=m but no sev-guest.ko file found in the modules directory.
    SupportedButNoModule,
    /// CONFIG_SEV_GUEST is absent or explicitly disabled.
    NotSupported,
}

impl SevGuestSupport {
    /// Returns `true` for any variant that allows SEV-SNP attestation.
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::SupportedBuiltIn | Self::SupportedModule)
    }
}

/// Extract the kernel version string from a kernel image path.
///
/// Expects a filename like `vmlinuz-5.15.0-91-generic` and returns
/// `5.15.0-91-generic`. Returns an error for unrecognised patterns.
pub fn kernel_version_from_path(kernel_path: &str) -> io::Result<&str> {
    let name = Path::new(kernel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid kernel path: {}", kernel_path),
            )
        })?;

    name.strip_prefix("vmlinuz-").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("cannot determine version for kernel: {}", name),
        )
    })
}

/// Core SEV-SNP support check from kernel config content.
///
/// `find_module` is called lazily only when `CONFIG_SEV_GUEST=m` is found.
/// It should return `Ok(true)` if `sev-guest.ko` (or a compressed variant) is
/// present in the kernel modules directory, `Ok(false)` if absent, or an error
/// if the underlying I/O operation failed.  This function is pure -- all I/O
/// and any diagnostic printing are the caller's responsibility.
pub fn sev_support_from_config<E>(
    config_content: &str,
    find_module: impl FnOnce() -> Result<bool, E>,
) -> Result<SevGuestSupport, E> {
    if config_content.contains("CONFIG_SEV_GUEST=y") {
        return Ok(SevGuestSupport::SupportedBuiltIn);
    }
    if config_content.contains("CONFIG_SEV_GUEST=m") {
        return Ok(if find_module()? {
            SevGuestSupport::SupportedModule
        } else {
            SevGuestSupport::SupportedButNoModule
        });
    }
    Ok(SevGuestSupport::NotSupported)
}

/// Check SEV-SNP support for a kernel on the live filesystem.
///
/// Reads `{boot_dir}/config-{version}` and searches
/// `/usr/lib/modules/{version}/` recursively for `sev-guest.ko`.
pub fn check_sev_support_live(boot_dir: &Path, version: &str) -> io::Result<SevGuestSupport> {
    let config_path = boot_dir.join(format!("config-{}", version));
    let config_content = fs::read_to_string(&config_path)?;
    let modules_dir = Path::new("/usr/lib/modules").join(version);
    sev_support_from_config(&config_content, || {
        Ok(modules_dir_has_sev_guest_module(&modules_dir))
    })
}

fn modules_dir_has_sev_guest_module(dir: &Path) -> bool {
    if !dir.exists() {
        return false;
    }
    dir_contains_sev_module(dir)
}

fn dir_contains_sev_module(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if dir_contains_sev_module(&path) {
                return true;
            }
        } else if path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.contains("sev-guest.ko"))
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}
