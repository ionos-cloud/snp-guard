mod local_ops;

use anyhow::{anyhow, bail, Context, Result};
use boot::grub::{self, GrubEntry};
use boot::sev::{kernel_version_from_path, sev_support_from_config, SevGuestSupport};
use clap::{Parser, Subcommand};
use dirs::config_dir;
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{Kem, X25519HkdfSha256},
    Deserializable, OpModeS, Serializable,
};
use pem::parse as pem_parse;
use rand::{rngs::OsRng, RngCore};
use scopeguard::defer;
use std::cell::RefCell;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const REQUIRED_FREE_BYTES: u64 = 500 * 1024 * 1024;

/// Round down `value` in bytes to 1MB
fn round_down_1mb(value: u64) -> u64 {
    const MB: u64 = 1024 * 1024;
    (value / MB) * MB
}

/// Round up `value` in bytes to 1MB
fn round_up_1mb(value: u64) -> u64 {
    const MB: u64 = 1024 * 1024;
    value.div_ceil(MB) * MB
}

#[derive(PartialEq)]
enum DistroFamily {
    Debian,
    Ubuntu,
    RedHat,
}

#[derive(Parser, Debug)]
#[command(author, version, about = "SnpGuard image tool")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a new Unsealing Keypair (Offline)
    Keygen {
        /// Output path for private key (e.g., unsealing.key)
        #[arg(long, default_value = "unsealing.key")]
        priv_out: PathBuf,
        /// Output path for public key (e.g., unsealing.pub)
        #[arg(long, default_value = "unsealing.pub")]
        pub_out: PathBuf,
    },
    /// Seal a file (e.g., VMK) for a specific Public Key (Offline)
    Seal {
        /// Path to the Unsealing Public Key
        #[arg(long)]
        pub_key: PathBuf,
        /// Path to the plaintext file to seal
        #[arg(long)]
        data: PathBuf,
        /// Output path for the sealed blob
        #[arg(long)]
        out: PathBuf,
    },
    /// Unseal a file (e.g., VMK) using a Private Key (Offline)
    Unseal {
        /// Path to the Unsealing Private Key
        #[arg(long)]
        priv_key: PathBuf,
        /// Path to the sealed blob to unseal
        #[arg(long)]
        sealed_data: PathBuf,
        /// Output path for the unsealed data
        #[arg(long)]
        out: PathBuf,
    },
    /// Convert a QCOW2 image: encrypt rootfs with LUKS2 and seal keys
    Convert {
        /// Input QCOW2 image path
        #[arg(long)]
        in_image: PathBuf,
        /// Output QCOW2 image path
        #[arg(long)]
        out_image: PathBuf,
        /// Staging directory for temporary files
        #[arg(long)]
        out_staging: PathBuf,
        /// Optional: Override attestation URL (uses config if not provided)
        #[arg(long)]
        attest_url: Option<String>,
        /// Optional: Override ingestion public key path (uses config if not provided)
        #[arg(long)]
        ingestion_public_key: Option<PathBuf>,
        /// Optional: Override CA certificate path (uses config if not provided)
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        /// Optional: Override identity public key path (uses config if not provided).
        /// This Ed25519 public key is baked into the initrd as /etc/snpguard/identity.pub
        /// so the guest can verify renewal responses from the attestation server.
        #[arg(long)]
        identity_pub: Option<PathBuf>,
        /// Firmware path (required)
        #[arg(long)]
        firmware: PathBuf,
        /// Skip rootfs encryption and initrd hook installation (debug mode for testing artifact delivery without attestation)
        #[arg(long)]
        no_hardening: bool,
        /// Prompt to manually select a kernel when multiple SEV-SNP supported kernels are found.
        /// By default the GRUB default kernel is selected automatically, or the first entry if no
        /// default is set.
        #[arg(long)]
        interactive: bool,
        /// Install the offline attestation script (attest-offline.sh) instead of the default
        /// online-only script. The offline script derives a hardware-bound key from the SEV-SNP
        /// chip (VCEK + launch measurement) and stores it in LUKS slot 1 after the first
        /// successful online attestation, allowing subsequent boots to proceed without network.
        #[arg(long)]
        offline_attestation: bool,
    },
    /// Embed boot artifacts into a QCOW2 image
    Embed {
        /// Path to the QCOW2 image file
        #[arg(long)]
        image: PathBuf,
        /// Path to the tar.gz bundle containing boot artifacts
        #[arg(long)]
        in_bundle: PathBuf,
    },
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct StoredConfig {
    url: Option<String>,
}

fn config_path() -> Result<PathBuf> {
    let base = config_dir().ok_or_else(|| anyhow!("Cannot determine config dir"))?;
    Ok(base.join("snpguard").join("config.json"))
}

fn ca_cert_path() -> Result<PathBuf> {
    let base = config_dir().ok_or_else(|| anyhow!("Cannot determine config dir"))?;
    Ok(base.join("snpguard").join("ca.pem"))
}

fn ingestion_key_path() -> Result<PathBuf> {
    let base = config_dir().ok_or_else(|| anyhow!("Cannot determine config dir"))?;
    Ok(base.join("snpguard").join("ingestion.pub"))
}

fn identity_pub_path() -> Result<PathBuf> {
    let base = config_dir().ok_or_else(|| anyhow!("Cannot determine config dir"))?;
    Ok(base.join("snpguard").join("identity.pub"))
}

fn load_config() -> Result<StoredConfig> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(StoredConfig::default());
    }
    let data = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config at {}", path.display()))?;
    let cfg: StoredConfig = serde_json::from_str(&data)
        .with_context(|| format!("Config file at {} is invalid JSON", path.display()))?;
    Ok(cfg)
}

/// Securely delete a file by overwriting with random data
fn secure_delete_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let metadata = fs::metadata(path)
        .with_context(|| format!("Failed to get file metadata: {}", path.display()))?;
    let file_size = metadata.len() as usize;

    if file_size == 0 {
        fs::remove_file(path)
            .with_context(|| format!("Failed to delete empty file: {}", path.display()))?;
        return Ok(());
    }

    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)
        .with_context(|| format!("Failed to stat {}", path.display()))?
        .permissions();

    if perms.mode() & 0o200 == 0 {
        // Add owner write bit (u+w) if missing
        perms.set_mode(perms.mode() | 0o200);

        fs::set_permissions(path, perms)
            .with_context(|| format!("Failed to chmod +w {}", path.display()))?;
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| {
            format!(
                "Failed to open file for secure deletion: {}",
                path.display()
            )
        })?;

    let mut rng = OsRng;
    let mut buffer = vec![0u8; file_size.min(64 * 1024)];
    let mut remaining = file_size;

    while remaining > 0 {
        let to_write = remaining.min(buffer.len());
        rng.fill_bytes(&mut buffer[..to_write]);
        file.write_all(&buffer[..to_write])
            .with_context(|| format!("Failed to overwrite file content: {}", path.display()))?;
        remaining -= to_write;
    }

    file.sync_all()
        .with_context(|| format!("Failed to sync file: {}", path.display()))?;
    drop(file);

    fs::remove_file(path)
        .with_context(|| format!("Failed to delete file after overwrite: {}", path.display()))?;
    Ok(())
}

/// Returns distribution family
fn get_dist_family(g: &guestfs::Handle, rootfs: &str) -> Result<DistroFamily> {
    // Get distribution
    let dist = g
        .inspect_get_distro(rootfs)
        .map_err(|e| anyhow!("Failed to inspect distro on {}: {:?}", rootfs, e))?;

    match dist.as_str() {
        "debian" => Ok(DistroFamily::Debian),
        "ubuntu" => Ok(DistroFamily::Ubuntu),
        "fedora" | "centos" | "rhel" => Ok(DistroFamily::RedHat),
        _ => bail!("Unsupported distribution {}", dist),
    }
}

/// Guard to ensure paths are cleaned up on error
struct CleanupGuard {
    dir: PathBuf,
    file: Option<PathBuf>,
    keep: bool,
}

impl CleanupGuard {
    fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            file: None,
            keep: false,
        }
    }

    fn register_file(&mut self, file: PathBuf) {
        self.file = Some(file);
    }

    fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if self.keep {
            return;
        }

        if self.dir.exists() {
            if let Err(e) = fs::remove_dir_all(&self.dir) {
                println!(
                    "Warning: Failed to cleanup staging directory {:?}: {}",
                    self.dir, e
                );
            }
        }
        if let Some(file) = &self.file {
            file.exists().then(|| {
                if let Err(e) = fs::remove_file(file) {
                    println!("Warning: Failed to cleanup file {:?}: {}", self.dir, e);
                }
            });
        }
    }
}

/// Creates a guestfs context with scratch, source, and target drives attached and launched.
/// Returns the handle and the scratch/source/target rootfs device paths.
fn create_guestfs_context(
    source_path: &Path,
    target_path: &Path,
) -> Result<(guestfs::Handle, String, String, String)> {
    use guestfs::{AddDriveOptArgs, AddDriveScratchOptArgs, Handle};

    let g = Handle::create().map_err(|e| anyhow!("Failed to create guestfs handle: {:?}", e))?;

    // Add scratch drive for rootfs, this provides the physical space
    // and writable rootfs
    g.add_drive_scratch(
        10 * 1024 * 1024,
        AddDriveScratchOptArgs {
            label: Some("rootfs"),
            ..Default::default()
        },
    )
    .map_err(|e| anyhow!("Failed to add scratch drive: {:?}", e))?;

    // Add the SOURCE drive (read-only)
    g.add_drive(
        &source_path.to_string_lossy(),
        AddDriveOptArgs {
            label: Some("source"),
            readonly: Some(true),
            format: Some("qcow2"),
            ..Default::default()
        },
    )
    .map_err(|e| anyhow!("Failed to add source drive: {:?}", e))?;

    // Add the TARGET drive (read-write)
    g.add_drive(
        &target_path.to_string_lossy(),
        AddDriveOptArgs {
            label: Some("target"),
            readonly: Some(false),
            format: Some("qcow2"),
            ..Default::default()
        },
    )
    .map_err(|e| anyhow!("Failed to add target drive: {:?}", e))?;

    // Enable network
    g.set_network(true)
        .map_err(|e| anyhow!("Failed to setup network: {:?}", e))?;

    // Launch the VM
    g.launch()
        .map_err(|e| anyhow!("Failed to launch guestfs: {:?}", e))?;

    // Inspect source and target and find rootfs
    let roots = g
        .inspect_os()
        .map_err(|e| anyhow!("Failed to inspect OS: {:?}", e))?;
    if roots.len() != 2 {
        bail!("Two root filesystems are expected: one from a source and one from a target.");
    }

    // Prepare the scratch disk to be our writable rootfs
    let scratch_rootfs = "/dev/disk/guestfs/rootfs";
    use guestfs::MkfsOptArgs;
    g.mkfs("ext4", scratch_rootfs, MkfsOptArgs::default())
        .map_err(|e| anyhow!("Failed to mkfs ext4 on /: {:?}", e))?;

    // Find source and target rootfs
    let mut source_rootfs: Option<String> = None;
    let mut target_rootfs: Option<String> = None;

    let labels = g
        .list_disk_labels()
        .map_err(|e| anyhow!("Failed to list disk labels: {:?}", e))?;

    for (label, disk) in labels {
        if roots.contains(&disk) {
            if label.starts_with("source") {
                source_rootfs = Some(disk);
            } else if label.starts_with("target") {
                target_rootfs = Some(disk);
            }
        }
    }
    let source_rootfs = source_rootfs.ok_or_else(|| anyhow!("Source rootfs not found"))?;
    let target_rootfs = target_rootfs.ok_or_else(|| anyhow!("Target rootfs not found"))?;

    Ok((g, scratch_rootfs.to_string(), source_rootfs, target_rootfs))
}

/// Checks if a specific kernel version supports SEV-SNP by examining its
/// config and modules via a guestfs handle.  Prints diagnostic messages to
/// stdout as it goes, matching the existing image-convert output style.
fn check_kernel_version_sev_support(g: &guestfs::Handle, version: &str) -> Result<SevGuestSupport> {
    let config_path = format!("/boot/config-{}", version);
    if !g
        .exists(&config_path)
        .map_err(|e| anyhow!("Failed to check if config exists: {:?}", e))?
    {
        bail!("ERROR: Config {} does not exist!", config_path);
    }

    let config_str = g
        .cat(&config_path)
        .map_err(|e| anyhow!("Failed to read config: {:?}", e))?;

    let modules_dir = format!("/usr/lib/modules/{}", version);

    let support = sev_support_from_config(&config_str, || -> Result<bool> {
        println!("  [*] Configured as module: Searching for sev-guest.ko...");

        let dir_exists = g
            .exists(&modules_dir)
            .map_err(|e| anyhow!("Failed to check if modules dir exists: {:?}", e))?;
        if !dir_exists {
            println!("  [!] ERROR: CONFIG_SEV_GUEST=m but modules directory not found!");
            return Ok(false);
        }

        let files = g
            .find(&modules_dir)
            .map_err(|e| anyhow!("Failed to find files: {:?}", e))?;
        if let Some(f) = files.iter().find(|f| f.contains("sev-guest.ko")) {
            println!("  [+] Found module file: {}{}", modules_dir, f);
            Ok(true)
        } else {
            println!("  [!] ERROR: CONFIG_SEV_GUEST=m but no .ko file exists on disk!");
            Ok(false)
        }
    })?;

    match support {
        SevGuestSupport::SupportedBuiltIn => {
            println!("  [+] Found: SEV-Guest is built into the kernel binary.");
        }
        SevGuestSupport::SupportedModule => {
            // =m with module found; the closure already printed the module path
        }
        SevGuestSupport::NotSupported => {
            println!("  [-] SEV-Guest support is disabled in this kernel's config.");
        }
        SevGuestSupport::SupportedButNoModule => {}
    }

    Ok(support)
}

/// Verifies if a kernel supports SEV-SNP by checking kernel config and modules.
fn verify_sev_guest_support(g: &guestfs::Handle, kernel_path: &str) -> Result<SevGuestSupport> {
    let version = kernel_version_from_path(kernel_path)
        .map_err(|e| anyhow!("Failed to extract kernel version: {}", e))?;
    check_kernel_version_sev_support(g, version)
}

/// Partition type where boot files are located
#[derive(Debug, Clone)]
enum BootPartition {
    Rootfs,
    Boot(String), // device path
}

/// Inspects source image to find GRUB entries and verify SEV-SNP support.
/// Returns (supported_entries, unsupported_entries, boot_partition)
fn inspect_source_image_boot_data(
    g: &guestfs::Handle,
    source_rootfs: &str,
) -> Result<(Vec<grub::GrubEntry>, Vec<grub::GrubEntry>, BootPartition)> {
    use grub::parse_grub_cfg_from_str;
    use guestfs::{IsFileOptArgs, UmountOptArgs};

    // Mount source rootfs read-only
    g.mount_ro(source_rootfs, "/")
        .map_err(|e| anyhow!("Failed to mount source rootfs: {:?}", e))?;
    defer! {
        if let Err(e) = g.umount("/", UmountOptArgs::default()) {
            println!("WARN: Failed to umount /: {:?}", e);
        }
    }

    // Get distribution family
    let dist_family = get_dist_family(g, source_rootfs)?;

    // Check for /boot partition or use root filesystem
    let mut grub_cfg_path = "/boot/grub/grub.cfg".to_string();
    let mut boot_partition = BootPartition::Rootfs;
    let _guards = RefCell::new(Vec::<Box<dyn FnOnce() + '_>>::new());
    defer! {
        let mut guards = _guards.borrow_mut();
        while let Some(cleanup) = guards.pop() {
            cleanup();
        }
    };

    // First, check if grub.cfg exists in root filesystem's /boot
    let root_grub_exists = g
        .is_file(&grub_cfg_path, IsFileOptArgs::default())
        .map_err(|e| anyhow!("Failed to check if grub.cfg exists: {:?}", e))?;

    if !root_grub_exists {
        println!("  /boot/grub/grub.cfg not found in root filesystem");
        println!("  Checking for separate /boot partition...");

        // Try to find separate /boot partition
        let partitions = g
            .list_partitions()
            .map_err(|e| anyhow!("Failed to list partitions: {:?}", e))?;

        let bootcheck_dir = "/boot";

        for part in partitions {
            // Skip the source rootfs partition
            if part == source_rootfs {
                continue;
            }

            // Try to mount this partition and check if it contains grub.cfg
            if let Ok(()) = g.mount_ro(&part, bootcheck_dir) {
                _guards.borrow_mut().push(Box::new(move || {
                    if let Err(e) = g.umount(bootcheck_dir, UmountOptArgs::default()) {
                        println!("WARN: Failed to umount {}: {:?}", bootcheck_dir, e);
                    }
                }));
                let boot_check_grub = format!("{}/grub/grub.cfg", bootcheck_dir);
                if g.is_file(boot_check_grub.as_str(), IsFileOptArgs::default())
                    .map_err(|e| anyhow!("Failed to check if file exists: {:?}", e))?
                {
                    println!("  Found /boot partition at: {}", part);
                    grub_cfg_path = boot_check_grub.to_string();
                    boot_partition = BootPartition::Boot(part);
                    break;
                }
                // Umount previously mounted bootcheck_dir, we continue mounting other partitions
                if let Some(umount) = _guards.borrow_mut().pop() {
                    umount();
                }
            }
        }
        if matches!(boot_partition, BootPartition::Rootfs) {
            println!("  No separate /boot partition found with grub.cfg");
        }
    } else {
        println!("  Found /boot/grub/grub.cfg in root filesystem");
    }

    // Final check if grub.cfg exists
    if !g
        .is_file(&grub_cfg_path, IsFileOptArgs::default())
        .map_err(|e| anyhow!("Failed to check if grub.cfg exists: {:?}", e))?
    {
        bail!(
            "GRUB configuration file not found at: {}. Please ensure the source image has a valid GRUB installation.",
            grub_cfg_path
        );
    }

    println!("  Reading GRUB configuration from: {}", grub_cfg_path);

    // Read grub.cfg file
    let grub_content = g
        .read_file(&grub_cfg_path)
        .map_err(|e| anyhow!("Failed to read grub.cfg: {:?}", e))?;
    let grub_str = String::from_utf8(grub_content)
        .map_err(|e| anyhow!("Failed to convert grub.cfg to UTF-8: {}", e))?;

    // Parse GRUB configuration; the parser collapses entries sharing a kernel binary.
    let entries = parse_grub_cfg_from_str(&grub_str, true)
        .map_err(|e| anyhow!("Failed to parse grub.cfg: {}", e))?;

    if entries.is_empty() {
        bail!("No GRUB menu entries found in grub.cfg. The file may be empty or malformed.");
    }

    println!(
        "  Found {} unique GRUB menu entr{}",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" }
    );

    // Verify SEV-SNP support for each entry
    let mut supported = Vec::new();
    let mut unsupported = Vec::new();

    for entry in entries {
        println!("\n  Checking SEV-SNP support for kernel: {}", entry.kernel);

        match verify_sev_guest_support(g, &entry.kernel) {
            Ok(SevGuestSupport::SupportedBuiltIn | SevGuestSupport::SupportedModule) => {
                println!("  [+] Kernel supports SEV-SNP");
                supported.push(entry);
            }
            Ok(SevGuestSupport::SupportedButNoModule) => {
                if dist_family == DistroFamily::Ubuntu {
                    println!("  [+] Kernel supports SEV-SNP, but no module is found. Since the guest is Ubuntu, the next step will be to try to install 'linux-modules-extra'");
                    supported.push(entry);
                } else {
                    println!("  [-] Kernel supports SEV-SNP, but no module is found");
                    unsupported.push(entry);
                }
            }
            Ok(SevGuestSupport::NotSupported) => {
                println!("  [-] Kernel does NOT support SEV-SNP");
                unsupported.push(entry);
            }
            Err(e) => {
                println!("  [!] Error checking SEV-SNP support: {}", e);
                unsupported.push(entry);
            }
        }
    }

    Ok((supported, unsupported, boot_partition))
}

/// Extracts kernel, initrd, and kernel parameters from target image using pre-verified GRUB entries.
/// Returns (kernel_data, initrd_data, kernel_params)
/// This function works on the target image and uses the pre-verified entry list from source image.
#[allow(clippy::too_many_arguments)]
fn extract_boot_data(
    g: &guestfs::Handle,
    scratch_rootfs: &str,
    target_rootfs: &str,
    vmk: &[u8],
    supported_entries: &[grub::GrubEntry],
    unsupported_entries: &[grub::GrubEntry],
    boot_partition: &BootPartition,
    no_hardening: bool,
    interactive: bool,
) -> Result<(Vec<u8>, Vec<u8>, String)> {
    use guestfs::UmountOptArgs;

    println!("  Scratch rootfs: {}", scratch_rootfs);
    println!("  Target rootfs: {}", target_rootfs);

    let _guards = RefCell::new(Vec::<Box<dyn FnOnce() + '_>>::new());
    defer! {
        let mut guards = _guards.borrow_mut();
        while let Some(cleanup) = guards.pop() {
            cleanup();
        }
    }

    // Handle boot partition based on type
    match boot_partition {
        BootPartition::Rootfs => {
            // Boot is on rootfs: decrypt target rootfs and mount it as /
            if !no_hardening {
                let luks_key = hex::encode(vmk);
                g.luks_open(target_rootfs, &luks_key, "root_crypt")
                    .map_err(|e| anyhow!("Failed to open LUKS: {:?}", e))?;
                _guards.borrow_mut().push(Box::new(move || {
                    if let Err(e) = g.luks_close("/dev/mapper/root_crypt") {
                        println!("WARN: Failed to close LUKS: {:?}", e);
                    }
                }));
                g.mount_ro("/dev/mapper/root_crypt", "/")
                    .map_err(|e| anyhow!("Failed to mount /dev/mapper/root_crypt: {:?}", e))?;
            } else {
                g.mount_ro(target_rootfs, "/")
                    .map_err(|e| anyhow!("Failed to mount target rootfs directly: {:?}", e))?;
            }
            _guards.borrow_mut().push(Box::new(move || {
                if let Err(e) = g.umount("/", UmountOptArgs::default()) {
                    println!("WARN: Failed to umount /: {:?}", e);
                }
            }));

            println!("  Mounted decrypted target rootfs as /");
            None // Boot is on rootfs, so no separate boot mount
        }
        BootPartition::Boot(boot_dev) => {
            // Mount scratch rootfs temporarily (needed for creating mount points)
            g.mount(scratch_rootfs, "/")
                .map_err(|e| anyhow!("Failed to mount {}: {:?}", scratch_rootfs, e))?;
            _guards.borrow_mut().push(Box::new(move || {
                if let Err(e) = g.umount("/", UmountOptArgs::default()) {
                    println!("WARN: Failed to umount /: {:?}", e);
                }
            }));

            // Boot is on separate partition: mount boot partition as /boot
            let boot_mountpoint = "/boot";
            g.mkdir(boot_mountpoint)
                .map_err(|e| anyhow!("Failed to create {}: {:?}", boot_mountpoint, e))?;
            _guards.borrow_mut().push(Box::new(move || {
                if let Err(e) = g.rmdir(boot_mountpoint) {
                    println!("WARN: Failed to rmdir {}: {:?}", boot_mountpoint, e);
                }
            }));

            g.mount_ro(boot_dev, boot_mountpoint)
                .map_err(|e| anyhow!("Failed to mount boot partition {}: {:?}", boot_dev, e))?;
            _guards.borrow_mut().push(Box::new(move || {
                if let Err(e) = g.umount(boot_mountpoint, UmountOptArgs::default()) {
                    println!("WARN: Failed to umount {}: {:?}", boot_mountpoint, e);
                }
            }));

            println!("  Mounted boot partition to {}", boot_mountpoint);
            Some(boot_mountpoint.to_string())
        }
    };

    // Display available entries
    println!("\n  Available GRUB menu entries:");

    // Show supported entries (selectable)
    if !supported_entries.is_empty() {
        println!("  SEV-SNP supported entries (selectable):");
        for (idx, entry) in supported_entries.iter().enumerate() {
            let default_marker = if entry.is_default { " (default)" } else { "" };
            println!("    [{}] Kernel: {}{}", idx, entry.kernel, default_marker);
            if let Some(ref initrd) = entry.initrd {
                println!("         Initrd: {}", initrd);
            }
            println!("         Parameters: {}", entry.params);
        }
    }

    // Show unsupported entries (not selectable, but visible)
    if !unsupported_entries.is_empty() {
        println!("\n  SEV-SNP unsupported entries (excluded from selection):");
        for (idx, entry) in unsupported_entries.iter().enumerate() {
            let entry_num = supported_entries.len() + idx;
            println!(
                "    [{}] Kernel: {} (SEV-SNP not supported)",
                entry_num, entry.kernel
            );
            if let Some(ref initrd) = entry.initrd {
                println!("         Initrd: {}", initrd);
            }
            println!("         Parameters: {}", entry.params);
        }
    }

    // Select entry from supported list only
    let selected_entry: &grub::GrubEntry = if supported_entries.is_empty() {
        bail!("No SEV-SNP supported kernels found. Cannot proceed.");
    } else if supported_entries.len() == 1 {
        // Single supported entry - use it automatically
        let entry = &supported_entries[0];
        println!("\n  Using single SEV-SNP supported menu entry:");
        println!("    Kernel: {}", entry.kernel);
        if let Some(ref initrd) = entry.initrd {
            println!("    Initrd: {}", initrd);
        } else {
            println!("    Initrd: (none)");
        }
        println!("    Parameters: {}", entry.params);
        entry
    } else if !interactive {
        // Multiple supported entries - auto-select GRUB default, fallback to first
        let selected_idx = supported_entries
            .iter()
            .position(|e| e.is_default)
            .unwrap_or(0);
        let entry = &supported_entries[selected_idx];
        let reason = if entry.is_default {
            "GRUB default"
        } else {
            "first available"
        };
        println!("\n  Auto-selected entry {} ({}):", selected_idx, reason);
        println!("    Kernel: {}", entry.kernel);
        if let Some(ref initrd) = entry.initrd {
            println!("    Initrd: {}", initrd);
        } else {
            println!("    Initrd: (none)");
        }
        println!("    Parameters: {}", entry.params);
        entry
    } else {
        // Multiple supported entries - ask user to select (--interactive mode)
        print!(
            "\n  Enter entry number (0-{}): ",
            supported_entries.len() - 1
        );
        io::stdout()
            .flush()
            .map_err(|e| anyhow!("Failed to flush stdout: {}", e))?;

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| anyhow!("Failed to read user input: {}", e))?;

        let selected_idx: usize = input
            .trim()
            .parse()
            .map_err(|_| anyhow!("Invalid entry number: {}", input.trim()))?;

        if selected_idx >= supported_entries.len() {
            bail!(
                "Entry number {} is out of range (0-{})",
                selected_idx,
                supported_entries.len() - 1
            );
        }

        let entry = &supported_entries[selected_idx];
        println!("\n  Selected entry {}:", selected_idx);
        println!("    Kernel: {}", entry.kernel);
        if let Some(ref initrd) = entry.initrd {
            println!("    Initrd: {}", initrd);
        } else {
            println!("    Initrd: (none)");
        }
        println!("    Parameters: {}", entry.params);
        entry
    };

    let kernel_path = if selected_entry.kernel.starts_with("/boot") {
        selected_entry.kernel.clone()
    } else {
        format!("/boot{}", selected_entry.kernel)
    };

    let initrd_path = selected_entry
        .initrd
        .as_deref()
        .map(|p| {
            if p.starts_with("/boot") {
                p.to_string()
            } else {
                format!("/boot{}", p)
            }
        })
        .ok_or_else(|| anyhow!("No initrd found in boot configuration"))?;

    // Read initrd from target image
    let initrd_data = g
        .read_file(&initrd_path)
        .map_err(|e| anyhow!("Failed to read initrd from {}: {:?}", initrd_path, e))?;

    // Read kernel from target image
    let kernel_data = g
        .read_file(&kernel_path)
        .map_err(|e| anyhow!("Failed to read kernel from {}: {:?}", kernel_path, e))?;

    Ok((kernel_data, initrd_data, selected_entry.params.clone()))
}

fn expand_rootfs(g: &guestfs::Handle, target_rootfs: &str, additional_bytes: u64) -> Result<()> {
    let target_dev = g
        .part_to_dev(target_rootfs)
        .map_err(|e| anyhow!("Failed to get device from target rootfs: {:?}", e))?;

    g.part_expand_gpt(&target_dev)
        .map_err(|e| anyhow!("Failed to expand GPT for target disk: {:?}", e))?;

    let part_num = g
        .part_to_partnum(target_rootfs)
        .map_err(|e| anyhow!("Failed to get partition number of target rootfs: {:?}", e))?;

    let parts = g
        .part_list(&target_dev)
        .map_err(|e| anyhow!("Failed to get partition lists on target rootfs: {:?}", e))?;

    let part_end = parts
        .iter()
        .find(|p| p.part_num == part_num)
        .map(|p| p.part_end)
        .ok_or_else(|| anyhow!("Failed to find the rootfs partition in the partition list"))?;

    // Round down to 1Mb
    let aligned_end_bytes = round_down_1mb(part_end + additional_bytes);

    // Convert to the last inclusive sector. Subtract 1 from bytes,
    // not from sectors to be on the safe side if round up above
    // changes.
    let end_sector = (aligned_end_bytes - 1) >> 9;

    g.part_resize(target_dev.as_str(), part_num, end_sector as i64)
        .map_err(|e| anyhow!("Failed to get resize target rootfs: {:?}", e))?;

    Ok(())
}

fn encrypt_and_copy_rootfs(
    g: &guestfs::Handle,
    scratch_rootfs: &str,
    source_rootfs: &str,
    target_rootfs: &str,
    vmk: &[u8],
) -> Result<()> {
    use guestfs::{MkfsOptArgs, UmountOptArgs};

    // Mount scratch rootfs
    g.mount(scratch_rootfs, "/")
        .map_err(|e| anyhow!("Failed to mount /: {:?}", e))?;
    defer! {
        if let Err(e) = g.umount("/", UmountOptArgs::default()) {
            println!("WARN: Failed to umount /: {:?}", e);
        }
    }

    // Create target and source mountpoints
    let source_dir = "/source";
    let target_dir = "/target";
    g.mkdir(source_dir)
        .map_err(|e| anyhow!("Failed to create {}: {:?}", source_dir, e))?;
    defer! {
        if let Err(e) = g.rmdir(source_dir) {
            println!("WARN: Failed to rmdir {}: {:?}", source_dir, e);
        }
    }
    g.mkdir(target_dir)
        .map_err(|e| anyhow!("Failed to create {}: {:?}", target_dir, e))?;
    defer! {
        if let Err(e) = g.rmdir(target_dir) {
            println!("WARN: Failed to rmdir {}: {:?}", target_dir, e);
        }
    }

    // Mount source rootfs
    g.mount_ro(source_rootfs, source_dir)
        .map_err(|e| anyhow!("Failed to mount {}: {:?}", source_rootfs, e))?;
    defer! {
        if let Err(e) = g.umount(source_dir, UmountOptArgs::default()) {
            println!("WARN: Failed to umount {}: {:?}", source_dir, e);
        }
    }

    // Wipe target rootfs
    g.wipefs(target_rootfs)
        .map_err(|e| anyhow!("Failed to wipefs on target: {:?}", e))?;

    // Expand target rootfs to have some free space
    expand_rootfs(g, target_rootfs, REQUIRED_FREE_BYTES)?;

    // Convert VMK to string for LUKS
    let luks_key = hex::encode(vmk);

    g.luks_format(target_rootfs, &luks_key, 0)
        .map_err(|e| anyhow!("Failed to format LUKS: {:?}", e))?;

    g.luks_open(target_rootfs, &luks_key, "root_crypt")
        .map_err(|e| anyhow!("Failed to open LUKS: {:?}", e))?;
    defer! {
        if let Err(e) = g.luks_close("/dev/mapper/root_crypt") {
            println!("WARN: Failed to close LUKS: {:?}", e);
        }
    }

    // Format the inner filesystem
    g.mkfs("ext4", "/dev/mapper/root_crypt", MkfsOptArgs::default())
        .map_err(|e| anyhow!("Failed to mkfs ext4: {:?}", e))?;

    g.mount("/dev/mapper/root_crypt", target_dir)
        .map_err(|e| anyhow!("Failed to mount /dev/mapper/root_crypt: {:?}", e))?;
    defer! {
        if let Err(e) = g.umount(target_dir, UmountOptArgs::default()) {
            println!("WARN: Failed to umount {}: {:?}", target_dir, e);
        }
    }

    // Copy files
    println!("Copying files from source to encrypted target...");
    for entry in g
        .ls(source_dir)
        .map_err(|e| anyhow!("Failed to `ls {}`: {:?}", source_dir, e))?
    {
        let src = format!("{}/{}", source_dir, entry);
        g.cp_a(&src, target_dir)
            .map_err(|e| anyhow!("Failed to copy {}: {:?}", src, e))?;
    }

    Ok(())
}

/// Upload snpguard files and scripts into a guest image rootfs
#[allow(clippy::too_many_arguments)]
pub fn upload_snpguard_files(
    g: &guestfs::Handle,
    snpguard_client_path: &str,
    ca_pem_path: &str,
    identity_pub_path: &str,
    vmk_sealed_path: &str,
    attest_url: &str,
    hook_path: &str,
    local_top_path: &str,
) -> Result<()> {
    // Create directories
    g.mkdir_p("/etc/snpguard")
        .map_err(|e| anyhow!("Failed to mkdir /etc/snpguard: {:?}", e))?;

    // Upload snpguard binary
    g.upload(snpguard_client_path, "/usr/bin/snpguard-client")
        .map_err(|e| anyhow!("Failed to upload /usr/bin/snpguard-client: {:?}", e))?;
    g.chmod(0o755, "/usr/bin/snpguard-client")
        .map_err(|e| anyhow!("Failed to chmod /usr/bin/snpguard-client: {:?}", e))?;

    // Upload config files
    g.upload(ca_pem_path, "/etc/snpguard/ca.pem")
        .map_err(|e| anyhow!("Failed to upload /etc/snpguard/ca.pem: {:?}", e))?;
    g.upload(identity_pub_path, "/etc/snpguard/identity.pub")
        .map_err(|e| anyhow!("Failed to upload /etc/snpguard/identity.pub: {:?}", e))?;
    g.upload(vmk_sealed_path, "/etc/snpguard/vmk.sealed")
        .map_err(|e| anyhow!("Failed to upload /etc/snpguard/vmk.sealed: {:?}", e))?;
    g.write("/etc/snpguard/attest.url", attest_url.as_bytes())
        .map_err(|e| anyhow!("Failed to write /etc/snpguard/attest.url: {:?}", e))?;

    // Upload initramfs hook script
    g.upload(hook_path, "/etc/initramfs-tools/hooks/snpguard")
        .map_err(|e| {
            anyhow!(
                "Failed to upload /etc/initramfs-tools/hooks/snpguard: {:?}",
                e
            )
        })?;
    g.chmod(0o755, "/etc/initramfs-tools/hooks/snpguard")
        .map_err(|e| {
            anyhow!(
                "Failed to chmod /etc/initramfs-tools/hooks/snpguard: {:?}",
                e
            )
        })?;

    // Upload local-top attestation script
    g.upload(
        local_top_path,
        "/etc/initramfs-tools/scripts/local-top/snpguard-attest",
    )
    .map_err(|e| {
        anyhow!(
            "Failed to upload /etc/initramfs-tools/scripts/local-top/snpguard-attest: {:?}",
            e
        )
    })?;

    g.chmod(
        0o755,
        "/etc/initramfs-tools/scripts/local-top/snpguard-attest",
    )
    .map_err(|e| {
        anyhow!(
            "Failed to chmod /etc/initramfs-tools/scripts/local-top/snpguard-attest: {:?}",
            e
        )
    })?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn install_snpguard_on_target(
    g: &guestfs::Handle,
    source_rootfs: &str,
    target_rootfs: &str,
    vmk: &[u8],
    supported_entries: &Vec<GrubEntry>,
    boot_partition: &BootPartition,
    snpguard_client_path: &str,
    ca_pem_path: &str,
    identity_pub_path: &str,
    vmk_sealed_path: &str,
    attest_url: &str,
    hook_path: &str,
    local_top_path: &str,
) -> Result<()> {
    // Convert VMK to string for LUKS
    let luks_key = hex::encode(vmk);

    g.luks_open(target_rootfs, &luks_key, "root_crypt")
        .map_err(|e| anyhow!("Failed to open LUKS: {:?}", e))?;
    defer! {
        if let Err(e) = g.luks_close("/dev/mapper/root_crypt") {
            println!("WARN: Failed to close LUKS: {:?}", e);
        }
    }

    // Get distribution family
    let dist_family = get_dist_family(g, target_rootfs)?;

    // Mount target as /
    g.mount("/dev/mapper/root_crypt", "/")
        .map_err(|e| anyhow!("Failed to mount /dev/mapper/root_crypt: {:?}", e))?;
    defer! {
        if let Err(e) = g.umount_all() {
            println!("WARN: Failed to umount all: {:?}", e);
        }
    }

    // Mount separate /boot if needed
    if let BootPartition::Boot(boot_dev) = boot_partition {
        let boot_mountpoint = "/boot";
        g.mount(boot_dev, boot_mountpoint)
            .map_err(|e| anyhow!("Failed to mount boot partition {}: {:?}", boot_dev, e))?;
    }

    // Installation and initramfs commands
    let (install_cmds, update_initramfs_cmd): (Vec<String>, Vec<String>) = match dist_family {
        DistroFamily::Debian | DistroFamily::Ubuntu => {
            let mut install = vec![
                // brings the whole network up
                "dhcpcd -1 eth0".to_string(),
                // super important to have this here, see a big comment below
                "echo nameserver 1.1.1.1 > /etc/resolv.conf".to_string(),
                "apt update -y".to_string(),
                "apt install -y cryptsetup cryptsetup-initramfs".to_string(),
            ];

            // Compute extra kernel module packages for Ubuntu
            let extra_modules_pkg = if dist_family == DistroFamily::Ubuntu {
                let mut seen = HashSet::new();
                for entry in supported_entries {
                    let version = kernel_version_from_path(&entry.kernel)
                        .map_err(|e| anyhow!("Failed to extract kernel version: {}", e))?;
                    seen.insert(version);
                }
                seen.iter()
                    .map(|s| format!("linux-modules-extra-{s}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                String::new()
            };

            // Extra modules
            if !extra_modules_pkg.is_empty() {
                install.push(format!("apt install -y {}", extra_modules_pkg));
            }

            // Update initramfs
            let update_initramfs = vec!["update-initramfs -u -k all".to_string()];

            (install, update_initramfs)
        }
        DistroFamily::RedHat => bail!("RedHat distributions are not supported at the moment"),
    };

    // Run install commands in one command. Why join? Each command is
    // not just a command; it is a set of preparations and cleaning
    // routines done by the guestfs daemon. For example, on each
    // command call a copy of /etc/resolv.conf from the appliance VM
    // to rootfs occurs. Therefore, if you update /etc/resolv.conf
    // inside rootfs in a separate command, the file will be
    // immediately overwritten. I encountered a situation where
    // /etc/resolv.conf was missing in the appliance VM (not sure if
    // that's a bug or feature), but the result was that every command
    // should be joined in a pipeline; otherwise, there's no DNS
    // resolving.
    let cmd = install_cmds.join("; ");
    let _out = g
        .sh(&cmd)
        .map_err(|e| anyhow!("Failed to execute '{}': {:?}", cmd, e))?;
    //println!("{}", _out);

    // Upload required files
    upload_snpguard_files(
        g,
        snpguard_client_path,
        ca_pem_path,
        identity_pub_path,
        vmk_sealed_path,
        attest_url,
        hook_path,
        local_top_path,
    )?;

    // Run update initramfs commands
    let cmd = update_initramfs_cmd.join("; ");
    let _out = g
        .sh(&cmd)
        .map_err(|e| anyhow!("Failed to execute '{}': {:?}", cmd, e))?;
    //println!("{}", _out);

    // Copy the source rootfs label to the target rootfs after
    // `cryptsetup` is installed.
    let rootfs_label = g
        .get_e2label(source_rootfs)
        .map_err(|e| anyhow!("Failed to get a label on source rootfs: {:?}", e))?;

    if !rootfs_label.is_empty() {
        let _out = g
            .sh(&format!(
                "cryptsetup config {} --label {}",
                target_rootfs, rootfs_label
            ))
            .map_err(|e| anyhow!("Failed to execute 'cryptsetup config': {:?}", e))?;
        //println!("{}", _out);
    }

    Ok(())
}

/// Resize a QCOW2 image, increasing its size by `additional_bytes`.
pub fn resize_qcow2(image_path: &Path, additional_bytes: u64) -> Result<()> {
    if !image_path.exists() {
        bail!("Image file does not exist: {:?}", image_path);
    }

    // Run qemu-img resize
    let status = std::process::Command::new("qemu-img")
        .args(["resize"])
        .arg(image_path)
        .arg(format!("+{}", additional_bytes))
        .stdout(std::process::Stdio::null())
        .status()?;

    if !status.success() {
        bail!("qemu-img resize failed");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_convert(
    in_image: &Path,
    out_image: &Path,
    out_staging: &Path,
    attest_url: Option<String>,
    ingestion_public_key: Option<PathBuf>,
    ca_cert: Option<PathBuf>,
    identity_pub: Option<PathBuf>,
    firmware: PathBuf,
    no_hardening: bool,
    interactive: bool,
    offline_attestation: bool,
) -> Result<()> {
    let musl_client_path = "target/x86_64-unknown-linux-musl/release/snpguard-client";

    // Verify musl client binary is present before doing any expensive work.
    if !no_hardening && !Path::new(musl_client_path).exists() {
        bail!(
            "snpguard-client (musl) not found at {musl_client_path}\n\
             Build it first:\n  make build-image"
        );
    }

    // Load config if available
    let config = load_config().ok();

    // Resolve attest_url (only required when not in no_hardening mode)
    if !no_hardening {
        let _url = attest_url
            .clone()
            .or_else(|| config.as_ref().and_then(|c| c.url.clone()))
            .ok_or_else(|| {
                anyhow!(
                    "Attestation URL not provided. Please run 'snpguard-client config login' first or provide --attest-url"
                )
            })?;
    }

    // Resolve ingestion public key path
    let ingestion_key_file = ingestion_public_key
        .or_else(|| ingestion_key_path().ok())
        .ok_or_else(|| {
            anyhow!(
                "Ingestion public key not provided. Please run 'snpguard-client config login' first or provide --ingestion-public-key"
            )
        })?;

    if !ingestion_key_file.exists() {
        bail!(
            "Ingestion public key not found at {:?}. Please run 'snpguard-client config login' first or provide --ingestion-public-key",
            ingestion_key_file
        );
    }

    if out_staging.exists() && out_image.exists() {
        bail!(
            "Staging directory {:?} and output image file {:?} already exist",
            out_staging,
            out_image
        );
    }
    if out_staging.exists() {
        bail!("Staging directory already exists: {:?}", out_staging);
    }
    if out_image.exists() {
        bail!("Output image file already exists: {:?}", out_image);
    }
    // Create staging directory
    fs::create_dir_all(out_staging)?;
    let mut cleanup_guard = CleanupGuard::new(out_staging.to_path_buf());

    // Generate random 64-byte VMK
    println!("Generating Volume Master Key (VMK)...");
    let mut vmk = vec![0u8; 64];
    let mut rng = OsRng;
    rng.fill_bytes(&mut vmk);
    let vmk_path = out_staging.join("vmk.bin");
    fs::write(&vmk_path, &vmk)?;

    println!("Generating unsealing keypair...");
    let unsealing_priv_path = out_staging.join("unsealing.key");
    let unsealing_pub_path = out_staging.join("unsealing.pub");
    local_ops::generate_keys(&unsealing_priv_path, &unsealing_pub_path)?;

    println!("Sealing VMK with unsealing public key...");
    let sealed_vmk_file = out_staging.join("vmk.sealed");
    local_ops::encrypt_file(&unsealing_pub_path, &vmk_path, &sealed_vmk_file)?;

    // Remove unsealing public key (not needed after sealing)
    fs::remove_file(&unsealing_pub_path).context("Failed to remove unsealing public key")?;

    println!("Sealing unsealing private key with ingestion public key...");

    // Load ingestion public key
    let ingestion_pub_pem_str = fs::read_to_string(&ingestion_key_file).with_context(|| {
        format!(
            "Failed to read ingestion public key from {:?}",
            ingestion_key_file
        )
    })?;

    let ingestion_pub_pem =
        pem_parse(&ingestion_pub_pem_str).context("Failed to parse ingestion public key PEM")?;

    if ingestion_pub_pem.tag() != "PUBLIC KEY" {
        bail!("Invalid ingestion public key PEM tag (expected PUBLIC KEY)");
    }

    let ingestion_pub_bytes: [u8; 32] = ingestion_pub_pem
        .contents()
        .try_into()
        .map_err(|_| anyhow!("Invalid ingestion public key length (expected 32 bytes)"))?;

    let server_pub = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&ingestion_pub_bytes)
        .map_err(|e| anyhow!("Failed to create ingestion public key: {}", e))?;

    // Load unsealing private key
    let unsealing_priv_pem_str =
        fs::read_to_string(&unsealing_priv_path).context("Failed to read unsealing private key")?;

    let unsealing_priv_pem =
        pem_parse(&unsealing_priv_pem_str).context("Failed to parse unsealing private key PEM")?;

    if unsealing_priv_pem.tag() != "PRIVATE KEY" {
        bail!("Invalid unsealing private key PEM tag (expected PRIVATE KEY)");
    }

    let unsealing_priv_bytes: [u8; 32] = unsealing_priv_pem
        .contents()
        .try_into()
        .map_err(|_| anyhow!("Invalid unsealing private key length (expected 32 bytes)"))?;

    // Encrypt with HPKE
    let mut rng = OsRng;
    let (encapped_key, mut sender_ctx) = hpke::setup_sender::<
        AesGcm256,
        HkdfSha256,
        X25519HkdfSha256,
        _,
    >(&OpModeS::Base, &server_pub, &[], &mut rng)
    .map_err(|e| anyhow!("HPKE setup failed: {}", e))?;

    let ciphertext = sender_ctx
        .seal(&unsealing_priv_bytes, &[])
        .map_err(|e| anyhow!("HPKE seal failed: {}", e))?;

    let encapped_bytes = encapped_key.to_bytes();
    let mut unsealing_key_encrypted = Vec::with_capacity(encapped_bytes.len() + ciphertext.len());
    unsealing_key_encrypted.extend_from_slice(&encapped_bytes);
    unsealing_key_encrypted.extend_from_slice(&ciphertext);

    // Save encrypted unsealing key
    let enc_unsealing_key_path = out_staging.join("unsealing.key.enc");
    fs::write(&enc_unsealing_key_path, &unsealing_key_encrypted)?;

    // Securely delete unencrypted unsealing private key
    println!("Securely deleting unencrypted unsealing private key...");
    secure_delete_file(&unsealing_priv_path)?;

    // Securely delete unencrypted VMK
    println!("Securely deleting unencrypted VMK...");
    secure_delete_file(&vmk_path)?;

    println!("Copying the whole source image to target image...");
    fs::copy(in_image, out_image).with_context(|| {
        format!(
            "Failed to copy {} to {}",
            in_image.display(),
            out_image.display()
        )
    })?;
    cleanup_guard.register_file(out_image.to_path_buf());

    println!(
        "Increase the size of the target QCOW image by {}MB...",
        REQUIRED_FREE_BYTES >> 20
    );
    // Resize the disk with a 2MB buffer. This ensures enough
    // physical space for the 1MB alignment offset at the
    // start and the secondary GPT header at the end of the
    // disk.
    resize_qcow2(out_image, REQUIRED_FREE_BYTES + (2 << 20))?;

    println!("Preparing Guestfs context, launch appliance VM...");
    let (g, scratch_rootfs, source_rootfs, target_rootfs) =
        create_guestfs_context(in_image, out_image)?;

    // Inspect source image to verify SEV-SNP support
    println!("Inspecting source image for SEV-SNP kernel support...");
    let (supported_entries, unsupported_entries, boot_partition) =
        inspect_source_image_boot_data(&g, &source_rootfs)?;

    // Check if any kernels support SEV-SNP
    if supported_entries.is_empty() {
        bail!(
            "No SEV-SNP supported kernels found in source image. Cannot proceed with conversion.\n\
            Found {} unsupported kernel(s). Please use an image with SEV-SNP enabled kernels.",
            unsupported_entries.len()
        );
    }

    println!(
        "\n  Found {} SEV-SNP supported kernel(s) and {} unsupported kernel(s)",
        supported_entries.len(),
        unsupported_entries.len()
    );

    if !no_hardening {
        println!("Encrypting root filesystem with LUKS2...");
        encrypt_and_copy_rootfs(&g, &scratch_rootfs, &source_rootfs, &target_rootfs, &vmk)?;
    }

    let sealed_vmk_path = sealed_vmk_file
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 path: {:?}", sealed_vmk_file))?;

    if !no_hardening {
        let ca_cert_file = ca_cert
            .or_else(|| ca_cert_path().ok())
            .ok_or_else(|| {
                anyhow!(
                    "CA certificate not provided. Please run 'snpguard-client config login' first or provide --ca-cert"
                )
            })?;
        if !ca_cert_file.exists() {
            bail!(
                "CA certificate not found at {:?}. Please run 'snpguard-client config login' first or provide --ca-cert",
                ca_cert_file
            );
        }
        let ca_cert_path_str = ca_cert_file
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non-UTF8 path: {:?}", ca_cert_file))?;
        let identity_pub_file = identity_pub
            .or_else(|| identity_pub_path().ok())
            .ok_or_else(|| {
                anyhow!(
                    "Identity public key not provided. Please run 'snpguard-client config login' first or provide --identity-pub"
                )
            })?;
        if !identity_pub_file.exists() {
            bail!(
                "Identity public key not found at {:?}. Please run 'snpguard-client config login' first or provide --identity-pub",
                identity_pub_file
            );
        }
        let identity_pub_path_str = identity_pub_file
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non-UTF8 path: {:?}", identity_pub_file))?;
        let attest_url_str = attest_url
            .or_else(|| config.as_ref().and_then(|c| c.url.clone()))
            .ok_or_else(|| {
                anyhow!(
                    "Attestation URL not provided. Please run 'snpguard-client config login' first or provide --attest-url"
                )
            })?;
        println!("Install snpguard-client on target and update initrd...");
        install_snpguard_on_target(
            &g,
            &source_rootfs,
            &target_rootfs,
            &vmk,
            &supported_entries,
            &boot_partition,
            musl_client_path,
            ca_cert_path_str,
            identity_pub_path_str,
            sealed_vmk_path,
            &attest_url_str,
            "scripts/initramfs-tools/hook.sh",
            if offline_attestation {
                "scripts/initramfs-tools/attest-offline.sh"
            } else {
                "scripts/initramfs-tools/attest-online.sh"
            },
        )?;
    }
    fs::remove_file(sealed_vmk_path).context("Failed to remove sealed VMK")?;

    println!("Extract boot artifacts (kernel, initrd, params) from target image");
    let (kernel_data, initrd_data, kernel_params) = extract_boot_data(
        &g,
        &scratch_rootfs,
        &target_rootfs,
        &vmk,
        &supported_entries,
        &unsupported_entries,
        &boot_partition,
        no_hardening,
        interactive,
    )?;

    // Write artifacts to staging directory
    // Copy firmware (required)
    let firmware_dest = out_staging.join("firmware-code.fd");
    fs::copy(&firmware, &firmware_dest).with_context(|| {
        format!(
            "Failed to copy firmware from {:?} to {:?}",
            firmware, firmware_dest
        )
    })?;
    println!("Copied firmware to firmware-code.fd");

    // Write extracted repacked initrd
    let initrd_dest = out_staging.join("initrd.img");
    fs::write(&initrd_dest, &initrd_data).context("Failed to write repacked initrd")?;
    println!("Wrote repacked initrd to initrd.img");

    // Write extracted kernel
    let kernel_dest = out_staging.join("vmlinuz");
    fs::write(&kernel_dest, &kernel_data).context("Failed to write kernel")?;
    println!("Wrote kernel to vmlinuz");

    // Write kernel params
    let params_dest = out_staging.join("kernel-params.txt");
    fs::write(&params_dest, &kernel_params).context("Failed to write kernel params")?;
    println!("Wrote kernel params to kernel-params.txt");

    // Mark staging and target image as kept
    cleanup_guard.keep();

    println!("Image conversion completed successfully!");
    println!("  Output image: {:?}", out_image);
    println!("  Staging directory: {:?}", out_staging);
    println!("  Encrypted unsealing key: {:?}", enc_unsealing_key_path);

    Ok(())
}

/// Embed boot artifacts into a QCOW2 image
///
/// This function implements an idempotent update of a boot partition
/// identified by filesystem label "launch_artifacts". If the
/// partition doesn't exist, it creates a new 512MB partition, formats
/// it as ext4, and sets the label. Then it wipes the partition and
/// extracts the bundle contents into a A/B directory structure.
fn run_embed(image_path: &Path, bundle_path: &Path) -> Result<()> {
    use guestfs::{AddDriveOptArgs, Handle, MkfsOptArgs};

    const LABEL: &str = "LAUNCH_ARTIFACTS";
    const PARTITION_SIZE_MB: u64 = 512;

    // Discovery
    let g = Handle::create().map_err(|e| anyhow!("Failed to create guestfs handle: {:?}", e))?;
    g.add_drive(
        &image_path.to_string_lossy(),
        AddDriveOptArgs {
            label: Some("source"),
            readonly: Some(false),
            format: Some("qcow2"),
            ..Default::default()
        },
    )
    .map_err(|e| anyhow!("Failed to add drive: {:?}", e))?;
    g.launch()
        .map_err(|e| anyhow!("Failed to launch guestfs: {:?}", e))?;

    // Disk labels
    let labels = g
        .list_disk_labels()
        .map_err(|e| anyhow!("Failed to list disk labels: {:?}", e))?;

    let disk = labels
        .iter()
        .find(|(label, _)| *label == "source")
        .map(|(_, disk)| disk)
        .ok_or_else(|| anyhow::anyhow!("Failed to find QCOW image by the label"))?;

    let parts = g
        .part_list(disk)
        .map_err(|e| anyhow!("Failed to get partition lists : {:?}", e))?;

    let mut target_partition = None;

    for p in parts {
        let candidate = format!("{}{}", disk, p.part_num);

        let label = g
            .vfs_label(&candidate)
            .map_err(|e| anyhow!("Failed to get FS label on {}: {:?}", candidate, e))?;

        if label == LABEL {
            target_partition = Some(candidate);
            break;
        }
    }

    // Try to find device by FS LABEL
    let (g, target_partition) = match target_partition {
        Some(dev) => {
            println!("Found a previously created `LAUNCH_ARTIFACTS` partition, wiping it...");

            // Wipefs partition
            g.wipefs(&dev)
                .map_err(|e| anyhow!("Failed to wipefs on target partition: {:?}", e))?;

            // Partition exists, proceed directly to population
            (g, dev)
        }
        _ => {
            // Create partition and populate

            // We must close the handle to resize the file safely
            g.shutdown()
                .map_err(|e| anyhow!("Failed to shutdown guestfs: {:?}", e))?;
            drop(g);

            println!(
                "Increase the size of the target QCOW image by {}MB...",
                PARTITION_SIZE_MB
            );

            // Resize the disk with a 2MB buffer. This ensures enough
            // physical space for the 1MB alignment offset at the
            // start and the secondary GPT header at the end of the
            // disk.
            resize_qcow2(image_path, (PARTITION_SIZE_MB + 2) << 20)?;

            // Create guestfs once again
            let g = Handle::create()
                .map_err(|e| anyhow!("Failed to create guestfs handle: {:?}", e))?;
            g.add_drive(
                &image_path.to_string_lossy(),
                AddDriveOptArgs {
                    label: Some("source"),
                    readonly: Some(false),
                    format: Some("qcow2"),
                    ..Default::default()
                },
            )
            .map_err(|e| anyhow!("Failed to add drive: {:?}", e))?;

            // Run appliance VM
            g.launch()
                .map_err(|e| anyhow!("Failed to launch guestfs: {:?}", e))?;

            // Disk labels
            let labels = g
                .list_disk_labels()
                .map_err(|e| anyhow!("Failed to list disk labels: {:?}", e))?;

            let disk = labels
                .iter()
                .find(|(label, _)| *label == "source")
                .map(|(_, disk)| disk)
                .ok_or_else(|| anyhow::anyhow!("Failed to find QCOW image by the label"))?;

            g.part_expand_gpt(disk)
                .map_err(|e| anyhow!("Failed to expand GPT for target disk: {:?}", e))?;

            // Calculate geometry
            let parts = g
                .part_list(disk)
                .map_err(|e| anyhow!("Failed to get partition list: {:?}", e))?;
            let last_end = parts.last().map(|p| p.part_end).ok_or_else(|| {
                anyhow::anyhow!("Failed to get the last partition; the disk is empty.")
            })?;

            // Align start to next 1MB
            let start = round_up_1mb(last_end);

            // End
            let end = start + (PARTITION_SIZE_MB << 20);

            let start_sector = start >> 9;
            let end_sector = (end - 1) >> 9;

            println!("Add new partition...");

            // Create primary partition
            g.part_add(disk, "p", start_sector as i64, end_sector as i64)
                .map_err(|e| anyhow!("Failed to add partition: {:?}", e))?;

            // Identify new partition (it is the last one)
            let parts = g
                .part_list(disk)
                .map_err(|e| anyhow!("Failed to get partition list: {:?}", e))?;
            let new_part_num = parts
                .last()
                .ok_or_else(|| anyhow!("Failed to find new partition"))?
                .part_num;
            let new_dev = format!("{}{}", disk, new_part_num);

            // Hand over control of the new handle
            (g, new_dev)
        }
    };

    println!("Format `LAUNCH_ARTIFACTS` partition as ext4...");

    // Population
    g.mkfs("ext4", &target_partition, MkfsOptArgs::default())
        .map_err(|e| anyhow!("Failed to format partition: {:?}", e))?;
    g.set_e2label(&target_partition, LABEL)
        .map_err(|e| anyhow!("Failed to set filesystem label: {:?}", e))?;
    g.mount(&target_partition, "/")
        .map_err(|e| anyhow!("Failed to mount partition: {:?}", e))?;

    println!("Populate the `LAUNCH_ARTIFACTS` partition with files from the bundle...");

    // Setup structure
    g.mkdir("/A")
        .map_err(|e| anyhow!("Failed to create /A directory: {:?}", e))?;
    g.mkdir("/B")
        .map_err(|e| anyhow!("Failed to create /B directory: {:?}", e))?;
    use guestfs::TarInOptArgs;

    let bundle_path_str = bundle_path.to_str().unwrap();
    if bundle_path_str.ends_with("gz") {
        g.tgz_in(bundle_path.to_str().unwrap(), "/A")
            .map_err(|e| anyhow!("Failed to extract tarball: {:?}", e))?;
    } else {
        g.tar_in(bundle_path.to_str().unwrap(), "/A", TarInOptArgs::default())
            .map_err(|e| anyhow!("Failed to extract tarball: {:?}", e))?;
    }

    // Create symlink (artifacts -> A)
    g.ln_s("A", "/artifacts")
        .map_err(|e| anyhow!("Failed to create symlink: {:?}", e))?;

    use guestfs::UmountOptArgs;
    g.umount("/", UmountOptArgs::default())
        .map_err(|e| anyhow!("Failed to unmount: {:?}", e))?;
    g.shutdown()
        .map_err(|e| anyhow!("Failed to shutdown guestfs: {:?}", e))?;

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Keygen { priv_out, pub_out } => {
            local_ops::generate_keys(&priv_out, &pub_out)?;
            Ok(())
        }
        Command::Seal { pub_key, data, out } => {
            local_ops::encrypt_file(&pub_key, &data, &out)?;
            Ok(())
        }
        Command::Unseal {
            priv_key,
            sealed_data,
            out,
        } => {
            local_ops::decrypt_file(&priv_key, &sealed_data, &out)?;
            Ok(())
        }
        Command::Convert {
            in_image,
            out_image,
            out_staging,
            attest_url,
            ingestion_public_key,
            ca_cert,
            identity_pub,
            firmware,
            no_hardening,
            interactive,
            offline_attestation,
        } => run_convert(
            &in_image,
            &out_image,
            &out_staging,
            attest_url,
            ingestion_public_key,
            ca_cert,
            identity_pub,
            firmware,
            no_hardening,
            interactive,
            offline_attestation,
        ),
        Command::Embed { image, in_bundle } => run_embed(&image, &in_bundle),
    }
}
