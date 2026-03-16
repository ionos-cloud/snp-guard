use crate::{config::DataPaths, ingestion_key, snpguest_wrapper};
use entity::{vm, vm_registration};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use rand::{rngs::OsRng, RngCore};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set, TransactionTrait};
use serde_json::json;
use sev::firmware::guest::GuestPolicy;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

/// Guard to ensure artifact directory is cleaned up on error
struct ArtifactDirGuard {
    path: PathBuf,
    should_cleanup: bool,
}

impl ArtifactDirGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            should_cleanup: true,
        }
    }

    fn keep(&mut self) {
        self.should_cleanup = false;
    }
}

impl Drop for ArtifactDirGuard {
    fn drop(&mut self) {
        if self.should_cleanup && self.path.exists() {
            if let Err(e) = fs::remove_dir_all(&self.path) {
                eprintln!(
                    "Warning: Failed to cleanup artifact directory {:?}: {}",
                    self.path, e
                );
            }
        }
    }
}

/// Remove an artifact directory, logging a warning on failure.
///
/// The removal is skipped silently if `artifact_dir` does not resolve to a
/// path inside `base_dir` (path-traversal safety check).
fn remove_artifact_dir(base_dir: &Path, artifact_dir: &Path) {
    if !artifact_dir.exists() {
        return;
    }
    let safe = base_dir
        .canonicalize()
        .ok()
        .and_then(|base| {
            artifact_dir
                .canonicalize()
                .ok()
                .map(|p| p.starts_with(&base))
        })
        .unwrap_or(false);
    if safe {
        if let Err(e) = fs::remove_dir_all(artifact_dir) {
            eprintln!(
                "Warning: failed to remove artifact dir {:?}: {}",
                artifact_dir, e
            );
        }
    }
}

#[derive(Debug)]
pub struct CreateRecordRequest {
    pub os_name: String,
    pub firmware_data: Option<Vec<u8>>,
    pub kernel_data: Option<Vec<u8>>,
    pub initrd_data: Option<Vec<u8>>,
    pub kernel_params: String,
    pub vcpus: u32,
    pub vcpu_type: String,
    pub unsealing_private_key_encrypted: Vec<u8>, // HPKE-encrypted unsealing private key
    pub allowed_debug: bool,
    pub allowed_migrate_ma: bool,
    pub allowed_smt: bool,
    pub min_tcb_bootloader: u32,
    pub min_tcb_tee: u32,
    pub min_tcb_snp: u32,
    pub min_tcb_microcode: u32,
}

/// Generate a secp384r1 EC private key in PEM format
fn generate_ec_key_pem() -> Result<Vec<u8>, String> {
    use openssl::pkey::PKey;

    let group = EcGroup::from_curve_name(Nid::SECP384R1)
        .map_err(|e| format!("Failed to create EC group: {}", e))?;
    let key = EcKey::generate(&group).map_err(|e| format!("Failed to generate EC key: {}", e))?;
    let pkey = PKey::from_ec_key(key).map_err(|e| format!("Failed to create PKey: {}", e))?;
    pkey.private_key_to_pem_pkcs8()
        .map_err(|e| format!("Failed to serialize key to PEM: {}", e))
}

/// Securely delete a file by overwriting its contents before removal.
/// This helps prevent recovery of sensitive data from disk.
fn secure_delete_file(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(()); // File doesn't exist, nothing to delete
    }

    // Get file size
    let metadata = fs::metadata(path).map_err(|e| format!("Failed to get file metadata: {}", e))?;
    let file_size = metadata.len() as usize;

    if file_size == 0 {
        // Empty file, just delete it
        fs::remove_file(path).map_err(|e| format!("Failed to delete empty file: {}", e))?;
        return Ok(());
    }

    // Open file for writing (truncate to overwrite)
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|e| format!("Failed to open file for secure deletion: {}", e))?;

    // Overwrite with random data (single pass is sufficient for modern systems)
    let mut rng = OsRng;
    let mut buffer = vec![0u8; file_size.min(64 * 1024)]; // 64KB buffer
    let mut remaining = file_size;

    while remaining > 0 {
        let to_write = remaining.min(buffer.len());
        rng.fill_bytes(&mut buffer[..to_write]);
        file.write_all(&buffer[..to_write])
            .map_err(|e| format!("Failed to overwrite file content: {}", e))?;
        remaining -= to_write;
    }

    // Sync to ensure data is written to disk
    file.sync_all()
        .map_err(|e| format!("Failed to sync file: {}", e))?;

    // Close file before deletion
    drop(file);

    // Delete the file
    fs::remove_file(path).map_err(|e| format!("Failed to delete file after overwrite: {}", e))?;

    Ok(())
}

/// Create a new VM registration with an associated attestation record.
///
/// Returns the VmRegistration ID (the stable, client-facing identifier).
/// The AttestationRecord ID is internal and used only for artifact directory
/// naming and attestation report matching.
pub async fn create_record_logic(
    db: &DatabaseConnection,
    paths: &DataPaths,
    ingestion_keys: Arc<ingestion_key::IngestionKeys>,
    req: CreateRecordRequest,
) -> Result<String, String> {
    // record_id names the artifact directory; reg_id is the client-facing ID
    let record_id = Uuid::new_v4().to_string();
    let reg_id = Uuid::new_v4().to_string();
    let artifact_dir = paths.attestations_dir.join(&record_id);

    // Create cleanup guard to ensure directory is removed on any error
    let mut cleanup_guard = ArtifactDirGuard::new(artifact_dir.clone());

    // Generate unique image_id as UUID (16 bytes)
    let image_id = Uuid::new_v4();

    let result = async {
        fs::create_dir_all(&artifact_dir)
            .map_err(|e| format!("Failed to create artifact directory: {}", e))?;

        // Generate ID and Auth keys on server
        let id_key_pem =
            generate_ec_key_pem().map_err(|e| format!("Failed to generate ID key: {}", e))?;
        let auth_key_pem =
            generate_ec_key_pem().map_err(|e| format!("Failed to generate auth key: {}", e))?;

        // Save generated keys
        fs::write(artifact_dir.join("id-block-key.pem"), &id_key_pem)
            .map_err(|e| format!("Failed to save ID key: {}", e))?;
        fs::write(artifact_dir.join("id-auth-key.pem"), &auth_key_pem)
            .map_err(|e| format!("Failed to save auth key: {}", e))?;

        // Unsealing private key is already encrypted by client with ingestion public key
        // Just store it directly
        if let Some(firmware) = req.firmware_data {
            fs::write(artifact_dir.join("firmware-code.fd"), firmware)
                .map_err(|e| format!("Failed to save firmware: {}", e))?;
        }
        if let Some(kernel) = req.kernel_data {
            fs::write(artifact_dir.join("vmlinuz"), kernel)
                .map_err(|e| format!("Failed to save kernel: {}", e))?;
        }
        if let Some(initrd) = req.initrd_data {
            fs::write(artifact_dir.join("initrd.img"), initrd)
                .map_err(|e| format!("Failed to save initrd: {}", e))?;
        }

        fs::write(artifact_dir.join("kernel-params.txt"), &req.kernel_params)
            .map_err(|e| format!("Failed to save kernel params: {}", e))?;

        let mut policy: GuestPolicy = Default::default();
        policy.set_debug_allowed(req.allowed_debug);
        policy.set_migrate_ma_allowed(req.allowed_migrate_ma);
        policy.set_smt_allowed(req.allowed_smt);

        let launch_config = json!({
            "vcpu-model": req.vcpu_type,
            "vcpu-count": req.vcpus,
            "guest-policy": format!("0x{:x}", u64::from(policy)),
        });

        let launch_config_bytes = serde_json::to_vec_pretty(&launch_config)
            .map_err(|e| format!("Failed to serialize launch config.: {}", e))?;

        // Create launch-config.json, which can be used for correct VM launch
        fs::write(artifact_dir.join("launch-config.json"), launch_config_bytes)
            .map_err(|e| format!("Failed to save launch config: {}", e))?;

        // Generate Measurements and Blocks
        let _ = snpguest_wrapper::generate_measurement_and_block(
            &artifact_dir.join("firmware-code.fd"),
            &artifact_dir.join("vmlinuz"),
            &artifact_dir.join("initrd.img"),
            &req.kernel_params,
            req.vcpus,
            &req.vcpu_type,
            policy.into(),
            &artifact_dir.join("id-block-key.pem"),
            &artifact_dir.join("id-auth-key.pem"),
            &artifact_dir,
            image_id.as_bytes(),
        )
        .map_err(|e| format!("Failed to generate measurement and blocks: {}", e))?;

        // Get Digests
        let id_digest = snpguest_wrapper::get_key_digest(&artifact_dir.join("id-block-key.pem"))
            .map_err(|e| format!("Failed to get ID key digest: {}", e))?;
        let auth_digest = snpguest_wrapper::get_key_digest(&artifact_dir.join("id-auth-key.pem"))
            .map_err(|e| format!("Failed to get auth key digest: {}", e))?;

        // Encrypt ID and Auth keys with ingestion key
        let id_key_encrypted = ingestion_keys
            .encrypt(&id_key_pem)
            .map_err(|e| format!("Failed to encrypt ID key: {}", e))?;
        let auth_key_encrypted = ingestion_keys
            .encrypt(&auth_key_pem)
            .map_err(|e| format!("Failed to encrypt Auth key: {}", e))?;

        // Securely delete key files after encryption (they're no longer needed)
        secure_delete_file(&artifact_dir.join("id-block-key.pem"))
            .map_err(|e| format!("Failed to securely delete ID key file: {}", e))?;
        secure_delete_file(&artifact_dir.join("id-auth-key.pem"))
            .map_err(|e| format!("Failed to securely delete Auth key file: {}", e))?;

        let now = chrono::Utc::now().naive_utc();

        // Insert attestation record first (artifact directory is named after record_id)
        let new_record = vm::ActiveModel {
            id: Set(record_id.clone()),
            registration_id: Set(reg_id.clone()),
            unsealing_private_key_encrypted: Set(req.unsealing_private_key_encrypted),
            vcpus: Set(req.vcpus as i32),
            vcpu_type: Set(req.vcpu_type),
            created_at: Set(now),
            image_id: Set(image_id.as_bytes().to_vec()),
            allowed_debug: Set(req.allowed_debug),
            allowed_migrate_ma: Set(req.allowed_migrate_ma),
            allowed_smt: Set(req.allowed_smt),
            min_tcb_bootloader: Set(req.min_tcb_bootloader as i32),
            min_tcb_tee: Set(req.min_tcb_tee as i32),
            min_tcb_snp: Set(req.min_tcb_snp as i32),
            min_tcb_microcode: Set(req.min_tcb_microcode as i32),
            kernel_params: Set(Some(req.kernel_params)),
            firmware_path: Set(Some("firmware-code.fd".into())),
            kernel_path: Set(Some("vmlinuz".into())),
            initrd_path: Set(Some("initrd.img".into())),
        };

        new_record
            .insert(db)
            .await
            .map_err(|e| format!("Failed to save attestation record: {}", e))?;

        // Insert vm_registration pointing at the record we just created.
        // SQLite does not enforce FK constraints by default, so insertion order
        // does not cause a constraint violation.
        let new_registration = vm_registration::ActiveModel {
            id: Set(reg_id.clone()),
            os_name: Set(req.os_name),
            enabled: Set(true),
            request_count: Set(0),
            current_record_id: Set(record_id.clone()),
            pending_record_id: Set(None),
            // Stable cryptographic identity -- generated once, reused across renewals
            id_key_digest: Set(id_digest),
            auth_key_digest: Set(auth_digest),
            id_key_encrypted: Set(Some(id_key_encrypted)),
            auth_key_encrypted: Set(Some(auth_key_encrypted)),
            created_at: Set(now),
        };

        if let Err(e) = new_registration.insert(db).await {
            // Roll back the attestation record we already inserted so the DB
            // does not contain an orphaned row.
            let _ = vm::Entity::delete_by_id(&record_id).exec(db).await;
            return Err(format!("Failed to save registration: {}", e));
        }

        Ok(reg_id.clone())
    }
    .await;

    // If successful, keep the artifact directory; otherwise it will be cleaned up on drop
    match &result {
        Ok(_) => cleanup_guard.keep(),
        Err(_) => {
            // Explicitly try cleanup (guard's Drop will also try, but this ensures it happens)
            let _ = fs::remove_dir_all(&artifact_dir);
        }
    }

    result
}

/// Artifact files included in a RenewResponse.
///
/// Kernel, initrd, and kernel-params are excluded: the guest supplied them
/// (or inherited them) and does not need them echoed back.
pub const RENEW_RESPONSE_ARTIFACTS: &[&str] = &[
    "firmware-code.fd",
    "id-block.bin",
    "id-auth.bin",
    "launch-config.json",
];

#[derive(Debug)]
pub struct RenewRecordRequest {
    pub firmware_data: Option<Vec<u8>>,
    pub kernel_data: Option<Vec<u8>>,
    pub initrd_data: Option<Vec<u8>>,
    pub kernel_params: Option<String>,
}

/// Create a pending attestation record for an existing VM registration.
///
/// Artifacts absent from the request are copied from the current record's
/// artifact directory so the pending record is self-contained.  Policy,
/// vCPU config, and the unsealing key are always inherited from the
/// current record.  The id/auth keys are the stable per-registration keys
/// stored on `registration`; they are decrypted, used for measurement, then
/// securely deleted from the temporary artifact directory.
/// On success, `vm_registration.pending_record_id` is set to the new record's ID.
pub async fn renew_record_logic(
    db: &DatabaseConnection,
    paths: &DataPaths,
    ingestion_keys: Arc<ingestion_key::IngestionKeys>,
    registration: vm_registration::Model,
    current_record: vm::Model,
    req: RenewRecordRequest,
) -> Result<String, String> {
    let pending_id = Uuid::new_v4().to_string();
    let artifact_dir = paths.attestations_dir.join(&pending_id);
    let current_dir = paths.attestations_dir.join(&current_record.id);
    let mut cleanup_guard = ArtifactDirGuard::new(artifact_dir.clone());
    let image_id = Uuid::new_v4();
    // Capture any existing pending record so we can replace it atomically.
    let old_pending_id = registration.pending_record_id.clone();

    let result = async {
        fs::create_dir_all(&artifact_dir)
            .map_err(|e| format!("Failed to create artifact directory: {}", e))?;

        // Decrypt the stable id/auth keys from the registration so they can
        // be passed to snpguest for measurement.  The encrypted copies remain
        // on the registration unchanged; only the temp files are deleted after use.
        let id_key_pem = ingestion_keys
            .decrypt(
                registration
                    .id_key_encrypted
                    .as_deref()
                    .ok_or_else(|| "Registration has no id_key_encrypted".to_string())?,
            )
            .map_err(|e| format!("Failed to decrypt ID key: {}", e))?;
        let auth_key_pem = ingestion_keys
            .decrypt(
                registration
                    .auth_key_encrypted
                    .as_deref()
                    .ok_or_else(|| "Registration has no auth_key_encrypted".to_string())?,
            )
            .map_err(|e| format!("Failed to decrypt auth key: {}", e))?;

        fs::write(artifact_dir.join("id-block-key.pem"), &id_key_pem)
            .map_err(|e| format!("Failed to write ID key: {}", e))?;
        fs::write(artifact_dir.join("id-auth-key.pem"), &auth_key_pem)
            .map_err(|e| format!("Failed to write auth key: {}", e))?;

        // Resolve firmware: from request or copy from current record dir
        let firmware_path: Option<String> = match req.firmware_data {
            Some(data) => {
                fs::write(artifact_dir.join("firmware-code.fd"), data)
                    .map_err(|e| format!("Failed to save firmware: {}", e))?;
                Some("firmware-code.fd".into())
            }
            None => {
                if let Some(p) = &current_record.firmware_path {
                    fs::copy(current_dir.join(p), artifact_dir.join(p))
                        .map_err(|e| format!("Failed to copy firmware: {}", e))?;
                    Some(p.clone())
                } else {
                    None
                }
            }
        };

        // Resolve kernel
        let kernel_path: Option<String> = match req.kernel_data {
            Some(data) => {
                fs::write(artifact_dir.join("vmlinuz"), data)
                    .map_err(|e| format!("Failed to save kernel: {}", e))?;
                Some("vmlinuz".into())
            }
            None => {
                if let Some(p) = &current_record.kernel_path {
                    fs::copy(current_dir.join(p), artifact_dir.join(p))
                        .map_err(|e| format!("Failed to copy kernel: {}", e))?;
                    Some(p.clone())
                } else {
                    None
                }
            }
        };

        // Resolve initrd
        let initrd_path: Option<String> = match req.initrd_data {
            Some(data) => {
                fs::write(artifact_dir.join("initrd.img"), data)
                    .map_err(|e| format!("Failed to save initrd: {}", e))?;
                Some("initrd.img".into())
            }
            None => {
                if let Some(p) = &current_record.initrd_path {
                    fs::copy(current_dir.join(p), artifact_dir.join(p))
                        .map_err(|e| format!("Failed to copy initrd: {}", e))?;
                    Some(p.clone())
                } else {
                    None
                }
            }
        };

        // Resolve kernel params
        let kernel_params = req
            .kernel_params
            .or_else(|| current_record.kernel_params.clone())
            .unwrap_or_default();
        fs::write(artifact_dir.join("kernel-params.txt"), &kernel_params)
            .map_err(|e| format!("Failed to save kernel params: {}", e))?;

        // Rebuild guest policy from inherited config
        let mut policy: GuestPolicy = Default::default();
        policy.set_debug_allowed(current_record.allowed_debug);
        policy.set_migrate_ma_allowed(current_record.allowed_migrate_ma);
        policy.set_smt_allowed(current_record.allowed_smt);

        let launch_config = json!({
            "vcpu-model": current_record.vcpu_type,
            "vcpu-count": current_record.vcpus,
            "guest-policy": format!("0x{:x}", u64::from(policy)),
        });
        let launch_config_bytes = serde_json::to_vec_pretty(&launch_config)
            .map_err(|e| format!("Failed to serialize launch config: {}", e))?;
        fs::write(artifact_dir.join("launch-config.json"), launch_config_bytes)
            .map_err(|e| format!("Failed to save launch config: {}", e))?;

        // Generate measurement and blocks
        let _ = snpguest_wrapper::generate_measurement_and_block(
            &artifact_dir.join(firmware_path.as_deref().unwrap_or("firmware-code.fd")),
            &artifact_dir.join(kernel_path.as_deref().unwrap_or("vmlinuz")),
            &artifact_dir.join(initrd_path.as_deref().unwrap_or("initrd.img")),
            &kernel_params,
            current_record.vcpus as u32,
            &current_record.vcpu_type,
            policy.into(),
            &artifact_dir.join("id-block-key.pem"),
            &artifact_dir.join("id-auth-key.pem"),
            &artifact_dir,
            image_id.as_bytes(),
        )
        .map_err(|e| format!("Failed to generate measurement and blocks: {}", e))?;

        // Securely delete the temp key files -- encrypted originals remain on the registration
        secure_delete_file(&artifact_dir.join("id-block-key.pem"))
            .map_err(|e| format!("Failed to securely delete ID key: {}", e))?;
        secure_delete_file(&artifact_dir.join("id-auth-key.pem"))
            .map_err(|e| format!("Failed to securely delete auth key: {}", e))?;

        let now = chrono::Utc::now().naive_utc();

        let pending_record = vm::ActiveModel {
            id: Set(pending_id.clone()),
            registration_id: Set(registration.id.clone()),
            unsealing_private_key_encrypted: Set(current_record
                .unsealing_private_key_encrypted
                .clone()),
            vcpus: Set(current_record.vcpus),
            vcpu_type: Set(current_record.vcpu_type.clone()),
            created_at: Set(now),
            image_id: Set(image_id.as_bytes().to_vec()),
            allowed_debug: Set(current_record.allowed_debug),
            allowed_migrate_ma: Set(current_record.allowed_migrate_ma),
            allowed_smt: Set(current_record.allowed_smt),
            min_tcb_bootloader: Set(current_record.min_tcb_bootloader),
            min_tcb_tee: Set(current_record.min_tcb_tee),
            min_tcb_snp: Set(current_record.min_tcb_snp),
            min_tcb_microcode: Set(current_record.min_tcb_microcode),
            kernel_params: Set(Some(kernel_params)),
            firmware_path: Set(firmware_path),
            kernel_path: Set(kernel_path),
            initrd_path: Set(initrd_path),
        };

        // Insert the new pending record, replace any previous one, and update
        // the registration pointer -- all three must succeed or none should.
        let txn = db
            .begin()
            .await
            .map_err(|e| format!("Failed to begin transaction: {}", e))?;

        pending_record
            .insert(&txn)
            .await
            .map_err(|e| format!("Failed to save pending record: {}", e))?;

        // If there was already a pending record, delete it in the same
        // transaction so we never leave a dangling reference.
        if let Some(ref old_id) = old_pending_id {
            vm::Entity::delete_by_id(old_id.as_str())
                .exec(&txn)
                .await
                .map_err(|e| format!("Failed to delete previous pending record: {}", e))?;
        }

        // Point the registration at the new pending record
        let mut active: vm_registration::ActiveModel = registration.into();
        active.pending_record_id = Set(Some(pending_id.clone()));
        active
            .update(&txn)
            .await
            .map_err(|e| format!("Failed to update registration: {}", e))?;

        txn.commit()
            .await
            .map_err(|e| format!("Failed to commit renewal: {}", e))?;

        Ok(pending_id)
    }
    .await;

    match &result {
        Ok(_) => {
            cleanup_guard.keep();
            // Remove the replaced pending artifact directory from disk.
            if let Some(ref old_id) = old_pending_id {
                remove_artifact_dir(
                    &paths.attestations_dir,
                    &paths.attestations_dir.join(old_id),
                );
            }
        }
        Err(_) => {
            let _ = fs::remove_dir_all(&artifact_dir);
        }
    }

    result
}
