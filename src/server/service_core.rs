use std::collections::HashMap;
use std::sync::Arc;

use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
    TransactionTrait,
};

use crate::config::DataPaths;
use crate::identity_key::IdentityKey;
use crate::ingestion_key::IngestionKeys;
use common::snpguard::{
    ArtifactEntry, AttestationRecord, AttestationRequest, AttestationResponse, CreateRecordRequest,
    RenewRequest, RenewRequestPayload, RenewResponse, RenewResponsePayload, ToggleEnabledRequest,
};
use entity::{token, vm, vm_registration};
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{Kem, X25519HkdfSha256},
    Deserializable, OpModeR, OpModeS, Serializable,
};
use rand::rngs::OsRng;
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use sha2::{Digest, Sha512};

use crate::business_logic;
use crate::snpguest_wrapper;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::Engine;
use prost::Message;
use rand::RngCore;
use uuid::Uuid;

pub struct ServiceState {
    pub db: DatabaseConnection,
    pub attestation_state: Arc<AttestationState>,
    pub data_paths: Arc<DataPaths>,
    pub ingestion_keys: Arc<IngestionKeys>,
    pub identity_key: Arc<IdentityKey>,
}

#[derive(Clone)]
pub struct AttestationState {
    pub db: DatabaseConnection,
    pub secret: [u8; 32],
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TokenInfo {
    pub id: String,
    pub label: String,
    pub created_at: String,
    pub expires_at: String,
    pub revoked: bool,
}

fn fmt_ts(ts: chrono::NaiveDateTime) -> String {
    ts.format("%Y-%m-%d %H:%M UTC").to_string()
}

fn parse_snp_report(report_data: &[u8]) -> Result<AttestationReport, String> {
    AttestationReport::from_bytes(report_data)
        .map_err(|e| format!("Failed to parse attestation report: {e}"))
}

/// Verify the binding hash embedded in the SNP report.
///
/// The report commits to SHA512(hash_input).  For the attestation flow
/// hash_input = server_nonce || client_pub_bytes; for the renewal flow it is
/// payload_bytes (which already contains server_nonce inside it).
fn verify_binding_hash(hash_input: &[u8], report_data: &[u8; 64]) -> Result<(), String> {
    let expected: [u8; 64] = Sha512::digest(hash_input).into();

    if report_data != &expected {
        return Err("Security Alert: REPORT_DATA binding mismatch!".to_string());
    }

    Ok(())
}

/// Cheap, synchronous part of report verification: parse, nonce, binding
/// hash, and VMPL.  Intentionally excludes signature verification, which
/// requires a network round-trip to AMD KDS and must run last (see
/// `verify_report_signature`).
fn verify_snp_report(
    report_data: &[u8],
    server_nonce: &[u8],
    hash_input: &[u8],
    nonce_secret: &[u8; 32],
) -> Result<AttestationReport, String> {
    let report = parse_snp_report(report_data)?;

    crate::nonce::verify_nonce(nonce_secret, server_nonce)
        .map_err(|e| format!("Invalid or expired nonce: {:?}", e))?;

    verify_binding_hash(hash_input, &report.report_data)?;

    if report.vmpl > 0 {
        return Err(format!(
            "Security Alert: Report generated from VMPL {} (expected 0)",
            report.vmpl
        ));
    }

    Ok(report)
}

/// Expensive last step: fetch AMD certificates over the network and verify the
/// report signature.  Must be called after all cheap checks and DB lookups
/// pass, to avoid unnecessary network traffic for invalid requests.
fn verify_report_signature(report_data: &[u8]) -> Result<(), String> {
    let temp_dir = tempfile::TempDir::new().map_err(|_| "Failed to create temp dir".to_string())?;
    let report_path = temp_dir.path().join("report.bin");
    std::fs::write(&report_path, report_data)
        .map_err(|_| "Failed to write report to temp file".to_string())?;
    snpguest_wrapper::verify_report_signature(&report_path)
        .map_err(|e| format!("Signature verification failed: {}", e))
}

/// Common verification path shared by the attest and renew flows.
///
/// Order is chosen for efficiency: cheap checks first, expensive AMD
/// certificate fetch last.
///
///   1. Validate `server_nonce` (64 bytes).
///   2. Parse report; verify nonce, binding hash, and VMPL.
///   3. Look up the VM record by `image_id + id_key_digest + auth_key_digest`.
///   4. Verify the record is enabled and meets TCB minimums.
///   5. Verify the AMD report signature (network call -- last).
///
/// `hash_input`: the bytes passed to SHA512 to produce report_data.
/// For the attest flow this is `server_nonce || client_pub_bytes`; for the
/// renew flow it is `payload_bytes` (which already contains server_nonce).
async fn verify_request_common(
    report_data: &[u8],
    server_nonce: &[u8],
    hash_input: &[u8],
    nonce_secret: &[u8; 32],
    db: &DatabaseConnection,
) -> Result<(AttestationReport, vm_registration::Model, vm::Model), String> {
    if server_nonce.len() != 64 {
        return Err(format!(
            "Invalid server_nonce length: {}",
            server_nonce.len()
        ));
    }

    let report = verify_snp_report(report_data, server_nonce, hash_input, nonce_secret)?;

    // Find registration by stable id/auth key digests
    let registration = vm_registration::Entity::find()
        .filter(vm_registration::Column::IdKeyDigest.eq(report.id_key_digest.to_vec()))
        .filter(vm_registration::Column::AuthKeyDigest.eq(report.author_key_digest.to_vec()))
        .one(db)
        .await
        .map_err(|_| "Database error".to_string())?
        .ok_or_else(|| "No matching registration found".to_string())?;

    // Find attestation record by image_id within this registration
    let attestation_record = vm::Entity::find()
        .filter(vm::Column::ImageId.eq(report.image_id.to_vec()))
        .filter(vm::Column::RegistrationId.eq(registration.id.clone()))
        .one(db)
        .await
        .map_err(|_| "Database error".to_string())?
        .ok_or_else(|| "No matching attestation record found".to_string())?;

    verify_vm_policy(&registration, &attestation_record, &report)?;

    verify_report_signature(report_data)?;

    Ok((report, registration, attestation_record))
}

/// Verify VM record policy against a verified attestation report.
///
/// Checks that are identical across every flow once the DB records are in hand:
///   1. Registration is enabled (enabled flag lives on vm_registration).
///   2. All four TCB component versions meet the stored minimums
///      (min_tcb_* live on the attestation record).
///
/// `verify_snp_report` must be called before this function.
fn verify_vm_policy(
    registration: &vm_registration::Model,
    attestation_record: &vm::Model,
    report: &AttestationReport,
) -> Result<(), String> {
    if !registration.enabled {
        return Err("Attestation record is disabled".to_string());
    }

    let tcb = &report.current_tcb;
    if tcb.bootloader < attestation_record.min_tcb_bootloader as u8 {
        return Err(format!(
            "Bootloader TCB version {} below minimum requirement {}",
            tcb.bootloader, attestation_record.min_tcb_bootloader
        ));
    }
    if tcb.tee < attestation_record.min_tcb_tee as u8 {
        return Err(format!(
            "TEE TCB version {} below minimum requirement {}",
            tcb.tee, attestation_record.min_tcb_tee
        ));
    }
    if tcb.snp < attestation_record.min_tcb_snp as u8 {
        return Err(format!(
            "SNP TCB version {} below minimum requirement {}",
            tcb.snp, attestation_record.min_tcb_snp
        ));
    }
    if tcb.microcode < attestation_record.min_tcb_microcode as u8 {
        return Err(format!(
            "Microcode TCB version {} below minimum requirement {}",
            tcb.microcode, attestation_record.min_tcb_microcode
        ));
    }

    Ok(())
}

/// Re-encrypt sealed blob (unseal VMK and reseal for client session)
fn reencrypt_sealed_blob(
    sealed_blob: &[u8],
    unsealing_priv_bytes: &[u8],
    client_pub_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Validate sealed blob length
    if sealed_blob.len() < 32 {
        return Err("Client blob corrupted (too short)".to_string());
    }

    // Split sealed blob into encapped key and ciphertext
    let (vmk_encapped_bytes, vmk_ciphertext) = sealed_blob.split_at(32);

    // Validate unsealing private key length (should be exactly 32 bytes)
    if unsealing_priv_bytes.len() != 32 {
        return Err(format!(
            "Invalid unsealing private key length: expected 32 bytes, got {}",
            unsealing_priv_bytes.len()
        ));
    }

    // Parse unsealing private key (raw 32 bytes, no PEM parsing needed)
    let priv_bytes: [u8; 32] = unsealing_priv_bytes
        .try_into()
        .map_err(|_| "Failed to convert to 32-byte array".to_string())?;

    let unsealing_priv = match <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&priv_bytes) {
        Ok(k) => k,
        Err(e) => {
            return Err(format!("Invalid unsealing private key format: {}", e));
        }
    };

    // Parse VMK encapped key
    let vmk_encapped_key =
        match <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(vmk_encapped_bytes) {
            Ok(k) => k,
            Err(e) => {
                return Err(format!("Failed to create VMK encapped key: {}", e));
            }
        };

    // Unseal VMK using unsealing private key
    let mut unsealing_ctx = match hpke::setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &unsealing_priv,
        &vmk_encapped_key,
        &[],
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            return Err(format!("Failed to unseal VMK: {}", e));
        }
    };

    let vmk_plaintext = match unsealing_ctx.open(vmk_ciphertext, &[]) {
        Ok(pt) => pt,
        Err(e) => {
            return Err(format!("Failed to decrypt VMK blob: {}", e));
        }
    };

    // Reseal VMK for client session using client's ephemeral pub
    let client_pub = match <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(client_pub_bytes) {
        Ok(k) => k,
        Err(e) => {
            return Err(format!("Invalid client public key: {}", e));
        }
    };

    let mut rng = OsRng;
    let (encapped_key, mut sender_ctx) = match hpke::setup_sender::<
        AesGcm256,
        HkdfSha256,
        X25519HkdfSha256,
        _,
    >(&OpModeS::Base, &client_pub, &[], &mut rng)
    {
        Ok((enc, ctx)) => (enc, ctx),
        Err(e) => {
            return Err(format!("Failed to setup session encryption: {}", e));
        }
    };

    let ciphertext = match sender_ctx.seal(&vmk_plaintext, &[]) {
        Ok(ct) => ct,
        Err(e) => {
            return Err(format!("Failed to encrypt session response: {}", e));
        }
    };

    Ok((encapped_key.to_bytes().to_vec(), ciphertext))
}

pub async fn verify_report_core(
    state: Arc<ServiceState>,
    req: AttestationRequest,
) -> AttestationResponse {
    macro_rules! fail {
        ($msg:expr) => {
            return AttestationResponse {
                success: false,
                encapped_key: vec![],
                ciphertext: vec![],
                error_message: $msg,
            }
        };
    }

    // Flow-specific prerequisite: sealed_blob must be present
    if req.sealed_blob.is_empty() {
        fail!("sealed_blob is required".to_string());
    }

    if req.client_pub_bytes.len() != 32 {
        fail!(format!(
            "Invalid client_pub_bytes length: {}",
            req.client_pub_bytes.len()
        ));
    }

    // Attest flow: report_data = SHA512(server_nonce || client_pub_bytes)
    let hash_input = [req.server_nonce.as_slice(), req.client_pub_bytes.as_slice()].concat();

    // Common path: field validation, report verification, DB lookup, policy,
    // and AMD signature check (last)
    let (_, registration, attestation_record) = match verify_request_common(
        &req.report_data,
        &req.server_nonce,
        &hash_input,
        &state.attestation_state.secret,
        &state.db,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => fail!(e),
    };

    // Decrypt unsealing private key from DB using ingestion key
    let unsealing_priv_bytes = match state
        .ingestion_keys
        .decrypt(&attestation_record.unsealing_private_key_encrypted)
    {
        Ok(decrypted) => decrypted,
        Err(e) => fail!(format!("Failed to decrypt unsealing key: {}", e)),
    };

    let (encapped_key, ciphertext) = match reencrypt_sealed_blob(
        &req.sealed_blob,
        &unsealing_priv_bytes,
        &req.client_pub_bytes,
    ) {
        Ok(result) => result,
        Err(e) => fail!(e),
    };

    // If the VM attested using the pending record's image_id, promote it to
    // current: swap current_record_id, clear pending_record_id, delete the
    // old current record and its artifact directory.
    let registration = if registration.pending_record_id.as_deref() == Some(&attestation_record.id)
    {
        match business_logic::promote_pending_to_current(&state.db, &state.data_paths, registration)
            .await
        {
            Ok(updated) => updated,
            Err(e) => {
                eprintln!("Warning: failed to promote pending record: {}", e);
                // VMK was already re-encrypted successfully; return success but
                // log the promotion failure so it can be retried on next boot.
                return AttestationResponse {
                    success: true,
                    encapped_key,
                    ciphertext,
                    error_message: String::new(),
                };
            }
        }
    } else {
        registration
    };

    // Increment request count on the registration
    let new_count = registration.request_count + 1;
    let mut reg_active: vm_registration::ActiveModel = registration.into();
    reg_active.request_count = Set(new_count);
    let _ = reg_active.update(&state.db).await;

    AttestationResponse {
        success: true,
        encapped_key,
        ciphertext,
        error_message: String::new(),
    }
}

/// Build an AttestationRecord proto from a registration + its current attestation record.
/// pending: optional pending attestation_record; if present, pending_since is set.
fn build_proto_record(
    reg: vm_registration::Model,
    rec: vm::Model,
    pending: Option<&vm::Model>,
) -> AttestationRecord {
    let pending_since = pending.map(|p| p.created_at.and_utc().timestamp());
    AttestationRecord {
        id: reg.id,
        os_name: reg.os_name,
        request_count: reg.request_count,
        vcpu_type: rec.vcpu_type,
        vcpus: rec.vcpus as u32,
        enabled: reg.enabled,
        created_at: reg.created_at.to_string(),
        kernel_params: rec.kernel_params.unwrap_or_default(),
        firmware_path: rec.firmware_path.unwrap_or_default(),
        kernel_path: rec.kernel_path.unwrap_or_default(),
        initrd_path: rec.initrd_path.unwrap_or_default(),
        allowed_debug: rec.allowed_debug,
        allowed_migrate_ma: rec.allowed_migrate_ma,
        allowed_smt: rec.allowed_smt,
        min_tcb_bootloader: rec.min_tcb_bootloader as u32,
        min_tcb_tee: rec.min_tcb_tee as u32,
        min_tcb_snp: rec.min_tcb_snp as u32,
        min_tcb_microcode: rec.min_tcb_microcode as u32,
        pending_since,
    }
}

pub async fn list_records_core(
    state: &Arc<ServiceState>,
) -> Result<Vec<AttestationRecord>, String> {
    let registrations = vm_registration::Entity::find()
        .order_by_asc(vm_registration::Column::OsName)
        .all(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    // Collect current record IDs and pending record IDs (where present).
    let mut all_record_ids: Vec<String> = registrations
        .iter()
        .map(|r| r.current_record_id.clone())
        .collect();
    for reg in &registrations {
        if let Some(pid) = &reg.pending_record_id {
            all_record_ids.push(pid.clone());
        }
    }

    let records = vm::Entity::find()
        .filter(vm::Column::Id.is_in(all_record_ids))
        .all(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    let record_map: HashMap<String, vm::Model> =
        records.into_iter().map(|r| (r.id.clone(), r)).collect();

    let proto_records = registrations
        .into_iter()
        .filter_map(|reg| {
            let rec = record_map.get(&reg.current_record_id)?.clone();
            let pending = reg
                .pending_record_id
                .as_ref()
                .and_then(|pid| record_map.get(pid));
            Some(build_proto_record(reg, rec, pending))
        })
        .collect();

    Ok(proto_records)
}

pub async fn get_record_core(
    state: &Arc<ServiceState>,
    id: String,
) -> Result<Option<AttestationRecord>, String> {
    // id is the VmRegistration ID
    let registration = vm_registration::Entity::find_by_id(&id)
        .one(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    let reg = match registration {
        Some(r) => r,
        None => return Ok(None),
    };

    let rec = vm::Entity::find_by_id(&reg.current_record_id)
        .one(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| {
            format!(
                "Attestation record {} not found for registration {}",
                reg.current_record_id, id
            )
        })?;

    let pending = if let Some(ref pid) = reg.pending_record_id {
        vm::Entity::find_by_id(pid)
            .one(&state.db)
            .await
            .map_err(|e| format!("Database error: {}", e))?
    } else {
        None
    };

    Ok(Some(build_proto_record(reg, rec, pending.as_ref())))
}

pub async fn create_record_core(
    state: &Arc<ServiceState>,
    req: CreateRecordRequest,
) -> Result<String, String> {
    let create_req = business_logic::CreateRecordRequest {
        os_name: req.os_name,
        firmware_data: if req.firmware.is_empty() {
            None
        } else {
            Some(req.firmware)
        },
        kernel_data: if req.kernel.is_empty() {
            None
        } else {
            Some(req.kernel)
        },
        initrd_data: if req.initrd.is_empty() {
            None
        } else {
            Some(req.initrd)
        },
        kernel_params: req.kernel_params,
        vcpus: req.vcpus,
        vcpu_type: req.vcpu_type,
        unsealing_private_key_encrypted: req.unsealing_private_key_encrypted,
        allowed_debug: req.allowed_debug,
        allowed_migrate_ma: req.allowed_migrate_ma,
        allowed_smt: req.allowed_smt,
        min_tcb_bootloader: req.min_tcb_bootloader,
        min_tcb_tee: req.min_tcb_tee,
        min_tcb_snp: req.min_tcb_snp,
        min_tcb_microcode: req.min_tcb_microcode,
    };

    // Returns the VmRegistration ID
    let res = business_logic::create_record_logic(
        &state.attestation_state.db,
        &state.data_paths,
        state.ingestion_keys.clone(),
        create_req,
    )
    .await?;
    Ok(res)
}

pub async fn renew_record_core(state: Arc<ServiceState>, req: RenewRequest) -> RenewResponse {
    macro_rules! fail {
        ($msg:expr) => {
            return RenewResponse {
                success: false,
                error_message: Some($msg.to_string()),
                signature: None,
                payload_bytes: None,
            }
        };
    }

    let payload = match RenewRequestPayload::decode(req.payload_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => fail!("Failed to decode RenewRequestPayload"),
    };

    if payload.server_nonce.len() != 64 {
        fail!(format!(
            "Invalid server_nonce length: {}",
            payload.server_nonce.len()
        ));
    }
    if payload.client_nonce.len() != 64 {
        fail!(format!(
            "Invalid client_nonce length: {}",
            payload.client_nonce.len()
        ));
    }

    // Renewal flow: report_data = SHA512(payload_bytes); server_nonce is inside payload_bytes
    let (_, registration, current_record) = match verify_request_common(
        &req.report_data,
        &payload.server_nonce,
        &req.payload_bytes,
        &state.attestation_state.secret,
        &state.db,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => fail!(e),
    };

    let renew_req = business_logic::RenewRecordRequest {
        firmware_data: payload.firmware,
        kernel_data: payload.kernel,
        initrd_data: payload.initrd,
        kernel_params: payload.kernel_params,
    };

    let pending_id = match business_logic::renew_record_logic(
        &state.db,
        &state.data_paths,
        state.ingestion_keys.clone(),
        registration,
        current_record,
        renew_req,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => fail!(e),
    };

    let artifact_dir = state.data_paths.attestations_dir.join(&pending_id);
    let mut artifacts = Vec::new();
    for filename in business_logic::RENEW_RESPONSE_ARTIFACTS {
        match std::fs::read(artifact_dir.join(filename)) {
            Ok(content) => artifacts.push(ArtifactEntry {
                filename: filename.to_string(),
                content,
            }),
            Err(e) => fail!(format!("Failed to read artifact {}: {}", filename, e)),
        }
    }

    let resp_payload = RenewResponsePayload {
        id: pending_id,
        client_nonce: payload.client_nonce,
        artifacts,
    };
    let mut resp_payload_bytes = Vec::new();
    resp_payload
        .encode(&mut resp_payload_bytes)
        .expect("RenewResponsePayload encode");
    let signature = state.identity_key.sign(&resp_payload_bytes);

    RenewResponse {
        success: true,
        error_message: None,
        signature: Some(signature),
        payload_bytes: Some(resp_payload_bytes),
    }
}

pub async fn delete_record_core(state: &Arc<ServiceState>, id: String) -> Result<(), String> {
    // id is the VmRegistration ID
    let registration = vm_registration::Entity::find_by_id(&id)
        .one(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "Registration not found".to_string())?;

    // Collect all attestation record IDs that belong to this registration
    let mut record_ids = vec![registration.current_record_id.clone()];
    if let Some(pending_id) = &registration.pending_record_id {
        record_ids.push(pending_id.clone());
    }

    // Delete attestation records and the registration in one transaction (FK order:
    // records first, then registration).
    let txn = state
        .db
        .begin()
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    for record_id in &record_ids {
        vm::Entity::delete_by_id(record_id)
            .exec(&txn)
            .await
            .map_err(|e| format!("Database error: {}", e))?;
    }

    vm_registration::Entity::delete_by_id(&id)
        .exec(&txn)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    txn.commit()
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    // Remove artifact directories (named after attestation_record IDs)
    for record_id in &record_ids {
        let artifact_dir = state.data_paths.attestations_dir.join(record_id);
        if artifact_dir.exists() {
            let safe_to_remove = state
                .data_paths
                .attestations_dir
                .canonicalize()
                .ok()
                .and_then(|base| {
                    artifact_dir
                        .canonicalize()
                        .ok()
                        .map(|p| p.starts_with(&base))
                })
                .unwrap_or(false);
            if safe_to_remove {
                if let Err(e) = std::fs::remove_dir_all(&artifact_dir) {
                    eprintln!(
                        "Warning: failed to remove artifacts for {}: {}",
                        record_id, e
                    );
                }
            }
        }
    }

    Ok(())
}

pub async fn discard_pending_core(state: &Arc<ServiceState>, id: String) -> Result<(), String> {
    business_logic::discard_pending_logic(&state.db, &state.data_paths, &id).await
}

pub async fn toggle_enabled_core(
    state: &Arc<ServiceState>,
    req: ToggleEnabledRequest,
    enabled: bool,
) -> Result<bool, String> {
    // req.id is the VmRegistration ID
    let reg = vm_registration::Entity::find_by_id(req.id.clone())
        .one(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "Registration not found".to_string())?;

    let mut active: vm_registration::ActiveModel = reg.into();
    active.enabled = Set(enabled);
    active
        .update(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?;
    Ok(enabled)
}

/// Returns the artifact directory path for the current record of a registration.
/// Used by export and download endpoints which need the filesystem path.
pub async fn get_current_artifact_dir(
    state: &Arc<ServiceState>,
    registration_id: &str,
) -> Result<std::path::PathBuf, String> {
    let reg = vm_registration::Entity::find_by_id(registration_id)
        .one(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "Registration not found".to_string())?;

    Ok(state
        .data_paths
        .attestations_dir
        .join(&reg.current_record_id))
}

fn hash_token(token: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    Argon2::default()
        .hash_password(token.as_bytes(), &salt)
        .map_err(|e| format!("Hash error: {e}"))
        .map(|h| h.to_string())
}

fn verify_token_hash(token: &str, hash: &str) -> bool {
    if let Ok(parsed) = PasswordHash::new(hash) {
        Argon2::default()
            .verify_password(token.as_bytes(), &parsed)
            .is_ok()
    } else {
        false
    }
}

pub async fn generate_token(
    state: &ServiceState,
    label: String,
    expires_at: Option<chrono::NaiveDateTime>,
) -> Result<(String, TokenInfo), String> {
    let token_plain = {
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    };
    let token_hash = hash_token(&token_plain)?;
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().naive_utc();

    let model = token::ActiveModel {
        id: Set(id.clone()),
        label: Set(label.clone()),
        token_hash: Set(token_hash),
        created_at: Set(now),
        expires_at: Set(expires_at),
        revoked: Set(false),
    };

    model
        .insert(&state.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

    let info = TokenInfo {
        id,
        label,
        created_at: fmt_ts(now),
        expires_at: expires_at.map(fmt_ts).unwrap_or_default(),
        revoked: false,
    };

    Ok((token_plain, info))
}

pub async fn list_tokens(state: &ServiceState) -> Result<Vec<TokenInfo>, String> {
    let tokens = token::Entity::find()
        .order_by_desc(token::Column::CreatedAt)
        .all(&state.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

    Ok(tokens
        .into_iter()
        .map(|t| TokenInfo {
            id: t.id,
            label: t.label,
            created_at: fmt_ts(t.created_at),
            expires_at: t.expires_at.map(fmt_ts).unwrap_or_default(),
            revoked: t.revoked,
        })
        .collect())
}

pub async fn revoke_token(state: &ServiceState, id: String) -> Result<(), String> {
    let mut model = token::Entity::find_by_id(id)
        .one(&state.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?
        .ok_or_else(|| "Token not found".to_string())?;

    model.revoked = true;
    let mut active: token::ActiveModel = model.into();
    active.revoked = Set(true);
    active
        .update(&state.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
    Ok(())
}

pub async fn auth_token_valid(state: &ServiceState, token_plain: &str) -> Result<bool, String> {
    let now = chrono::Utc::now().naive_utc();
    let records = token::Entity::find()
        .filter(token::Column::Revoked.eq(false))
        .all(&state.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

    for rec in records {
        if let Some(exp) = rec.expires_at {
            if now > exp {
                continue;
            }
        }
        if verify_token_hash(token_plain, &rec.token_hash) {
            return Ok(true);
        }
    }
    Ok(false)
}
