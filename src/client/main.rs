use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use common::snpguard::{
    AttestationRequest, AttestationResponse, CreateRecordRequest, CreateRecordResponse,
    DeleteRecordResponse, GetRecordResponse, ListRecordsResponse, NonceRequest, NonceResponse,
    ToggleEnabledResponse,
};
use dirs::config_dir;
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{Kem, X25519HkdfSha256},
    Deserializable, OpModeR, OpModeS, Serializable,
};
use prost::Message;
use rand::rngs::OsRng;
use reqwest::Certificate;
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
use sha2::{Digest, Sha256, Sha512};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

// Default timeout for all client requests
const TIMEOUT_SECS: u64 = 60;

#[derive(Parser, Debug)]
#[command(author, version, about = "SnpGuard client")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Perform attestation and output the released secret
    Attest {
        #[arg(long, value_name = "URL")]
        url: String,
        #[arg(long, value_name = "PATH")]
        ca_cert: String,
        #[arg(long, value_name = "PATH")]
        sealed_blob: PathBuf,
    },
    /// Management operations (requires stored token)
    Manage {
        #[arg(long, value_name = "URL")]
        url: Option<String>,
        #[arg(long, value_name = "PATH")]
        ca_cert: Option<String>,
        #[command(subcommand)]
        action: ManageCmd,
    },
    /// Configure stored management token
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
    /// Derive a 32-byte key from the AMD SEV-SNP hardware using the chip's VCEK (or VMRK).
    /// Outputs the key as a hex string on stdout, suitable for use as a LUKS passphrase.
    /// For security, always include --mix-measurement to bind the key to the launch digest.
    DeriveKey {
        /// Use VMRK as the root key instead of VCEK (default: VCEK, chip-specific)
        #[arg(long, default_value_t = false)]
        vmrk: bool,
        /// Mix the guest policy into the derived key
        #[arg(long, default_value_t = false)]
        mix_policy: bool,
        /// Mix the launch measurement (firmware+kernel+initrd digest) into the derived key.
        /// Strongly recommended: without this, any guest on the same chip derives the same key.
        #[arg(long, default_value_t = false)]
        mix_measurement: bool,
        /// Mix the image ID into the derived key
        #[arg(long, default_value_t = false)]
        mix_image_id: bool,
        /// Mix the family ID into the derived key
        #[arg(long, default_value_t = false)]
        mix_family_id: bool,
        /// VMPL level to mix into the derived key (must be >= current VMPL; default: 0)
        #[arg(long, default_value_t = 0)]
        vmpl: u32,
        /// Guest SVN to mix into the derived key (must not exceed the SVN in the ID block; default: 0)
        #[arg(long, default_value_t = 0)]
        guest_svn: u32,
        /// TCB version to bind into the derived key (must not exceed CommittedTcb; 0 = don't bind)
        #[arg(long, default_value_t = 0u64)]
        tcb_version: u64,
        /// Launch mitigation vector to mix into the derived key (default: 0)
        #[arg(long, default_value_t = 0u64)]
        mit_vector: u64,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigCmd {
    /// Store a management token (TOFU - Trust On First Use)
    Login {
        #[arg(long)]
        token: String,
        #[arg(long, value_name = "URL")]
        url: String,
    },
    /// Remove stored token
    Logout,
}

#[derive(Subcommand, Debug)]
enum ManageCmd {
    List {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Show {
        id: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Enable {
        id: String,
    },
    Disable {
        id: String,
    },
    Delete {
        id: String,
    },
    Export {
        id: String,
        #[arg(long, value_parser = ["tar", "squash", "squashfs"], default_value = "tar")]
        format: String,
        #[arg(long, value_name = "PATH")]
        out_bundle: PathBuf,
    },
    Register {
        #[arg(long)]
        os_name: String,
        #[arg(long, value_name = "PATH", group = "unsealing_key")]
        unsealing_private_key: Option<PathBuf>,
        #[arg(long, value_name = "PATH", group = "unsealing_key")]
        enc_unsealing_private_key: Option<PathBuf>,
        #[arg(long, default_value = "4")]
        vcpus: u32,
        #[arg(long, default_value = "EPYC")]
        vcpu_type: String,
        #[arg(long, default_value_t = false)]
        allowed_debug: bool,
        #[arg(long, default_value_t = false)]
        allowed_migrate_ma: bool,
        #[arg(long, default_value_t = false)]
        allowed_smt: bool,
        #[arg(long, default_value = "0")]
        min_tcb_bootloader: u32,
        #[arg(long, default_value = "0")]
        min_tcb_tee: u32,
        #[arg(long, default_value = "0")]
        min_tcb_snp: u32,
        #[arg(long, default_value = "0")]
        min_tcb_microcode: u32,
        /// Optional staging directory (generated by image convert --out-staging)
        #[arg(long, value_name = "PATH")]
        staging_dir: Option<PathBuf>,
        #[arg(long)]
        firmware: Option<PathBuf>,
        #[arg(long)]
        kernel: Option<PathBuf>,
        #[arg(long)]
        initrd: Option<PathBuf>,
        #[arg(long)]
        kernel_params: Option<String>,
        /// If set, disable the record after creation
        #[arg(long, default_value_t = false)]
        disable: bool,
        /// Output bundle path (same format as manage export)
        #[arg(long, value_name = "PATH")]
        out_bundle: Option<PathBuf>,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Attest {
            url,
            ca_cert,
            sealed_blob,
        } => run_attest(&url, &ca_cert, &sealed_blob).await,
        Command::Manage {
            url,
            ca_cert,
            action,
        } => run_manage(url.as_deref(), ca_cert.as_deref(), action).await,
        Command::Config { action } => run_config(action).await,
        Command::DeriveKey {
            vmrk,
            mix_policy,
            mix_measurement,
            mix_image_id,
            mix_family_id,
            vmpl,
            guest_svn,
            tcb_version,
            mit_vector,
        } => run_derive_key(
            vmrk,
            mix_policy,
            mix_measurement,
            mix_image_id,
            mix_family_id,
            vmpl,
            guest_svn,
            tcb_version,
            mit_vector,
        ),
    }
}

fn token_path() -> Result<PathBuf> {
    let base = config_dir().ok_or_else(|| anyhow!("Cannot determine config dir"))?;
    Ok(base.join("snpguard").join("config.json"))
}

fn ca_dest_path() -> Result<PathBuf> {
    let base = config_dir().ok_or_else(|| anyhow!("Cannot determine config dir"))?;
    Ok(base.join("snpguard").join("ca.pem"))
}

fn ingestion_key_dest_path() -> Result<PathBuf> {
    let base = config_dir().ok_or_else(|| anyhow!("Cannot determine config dir"))?;
    Ok(base.join("snpguard").join("ingestion.pub"))
}

fn identity_key_dest_path() -> Result<PathBuf> {
    let base = config_dir().ok_or_else(|| anyhow!("Cannot determine config dir"))?;
    Ok(base.join("snpguard").join("identity.pub"))
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct StoredConfig {
    token: Option<String>,
    url: Option<String>,
    ca_cert: Option<String>, // stored filename under config dir (e.g., ca.pem)
}

fn load_config() -> Result<StoredConfig> {
    let path = token_path()?;
    if !path.exists() {
        return Ok(StoredConfig::default());
    }
    let data = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config at {}", path.display()))?;
    let cfg: StoredConfig = serde_json::from_str(&data)
        .with_context(|| format!("Config file at {} is invalid JSON", path.display()))?;
    Ok(cfg)
}

fn save_config(cfg: &StoredConfig) -> Result<()> {
    let path = token_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    let data = serde_json::to_string(cfg)?;
    fs::write(&path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn delete_config() -> Result<()> {
    let path = token_path()?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    let ca_path = ca_dest_path()?;
    if ca_path.exists() {
        fs::remove_file(ca_path)?;
    }
    let ingestion_key_path = ingestion_key_dest_path()?;
    if ingestion_key_path.exists() {
        fs::remove_file(ingestion_key_path)?;
    }
    let identity_key_path = identity_key_dest_path()?;
    if identity_key_path.exists() {
        fs::remove_file(identity_key_path)?;
    }
    Ok(())
}

fn build_client(ca_cert_path: &str) -> Result<reqwest::Client> {
    let ca_pem = fs::read(ca_cert_path)
        .with_context(|| format!("Failed to read pinned CA certificate at {}", ca_cert_path))?;
    build_client_from_bytes(&ca_pem)
}

fn build_client_from_bytes(ca_pem: &[u8]) -> Result<reqwest::Client> {
    let ca_cert =
        Certificate::from_pem(ca_pem).context("Pinned CA certificate is not valid PEM")?;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca_cert)
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .build()
        .context("Failed to create HTTP client with pinned CA")?;
    Ok(client)
}

async fn run_attest(url: &str, ca_cert: &str, sealed_blob: &Path) -> Result<()> {
    let client = build_client(ca_cert)?;
    let base = normalize_https(url)?;
    let mut rng = OsRng;

    // Get server nonce
    let mut buf = Vec::new();
    NonceRequest {}.encode(&mut buf)?;
    let resp = client
        .post(format!("{}/v1/attest/nonce", base))
        .header("Content-Type", "application/x-protobuf")
        .body(buf)
        .send()
        .await
        .context("Failed to request nonce")?;
    let resp = ensure_success(resp, "nonce").await?;
    let bytes = resp.bytes().await?;
    let nonce_resp = NonceResponse::decode(&bytes[..]).context("Decode nonce response")?;
    if nonce_resp.nonce.len() != 64 {
        bail!("Invalid nonce length: {}", nonce_resp.nonce.len());
    }
    let server_nonce = nonce_resp.nonce;

    // Generate ephemeral session key (X25519)
    let (client_secret, client_public) = <X25519HkdfSha256 as Kem>::gen_keypair(&mut rng);
    let client_pub_bytes = client_public.to_bytes().to_vec();

    // Create binding hash: SHA512(server_nonce || client_pub_bytes)
    let mut hasher = Sha512::new();
    hasher.update(&server_nonce);
    hasher.update(&client_pub_bytes);
    let binding_digest: [u8; 64] = hasher.finalize().into();

    // Get AMD SNP report with binding digest in report_data
    let mut fw = Firmware::open().context(
        "Failed to open SEV firmware device (/dev/sev-guest). Ensure SEV-SNP is enabled.",
    )?;
    let report_bytes = fw
        .get_report(None, Some(binding_digest), Some(0))
        .context("Failed to get attestation report from SEV firmware")?;

    let report_data = report_bytes.to_vec();

    // Read sealed blob
    let sealed_blob_data = fs::read(sealed_blob)
        .with_context(|| format!("Failed to read sealed blob from {:?}", sealed_blob))?;

    // Send attestation request
    let mut req_bytes = Vec::new();
    AttestationRequest {
        report_data,
        server_nonce: server_nonce.clone(),
        client_pub_bytes: client_pub_bytes.clone(),
        sealed_blob: sealed_blob_data,
    }
    .encode(&mut req_bytes)?;

    let resp = client
        .post(format!("{}/v1/attest/report", base))
        .header("Content-Type", "application/x-protobuf")
        .body(req_bytes)
        .send()
        .await
        .context("Failed to verify report")?;
    let resp = ensure_success(resp, "verify").await?;
    let bytes = resp.bytes().await?;
    let verify_resp =
        AttestationResponse::decode(&bytes[..]).context("Decode verification response")?;

    if !verify_resp.success {
        bail!("Attestation failed: {}", verify_resp.error_message);
    }

    // Parse server's encapped key
    let encapped = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&verify_resp.encapped_key)
        .map_err(|_| anyhow!("Invalid server encapped key"))?;

    // Setup HPKE receiver
    let mut receiver_ctx = hpke::setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &client_secret,
        &encapped,
        &[],
    )
    .map_err(|e| anyhow!("HPKE setup failed: {}", e))?;

    // Open ciphertext to get VMK
    let vmk = receiver_ctx
        .open(&verify_resp.ciphertext, &[])
        .map_err(|e| anyhow!("Session decryption failed: {}", e))?;

    // Output VMK to stdout in hex format
    let vmk_hex = hex::encode(&vmk);
    println!("{}", vmk_hex);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_derive_key(
    vmrk: bool,
    mix_policy: bool,
    mix_measurement: bool,
    mix_image_id: bool,
    mix_family_id: bool,
    vmpl: u32,
    guest_svn: u32,
    tcb_version: u64,
    mit_vector: u64,
) -> Result<()> {
    let mut field_select = GuestFieldSelect::default();
    if mix_policy {
        field_select.set_guest_policy(true);
    }
    if mix_measurement {
        field_select.set_measurement(true);
    }
    if mix_image_id {
        field_select.set_image_id(true);
    }
    if mix_family_id {
        field_select.set_family_id(true);
    }

    let (mit, version) = if mit_vector != 0 {
        (Some(mit_vector), Some(2))
    } else {
        // Not all firmware supports version 2, so if the Mitigation
        // Vector is 0, we force the version to be 1.
        (None, Some(1))
    };

    let request = DerivedKey::new(vmrk, field_select, vmpl, guest_svn, tcb_version, mit);

    let mut fw = Firmware::open().context(
        "Failed to open SEV firmware device (/dev/sev-guest). Ensure SEV-SNP is enabled.",
    )?;
    let key = fw
        .get_derived_key(version, request)
        .context("Failed to derive key from SEV firmware")?;

    println!("{}", hex::encode(key));
    Ok(())
}

async fn run_manage(url: Option<&str>, ca_cert: Option<&str>, action: ManageCmd) -> Result<()> {
    let cfg = load_config()?;
    let token = cfg
        .token
        .clone()
        .ok_or_else(|| anyhow!("Token not found; run config login"))?;

    let base = if let Some(u) = url {
        normalize_https(u)?
    } else if let Some(u) = cfg.url {
        u
    } else {
        bail!("URL not provided and not stored; pass --url or run config login")
    };

    let ca_path = if let Some(ca_path) = ca_cert {
        ca_path.to_string()
    } else if let Some(stored) = cfg.ca_cert {
        config_dir()
            .unwrap_or_default()
            .join("snpguard")
            .join(stored)
            .to_string_lossy()
            .to_string()
    } else {
        bail!("ca_cert not provided and not stored; pass --ca-cert or run config login")
    };

    let client = build_client(&ca_path)?;
    match action {
        ManageCmd::List { json } => {
            let resp = client
                .get(format!("{}/v1/records", base))
                .bearer_auth(&token)
                .send()
                .await?;
            let resp = ensure_success(resp, "list").await?;
            let bytes = resp.bytes().await?;
            let list = ListRecordsResponse::decode(&bytes[..])?;
            print_list(list.records, json)?;
        }
        ManageCmd::Show { id, json } => {
            let resp = client
                .get(format!("{}/v1/records/{}", base, id))
                .bearer_auth(&token)
                .send()
                .await?;
            let resp = ensure_success(resp, "show").await?;
            let bytes = resp.bytes().await?;
            let rec = GetRecordResponse::decode(&bytes[..])?;
            if let Some(r) = rec.record {
                print_record(&r, json)?;
            } else {
                println!("Record not found");
            }
        }
        ManageCmd::Enable { id } => toggle(&client, &base, &token, &id, true).await?,
        ManageCmd::Disable { id } => toggle(&client, &base, &token, &id, false).await?,
        ManageCmd::Delete { id } => {
            let resp = client
                .delete(format!("{}/v1/records/{}", base, id))
                .bearer_auth(&token)
                .send()
                .await?;
            let resp = ensure_success(resp, "delete").await?;
            let bytes = resp.bytes().await?;
            let _ = DeleteRecordResponse::decode(&bytes[..])?;
        }
        ManageCmd::Export {
            id,
            format,
            out_bundle,
        } => {
            let endpoint = match format.as_str() {
                "tar" => "export/tar",
                "squash" | "squashfs" => "export/squash",
                _ => unreachable!(),
            };
            let resp = client
                .get(format!("{}/v1/records/{}/{}", base, id, endpoint))
                .bearer_auth(&token)
                .send()
                .await?;
            let resp = ensure_success(resp, "export").await?;
            let bytes = resp.bytes().await?;
            fs::write(&out_bundle, &bytes)?;
        }
        ManageCmd::Register {
            os_name,
            unsealing_private_key,
            enc_unsealing_private_key,
            vcpus,
            vcpu_type,
            allowed_debug,
            allowed_migrate_ma,
            allowed_smt,
            min_tcb_bootloader,
            min_tcb_tee,
            min_tcb_snp,
            min_tcb_microcode,
            staging_dir,
            firmware,
            kernel,
            initrd,
            kernel_params,
            disable,
            out_bundle,
        } => {
            let mut firmware_data = None;
            let mut kernel_data = None;
            let mut initrd_data = None;
            let mut params = None;
            let mut staging_enc_key = None;

            // Read from staging directory if provided
            if let Some(ref staging_path) = staging_dir {
                let (fw, k, i, p, enc_key) = read_staging_dir(staging_path)?;
                firmware_data = fw;
                kernel_data = k;
                initrd_data = i;
                params = p;
                staging_enc_key = enc_key;
            }

            // Override with explicit options if provided
            if let Some(path) = firmware {
                firmware_data = Some(fs::read(path)?);
            }
            if let Some(path) = kernel {
                kernel_data = Some(fs::read(path)?);
            }
            if let Some(path) = initrd {
                initrd_data = Some(fs::read(path)?);
            }
            if let Some(p) = kernel_params {
                params = Some(p);
            }

            if firmware_data.is_none() || kernel_data.is_none() || initrd_data.is_none() {
                bail!("firmware, kernel, and initrd are required (either in staging directory or as --firmware/--kernel/--initrd)");
            }

            let params = params.unwrap_or_else(|| "console=ttyS0".to_string());

            // Handle unsealing key: either plain or encrypted
            let unsealing_key_encrypted = if let Some(enc_key_path) = enc_unsealing_private_key {
                // Use provided encrypted key directly
                fs::read(enc_key_path)?
            } else if let Some(plain_key_path) = unsealing_private_key {
                // Encrypt plain key with ingestion public key
                let unsealing_key_pem_str =
                    fs::read_to_string(&plain_key_path).with_context(|| {
                        format!(
                            "Failed to read unsealing private key from {:?}",
                            plain_key_path
                        )
                    })?;

                let unsealing_key_pem = pem::parse(&unsealing_key_pem_str)
                    .context("Failed to parse unsealing private key PEM")?;
                if unsealing_key_pem.tag() != "PRIVATE KEY" {
                    bail!("Invalid unsealing private key PEM tag (expected PRIVATE KEY)");
                }
                let unsealing_key_bytes: [u8; 32] =
                    unsealing_key_pem.contents().try_into().map_err(|_| {
                        anyhow!("Invalid unsealing private key length (expected 32 bytes)")
                    })?;

                // Read ingestion public key from saved config (stored during login)
                let ingestion_key_path = ingestion_key_dest_path()?;
                let ingestion_pub_pem = fs::read_to_string(&ingestion_key_path)
                    .with_context(|| {
                        format!(
                            "Failed to read ingestion public key from {:?}. Please run 'config login' first.",
                            ingestion_key_path
                        )
                    })?;

                let pub_pem_parsed = pem::parse(&ingestion_pub_pem)
                    .context("Failed to parse ingestion public key PEM")?;
                if pub_pem_parsed.tag() != "PUBLIC KEY" {
                    bail!("Invalid ingestion public key PEM tag");
                }
                let public_bytes: [u8; 32] = pub_pem_parsed
                    .contents()
                    .try_into()
                    .map_err(|_| anyhow!("Invalid public key length"))?;

                let server_pub = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&public_bytes)
                    .map_err(|e| anyhow!("Failed to create public key: {}", e))?;

                let mut rng = OsRng;
                let (encapped_key, mut sender_ctx) =
                    hpke::setup_sender::<AesGcm256, HkdfSha256, X25519HkdfSha256, _>(
                        &OpModeS::Base,
                        &server_pub,
                        &[],
                        &mut rng,
                    )
                    .map_err(|e| anyhow!("HPKE setup failed: {}", e))?;

                let ciphertext = sender_ctx
                    .seal(&unsealing_key_bytes, &[])
                    .map_err(|e| anyhow!("HPKE seal failed: {}", e))?;

                let encapped_bytes = encapped_key.to_bytes();
                let mut encrypted = Vec::with_capacity(encapped_bytes.len() + ciphertext.len());
                encrypted.extend_from_slice(&encapped_bytes);
                encrypted.extend_from_slice(&ciphertext);
                encrypted
            } else if let Some(key) = staging_enc_key {
                // Use encrypted key from staging directory
                key
            } else {
                bail!("Either --unsealing-private-key or --enc-unsealing-private-key must be provided, or unsealing.key.enc must be in --staging-dir");
            };

            let req = CreateRecordRequest {
                os_name,
                firmware: firmware_data.unwrap_or_default(),
                kernel: kernel_data.unwrap_or_default(),
                initrd: initrd_data.unwrap_or_default(),
                kernel_params: params,
                unsealing_private_key_encrypted: unsealing_key_encrypted,
                vcpus,
                vcpu_type,
                allowed_debug,
                allowed_migrate_ma,
                allowed_smt,
                min_tcb_bootloader,
                min_tcb_tee,
                min_tcb_snp,
                min_tcb_microcode,
            };

            let mut buf = Vec::new();
            req.encode(&mut buf)?;
            let resp = client
                .post(format!("{}/v1/records", base))
                .bearer_auth(&token)
                .header("Content-Type", "application/x-protobuf")
                .body(buf)
                .send()
                .await?;
            let resp = ensure_success(resp, "register").await?;
            let bytes = resp.bytes().await?;
            let created = CreateRecordResponse::decode(&bytes[..])?;
            if let Some(err) = created.error_message {
                bail!("register failed: {}", err);
            }
            let id = created.id;
            if id.is_empty() {
                bail!("register failed: empty id returned");
            }
            if disable {
                toggle(&client, &base, &token, &id, false).await?;
            }

            // If --out-bundle is provided, export the bundle
            if let Some(bundle_path) = out_bundle {
                let endpoint = "export/tar"; // Default to tar format
                let resp = client
                    .get(format!("{}/v1/records/{}/{}", base, id, endpoint))
                    .bearer_auth(&token)
                    .send()
                    .await?;
                let resp = ensure_success(resp, "export").await?;
                let bytes = resp.bytes().await?;
                fs::write(&bundle_path, &bytes)?;
            }

            println!("{id}");
        }
    }
    Ok(())
}

type StagingContents = (
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    Option<Vec<u8>>,
);

#[allow(clippy::type_complexity)]
fn read_staging_dir(path: &Path) -> Result<StagingContents> {
    if !path.is_dir() {
        bail!("Staging directory path is not a directory: {:?}", path);
    }

    let mut fw = None;
    let mut k = None;
    let mut i = None;
    let mut params = None;
    let mut enc_key = None;

    // Read firmware-code.fd
    let fw_path = path.join("firmware-code.fd");
    if fw_path.exists() {
        fw = Some(fs::read(&fw_path)?);
    }

    // Read vmlinuz
    let k_path = path.join("vmlinuz");
    if k_path.exists() {
        k = Some(fs::read(&k_path)?);
    }

    // Read initrd.img
    let i_path = path.join("initrd.img");
    if i_path.exists() {
        i = Some(fs::read(&i_path)?);
    }

    // Read kernel-params.txt
    let params_path = path.join("kernel-params.txt");
    if params_path.exists() {
        let content = fs::read_to_string(&params_path)?;
        params = Some(content.trim().to_string());
    }

    // Read unsealing.key.enc
    let enc_key_path = path.join("unsealing.key.enc");
    if enc_key_path.exists() {
        enc_key = Some(fs::read(&enc_key_path)?);
    }

    Ok((fw, k, i, params, enc_key))
}

fn get_user_confirmation(prompt: &str) -> Result<bool> {
    use std::io::{self, BufRead};
    let stdin = io::stdin();
    let mut line = String::new();
    print!("{} (yes/no): ", prompt);
    io::stdout().flush()?;
    stdin.lock().read_line(&mut line)?;
    let answer = line.trim().to_lowercase();
    Ok(answer == "yes" || answer == "y")
}

async fn run_config(action: ConfigCmd) -> Result<()> {
    match action {
        ConfigCmd::Login { token, url } => {
            let mut cfg = load_config()?;
            let base = normalize_https(&url)?;
            let ca_dest = ca_dest_path()?;
            let ingestion_key_dest = ingestion_key_dest_path()?;
            let identity_key_dest = identity_key_dest_path()?;

            // Request public info (without TLS verification - TOFU)
            println!("Requesting server public information...");
            let insecure_client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(Duration::from_secs(TIMEOUT_SECS))
                .build()
                .context("Failed to create insecure HTTP client")?;

            let public_info_resp = insecure_client
                .get(format!("{}/v1/public/info", base))
                .send()
                .await
                .map_err(|e| anyhow!("Failed to contact server: {}", e))?;

            let public_info_resp = public_info_resp
                .error_for_status()
                .map_err(|e| anyhow!("Server returned error: {}", e))?;

            let public_info_text = public_info_resp
                .text()
                .await
                .map_err(|e| anyhow!("Failed to read server response: {}", e))?;
            let public_info: serde_json::Value = serde_json::from_str(&public_info_text)
                .map_err(|e| anyhow!("Failed to parse server response as JSON: {}", e))?;

            let ca_cert = public_info
                .get("ca_cert")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Server response missing 'ca_cert' field"))?;
            let ingestion_pub_key = public_info
                .get("ingestion_pub_key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Server response missing 'ingestion_pub_key' field"))?;
            let identity_pub_key = public_info
                .get("identity_pub_key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Server response missing 'identity_pub_key' field"))?;

            // Hash the CA cert and show to user
            let mut hasher = Sha256::new();
            hasher.update(ca_cert.as_bytes());
            let ca_hash = hex::encode(hasher.finalize());

            println!("\n=== Server Identity Verification (TOFU) ===");
            println!("CA Certificate SHA256: {}", ca_hash);
            println!("\nPlease verify this hash matches the server's CA certificate hash.");
            println!("You can obtain the hash from the server administrator or");
            println!("by inspecting the server's CA certificate file.\n");

            // Get user confirmation
            if !get_user_confirmation("Does this hash match the server's CA certificate?")? {
                println!("Aborted. Hash verification failed.");
                std::process::exit(1);
            }

            // Validate token via health endpoint using received CA cert
            println!("\nValidating token with server...");
            let client = build_client_from_bytes(ca_cert.as_bytes())?;
            let resp = client
                .get(format!("{}/v1/health", base))
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|e| anyhow!("Failed to contact server: {}", e))?;

            if !resp.status().is_success() {
                println!("Failed to validate token: status {}", resp.status());
                std::process::exit(1);
            }

            // Save CA cert and ingestion key to config dir
            let config_parent = ca_dest
                .parent()
                .ok_or_else(|| anyhow!("Cannot determine config directory"))?;
            fs::create_dir_all(config_parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(config_parent, fs::Permissions::from_mode(0o700))?;
            }

            // Save CA cert
            fs::write(&ca_dest, ca_cert.as_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&ca_dest, fs::Permissions::from_mode(0o600))?;
            }

            // Save ingestion public key
            fs::write(&ingestion_key_dest, ingestion_pub_key.as_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&ingestion_key_dest, fs::Permissions::from_mode(0o600))?;
            }

            // Save identity public key (Ed25519; to be baked into guest initrd)
            fs::write(&identity_key_dest, identity_pub_key.as_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&identity_key_dest, fs::Permissions::from_mode(0o600))?;
            }

            // Save config
            cfg.token = Some(token);
            cfg.url = Some(base);
            cfg.ca_cert = Some("ca.pem".to_string());
            save_config(&cfg)?;
            println!("Successfully logged in, config stored");
        }
        ConfigCmd::Logout => {
            delete_config()?;
            println!("Token removed");
        }
    }
    Ok(())
}

fn print_kv(key: &str, val: &str) {
    println!("{:<20}: {}", key, val);
}

fn print_record(r: &common::snpguard::AttestationRecord, json: bool) -> Result<()> {
    if json {
        #[derive(serde::Serialize)]
        struct JsonRecord<'a> {
            id: &'a str,
            os_name: &'a str,
            request_count: i32,
            enabled: bool,
            kernel_params: &'a str,
            firmware_path: &'a str,
            kernel_path: &'a str,
            initrd_path: &'a str,
            vcpus: u32,
            vcpu_type: &'a str,
            allowed_debug: bool,
            allowed_migrate_ma: bool,
            allowed_smt: bool,
            min_tcb_bootloader: u32,
            min_tcb_tee: u32,
            min_tcb_snp: u32,
            min_tcb_microcode: u32,
            image_id: String,
            created_at: &'a str,
        }
        let jr = JsonRecord {
            id: &r.id,
            os_name: &r.os_name,
            request_count: r.request_count,
            enabled: r.enabled,
            kernel_params: &r.kernel_params,
            firmware_path: &r.firmware_path,
            kernel_path: &r.kernel_path,
            initrd_path: &r.initrd_path,
            vcpus: r.vcpus,
            vcpu_type: &r.vcpu_type,
            allowed_debug: r.allowed_debug,
            allowed_migrate_ma: r.allowed_migrate_ma,
            allowed_smt: r.allowed_smt,
            min_tcb_bootloader: r.min_tcb_bootloader,
            min_tcb_tee: r.min_tcb_tee,
            min_tcb_snp: r.min_tcb_snp,
            min_tcb_microcode: r.min_tcb_microcode,
            image_id: hex::encode(&r.image_id),
            created_at: &r.created_at,
        };
        let val = serde_json::to_string_pretty(&jr)?;
        println!("{}", val);
    } else {
        print_kv("ID", &r.id);
        print_kv("OS Name", &r.os_name);
        print_kv("Requests", &r.request_count.to_string());
        print_kv("Status", if r.enabled { "enabled" } else { "disabled" });
        print_kv("Kernel Params", &r.kernel_params);
        print_kv("Firmware Path", &r.firmware_path);
        print_kv("Kernel Path", &r.kernel_path);
        print_kv("Initrd Path", &r.initrd_path);
        print_kv("vCPUs", &r.vcpus.to_string());
        print_kv("vCPU Type", &r.vcpu_type);
        print_kv("Allowed Debug", &r.allowed_debug.to_string());
        print_kv("Allowed Migrate MA", &r.allowed_migrate_ma.to_string());
        print_kv("Allowed SMT", &r.allowed_smt.to_string());
        print_kv("Min TCB Bootloader", &r.min_tcb_bootloader.to_string());
        print_kv("Min TCB TEE", &r.min_tcb_tee.to_string());
        print_kv("Min TCB SNP", &r.min_tcb_snp.to_string());
        print_kv("Min TCB Microcode", &r.min_tcb_microcode.to_string());
        print_kv("Image ID", &hex::encode(&r.image_id));
        print_kv("Created At", &r.created_at);
    }
    Ok(())
}

fn print_list(records: Vec<common::snpguard::AttestationRecord>, json: bool) -> Result<()> {
    if json {
        #[derive(serde::Serialize)]
        struct JsonRec<'a> {
            id: &'a str,
            os_name: &'a str,
            request_count: i32,
            enabled: bool,
        }
        let out: Vec<JsonRec> = records
            .iter()
            .map(|r| JsonRec {
                id: &r.id,
                os_name: &r.os_name,
                request_count: r.request_count,
                enabled: r.enabled,
            })
            .collect();
        let val = serde_json::to_string_pretty(&out)?;
        println!("{}", val);
    } else {
        println!(
            "{:<36}  {:<24}  {:>8}  {:<8}",
            "ID", "OS NAME", "REQUESTS", "STATUS"
        );
        for r in records {
            let status = if r.enabled { "enabled" } else { "disabled" };
            println!(
                "{:<36}  {:<24}  {:>8}  {:<8}",
                r.id, r.os_name, r.request_count, status
            );
        }
    }
    Ok(())
}

async fn toggle(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    id: &str,
    enable: bool,
) -> Result<()> {
    let endpoint = if enable { "enable" } else { "disable" };
    let resp = client
        .post(format!("{}/v1/records/{}/{}", base, id, endpoint))
        .bearer_auth(token)
        .send()
        .await?;
    let resp = ensure_success(resp, "toggle").await?;
    let bytes = resp.bytes().await?;
    let _ = ToggleEnabledResponse::decode(&bytes[..])?;
    Ok(())
}

async fn ensure_success(resp: reqwest::Response, op: &str) -> Result<reqwest::Response> {
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("{} failed: {} {}", op, status, body);
    }
    Ok(resp)
}

fn normalize_https(url: &str) -> Result<String> {
    let u = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{}", url)
    };
    if !u.starts_with("https://") {
        bail!("URL must use HTTPS");
    }
    Ok(u.trim_end_matches('/').to_string())
}
