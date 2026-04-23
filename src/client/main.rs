// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 IONOS SE
// Author: Roman Penyaev <r.peniaev@gmail.com>

use anyhow::{anyhow, bail, Context, Result};
use boot::sev::{check_sev_support_live, kernel_version_from_path};
use clap::{Parser, Subcommand};
use common::snpguard::{
    ArtifactEntry, AttestationRequest, AttestationResponse, CreateRecordRequest,
    CreateRecordResponse, DeleteRecordResponse, GetRecordResponse, ListRecordsResponse,
    NonceRequest, NonceResponse, RenewRequest, RenewRequestPayload, RenewResponse,
    RenewResponsePayload, ToggleEnabledResponse,
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
use rand::RngCore;
use reqwest::Certificate;
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
use sha2::{Digest, Sha256, Sha512};
use std::fs;
use std::io::{self, Write};
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
enum AttestCmd {
    /// Perform online attestation and output the released secret
    Report {
        #[arg(long, value_name = "PATH")]
        sealed_blob: PathBuf,
    },
    /// Request a renewal of the current attestation record from inside the running VM
    Renew {
        /// Path to the server Ed25519 identity public key (PEM) used to verify the response
        #[arg(
            long,
            value_name = "PATH",
            default_value = "/etc/snpguard/identity.pub"
        )]
        identity_pub: String,
        /// Path to grub.cfg used to discover the boot kernel and initrd
        #[arg(long, value_name = "PATH", default_value = "/boot/grub/grub.cfg")]
        grub_cfg: PathBuf,
        /// Prompt interactively when multiple SEV-SNP supported kernels are found in grub.cfg
        #[arg(long, default_value_t = false)]
        interactive: bool,
        /// Write the response artifact bundle to this path (tar archive)
        #[arg(long, value_name = "PATH")]
        out_bundle: Option<PathBuf>,
        /// Firmware image to send (overrides grub discovery)
        #[arg(long)]
        firmware: Option<PathBuf>,
        /// Kernel binary to send (overrides grub discovery)
        #[arg(long)]
        kernel: Option<PathBuf>,
        /// Initrd image to send (overrides grub discovery)
        #[arg(long)]
        initrd: Option<PathBuf>,
        /// Kernel command-line parameters (overrides grub discovery)
        #[arg(long)]
        kernel_params: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Attestation operations (report, renew)
    Attest {
        #[arg(
            long,
            value_name = "URL",
            help = "Attestation service URL [default: contents of /etc/snpguard/attest.url]"
        )]
        url: Option<String>,
        #[arg(
            long,
            value_name = "PATH",
            help = "Path to the pinned CA certificate for TLS verification. \
                    Defaults to /etc/snpguard/ca.pem when that file exists; \
                    falls back to the built-in public root CA bundle otherwise."
        )]
        ca_cert: Option<String>,
        #[command(subcommand)]
        action: AttestCmd,
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
    /// List all attestation records
    List {
        /// Output as JSON instead of a human-readable table
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Show details of a single attestation record
    Show {
        /// UUID of the attestation record
        id: String,
        /// Output as JSON instead of key-value text
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Enable an attestation record (allows attestations to succeed)
    Enable {
        /// UUID of the attestation record
        id: String,
    },
    /// Disable an attestation record (blocks all attestations)
    Disable {
        /// UUID of the attestation record
        id: String,
    },
    /// Delete an attestation record and its stored artifacts
    Delete {
        /// UUID of the attestation record
        id: String,
    },
    /// Download the launch artifact bundle for a record
    Export {
        /// UUID of the attestation record
        id: String,
        /// Archive format to download
        #[arg(long, value_parser = ["tar", "squash", "squashfs"], default_value = "tar")]
        format: String,
        /// Path to write the downloaded bundle
        #[arg(long, value_name = "PATH")]
        out_bundle: PathBuf,
        /// Export the pending renewal artifacts instead of the current ones
        #[arg(long, default_value_t = false)]
        pending: bool,
    },
    /// Discard a pending renewal for a registration
    DiscardPending {
        /// UUID of the attestation record whose pending renewal should be discarded
        id: String,
    },
    /// Create a new attestation record and upload its boot artifacts
    Register {
        /// Human-readable name for this VM registration
        #[arg(long)]
        os_name: String,
        /// Path to the plaintext unsealing private key (will be encrypted with the server ingestion key)
        #[arg(long, value_name = "PATH", group = "unsealing_key")]
        unsealing_private_key: Option<PathBuf>,
        /// Path to the pre-encrypted unsealing private key (HPKE-sealed with the server ingestion key)
        #[arg(long, value_name = "PATH", group = "unsealing_key")]
        enc_unsealing_private_key: Option<PathBuf>,
        /// Number of virtual CPUs
        #[arg(long, default_value = "4")]
        vcpus: u32,
        /// vCPU model (EPYC, EPYC-Milan, EPYC-Rome, EPYC-Genoa)
        #[arg(long, default_value = "EPYC")]
        vcpu_type: String,
        /// Allow the guest policy debug flag
        #[arg(long, default_value_t = false)]
        allowed_debug: bool,
        /// Allow migration with migration agent
        #[arg(long, default_value_t = false)]
        allowed_migrate_ma: bool,
        /// Allow simultaneous multi-threading (SMT)
        #[arg(long, default_value_t = false)]
        allowed_smt: bool,
        /// Minimum required TCB bootloader version
        #[arg(long, default_value = "0")]
        min_tcb_bootloader: u32,
        /// Minimum required TCB TEE version
        #[arg(long, default_value = "0")]
        min_tcb_tee: u32,
        /// Minimum required TCB SNP firmware version
        #[arg(long, default_value = "0")]
        min_tcb_snp: u32,
        /// Minimum required TCB microcode version
        #[arg(long, default_value = "0")]
        min_tcb_microcode: u32,
        /// Optional staging directory (generated by image convert --out-staging)
        #[arg(long, value_name = "PATH")]
        staging_dir: Option<PathBuf>,
        /// Firmware image to upload (overrides staging directory)
        #[arg(long)]
        firmware: Option<PathBuf>,
        /// Kernel binary to upload (overrides staging directory)
        #[arg(long)]
        kernel: Option<PathBuf>,
        /// Initrd image to upload (overrides staging directory)
        #[arg(long)]
        initrd: Option<PathBuf>,
        /// Kernel command-line parameters (overrides staging directory)
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
    // Install ring as the rustls crypto provider before any TLS operations.
    // Required for the raw TLS connection used during TOFU cert capture.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    match cli.cmd {
        Command::Attest {
            url,
            ca_cert,
            action,
        } => {
            let base = if let Some(u) = url {
                normalize_https(&u)?
            } else {
                let raw = fs::read_to_string("/etc/snpguard/attest.url")
                    .context("--url not given and /etc/snpguard/attest.url not found")?;
                normalize_https(raw.trim())?
            };
            // Resolve CA cert path: explicit flag > initramfs default > system roots.
            // The initramfs default (/etc/snpguard/ca.pem) is only used when the file
            // actually exists; otherwise fall through to the built-in root CA bundle.
            let ca_path: Option<String> = ca_cert.or_else(|| {
                let default = "/etc/snpguard/ca.pem";
                if std::path::Path::new(default).exists() {
                    Some(default.to_string())
                } else {
                    None
                }
            });
            match action {
                AttestCmd::Report { sealed_blob } => {
                    run_attest_report(&base, ca_path.as_deref(), &sealed_blob).await
                }
                AttestCmd::Renew {
                    identity_pub,
                    grub_cfg,
                    interactive,
                    out_bundle,
                    firmware,
                    kernel,
                    initrd,
                    kernel_params,
                } => {
                    run_attest_renew(
                        &base,
                        ca_path.as_deref(),
                        &identity_pub,
                        &grub_cfg,
                        interactive,
                        out_bundle.as_deref(),
                        firmware.as_deref(),
                        kernel.as_deref(),
                        initrd.as_deref(),
                        kernel_params.as_deref(),
                    )
                    .await
                }
            }
        }
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
    // Stored filename under config dir (e.g. "ca.pem") for self-signed / private CA.
    // None means the server uses a public CA; built-in webpki roots are used instead.
    ca_cert: Option<String>,
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

// ---------------------------------------------------------------------------
// TLS certificate capture (TOFU)
// ---------------------------------------------------------------------------
// On first login, the client makes a raw TLS connection to the server and
// captures the certificate chain presented during the handshake.
//
// A second connection verifies the chain against the built-in Mozilla/webpki
// root CA bundle to decide how to treat it:
//
//   Public CA (e.g. Let's Encrypt / platform-managed TLS):
//     No CA pinning.  Subsequent connections use the built-in root bundle.
//     Nothing from the captured chain is stored on disk.
//
//   Self-signed / private CA:
//     The CA portion of the chain is stored as ca.pem and used to pin all
//     subsequent connections (SSH known_hosts style).
//     Chain selection for pinning:
//       - Single cert: the cert is both leaf and CA -- store it.
//       - Multi-cert: drop the leaf (index 0), store the intermediates.
//         The leaf rotates on renewal; intermediates are stable.
//
// In both cases the chain is converted to PEM for the fingerprint display
// shown to the user.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName as TlsServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::sync::{Arc as StdArc, Mutex};
use tokio_rustls::TlsConnector;

#[derive(Debug)]
struct CertCapture {
    chain: StdArc<Mutex<Vec<Vec<u8>>>>,
}

impl ServerCertVerifier for CertCapture {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &TlsServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        let mut chain = self.chain.lock().unwrap();
        chain.push(end_entity.to_vec());
        for cert in intermediates {
            chain.push(cert.to_vec());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn fetch_tls_cert_chain(host: &str, port: u16) -> Result<Vec<Vec<u8>>> {
    use tokio::net::TcpStream;

    let captured: StdArc<Mutex<Vec<Vec<u8>>>> = StdArc::new(Mutex::new(Vec::new()));
    let verifier = CertCapture {
        chain: captured.clone(),
    };
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(StdArc::new(verifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(StdArc::new(config));
    let stream = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("Failed to connect to {}:{}", host, port))?;
    let server_name = TlsServerName::try_from(host.to_string())
        .map_err(|e| anyhow!("Invalid server name '{}': {}", host, e))?;
    let _ = connector
        .connect(server_name, stream)
        .await
        .with_context(|| format!("TLS handshake failed with {}:{}", host, port))?;
    let chain = captured.lock().unwrap().clone();
    if chain.is_empty() {
        bail!("No certificates received from server");
    }
    Ok(chain)
}

/// Encode the CA portion of a captured chain as PEM bytes.
/// For a single-cert chain (self-signed) that cert is stored as-is.
/// For multi-cert chains the leaf (index 0) is dropped; the remaining
/// intermediates are stored so that leaf renewals do not break pinning.
fn chain_to_ca_pem(chain: &[Vec<u8>]) -> Vec<u8> {
    let certs = if chain.len() == 1 { chain } else { &chain[1..] };
    let mut out = Vec::new();
    for der in certs {
        let p = pem::Pem::new("CERTIFICATE", der.as_slice());
        out.extend_from_slice(pem::encode(&p).as_bytes());
    }
    out
}

/// Check whether the server's TLS certificate is trusted by the public Mozilla root CA bundle.
///
/// Returns true if the certificate chain is verifiable by a well-known public CA (e.g.
/// Let's Encrypt, DigiCert, platform-managed certs on fly.io / Railway / Render).
/// Returns false if the cert is self-signed or issued by a private CA.
///
/// This check is advisory: it helps the user understand how thoroughly to verify
/// the displayed fingerprints, but does not block login in either case.
async fn check_publicly_trusted(host: &str, port: u16) -> bool {
    let url = format!("https://{}:{}/v1/health", host, port);
    let Ok(client) = reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .tls_built_in_root_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
    else {
        return false;
    };
    // Any HTTP response (even 4xx/5xx) means TLS verification succeeded.
    // A connect-phase error means TLS verification failed (self-signed / private CA).
    match client.head(&url).send().await {
        Ok(_) => true,
        Err(e) if e.is_connect() => false,
        Err(_) => true,
    }
}

/// Parse host and port from a normalised https:// URL.
fn parse_https_host_port(base: &str) -> Result<(String, u16)> {
    let rest = base
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("Expected https:// URL, got: {}", base))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    if let Some(colon) = authority.rfind(':') {
        let host = authority[..colon].to_string();
        let port: u16 = authority[colon + 1..]
            .parse()
            .with_context(|| format!("Invalid port in URL: {}", base))?;
        Ok((host, port))
    } else {
        Ok((authority.to_string(), 443))
    }
}

/// Build a client that trusts only a specific pinned CA (PEM file on disk).
fn build_client(ca_cert_path: &str) -> Result<reqwest::Client> {
    let ca_pem = fs::read(ca_cert_path)
        .with_context(|| format!("Failed to read pinned CA certificate at {}", ca_cert_path))?;
    build_client_from_bytes(&ca_pem)
}

/// Build a client that trusts the embedded Mozilla/webpki root CA bundle.
/// Used when the server's TLS certificate is issued by a public CA and no
/// pinned ca.pem was stored during login.
fn build_client_system_roots() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .tls_built_in_root_certs(true)
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .build()
        .context("Failed to create HTTP client with system root CAs")
}

/// Build a client using a pinned CA file when one is provided, or fall back
/// to the system root CA bundle when `ca_cert_path` is None.
fn build_client_maybe_pinned(ca_cert_path: Option<&str>) -> Result<reqwest::Client> {
    match ca_cert_path {
        Some(path) => build_client(path),
        None => build_client_system_roots(),
    }
}

fn build_client_from_bytes(ca_pem: &[u8]) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .tls_built_in_root_certs(false)
        .timeout(Duration::from_secs(TIMEOUT_SECS));
    for item in pem::parse_many(ca_pem).map_err(|e| anyhow!("Failed to parse CA PEM: {}", e))? {
        let cert = Certificate::from_der(item.contents())
            .context("Failed to create certificate from DER")?;
        builder = builder.add_root_certificate(cert);
    }
    builder
        .build()
        .context("Failed to create HTTP client with pinned CA")
}

async fn run_attest_report(url: &str, ca_cert: Option<&str>, sealed_blob: &Path) -> Result<()> {
    let client = build_client_maybe_pinned(ca_cert)?;
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

fn is_root() -> bool {
    rustix::process::getuid().is_root()
}

/// Discover the kernel, initrd, and kernel parameters from grub.cfg on the live filesystem.
///
/// Returns `(kernel_bytes, initrd_bytes, params)`. `initrd_bytes` is None if the selected
/// entry has no initrd line. `params` may be an empty string.
fn discover_boot_artifacts(
    grub_cfg: &Path,
    interactive: bool,
) -> Result<(Vec<u8>, Option<Vec<u8>>, String)> {
    let grub_content = fs::read_to_string(grub_cfg)
        .with_context(|| format!("Failed to read grub.cfg: {:?}", grub_cfg))?;
    let entries = boot::grub::parse_grub_cfg_from_str(&grub_content, true)
        .context("Failed to parse grub.cfg")?;

    let boot_dir = Path::new("/boot");
    let mut supported: Vec<&boot::grub::GrubEntry> = Vec::new();

    println!("Scanning grub.cfg for SEV-SNP capable kernels...");
    for entry in &entries {
        match kernel_version_from_path(&entry.kernel) {
            Ok(version) => match check_sev_support_live(boot_dir, version) {
                Ok(support) if support.is_supported() => {
                    println!("  [+] Supported: {}", entry.kernel);
                    supported.push(entry);
                }
                Ok(_) => println!("  [-] No SEV-SNP support: {}", entry.kernel),
                Err(e) => println!("  [!] Cannot check {}: {}", entry.kernel, e),
            },
            Err(e) => println!("  [!] Unrecognised kernel name {}: {}", entry.kernel, e),
        }
    }

    if supported.is_empty() {
        bail!("No SEV-SNP capable kernels found in {:?}", grub_cfg);
    }

    let selected: &boot::grub::GrubEntry = if supported.len() == 1 {
        let entry = supported[0];
        println!("\n  Using single SEV-SNP supported entry:");
        println!("    Kernel: {}", entry.kernel);
        println!(
            "    Initrd: {}",
            entry.initrd.as_deref().unwrap_or("(none)")
        );
        println!("    Params: {}", entry.params);
        entry
    } else if !interactive {
        let idx = supported.iter().position(|e| e.is_default).unwrap_or(0);
        let entry = supported[idx];
        let reason = if entry.is_default {
            "GRUB default"
        } else {
            "first available"
        };
        println!("\n  Auto-selected entry {} ({}):", idx, reason);
        println!("    Kernel: {}", entry.kernel);
        println!(
            "    Initrd: {}",
            entry.initrd.as_deref().unwrap_or("(none)")
        );
        println!("    Params: {}", entry.params);
        entry
    } else {
        println!("\n  Available SEV-SNP capable kernels:");
        for (i, e) in supported.iter().enumerate() {
            let marker = if e.is_default { " (default)" } else { "" };
            println!("    [{}] {}{}", i, e.kernel, marker);
        }
        print!("\n  Enter entry number (0-{}): ", supported.len() - 1);
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let idx: usize = line
            .trim()
            .parse()
            .with_context(|| format!("Invalid entry number: {}", line.trim()))?;
        if idx >= supported.len() {
            bail!(
                "Entry number {} out of range (0-{})",
                idx,
                supported.len() - 1
            );
        }
        let entry = supported[idx];
        println!("\n  Selected entry {}:", idx);
        println!("    Kernel: {}", entry.kernel);
        println!(
            "    Initrd: {}",
            entry.initrd.as_deref().unwrap_or("(none)")
        );
        println!("    Params: {}", entry.params);
        entry
    };

    // Grub paths are relative to the boot partition root (e.g. /vmlinuz-6.8-generic).
    // On systems with a separate /boot partition they are not directly accessible
    // without the /boot prefix.  Match the same logic used in image convert.
    let kernel_file = if selected.kernel.starts_with("/boot") {
        selected.kernel.clone()
    } else {
        format!("/boot{}", selected.kernel)
    };
    let kernel_bytes = fs::read(&kernel_file)
        .with_context(|| format!("Failed to read kernel: {}", kernel_file))?;

    let initrd_bytes = selected
        .initrd
        .as_ref()
        .map(|p| {
            let initrd_file = if p.starts_with("/boot") {
                p.clone()
            } else {
                format!("/boot{}", p)
            };
            fs::read(&initrd_file)
                .with_context(|| format!("Failed to read initrd: {}", initrd_file))
        })
        .transpose()?;

    Ok((kernel_bytes, initrd_bytes, selected.params.clone()))
}

#[allow(clippy::too_many_arguments)]
async fn run_attest_renew(
    url: &str,
    ca_cert: Option<&str>,
    identity_pub: &str,
    grub_cfg: &Path,
    interactive: bool,
    out_bundle: Option<&Path>,
    firmware: Option<&Path>,
    kernel: Option<&Path>,
    initrd: Option<&Path>,
    kernel_params: Option<&str>,
) -> Result<()> {
    // Reading boot artifacts from disk and interacting with /dev/sev-guest requires root.
    if !is_root() {
        bail!("attest renew must be run as root");
    }

    // If no --out-bundle is provided, artifacts are written to the LAUNCH_ARTIFACTS
    // partition.  Verify it is reachable before doing any expensive work.
    if out_bundle.is_none() {
        let label = Path::new("/dev/disk/by-label/LAUNCH_ARTIFACTS");
        if !label.exists() {
            bail!(
                "/dev/disk/by-label/LAUNCH_ARTIFACTS not found.\n\
                 Ensure the LAUNCH_ARTIFACTS partition is attached, \
                 or pass --out-bundle <PATH> to write a local archive instead."
            );
        }
    }

    let client = build_client_maybe_pinned(ca_cert)?;
    let base = normalize_https(url)?;

    let mut firmware_data: Option<Vec<u8>> = None;
    let mut kernel_data: Option<Vec<u8>>;
    let mut initrd_data: Option<Vec<u8>>;
    let mut params_data: Option<String>;

    if let (Some(k), Some(i), Some(p)) = (kernel, initrd, kernel_params) {
        // All three boot artifacts provided explicitly -- skip grub discovery entirely.
        kernel_data = Some(fs::read(k)?);
        initrd_data = Some(fs::read(i)?);
        params_data = Some(p.to_string());
    } else {
        // Discover from grub.cfg; explicit overrides below take precedence.
        let (grub_kernel, grub_initrd, grub_params) =
            discover_boot_artifacts(grub_cfg, interactive)?;
        kernel_data = Some(grub_kernel);
        initrd_data = grub_initrd;
        params_data = if grub_params.is_empty() {
            None
        } else {
            Some(grub_params)
        };

        if let Some(path) = kernel {
            kernel_data = Some(fs::read(path)?);
        }
        if let Some(path) = initrd {
            initrd_data = Some(fs::read(path)?);
        }
        if let Some(p) = kernel_params {
            params_data = Some(p.to_string());
        }
    }

    if let Some(path) = firmware {
        firmware_data = Some(fs::read(path)?);
    }

    // Fetch a fresh server nonce to prove request freshness.
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

    // Generate a 64-byte client nonce to prevent replay of signed responses.
    let mut client_nonce = vec![0u8; 64];
    OsRng.fill_bytes(&mut client_nonce);

    // Encode RenewRequestPayload once; the SNP report_data will be SHA512 of these bytes.
    // server_nonce is included inside so no separate concatenation is needed.
    let payload = RenewRequestPayload {
        server_nonce: server_nonce.clone(),
        client_nonce: client_nonce.clone(),
        firmware: firmware_data.clone(),
        kernel: kernel_data.clone(),
        initrd: initrd_data.clone(),
        kernel_params: params_data.clone(),
    };
    let mut payload_bytes = Vec::new();
    payload.encode(&mut payload_bytes)?;

    let binding_digest: [u8; 64] = Sha512::digest(&payload_bytes).into();

    // Request an SNP attestation report that binds the payload via report_data.
    let mut fw = Firmware::open().context(
        "Failed to open SEV firmware device (/dev/sev-guest). Ensure SEV-SNP is enabled.",
    )?;
    let report_bytes = fw
        .get_report(None, Some(binding_digest), Some(0))
        .context("Failed to get attestation report from SEV firmware")?;

    let req = RenewRequest {
        report_data: report_bytes.to_vec(),
        payload_bytes: payload_bytes.clone(),
    };
    let mut req_bytes = Vec::new();
    req.encode(&mut req_bytes)?;

    let resp = client
        .post(format!("{}/v1/attest/renew", base))
        .header("Content-Type", "application/x-protobuf")
        .body(req_bytes)
        .send()
        .await
        .context("Failed to send renewal request")?;
    let resp = ensure_success(resp, "renew").await?;
    let bytes = resp.bytes().await?;
    let renew_resp = RenewResponse::decode(&bytes[..]).context("Decode renewal response")?;

    if !renew_resp.success {
        bail!(
            "Renewal failed: {}",
            renew_resp.error_message.unwrap_or_default()
        );
    }

    // Verify the Ed25519 signature before trusting any response content.
    let sig = renew_resp
        .signature
        .ok_or_else(|| anyhow!("Server response missing signature"))?;
    let resp_payload_bytes = renew_resp
        .payload_bytes
        .ok_or_else(|| anyhow!("Server response missing payload_bytes"))?;
    let identity_pub_pem = fs::read_to_string(identity_pub)
        .with_context(|| format!("Failed to read identity public key from {}", identity_pub))?;
    let identity_pub_bytes = pem::parse(identity_pub_pem)
        .context("Failed to parse identity.pub PEM")?
        .into_contents();
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &identity_pub_bytes)
        .verify(&resp_payload_bytes, &sig)
        .map_err(|_| anyhow!("Ed25519 signature verification failed"))?;

    let resp_payload = RenewResponsePayload::decode(resp_payload_bytes.as_slice())
        .context("Decode RenewResponsePayload")?;

    if resp_payload.client_nonce != client_nonce {
        bail!("client_nonce mismatch in response -- possible replay attack");
    }

    println!("Renewal accepted. Pending record: {}", resp_payload.id);
    for artifact in &resp_payload.artifacts {
        println!("  {} ({} bytes)", artifact.filename, artifact.content.len());
    }

    // Assemble local artifacts in canonical order: kernel, initrd, params, firmware.
    let mut local_artifacts: Vec<ArtifactEntry> = Vec::new();
    if let Some(data) = kernel_data {
        local_artifacts.push(ArtifactEntry {
            filename: "vmlinuz".to_string(),
            content: data,
        });
    }
    if let Some(data) = initrd_data {
        local_artifacts.push(ArtifactEntry {
            filename: "initrd.img".to_string(),
            content: data,
        });
    }
    if let Some(params) = params_data {
        local_artifacts.push(ArtifactEntry {
            filename: "kernel-params.txt".to_string(),
            content: params.into_bytes(),
        });
    }
    if let Some(data) = firmware_data {
        local_artifacts.push(ArtifactEntry {
            filename: "firmware-code.fd".to_string(),
            content: data,
        });
    }

    if let Some(bundle_path) = out_bundle {
        let mut all_artifacts = local_artifacts;
        all_artifacts.extend(resp_payload.artifacts);
        write_artifact_bundle(bundle_path, &all_artifacts)?;
        println!("Bundle written to {:?}", bundle_path);
    } else {
        write_to_launch_artifacts(&local_artifacts, &resp_payload.artifacts)?;
    }

    println!("Relaunch the VM with the updated artifacts to promote the pending record.");
    Ok(())
}

/// Write a list of artifact entries to a gzip-compressed tar archive at `path`.
fn write_artifact_bundle(path: &Path, artifacts: &[ArtifactEntry]) -> Result<()> {
    use flate2::{write::GzEncoder, Compression};
    use tar::Builder;

    let file = fs::File::create(path)
        .with_context(|| format!("Failed to create bundle file {:?}", path))?;
    let gz = GzEncoder::new(file, Compression::default());
    let mut archive = Builder::new(gz);
    for artifact in artifacts {
        let mut header = tar::Header::new_gnu();
        header.set_size(artifact.content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, &artifact.filename, artifact.content.as_slice())
            .with_context(|| format!("Failed to append {} to bundle", artifact.filename))?;
    }
    archive
        .finish()
        .context("Failed to finalize bundle archive")?;
    Ok(())
}

/// Write artifact files into the inactive LAUNCH_ARTIFACTS slot using an atomic A/B swap.
///
/// Mounts the LAUNCH_ARTIFACTS partition, determines the inactive slot by reading the
/// current /artifacts symlink, writes all files there with per-file fsync, then atomically
/// replaces the symlink and unmounts.
fn write_to_launch_artifacts(
    local_artifacts: &[ArtifactEntry],
    server_artifacts: &[ArtifactEntry],
) -> Result<()> {
    use rustix::mount::{mount, unmount, MountFlags, UnmountFlags};
    use std::ffi::CStr;

    let label = Path::new("/dev/disk/by-label/LAUNCH_ARTIFACTS");
    let device = fs::canonicalize(label).context("Failed to resolve LAUNCH_ARTIFACTS device")?;

    let mountpoint = PathBuf::from(format!("/tmp/snpguard-mount-{}", std::process::id()));
    fs::create_dir(&mountpoint)
        .with_context(|| format!("Failed to create mountpoint {:?}", mountpoint))?;

    mount(
        &device,
        &mountpoint,
        "ext4",
        MountFlags::empty(),
        None::<&CStr>,
    )
    .with_context(|| format!("Failed to mount {:?} at {:?}", device, mountpoint))?;

    let result = write_artifacts_ab(&mountpoint, local_artifacts, server_artifacts);

    unmount(&mountpoint, UnmountFlags::empty())
        .with_context(|| format!("Failed to unmount {:?}", mountpoint))?;
    fs::remove_dir(&mountpoint)
        .with_context(|| format!("Failed to remove mountpoint {:?}", mountpoint))?;

    result
}

/// Write artifacts into the inactive slot directory and atomically update the /artifacts symlink.
fn write_artifacts_ab(
    root: &Path,
    local_artifacts: &[ArtifactEntry],
    server_artifacts: &[ArtifactEntry],
) -> Result<()> {
    use std::os::unix::fs::symlink;

    // /.booted is written by the initrd attestation script at boot time
    // and always points to the slot the running system was loaded from.
    // Using it (rather than /artifacts) makes multiple attest renew calls
    // idempotent: the pending slot is always overwritten, never the booted one.
    // Fall back to /artifacts on images that predate this feature.
    let booted_link = root.join(".booted");
    let artifacts_link = root.join("artifacts");
    let booted = if booted_link.exists() {
        fs::read_link(&booted_link)
            .context("Failed to read /.booted symlink on LAUNCH_ARTIFACTS")?
    } else {
        fs::read_link(&artifacts_link)
            .context("Failed to read /artifacts symlink on LAUNCH_ARTIFACTS")?
    };
    let booted_str = booted
        .to_str()
        .ok_or_else(|| anyhow!("Non-UTF8 slot symlink target"))?;

    let next_slot = match booted_str {
        "A" => "B",
        "B" => "A",
        other => bail!("Unexpected slot value: {}", other),
    };

    let slot_dir = root.join(next_slot);
    fs::create_dir_all(&slot_dir)
        .with_context(|| format!("Failed to create slot directory {:?}", slot_dir))?;

    for artifact in local_artifacts.iter().chain(server_artifacts.iter()) {
        let dest = slot_dir.join(&artifact.filename);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&dest)
            .with_context(|| format!("Failed to open {:?} for writing", dest))?;
        f.write_all(&artifact.content)
            .with_context(|| format!("Failed to write {:?}", dest))?;
        f.sync_all()
            .with_context(|| format!("Failed to fsync {:?}", dest))?;
    }

    // fsync the slot directory to make the new files durable.
    fs::File::open(&slot_dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("Failed to fsync slot directory {:?}", slot_dir))?;

    // Atomically replace the /artifacts symlink.
    let tmp_link = root.join(".artifacts.new");
    symlink(next_slot, &tmp_link)
        .with_context(|| format!("Failed to create temp symlink {:?}", tmp_link))?;
    fs::rename(&tmp_link, &artifacts_link)
        .context("Failed to rename temp symlink over /artifacts")?;

    // fsync the partition root to make the rename durable.
    fs::File::open(root)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("Failed to fsync partition root {:?}", root))?;

    println!(
        "Artifacts written to LAUNCH_ARTIFACTS slot {} (was {}).",
        next_slot, booted_str
    );
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

    // Resolve CA cert: explicit flag > stored path > None (use system roots for public CA login).
    let ca_path: Option<String> = ca_cert.map(|p| p.to_string()).or_else(|| {
        cfg.ca_cert.map(|stored| {
            config_dir()
                .unwrap_or_default()
                .join("snpguard")
                .join(stored)
                .to_string_lossy()
                .to_string()
        })
    });

    let client = build_client_maybe_pinned(ca_path.as_deref())?;
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
            pending,
        } => {
            let endpoint = match format.as_str() {
                "tar" => "export/tar",
                "squash" | "squashfs" => "export/squash",
                _ => unreachable!(),
            };
            let mut url = format!("{}/v1/records/{}/{}", base, id, endpoint);
            if pending {
                url.push_str("?pending=true");
            }
            let resp = client.get(url).bearer_auth(&token).send().await?;
            let resp = ensure_success(resp, "export").await?;
            let bytes = resp.bytes().await?;
            fs::write(&out_bundle, &bytes)?;
        }
        ManageCmd::DiscardPending { id } => {
            let resp = client
                .post(format!("{}/v1/records/{}/discard-pending", base, id))
                .bearer_auth(&token)
                .send()
                .await?;
            let resp = ensure_success(resp, "discard-pending").await?;
            let bytes = resp.bytes().await?;
            let r = common::snpguard::DeleteRecordResponse::decode(&bytes[..])?;
            if !r.success {
                bail!(
                    "discard-pending failed: {}",
                    r.error_message.unwrap_or_default()
                );
            }
            println!("pending renewal discarded");
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

            // TOFU: capture the TLS certificate chain from the server's TLS handshake.
            // The CA portion (everything except the leaf cert) is stored and used to pin
            // subsequent connections. The server no longer needs to serve its own CA via REST.
            println!("Capturing server TLS certificate (TOFU)...");
            let (host, port) = parse_https_host_port(&base)?;
            let chain = fetch_tls_cert_chain(&host, port).await?;
            let ca_pem = chain_to_ca_pem(&chain);

            // Check whether the cert is issued by a known public CA (advisory only).
            let publicly_trusted = check_publicly_trusted(&host, port).await;

            // For public CA use the system root bundle throughout (no pinning at all).
            // For self-signed / private CA pin to the captured chain.
            let client = if publicly_trusted {
                build_client_system_roots()?
            } else {
                build_client_from_bytes(&ca_pem)?
            };

            // Fetch ingestion and identity keys using the pinned client.
            println!("Requesting server public information...");
            let public_info_resp = client
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

            let ingestion_pub_key = public_info
                .get("ingestion_pub_key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Server response missing 'ingestion_pub_key' field"))?;
            let identity_pub_key = public_info
                .get("identity_pub_key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Server response missing 'identity_pub_key' field"))?;

            // Compute fingerprints.
            // CA cert: SHA256 of the DER bytes (canonical, PEM-encoder-independent).
            // Matches the server's print_key_fingerprints which also hashes DER.
            // Public keys: SHA256 of the raw 32-byte key material extracted from the PEM.
            let ca_fp = {
                let ca_certs = if chain.len() == 1 {
                    &chain[..]
                } else {
                    &chain[1..]
                };
                match ca_certs.first() {
                    Some(der) => hex::encode(Sha256::digest(der.as_slice())),
                    None => "N/A".to_string(),
                }
            };

            let ingestion_fp = {
                let parsed = pem::parse(ingestion_pub_key)
                    .map_err(|e| anyhow!("Failed to parse ingestion public key PEM: {}", e))?;
                hex::encode(Sha256::digest(parsed.contents()))
            };

            let identity_fp = {
                let parsed = pem::parse(identity_pub_key)
                    .map_err(|e| anyhow!("Failed to parse identity public key PEM: {}", e))?;
                hex::encode(Sha256::digest(parsed.contents()))
            };

            println!("\n=== Server Identity Verification (SHA256) ===");
            if publicly_trusted {
                println!("CA Certificate  : {} [public CA]", ca_fp);
            } else {
                println!("CA Certificate  : {} [self-signed / private CA]", ca_fp);
            }
            println!("Ingestion Key   : {}", ingestion_fp);
            println!("Identity Key    : {}", identity_fp);
            println!();
            if publicly_trusted {
                println!("The TLS certificate was issued by a recognized public CA.");
                println!("Verify the Ingestion Key and Identity Key fingerprints with the");
                println!(
                    "server administrator or from /data/auth/ (ingestion.pub, identity.pub).\n"
                );
            } else {
                println!("WARNING: The TLS certificate is self-signed or issued by a private CA.");
                println!("Verify ALL three fingerprints carefully out-of-band with the server");
                println!(
                    "administrator (CA cert, ingestion.pub, identity.pub from /data/auth/).\n"
                );
            }

            // Get user confirmation
            let prompt = if publicly_trusted {
                "Do both key fingerprints match the server?"
            } else {
                "Do all three fingerprints match the server?"
            };
            if !get_user_confirmation(prompt)? {
                println!("Aborted. Fingerprint verification failed.");
                std::process::exit(1);
            }

            // Validate token via health endpoint using the pinned client
            println!("\nValidating token with server...");
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

            // Create config directory
            let config_parent = ingestion_key_dest
                .parent()
                .ok_or_else(|| anyhow!("Cannot determine config directory"))?;
            fs::create_dir_all(config_parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(config_parent, fs::Permissions::from_mode(0o700))?;
            }

            // Save CA cert only for self-signed / private CA.
            // For publicly-trusted certs the built-in root bundle is used; no file needed.
            if publicly_trusted {
                // Remove any stale ca.pem from a previous self-signed login.
                let _ = fs::remove_file(&ca_dest);
            } else {
                fs::write(&ca_dest, &ca_pem)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&ca_dest, fs::Permissions::from_mode(0o600))?;
                }
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

            // Save config: ca_cert is None for public CA (use system roots), Some("ca.pem") for pinned.
            cfg.token = Some(token);
            cfg.url = Some(base);
            cfg.ca_cert = if publicly_trusted {
                None
            } else {
                Some("ca.pem".to_string())
            };
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
            created_at: &'a str,
            pending_since: Option<i64>,
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
            created_at: &r.created_at,
            pending_since: r.pending_since,
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
        print_kv("Created At", &r.created_at);
        if let Some(ts) = r.pending_since {
            let dt = chrono::DateTime::from_timestamp(ts, 0)
                .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_else(|| ts.to_string());
            print_kv("Pending Renewal", &format!("yes, since {}", dt));
        }
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
            pending_since: Option<i64>,
        }
        let out: Vec<JsonRec> = records
            .iter()
            .map(|r| JsonRec {
                id: &r.id,
                os_name: &r.os_name,
                request_count: r.request_count,
                enabled: r.enabled,
                pending_since: r.pending_since,
            })
            .collect();
        let val = serde_json::to_string_pretty(&out)?;
        println!("{}", val);
    } else {
        println!(
            "{:<36}  {:<24}  {:>8}  {:<8}  {:<7}",
            "ID", "OS NAME", "REQUESTS", "STATUS", "RENEWAL"
        );
        for r in records {
            let status = if r.enabled { "enabled" } else { "disabled" };
            let renewal = if r.pending_since.is_some() {
                "pending"
            } else {
                "-"
            };
            println!(
                "{:<36}  {:<24}  {:>8}  {:<8}  {:<7}",
                r.id, r.os_name, r.request_count, status, renewal
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
