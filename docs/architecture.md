# SnpGuard Architecture

## Overview

SnpGuard is a SEV-SNP attestation service that verifies the integrity of guest VMs and releases secrets upon successful attestation. The system consists of three main components:

1. **Attestation Service** (Server)
2. **Attestation Client** (Guest VM)
3. **Management Frontend** (Web UI)

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Guest VM                                │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Initrd (initramfs-tools)                                │   │
│  │  - Hook: /etc/initramfs-tools/hooks/snpguard             │   │
│  │  - Script: scripts/local-top/snpguard-attest             │   │
│  │  Note: dracut support is in progress                     │   │
│  │  ┌────────────────────────────────────────────────────┐  │   │
│  │  │  snpguard-client (static binary, musl)             │  │   │
│  │  │  - Requests nonce                                  │  │   │
│  │  │  - Generates report via sev library                │  │   │
│  │  │  - Sends report for verification                   │  │   │
│  │  │  - Receives secret                                 │  │   │
│  │  └────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  SEV-SNP Hardware                                               │
│  - Memory encryption                                            │
│  - Attestation report generation                                │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ HTTPS/TLS + Protobuf
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    SnpGuard Server                              │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Attestation Service                                      │  │
│  │  - /v1/attest/nonce                                       │  │
│  │  - /v1/attest/report                                      │  │
│  │  - Verifies AMD certificate chain                         │  │
│  │  - Validates attestation reports                          │  │
│  │  - Releases secrets                                       │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Management Service                                       │  │
│  │  - Web UI (HTML/CSS/JavaScript)                           │  │
│  │  - CRUD operations for attestation records                │  │
│  │  - Artifact generation and download                       │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Database (SQLite)                                        │  │
│  │  - Attestation records                                    │  │
│  │  - Key digests                                            │  │
│  │  - Encrypted unsealing private keys                       │  │
│  │  - Encrypted ID/Auth keys                                 │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Artifact Storage                                         │  │
│  │  - Firmware, kernel, initrd                               │  │
│  │  - ID-Block, Auth-Block                                   │  │
│  │  - Generated artifacts                                    │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ HTTPS
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Management User                              │
│  - Creates attestation records                                  │
│  - Uploads firmware/kernel/initrd                               │
│  - Provides encrypted unsealing private key                     │
│  - Downloads artifacts                                          │
└─────────────────────────────────────────────────────────────────┘
```

## Component Details

### Attestation Service

**Responsibilities**:
- Generate random nonces for attestation
- Verify attestation reports using AMD's certificate chain (via integrated `snpguest`)
- Look up attestation records by image_id and key digests
- Decrypt sealed VMK using unsealing private key
- Encrypt VMK with ephemeral session key for secure delivery

**Key Functions**:
1. **Nonce Generation**: Creates cryptographically secure 64-byte nonces
2. **Certificate Fetching**: Retrieves CA and VCEK certificates from AMD KDS
3. **Report Verification**: Validates report signatures and structure
4. **Key Digest Extraction**: Extracts IMAGE_ID, ID_KEY_DIGEST and AUTHOR_KEY_DIGEST from reports
5. **Record Lookup**: Finds matching attestation records by image_id and key digests
6. **VMK Decryption**: Decrypts sealed VMK blob using unsealing private key (stored encrypted in DB)
7. **Session Encryption**: Encrypts VMK with ephemeral session key using client's public key (HPKE)
8. **Artifact Signing**: Signs artifacts delivered to guests using the server's Ed25519 identity key

### Attestation Client

**Responsibilities**:
- Request nonce from attestation service
- Generate ephemeral session keypair (X25519)
- Generate attestation report using `sev` library directly (with binding hash)
- Send report with sealed VMK blob for verification
- Receive session-encrypted VMK and decrypt it
- Output decrypted VMK (for LUKS disk decryption)

**Key Features**:
- Static binary (no glibc dependencies)
- Built with musl libc for initrd compatibility
- Direct SEV-SNP hardware access via sev library
- HTTPS client with certificate verification
- Protobuf message serialization

**Installation**:
- Installed automatically during `snpguard-image convert`
- Hook scripts (`hook.sh` and `attest.sh`) are installed into the guest image
- Initrd is regenerated with hooks included
- Currently supports initramfs-tools (Debian/Ubuntu) only
- Dracut support is in progress

### Management Frontend

**Responsibilities**:
- Provide web UI for managing attestation records
- Handle file uploads (firmware, kernel, initrd, unsealing private key)
- Generate random ID-Block and Auth-Block keys (secp384r1 EC keys) when creating records
- Encrypt ID and Auth keys with ingestion key before storing in database
- Generate ID-Block and Auth-Block using integrated `snpguest`
- Serve artifact downloads

**Key Features**:
- Modern, responsive UI (Tailwind CSS)
- File upload with size validation
- Artifact generation (tarball, SquashFS)
- Enable/disable attestation records

## Data Flow

### Attestation Flow

```
1. Guest VM boots
   │
   ├─> Network initialized
   │
   ├─> Initrd hook runs (/scripts/local-top/snpguard-attest)
   │
   ├─> Client requests nonce
   │   POST /v1/attest/nonce
   │   │
   │   └─> Server generates 64-byte nonce
   │       Returns: NonceResponse
   │
   ├─> Client generates report
   │   Direct sev library call
   │   │
   │   └─> SEV-SNP hardware generates report
   │
   ├─> Client sends report with sealed VMK blob
   │   POST /v1/attest/report
   │   │   - report_data: SEV-SNP attestation report
   │   │   - server_nonce: 64-byte nonce from server
   │   │   - client_pub_bytes: 32-byte ephemeral session public key
   │   │   - sealed_blob: HPKE-encrypted VMK (encrypted with unsealing public key)
   │   │
   │   └─> Server verifies:
   │       ├─> Parse and verify report structure
   │       ├─> Verify stateless nonce from report.report_data
   │       ├─> Verify hash binding (SHA512(server_nonce || client_pub_bytes))
   │       ├─> Extract image_id, id_key_digest, auth_key_digest from report
   │       ├─> Look up record by image_id and key digests
   │       ├─> Check if record is enabled
   │       ├─> Check TCB versions meet minimum requirements
   │       ├─> Check VMPL (must be 0)
   │       ├─> Fetch AMD certificates and verify report signature
   │       ├─> Decrypt sealed VMK using unsealing private key
   │       └─> Encrypt VMK with ephemeral session key (client's pub)
   │
   └─> Server responds
       ├─> Success: AttestationResponse {
       │       success: true,
       │       encapped_key: ephemeral session public key (32 bytes),
       │       ciphertext: VMK encrypted with session key
       │   }
       └─> Failure: AttestationResponse {
               success: false,
               error_message: ...
           }
```

### Record Creation Flow

```
1. User fills form in web UI
   │
   ├─> Uploads: firmware, kernel, initrd
   │
   ├─> Enters: OS name, vCPUs, vCPU type, kernel params, service URL
   │
   ├─> Provides: Unsealing private key (encrypted with ingestion public key)
   │
   └─> Submits form
       │
       ├─> Server saves files to artifacts/{id}/
       │
       ├─> Generates random 16-byte UUID for image-id
       │   let image_id = Uuid::new_v4();
       │
       ├─> Generates random ID-Block and Auth-Block keys (secp384r1 EC keys)
       │   - ID key: randomly generated secp384r1 EC private key
       │   - Auth key: randomly generated secp384r1 EC private key
       │   - Keys are generated once per attestation record
       │
       ├─> Runs integrated snpguest generate measurement
       │   --ovmf firmware-code.fd
       │   --kernel vmlinuz
       │   --initrd initrd.img
       │   --append "kernel-params"
       │   --vcpus N
       │   --vcpu-type EPYC-*
       │   --image-id <random_16_bytes>
       │
       ├─> Runs integrated snpguest generate id-block
       │   --id-file id-block.bin
       │   --auth-file id-auth.bin
       │
       ├─> Computes key digests
       │   snpguest generate key-digest id-block-key.pem
       │   snpguest generate key-digest id-auth-key.pem
       │
       ├─> Encrypts ID and Auth keys with ingestion key (HPKE)
       │   - Keys are encrypted before storage
       │
       ├─> Securely deletes key files from artifacts folder
       │   - Plaintext keys are removed after encryption
       │
       └─> Saves record to database
           - id, os_name, vcpu_type, image_id
           - unsealing_private_key_encrypted (HPKE-encrypted)
           - id_key_digest, auth_key_digest (computed from plaintext keys)
           - id_key_encrypted, auth_key_encrypted (HPKE-encrypted, stored in DB)
           - kernel_params, enabled, request_count
           - TCB minimums, policy flags
```

## Security Model

### Threat Model

**Threats**:
1. Man-in-the-middle attacks on attestation communication
2. Replay attacks using old attestation reports
3. Unauthorized access to management UI
4. Database compromise exposing encrypted keys

**Mitigations**:
1. **TLS with Certificate Verification**: All communication uses HTTPS with verified certificates
2. **Nonce-based Reports**: Each report includes a fresh nonce from the server
3. **HTTP Basic Auth**: Management UI requires authentication
4. **Key Digest Lookup**: Only records with matching key digests can be verified
5. **Enable/Disable Toggle**: Records can be disabled without deletion

### Trust Boundaries

```
┌─────────────────────────────────────────┐
│  Trusted: SnpGuard Server               │
│  - Verifies AMD certificates            │
│  - Validates attestation reports        │
│  - Decrypts sealed VMK                  │
│  - Encrypts VMK with session key        │
│  - Stores encrypted keys securely       │
└─────────────────────────────────────────┘
              │
              │ HTTPS (verified)
              │
┌─────────────────────────────────────────┐
│  Trusted: Guest VM (SEV-SNP)            │
│  - Hardware-protected memory            │
│  - Authentic attestation reports        │
└─────────────────────────────────────────┘
```

## Database Schema

### attestation_records

```sql
CREATE TABLE attestation_records (
    id TEXT PRIMARY KEY,                    -- UUID
    os_name TEXT NOT NULL,                   -- Descriptive name
    request_count INTEGER NOT NULL DEFAULT 0, -- Number of successful attestations
    unsealing_private_key_encrypted BLOB NOT NULL, -- HPKE-encrypted unsealing private key
    vcpu_type TEXT NOT NULL,                 -- EPYC variant
    enabled BOOLEAN NOT NULL DEFAULT TRUE,   -- Enable/disable flag
    image_id BLOB NOT NULL,                  -- Random 16-byte ASCII image ID
    id_key_digest BLOB NOT NULL,             -- ID-Block key digest (48 bytes, computed from randomly generated key)
    auth_key_digest BLOB NOT NULL,           -- Auth-Block key digest (48 bytes, computed from randomly generated key)
    id_key_encrypted BLOB,                   -- HPKE-encrypted ID-Block key (randomly generated, encrypted with ingestion key)
    auth_key_encrypted BLOB,                 -- HPKE-encrypted Auth-Block key (randomly generated, encrypted with ingestion key)
    created_at DATETIME NOT NULL,            -- Creation timestamp
    kernel_params TEXT NOT NULL,             -- Full kernel command line
    firmware_path TEXT NOT NULL,             -- Relative path to firmware
    kernel_path TEXT NOT NULL,               -- Relative path to kernel
    initrd_path TEXT NOT NULL,               -- Relative path to initrd
    allowed_debug BOOLEAN NOT NULL,          -- Allow debug mode
    allowed_migrate_ma BOOLEAN NOT NULL,      -- Allow migration with MA
    allowed_smt BOOLEAN NOT NULL,             -- Allow Simultaneous Multithreading
    min_tcb_bootloader INTEGER NOT NULL,      -- Minimum PSP bootloader version
    min_tcb_tee INTEGER NOT NULL,            -- Minimum SNP firmware version
    min_tcb_snp INTEGER NOT NULL,             -- Minimum SNP implementation version
    min_tcb_microcode INTEGER NOT NULL       -- Minimum CPU microcode version
);
```

**Key Management Notes**:

- **Server Identity Key** (`/data/auth/identity.key` / `identity.pub`): A stable Ed25519 signing
  keypair generated on first server start. The private key signs artifacts sent to guests
  (RenewResponse). The public key is returned by `GET /v1/public/info` under `identity_pub_key` and
  is baked into the guest initrd at image conversion time, enabling the guest to verify artifact
  authenticity offline without trusting the network. Must be backed up alongside the ingestion key.

- **Ingestion Key** (`/data/auth/ingestion.key` / `ingestion.pub`): X25519 HPKE keypair used to
  encrypt the unsealing private key before it is uploaded to the server. Also backs the
  `ingestion_pub_key` field of `GET /v1/public/info`.

- **ID and Auth Keys**: Randomly generated secp384r1 EC private keys created once when an attestation record is created. They are encrypted with the ingestion public key (HPKE) and stored in the database (`id_key_encrypted`, `auth_key_encrypted`). The plaintext keys are securely deleted after encryption. Key digests are computed from the plaintext keys before encryption and stored for lookup purposes.

- **VMK (Volume Master Key)**: Not stored in the database. Instead:
  - The VMK is sealed (encrypted) with the unsealing public key during image conversion
  - The sealed VMK blob is stored in the guest image at `/etc/snpguard/vmk.sealed`
  - During attestation, the client sends the sealed blob to the server
  - The server decrypts it using the unsealing private key (stored encrypted in DB)
  - The server then encrypts the VMK with an ephemeral session key and returns it to the client

## File Structure

```
artifacts/
└── {record-id}/
    ├── firmware-code.fd      # OVMF firmware
    ├── vmlinuz               # Kernel binary
    ├── initrd.img            # Initrd image
    ├── kernel-params.txt     # Kernel parameters
    ├── id-block.bin          # Generated ID-Block
    └── id-auth.bin           # Generated Auth-Block

Note: ID-Block and Auth-Block key files are deleted after encryption and storage in the database.
Keys are stored encrypted in the database (id_key_encrypted, auth_key_encrypted fields).
```

## Dependencies

### External Tools

- **snpguest**: Included as git submodule, built automatically, used
  only on server side to generate measurements and ID/Auth launch
  blocks

- **mksquashfs**: Required for SquashFS artifact generation

- **tar/gzip**: Required for tarball generation

- **libguestfs**: Required for the image conversion tool

- **qemu-img**: Required for the image conversion tool

## Performance Considerations

1. **Certificate Fetching**: AMD certificate fetching happens over the network and may add latency. Consider caching certificates.

2. **Report Verification**: Cryptographic verification is CPU-intensive. Consider rate limiting or async processing for high-volume deployments.

3. **Database**: SQLite is suitable for small to medium deployments. For larger scale, consider PostgreSQL or MySQL.

4. **File Storage**: Artifacts are stored on the filesystem. For distributed deployments, consider object storage (S3, etc.).
