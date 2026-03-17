# SnpGuard User Guide

## Quick Start

### 0. Clone Repository and Initialize Submodules

```bash
# Clone the repository
git clone <repository-url>
cd snp-guard

# Initialize and update git submodules (required for snpguest)
git submodule update --init --recursive
```

**Note**: The `snpguest` tool is included as a git submodule and must be initialized before building.

### 1. Build the Project

```bash
# Build everything (server, client, snpguest)
make build

# Or build separately
make build-server
make build-client
make build-image
make build-snpguest
```

### 2. Attestation Server & Web Dashboard

Generate TLS certificates:

```bash
./scripts/generate-tls-certs.sh --output data/tls --ip ${IP}
```

If a hostname should be used instead of `${IP}`, please provide the `--dns <HOSTNAME>` option instead of the `--ip` option. Multiple `--ip <IP>` or `--dns <HOSTNAME>` entries can be provided one after another.

Start the server. The server provides both the Attestation API and the Management Web UI.

```bash
make run-server
```

On first start, the server generates a master password and prints it to stdout. Copy it, then:

- Navigate to the Web Dashboard at `https://${HOSTNAME_OR_IP}:3000`
- Log in with the master password
- Go to `Tokens` to create an API token for your CLI client

### 3. Attestation Client Configuration

Configure the client to connect to the attestation server:

```bash
cargo run --bin snpguard-client config login \
  --url https://${HOSTNAME_OR_IP}:3000 \
  --token ${TOKEN}
```

This implements TOFU (Trust On First Use) - fetches server's public identity (CA cert, ingestion
public key, and identity public key) from `/v1/public/info`, displays CA cert hash for user
verification, validates token via `/v1/health` with the received CA cert, then stores URL/token, CA
cert, ingestion public key, and identity public key to `~/.config/snpguard/`.

### 4. Image Conversion (Prepare Guest VM)

Download a standard cloud image and convert it to a confidential-ready image. This process uses **qemu-img** and **libguestfs** to perform surgical, offline manipulation of the QCOW2 image, including root filesystem encryption (LUKS), partition management, and injecting the attestation agent into the initrd.

```bash
# Download latest Debian trixie
wget https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2

# Convert standard Debian to a confidential-ready Debian
cargo run --bin snpguard-image convert \
  --in-image ./debian-13-genericcloud-amd64.qcow2 \
  --out-image confidential.qcow2 \
  --out-staging ./staging \
  --firmware ./OVMF.AMDSEV.fd
```

**What the conversion does:**

1. Increase the target QCOW image and root filesystem partition sizes
1. Encrypts the target root filesystem with LUKS2
1. Generates a random Volume Master Key (VMK) for disk encryption
1. Generates an unsealing keypair internally (used to encrypt the VMK)
1. Encrypts the unsealing private key using the public SnpGuard server's ingestion key and places it in the staging directory
1. Encrypts (seals) the VMK with the unsealing public key
1. Uploads the sealed VMK into the guest image
1. Installs `cryptsetup-initramfs` in the guest image
1. Installs the SnpGuard client binary and configuration files (CA cert, identity public key, attestation URL, sealed VMK)
1. Installs initramfs-tools hooks (`hook.sh` and `attest-online.sh`)
1. Regenerates the initrd with hooks included
1. Extracts boot artifacts (kernel, initrd, kernel parameters, firmware) to the staging directory

**Prerequisites:**

- The client binary must be built: `make build-client`
- `libguestfs` and `qemu-img` must be installed on the system for the `convert` subcommand
- SEV-SNP must be enabled in the guest firmware and hardware
- The image must use initramfs-tools (Debian/Ubuntu) - dracut is not yet supported

**Notes:**

- To use AMD SEV-SNP technology, SEV-SNP must be enabled in guest kernels, which is verified by the image tool. For example, default Debian cloud images support SEV-SNP starting from the Trixie distribution (Debian 13). Ubuntu introduced SEV-SNP support starting from Ubuntu Noble (Ubuntu 22.04).
- The image tool requires `qemu-img` and `libguestfs` to be installed on the system for the `convert` subcommand to inspecet and modify the QCOW2 image.
- The image tool lists the available kernels and initrd images with their kernel parameters. By default, the GRUB default kernel is selected automatically; if no default is set in the GRUB configuration, the first SEV-SNP supported entry is used. Pass `--interactive` to be prompted to choose interactively instead.
- The OVMF firmware binary must include `SNP_KERNEL_HASHES`, which is achieved by the special AmdSevX64 build. Refer to [this guide](https://rouming.github.io/2025/04/01/coco-with-amd-sev.html#guest-ovmf-firmware) to build OVMF with `SNP_KERNEL_HASHES` enabled.
- For the image `convert` tool, if you've run `snpguard-client config login`, the attestation URL, ingestion public key, CA certificate, and identity public key will be read from the stored configuration. Otherwise, you must provide them via `--attest-url`, `--ingestion-public-key`, `--ca-cert`, and `--identity-pub` options.

**Offline Attestation Mode (`--offline-attestation`)**

By default the `convert` subcommand installs `attest-online.sh`, which contacts
the snpguard service on every boot to obtain the VMK and unlock the rootfs.
Pass `--offline-attestation` to install `attest-offline.sh` instead, which
implements a two-slot LUKS strategy that eliminates the network dependency from
steady-state boots:

| LUKS slot | Key | Unlocked by |
|-----------|-----|-------------|
| 0 | Sealed VMK | Online attestation (snpguard service) |
| 1 | Hardware-bound derived key | SEV-SNP chip (offline, no network) |

The hardware-bound key is produced by the AMD Secure Processor using
`snpguard-client derive-key` with the following fields mixed in:

| Flag | What it binds |
|------|---------------|
| `--mix-measurement` | Launch digest (OVMF + kernel + initrd + cmdline). Also implicitly covers `id_key_digest` and `author_key_digest`, because the signed ID block that produces those digests commits to the measurement. |
| `--mix-image-id` | UUID identifying the registered image. The server explicitly filters attestation records by `image_id`; this flag ensures the derived key is tied to the same registration. |
| `--mix-policy` | Guest launch policy bitmask (controls hypervisor capabilities: debug mode, live migration, SMT, etc.). A policy change invalidates the offline key and forces re-enrollment via online attestation. |
| `--vmpl 0` | Derives the key at VMPL 0, matching the server requirement that attestation reports must come from VMPL 0. |

The key can only be reproduced by an identical guest image running on the
same physical AMD chip under the same launch policy.

**Boot flow:**

1. The derived key is requested from the SEV-SNP chip (no network).
2. LUKS slot 1 is tried with the derived key.  If it matches, the rootfs is
   unlocked immediately and the boot continues — no network required.
3. On failure (first boot or chip migration), the network is brought up and
   online attestation is performed via the snpguard service (slot 0).
4. After a successful online attestation the derived key is enrolled into slot 1
   (replacing any stale key from a previous chip), so subsequent boots proceed
   offline.

**Network requirements:**

- **First boot**: network is required to perform the initial online attestation
  and enrol the derived key into slot 1.
- **Subsequent boots on the same chip**: fully offline, no network needed.
- **After chip migration** (VM moved to different AMD hardware): network is
  required once on the new chip to re-enrol the derived key.  The VCEK is
  chip-specific, so the derived key changes and slot 1 must be refreshed.
  Once re-enrolled, subsequent boots on the new chip are again offline.

```bash
# Convert with offline attestation support
cargo run --bin snpguard-image convert \
  --in-image ./debian-13-genericcloud-amd64.qcow2 \
  --out-image confidential.qcow2 \
  --out-staging ./staging \
  --firmware ./OVMF.AMDSEV.fd \
  --offline-attestation
```

**Staging Directory Contents:**

After conversion, the staging directory (`./staging`) contains:
- `firmware-code.fd`: OVMF firmware binary
- `vmlinuz`: Kernel binary
- `initrd.img`: Repacked initrd with SnpGuard client and hooks
- `kernel-params.txt`: Kernel command-line parameters
- `vmk.sealed`: Sealed VMK blob (encrypted with unsealing public key)
- `unsealing.key.enc`: Encrypted unsealing private key (encrypted with the SnpGuard's server ingestion public key)

### 5. Register Attestation Record

Register the new image with the server. This uploads the measurements and the encrypted key, and returns the signed launch artifacts.

```bash
cargo run --bin snpguard-client manage register \
  --os-name Debian13-CVM \
  --vcpus 4 --vcpu-type EPYC-Milan \
  --allowed-smt \
  --min-tcb-bootloader 0 --min-tcb-tee 0 --min-tcb-snp 0 --min-tcb-microcode 0 \
  --staging-dir ./staging \
  --out-bundle ./launch-artifacts.tar.gz
```

**What registration does:**

1. Reads boot artifacts from the staging directory (or individual files if provided)
2. Generates random ID-Block and Auth-Block keys (secp384r1 EC keys) on the server
3. Generates measurements using `snpguest` with the firmware, kernel, initrd, and kernel parameters
4. Creates ID-Block and Auth-Block using the generated keys
5. Computes key digests for lookup
6. Encrypts ID and Auth keys with the ingestion public key (HPKE) and stores in database
7. Stores the encrypted unsealing private key (from `unsealing.key.enc` if using staging directory)
8. Generates a random 16-byte image-id for the attestation record
9. Stores the record in the database
10. Exports launch artifacts bundle (if `--out-bundle` is provided)

**Using staging directory (recommended):**

When using `--staging-dir`, the command expects:
- `firmware-code.fd`: Firmware binary
- `vmlinuz`: Kernel binary
- `initrd.img`: Initrd image
- `kernel-params.txt`: Kernel parameters
- `unsealing.key.enc`: Encrypted unsealing private key (optional, generated during conversion)

**Using individual files:**

Alternatively, you can provide individual files:

```bash
cargo run --bin snpguard-client manage register \
  --os-name Ubuntu22.04 \
  --enc-unsealing-private-key ./staging/unsealing.key.enc \
  --firmware ./staging/firmware-code.fd \
  --kernel ./staging/vmlinuz \
  --initrd ./staging/initrd.img \
  --kernel-params "$(cat ./staging/kernel-params.txt)" \
  --vcpus 4 --vcpu-type EPYC \
  --out-bundle ./launch-artifacts.tar.gz
```

**Options:**

- `--os-name <NAME>`: Descriptive name for the OS/VM (required)
- `--staging-dir <PATH>`: Directory generated by `snpguard-image convert --out-staging` (expects: `firmware-code.fd`, `vmlinuz`, `initrd.img`, `kernel-params.txt`, optionally `unsealing.key.enc`)
- `--enc-unsealing-private-key <PATH>`: Encrypted unsealing private key (required if not using staging directory)
- `--firmware <PATH>`, `--kernel <PATH>`, `--initrd <PATH>`, `--kernel-params <STRING>`: Override individual files from staging directory
- `--vcpus <N>`: Number of virtual CPUs (default: `4`)
- `--vcpu-type <TYPE>`: EPYC variant: `EPYC`, `EPYC-Milan`, `EPYC-Rome`, or `EPYC-Genoa` (default: `EPYC`)
- `--allowed-debug`: Allow debug mode (default: `false`)
- `--allowed-migrate-ma`: Allow migration with MA (default: `false`)
- `--allowed-smt`: Allow Simultaneous Multithreading (default: `false`)
- `--min-tcb-bootloader <N>`, `--min-tcb-tee <N>`, `--min-tcb-snp <N>`, `--min-tcb-microcode <N>`: Minimum TCB versions (default: `0`)
- `--disable`: Disable the record after creation (default: `false`)
- `--out-bundle <PATH>`: Export artifacts bundle after registration (same format as `manage export`)

You can now view this registered image and its measurements in the Web Dashboard.

### 6. (Optional) Embed Launch Artifacts

Optionally, you can embed the launch artifacts bundle into the confidential image.
This creates a dedicated partition with the label `LAUNCH_ARTIFACTS` containing the boot
artifacts (kernel, initrd, ID-Block, Auth-Block) in an A/B directory structure.

```bash
cargo run --bin snpguard-image embed \
  --image ./confidential.qcow2 \
  --in-bundle ./launch-artifacts.tar.gz
```

**What the embed command does:**

1. Checks for an existing partition with the `LAUNCH_ARTIFACTS` filesystem label
2. If missing, creates a new 512MB partition, formats it as ext4, and sets the label
3. Wipes the partition content (idempotent operation - safe to run multiple times)
4. Extracts the bundle contents into `/A` directory
5. Creates `/B` directory for future updates
6. Creates symlink `/artifacts -> A` pointing to the active artifacts

The A/B structure enables atomic artifact updates: new attested artifacts are written to the inactive directory (e.g., `/B`), then the symlink is atomically switched to point to the new directory. On the next VM poweroff/poweron cycle, the new artifacts will be used.

**Prerequisites:**

- `libguestfs` and `qemu-img` must be installed on the system
- The image must have been converted using `snpguard-image convert`
- The launch artifacts bundle must have been generated using `snpguard-client manage register --out-bundle`

**Notes:**

- The embed command is idempotent - you can run it multiple times safely
- The partition is identified by filesystem label, not GPT partition label (works even if GPT labels are stripped)
- Supports both `.tar` and `.tar.gz` bundle formats
- The A/B directory structure enables atomic artifact updates: new artifacts are written to the inactive directory, then the symlink is atomically switched. The new artifacts take effect on the next VM reboot.
- **This step is optional** - you can still provide artifacts externally when launching the VM using the `--artifacts` parameter

### 7. Run CVM

Launch the confidential VM on the platform using the secured disk and
the signed artifacts:

```bash
sudo ./scripts/launch-qemu-snp.sh \
  --hda confidential.qcow2 \
  --artifacts launch-artifacts.tar.gz
```

The launch script automatically reads the `launch-config.json` file from the artifacts bundle and enforces the correct vCPU count, vCPU model, and guest policy. These parameters must match exactly for VM to be launched.

Upon boot, the VM will verify itself against the server, receive the key, unlock the disk, and boot the OS.

## Managing Attestation Records

### Viewing Records

Use the CLI to list and view records:

```bash
# List all records
cargo run --bin snpguard-client manage list

# List with JSON output
cargo run --bin snpguard-client manage list --json

# Show record details
cargo run --bin snpguard-client manage show <record-id>

# Show with JSON output
cargo run --bin snpguard-client manage show <record-id> --json
```

Alternatively, use the Web Dashboard at `https://${HOSTNAME_OR_IP}:3000` to view records with:
- **Status**: Active (green) or Disabled (gray)
- **OS Name**: Click to view details
- **Requests**: Number of successful attestations
- **Actions**: View or Delete

### Enabling/Disabling Records

```bash
# Disable a record
cargo run --bin snpguard-client manage disable <record-id>

# Enable a record
cargo run --bin snpguard-client manage enable <record-id>
```

Disabled records will cause attestation requests to fail, but the record remains in the database.

### Exporting Artifacts

Export launch artifacts bundle:

```bash
cargo run --bin snpguard-client manage export \
  --id <record-id> \
  --format tar \
  --out-bundle artifacts.tar.gz
```

Formats: `tar`, `squash`, or `squashfs` (default: `tar`)

**Bundle Contents:**
- `launch-config.json`: Launch configuration (vCPU model, count, guest policy)
- `firmware-code.fd`: Firmware binary
- `vmlinuz`: Kernel binary
- `initrd.img`: Initrd image
- `kernel-params.txt`: Kernel command-line parameters
- `id-block.bin`: ID-Block binary
- `id-auth.bin`: Auth-Block binary

### Deleting Records

```bash
cargo run --bin snpguard-client manage delete <record-id>
```

This permanently removes the record and all associated artifacts.

**Note**: To update boot artifacts (kernel, initrd, firmware, kernel parameters) on a running VM,
use the renewal flow (`snpguard-client attest renew`) instead of deleting and re-creating the record.
Deletion is permanent and removes all associated artifacts.

## Using the Client

### Configuration Commands

- `config login --url <URL> --token <TOKEN>`: Store management token (TOFU - Trust On First Use)
  - Fetches server's public identity (CA cert, ingestion public key, identity public key) from `/v1/public/info`
  - Displays CA cert hash for user verification
  - Validates token via `/v1/health` with the received CA cert
  - Stores URL/token, CA cert, ingestion public key, and identity public key to `~/.config/snpguard/`

- `config logout`: Remove all stored configuration files (token, URL, CA cert, ingestion public key, identity public key)

### Attestation Command

- `attest --url <URL> [--ca-cert <PATH>] [--sealed-blob <PATH>]`: Perform attestation and output decrypted VMK in hex format to stdout
  - `--url`: Attestation server URL (required)
  - `--ca-cert`: Path to CA certificate (optional, defaults to `/etc/snpguard/ca.pem`)
  - `--sealed-blob`: Path to sealed VMK blob (optional, if not provided reads from `/etc/snpguard/vmk.sealed`)

**Note**: This command is typically used by the initrd hook during boot, not manually.

### Management Commands

- `manage list [--json]`: List all attestation records (RENEWAL column shows pending status)
- `manage show <id> [--json]`: Show details of a specific attestation record (prints pending-since when a renewal is in flight)
- `manage enable <id>`: Enable an attestation record
- `manage disable <id>`: Disable an attestation record
- `manage delete <id>`: Delete an attestation record and all associated artifacts
- `manage discard-pending <id>`: Cancel a pending renewal (clears the pending record)
- `manage export --id <id> --format <tar|squash|squashfs> --out-bundle <PATH>`: Export current artifacts bundle
- `manage register`: Register a new attestation record (see section 5 above for details)

All management commands use stored config by default (from `config login`), or provide `--url` and `--ca-cert` to override.

## Troubleshooting

### Client Connection Issues

**Problem**: Client fails to connect to server

**Solutions**:
- Verify the URL is correct and uses HTTPS
- Check network connectivity from the guest VM
- Ensure TLS certificate is valid
- Check server logs for errors

### Attestation Fails

**Problem**: Attestation verification fails

**Solutions**:
1. **Check Nonce Validity**:
   - Ensure the nonce was received from the server (not reused or expired)
   - Ensure the nonce used within 60 seconds of generation
   - Check server logs for nonce verification errors
2. **Check Binding Hash**:
   - Ensure the binding hash (SHA512(server_nonce || client_pub_bytes)) matches the report_data field
   - Verify the client is using the correct server_nonce and client_pub_bytes
3. **Check Record Status**: Ensure the attestation record is enabled
4. **Verify Key Digests**: The ID-Block and Auth-Block key digests must match those stored in the record (keys are generated by the server)
5. **Check CPU Family**: Ensure the vCPU type matches your actual CPU
6. **Review Server Logs**: Check for detailed error messages
7. **Verify Report**: Ensure `snpguest` is generating valid reports

### Report Verification Fails

**Problem**: Server cannot verify the attestation report

**Solutions**:
- The server uses the integrated `snpguest` binary built from the submodule
- Check network connectivity to AMD KDS (for certificate fetching)
- Verify the attestation report is not corrupted
- Check that the CPU family detection is correct
- Ensure the snpguest binary was built successfully: `make build-snpguest`

### File Upload Issues

**Problem**: File upload fails or is rejected

**Solutions**:
- Check file size limits:
  - Firmware: <50 MB
  - Kernel: <50 MB
  - Initrd: <150 MB
- Ensure files are in the correct format
- Check server disk space

### Image Conversion Issues

**Problem**: Image conversion fails or hooks are not installed

**Solutions**:
- Ensure the source image uses initramfs-tools (Debian/Ubuntu) - dracut is not yet supported
- Verify the client binary is built: `make build-client`
- Check that `libguestfs` is installed on the system
- Check that `cryptsetup-initramfs` can be installed in the guest image
- Verify network access during conversion (needed to install packages)
- Check conversion logs for errors during hook installation
- Verify the staging directory contains all required artifacts after conversion
- Ensure the converted initrd includes the SnpGuard client and hooks
- Test the converted image in a VM before production use
- Check boot logs for hook execution messages

## Advanced Usage

### Using snpguard-image Tool

The `snpguard-image` tool provides utilities for managing keys and converting VM images:

#### Key Generation (Internal Use)

The `keygen` command is used internally by the `convert` command to generate unsealing keypairs. You typically don't need to use it manually, but it's available for advanced use cases:

- `keygen [--priv-out <PATH>] [--pub-out <PATH>]`: Generate X25519 unsealing keypair
  - `--priv-out`: Output path for private key (default: `unsealing.key`)
  - `--pub-out`: Output path for public key (default: `unsealing.pub`)

**Note**: Keys generated by `snpguard-image keygen` use a non-standard PEM format (raw 32-byte keys wrapped in PEM). This is NOT standard PKCS#8 format. Standard tools like `openssl` may not recognize this format, but it works correctly with SnpGuard.

#### Sealing and Unsealing

- `seal --pub-key <PATH> --data <PATH> --out <PATH>`: Seal a file (e.g., VMK) with a public key
  - `--pub-key`: Path to unsealing public key
  - `--data`: Path to plaintext file to seal
  - `--out`: Output path for sealed blob

- `unseal --priv-key <PATH> --sealed-data <PATH> --out <PATH>`: Unseal a sealed blob
  - `--priv-key`: Path to unsealing private key
  - `--sealed-data`: Path to sealed blob
  - `--out`: Output path for unsealed data

#### Image Conversion

- `convert --in-image <PATH> --out-image <PATH> --out-staging <PATH> --firmware <PATH> [--attest-url <URL>] [--ingestion-public-key <PATH>] [--ca-cert <PATH>] [--identity-pub <PATH>]`: Convert QCOW2 image to confidential-ready image
  - `--in-image`: Input QCOW2 image path (required)
  - `--out-image`: Output QCOW2 image path (required)
  - `--out-staging`: Staging directory for temporary files (required)
  - `--firmware`: Path to OVMF firmware binary (required)
  - `--attest-url`: Attestation URL (optional, uses config from `snpguard-client config login` if not provided)
  - `--ingestion-public-key`: Path to ingestion public key (optional, uses config if not provided)
  - `--ca-cert`: Path to CA certificate (optional, uses config if not provided)
  - `--identity-pub`: Path to server Ed25519 identity public key (optional, uses config if not provided); baked into the initrd as `/etc/snpguard/identity.pub` so the guest can verify renewal responses

#### Embedding Launch Artifacts

- `embed --image <PATH> --in-bundle <PATH>`: Embed launch artifacts bundle into QCOW2 image
  - `--image`: Path to the QCOW2 image file (required)
  - `--in-bundle`: Path to the tar.gz bundle containing boot artifacts (required)
  
  Creates or updates a dedicated partition with the `LAUNCH_ARTIFACTS` filesystem label containing the boot artifacts in an A/B directory structure. The command is idempotent and can be run multiple times safely.

### API Integration

You can integrate the attestation API into your own tools. See `docs/api.md` for details.

### Environment Variables

- `DATA_DIR`: Root persistence directory (default: `/data`)

## Getting Help

- **Documentation**: See `docs/` directory for detailed documentation
