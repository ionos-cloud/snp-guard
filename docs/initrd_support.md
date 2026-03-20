# Initrd Support: initramfs-tools

SnpGuard supports **initramfs-tools** (used by Ubuntu/Debian) for installing attestation hooks into guest VM images. Support for **dracut** (used by RedHat/CentOS/Fedora) is in progress and not yet implemented.

## Installation Method

The attestation hooks are automatically installed during the image conversion phase using `snpguard-image convert`. The conversion process:

1. Encrypts the root filesystem with LUKS2 (label: `snpguard-luks`)
2. Installs `cryptsetup-initramfs` package in the guest image
3. Writes `/etc/default/grub.d/90_snpguard.cfg` disabling UUID/PARTUUID in grub entries
4. Rewrites the root entry in `/etc/fstab` to `/dev/mapper/cryptroot`
5. Uploads the SnpGuard client binary and configuration files
6. Installs initramfs-tools hooks:
   - `hook.sh` → `/etc/initramfs-tools/hooks/snpguard` (installs client and config into initrd)
   - `attest-online.sh` or `attest-offline.sh` → `/etc/initramfs-tools/scripts/local-top/snpguard-attest`
7. Regenerates the initrd using `update-initramfs -u -k all`
8. Regenerates grub configuration using `update-grub`

The hooks are installed directly into the guest image filesystem, and the initrd is regenerated automatically. No manual repacking is required.

## initramfs-tools (Ubuntu, Debian)

### Hook Files

The image conversion installs two files:

1. **Hook Script** (`scripts/initramfs-tools/hook.sh`):
   - Installed at: `/etc/initramfs-tools/hooks/snpguard`
   - Purpose: Runs during initrd generation to include the SnpGuard client binary and configuration files
   - Includes: `snpguard-client` binary, identity public key, attestation URL, sealed VMK blob, and
     CA certificate (only present for self-signed / private CA deployments; omitted when the server
     uses a public CA since the client falls back to its built-in webpki root bundle)

2. **Attestation Script** (`scripts/initramfs-tools/attest-online.sh` or `attest-offline.sh`):
   - Installed at: `/etc/initramfs-tools/scripts/local-top/snpguard-attest`
   - Purpose: Runs during boot to perform attestation and unlock the encrypted root filesystem
   - Phase: `local-top` (after network initialization, before root mounting)
   - `attest-online.sh`: contacts the snpguard server on every boot (default)
   - `attest-offline.sh`: derives a hardware-bound key from the SEV-SNP chip for offline unlocking;
     falls back to online attestation on first boot or after chip migration

### Boot Phase

- **Phase**: `local-top`
- **Timing**: After network initialization, before root filesystem mounting
- **Purpose**: Ensures network is available for attestation, but runs before disk decryption

### Hook Behavior

The attestation script performs the following (online variant):

1. **Network Setup**: Ensures network is configured and routing is correct
2. **Record boot slot**: Writes `/.booted` symlink on the LAUNCH_ARTIFACTS partition
3. **Resolve root device**: Looks up the LUKS container via `/dev/disk/by-label/snpguard-luks`
4. **Perform Attestation**: Calls `/usr/bin/snpguard-client attest` with:
   - URL from `/etc/snpguard/attest.url`
   - CA certificate from `/etc/snpguard/ca.pem` if present (self-signed CA); otherwise the
     client uses its built-in webpki root bundle (public CA / platform TLS)
   - Sealed VMK blob from `/etc/snpguard/vmk.sealed`
5. **Unlock Root**: Uses the decrypted VMK to unlock the LUKS-encrypted root device via `cryptsetup luksOpen`
6. **Error Handling**: Drops to a shell if any step fails

The offline variant skips the network on subsequent boots by first trying a hardware-bound key
derived from the SEV-SNP chip (LUKS slot 1), and only falls back to the online flow when the
derived key does not match (first boot, chip migration).

### Supported Distributions

- Ubuntu (all versions)
- Debian (all versions)
- Linux Mint
- Other Debian-based distributions

## dracut (RedHat, CentOS, Fedora)

**Status**: Support for dracut is in progress and not yet implemented. Only initramfs-tools (Debian flavors) is currently supported.

When implemented, dracut support will:
- Install hooks at `lib/dracut/hooks/pre-mount/99-snpguard.sh`
- Run in the `pre-mount` phase (before root filesystem mounting)
- Support RedHat Enterprise Linux, CentOS, Fedora, Rocky Linux, AlmaLinux, and other RHEL-based distributions

## Boot Sequence

The complete boot sequence with SnpGuard attestation:

```
1. Kernel loads
2. Initrd starts
3. [SnpGuard Hook Runs Here] <- Attestation happens
   - Resolves LUKS root device via /dev/disk/by-label/snpguard-luks
   - (offline) Tries hardware-bound derived key from SEV-SNP chip (LUKS slot 1)
   - (online fallback) Network initialized, snpguard-client contacts server,
     receives decrypted VMK, unlocks LUKS root via cryptsetup luksOpen
4. Root filesystem mounting (/dev/mapper/cryptroot)
5. System boot continues
```

## Usage

The hooks are automatically installed when converting an image:

```bash
cargo run --bin snpguard-image convert \
  --in-image ./debian-13-genericcloud-amd64.qcow2 \
  --out-image confidential.qcow2 \
  --out-staging ./staging \
  --firmware ./OVMF.AMDSEV.fd
```

The conversion process will:
1. Encrypt the root filesystem
2. Install cryptsetup-initramfs
3. Install SnpGuard hooks
4. Regenerate the initrd with hooks included

No manual intervention is required.

## Verification

After image conversion, you can verify the hooks were installed by examining the staging directory:

```bash
# The converted initrd is in the staging directory
ls -la staging/initrd.img
```

The initrd contains:
- `/usr/bin/snpguard-client` (client binary)
- `/etc/snpguard/ca.pem` (CA certificate; only present for self-signed / private CA deployments)
- `/etc/snpguard/identity.pub` (server Ed25519 identity public key, used to verify renewal responses)
- `/etc/snpguard/attest.url` (attestation URL)
- `/etc/snpguard/vmk.sealed` (sealed VMK blob)
- The attestation script in `scripts/local-top/snpguard-attest`

## Troubleshooting

### Hook Not Running

1. **Check initrd was regenerated**: Verify `update-initramfs` ran successfully during conversion
2. **Check boot logs**: Look for "snpguard attest" messages in boot logs
3. **Verify configuration**: Ensure `/etc/snpguard/attest.url` contains the correct URL
4. **Network issues**: Ensure network is properly configured in initrd

### Attestation Fails

1. **Check network connectivity**: The guest VM must be able to reach the attestation server
2. **Verify CA certificate**: Ensure the CA certificate matches the server's certificate
3. **Check sealed blob**: Verify `vmk.sealed` was created correctly during conversion
4. **Review server logs**: Check attestation server logs for detailed error messages

### SEV-SNP Not Available

- The client requires direct access to SEV-SNP hardware via `/dev/sev-guest`
- Ensure the guest firmware supports SEV-SNP
- Ensure SEV-SNP is enabled in the hypervisor configuration
- The client will fail with a clear error if SEV-SNP is not available

## Differences Between Systems

| Feature | initramfs-tools | dracut |
|---------|----------------|--------|
| Status | Implemented | In progress |
| Hook location | `/etc/initramfs-tools/hooks/snpguard` | (not yet implemented) |
| Script location | `/etc/initramfs-tools/scripts/local-top/snpguard-attest` | (not yet implemented) |
| Boot phase | `local-top` | `pre-mount` (planned) |
| Supported distros | Debian, Ubuntu | (planned: RHEL, CentOS, Fedora) |

## Best Practices

1. **Use image conversion**: Always use `snpguard-image convert` to prepare images - it handles hook installation automatically
2. **Verify conversion**: Check that the staging directory contains all required artifacts
3. **Test before production**: Always test the converted image in a VM before deploying
4. **Network configuration**: Ensure network is properly configured in the guest image
5. **Backup original**: Keep a backup of the original image before conversion
