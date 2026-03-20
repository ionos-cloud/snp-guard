# SnpGuard API Documentation

## Overview

SnpGuard provides two main API interfaces:

1. **Attestation API**: Used by guest VMs to perform attestation (HTTPS + Protobuf, REST)
2. **Management API**: Used by the web UI/automation for managing attestation records (HTTPS + Protobuf/JSON)

## Attestation API

The Attestation API uses HTTPS with Protocol Buffers for secure, efficient communication.

### Base URL

```
https://your-attestation-service.com
```

### Content-Type

All attestation endpoints use:
```
Content-Type: application/x-protobuf
```

### Endpoints

#### GET `/v1/public/info`

Get the server's public keys for image conversion and TOFU (Trust On First Use) authentication.
Returns the HPKE ingestion public key used to encrypt the unsealing private key, and the Ed25519
identity public key used to sign artifacts delivered to guests.

**Note**: The TLS CA certificate is no longer part of this response.  During `config login` the
client captures the server's TLS certificate chain directly from the TLS handshake (TOFU), so the
CA does not need to travel over an unauthenticated REST call.

**Request**: No body required

**Response** (200 OK):
- Content-Type: `application/json`
- Body: JSON object with:
  ```json
  {
    "ingestion_pub_key": "-----BEGIN PUBLIC KEY-----\n...",
    "identity_pub_key": "-----BEGIN PUBLIC KEY-----\n..."
  }
  ```
  - `ingestion_pub_key`: X25519 HPKE public key (raw 32 bytes, non-standard PEM). Used to encrypt
    the unsealing private key before uploading it to the server during image registration.
  - `identity_pub_key`: Ed25519 public key (raw 32 bytes, non-standard PEM). Stable server signing
    key; to be baked into the guest initrd so the guest can verify artifacts received from the server
    without a separate network round-trip.

**Authentication**: Not required.

**Error Responses**:
- `500 Internal Server Error`: Server error retrieving public information

**Example** (using curl):
```bash
# Self-signed CA (ca.pem stored by config login):
curl --cacert ~/.config/snpguard/ca.pem -X GET https://localhost:3000/v1/public/info

# Public CA (platform TLS, e.g. fly.io -- no ca.pem needed):
curl -X GET https://my-server.fly.dev/v1/public/info
```

#### POST `/v1/attest/nonce`

Request a random 64-byte nonce for attestation report generation.

**Request**:
```protobuf
message NonceRequest {}
```

**Response** (200 OK):
```protobuf
message NonceResponse {
  bytes nonce = 1;  // Exactly 64 bytes of random data
}
```

**Error Responses**:
- `400 Bad Request`: Invalid protobuf message
- `500 Internal Server Error`: Server error generating nonce

#### POST `/v1/attest/renew`

Request a renewal of the current attestation record from inside a running VM.  The VM provides
its SNP attestation report (binding the renewal request payload) and any artifacts it wants to
update.  Fields not provided are inherited from the current record on the server.

**Request**:
```protobuf
message RenewRequest {
  bytes report_data = 1;   // SEV-SNP attestation report (binary)
  bytes payload_bytes = 2; // Pre-serialized RenewRequestPayload (see below)
}

// Serialized into RenewRequest.payload_bytes; all fields are hardware-signed.
message RenewRequestPayload {
  bytes server_nonce = 1;           // Server nonce (64 bytes); proves freshness
  bytes client_nonce = 2;           // Client nonce (64 bytes); prevents response replay
  optional bytes firmware = 3;      // New firmware (omit to inherit current)
  optional bytes kernel = 4;        // New kernel (omit to inherit current)
  optional bytes initrd = 5;        // New initrd (omit to inherit current)
  optional string kernel_params = 6; // New kernel parameters (omit to inherit current)
}
```

**Binding protocol**: `report_data` must equal `SHA512(payload_bytes)` where `payload_bytes` is
the pre-serialized `RenewRequestPayload`.  All fields -- nonces and optional artifacts -- are
covered by the SNP hardware signature.

**Response** (200 OK):
```protobuf
message RenewResponse {
  bool success = 1;
  optional string error_message = 2;
  optional bytes signature = 3;    // Ed25519 over payload_bytes; verify BEFORE deserializing
  optional bytes payload_bytes = 4; // Pre-serialized RenewResponsePayload
}

// Serialized into RenewResponse.payload_bytes; covered by the Ed25519 signature.
message RenewResponsePayload {
  string id = 1;                    // UUID of the newly created pending record
  bytes client_nonce = 2;           // Echoed from RenewRequestPayload
  repeated ArtifactEntry artifacts = 3; // Server-generated artifacts (id-block, auth-block, etc.)
}
```

On success the server creates a pending attestation record with a fresh `image_id`, sets
`vm_registration.pending_record_id`, signs the response payload with the server Ed25519 identity
key, and returns the pending record UUID and the server-generated artifacts.

The pending record is promoted to current automatically on the next successful attestation
that presents the new `image_id`.

**Validation** (in order):
1. Validate `server_nonce` length (64 bytes) in `RenewRequestPayload`
2. Parse SNP report
3. Verify nonce freshness (60-second window)
4. Verify binding hash: `SHA512(payload_bytes) == report_data`
5. Verify VMPL == 0
6. Two-step record lookup (same as `/v1/attest/report`)
7. Check registration is enabled and has no existing pending record
8. Verify report signature
9. Create pending record, sign response payload with Ed25519, return `id` + `artifacts`

**Error Responses**:
- `400 Bad Request`: Invalid protobuf message
- `500 Internal Server Error`: Server error

#### POST `/v1/attest/report`

Verify an attestation report, unseal VMK from sealed blob, and return session-encrypted VMK if successful.

**Note**: The client outputs the decrypted VMK in hex format (not raw bytes) to stdout.

**Request**:
```protobuf
message AttestationRequest {
  bytes report_data = 1;           // SEV-SNP attestation report (binary, 1184 bytes)
  bytes server_nonce = 2;           // Server nonce (64 bytes) used for binding
  bytes client_pub_bytes = 3;       // X25519 Session Public Key (32 bytes)
  bytes sealed_blob = 4;           // HPKE-encrypted VMK blob [Encapped_Key (32 bytes) || Ciphertext]
}
```

**Response** (200 OK):
```protobuf
message AttestationResponse {
  bool success = 1;                // true if attestation passed
  bytes encapped_key = 2;           // HPKE Encapsulated Key (32 bytes) - Server Ephemeral Pub
  bytes ciphertext = 3;             // Session-encrypted VMK (HPKE ciphertext)
  string error_message = 4;         // Error description (if !success)
}
```

**Verification Process** (in order):

1. Validate request fields (server_nonce: 64 bytes, client_pub_bytes: 32 bytes, sealed_blob: >= 32 bytes)
2. Parse report with sev call from bytes
3. Verify the stateless nonce from the report.report_data - ensure it is signed by , signed with an ephemeral secret, and has not expired within 60 seconds.
4. Verify hash binding - SHA512(server_nonce || client_pub_bytes) must match report.report_data (64 bytes)
5. Two-step record lookup:
   a. Find vm_registration by report.id_key_digest + report.auth_key_digest (stable VM identity)
   b. Find attestation_record by report.image_id + registration_id (specific artifact snapshot)
6. Check if registration is not disabled
7. Check TCB (bootloader, TEE, SNP, microcode versions meet minimum requirements)
8. Check VMPL (must be 0 for kernel level)
9. Verify report certs (verify report signature using integrated `snpguest` which fetches AMD certificates from KDS)
10. Reencrypt sealed blob (unseal VMK using unsealing private key, reseal for client session)
11. Return success with encapped_key and ciphertext if all checks pass

**Security Notes**:
- Nonce verification ensures the nonce was legitimately issued by the server before validating the binding hash
- The binding hash binds the attestation report to the specific session, preventing replay attacks
- Both verifications must pass for attestation to proceed

**Error Responses**:
- `400 Bad Request`: Invalid protobuf message or report too short
- `500 Internal Server Error`: Server error during verification

## Management API (HTTPS)

Authentication:
- Master password (Diceware, printed once, Argon2 hash stored)
- Bearer tokens for automation (create/revoke via web UI Tokens page)

Endpoints (protobuf payloads, `application/x-protobuf`):
- `GET/POST /v1/records` (list/create)
- `GET/DELETE /v1/records/{id}` (view/delete)
- `POST /v1/records/{id}/enable`, `/disable`
- `POST /v1/records/{id}/discard-pending` -- cancel a pending renewal before the VM is relaunched
- `GET /v1/records/{id}/export/tar[?pending=true]` -- download artifacts as tar.gz (pending flag serves the in-flight renewal artifacts)
- `GET /v1/records/{id}/export/squash[?pending=true]` -- download artifacts as squashfs
- `GET/POST /v1/tokens`, `POST /v1/tokens/{id}/revoke`

**Renewal**: A running VM can update its kernel, initrd, firmware, or kernel parameters without
re-registering.  Use `POST /v1/attest/renew` (public endpoint, authenticated via SNP report).
The server creates a pending attestation record; the pending record is promoted to current
automatically on the next successful attestation using the new image_id.  To cancel a pending
renewal before the VM is relaunched, use `POST /v1/records/{id}/discard-pending`.

**Note**: Management records are immutable via the management API. Use the renewal flow for
in-place artifact updates on running VMs.

### Endpoints

#### GET `/`

List all attestation records.

**Response**: HTML page with table of records

#### GET `/create`

Display form for creating a new attestation record.

**Response**: HTML form

#### POST `/create`

Create a new attestation record.

**Request**: `multipart/form-data` with:
- `os_name` (text): Name of the OS/VM
- `unsealing_private_key` (text): Unsealing private key (non-standard PEM format - raw 32-byte key wrapped in PEM, NOT PKCS#8, will be encrypted with the server ingestion key)
- `firmware` (file): Firmware image (<50 MB)
- `kernel` (file): Kernel binary (<50 MB)
- `initrd` (file): Initrd image (<150 MB)
- `kernel_params` (text): Kernel command-line parameters
- `vcpus` (text): Number of vCPUs
- `vcpu_type` (text): EPYC, EPYC-Milan, EPYC-Rome, or EPYC-Genoa

**Note**: ID Block Key and Auth Block Key are now automatically generated by the server.

**Response**: Redirect to `/` on success, error page on failure

#### GET `/view/:id`

View an attestation record (read-only).

**Parameters**:
- `id`: UUID of the attestation record

**Response**: HTML page displaying record details.  When a renewal is in flight the page shows
an amber banner with the pending-since timestamp, a pending artifacts section with download
links, and a Discard Pending button.

**Note**: Boot artifacts (kernel, initrd, firmware, kernel parameters) are updated via the
renewal flow (`snpguard-client attest renew` from inside the running VM), not by editing records
directly.  To replace a record entirely, delete it and create a new one.

#### POST `/toggle/:id`

Toggle enabled/disabled status of an attestation record.

**Response**: Redirect to `/`

#### GET `/delete/:id`

Delete an attestation record.

**Response**: Redirect to `/`

#### GET `/download/:id/:file`

Download an artifact file.

**Parameters**:
- `id`: UUID of the attestation record
- `file`: Filename to download

**Query parameters**:
- `pending=true`: Serve the file from the pending renewal artifact directory instead of the
  current one.  Returns an error if no renewal is in flight for this record.

**Available Files**:
- `launch-config.json`: Launch configuration (vCPU model, count, guest policy)
- `id-block.bin`: ID-Block binary
- `id-auth.bin`: Auth-Block binary
- `firmware-code.fd`: Firmware image
- `vmlinuz`: Kernel binary
- `initrd.img`: Initrd image
- `kernel-params.txt`: Kernel parameters
- `artifacts.tar.gz`: Tarball with all files (regenerated on every request)
- `artifacts.squashfs`: SquashFS image with all files (regenerated on every request)

**Response**: Binary file download

## Protocol Buffer Definitions

See `protos/attestation.proto` for the complete protobuf schema.

## Error Handling

All endpoints return appropriate HTTP status codes:
- `200 OK`: Success
- `400 Bad Request`: Invalid request
- `401 Unauthorized`: Authentication required (management endpoints)
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server error

Error messages in protobuf responses are human-readable strings.

## Rate Limiting

Currently, there is no rate limiting implemented. Consider adding rate limiting for production deployments.

## Security Considerations

1. **TLS**: Always use HTTPS in production. The attestation API requires TLS certificate verification.

2. **Authentication**: Use strong passwords for the management API. Consider implementing additional security measures (2FA, IP whitelisting) for production.

3. **Input Validation**: All file uploads are validated for size limits. File paths are sanitized to prevent directory traversal.

4. **Key Encryption**: ID-Block keys, Auth-Block keys, and unsealing private keys are all encrypted with HPKE (Hybrid Public Key Encryption) using X25519HkdfSha256, HkdfSha256, and AesGcm256 before storage. The ingestion private key (`/data/auth/ingestion.key`) must be backed up securely - if lost, encrypted keys cannot be recovered. The ingestion public key is available via `GET /v1/public/info` for TOFU and client-side encryption. ID and Auth key files are deleted from the artifacts folder after encryption and storage in the database.

5. **Server Identity Key**: The server generates a stable Ed25519 signing keypair on first start and persists it at `/data/auth/identity.key` (private, PKCS#8 DER in PEM, mode 0400) and `/data/auth/identity.pub` (public, raw 32 bytes in PEM). The private key is used to sign artifacts sent to guests in RenewResponse messages. The public key is exposed via `GET /v1/public/info` and is meant to be baked into the guest initrd during image conversion, so the guest can verify artifact authenticity without trusting the network. Back up `identity.key` alongside `ingestion.key` - regenerating it would invalidate all previously prepared guest images.

6. **TOFU (Trust On First Use)**: During `config login`, the client makes a raw TLS connection to
   the server and captures the certificate chain from the handshake.  A second connection verifies
   the chain against the built-in Mozilla/webpki root bundle to determine the trust mode:

   - **Public CA** (platform-managed TLS, e.g. fly.io with Let's Encrypt): no CA is pinned or
     stored.  All connections use the built-in root bundle.  Only `ingestion.pub` and `identity.pub`
     are written to `~/.config/snpguard/`.
   - **Self-signed / private CA**: the CA portion of the chain is pinned and written as `ca.pem`.
     All connections verify against this file.  `ca.pem`, `ingestion.pub`, and `identity.pub` are
     written to `~/.config/snpguard/`.

   In both cases the user is shown fingerprints to verify out-of-band before confirmation.  All
   stored values are removed on `config logout`.

7. **Key Format**: All X25519 keys (unsealing and ingestion) use a non-standard PEM format (raw 32-byte keys wrapped in PEM). This is NOT standard PKCS#8 format. Standard tools like `openssl` may not recognize this format, but it works correctly with SnpGuard.
