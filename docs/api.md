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

Get the server's public identity for TOFU (Trust On First Use) authentication and image conversion.
Returns the TLS CA certificate, the HPKE ingestion public key used to encrypt the unsealing private
key, and the Ed25519 identity public key used to sign artifacts delivered to guests.

**Request**: No body required

**Response** (200 OK):
- Content-Type: `application/json`
- Body: JSON object with:
  ```json
  {
    "ca_cert": "-----BEGIN CERTIFICATE-----\n...",
    "ingestion_pub_key": "-----BEGIN PUBLIC KEY-----\n...",
    "identity_pub_key": "-----BEGIN PUBLIC KEY-----\n..."
  }
  ```
  - `ca_cert`: TLS CA certificate (PEM). Used by clients to verify the server's TLS certificate.
  - `ingestion_pub_key`: X25519 HPKE public key (raw 32 bytes, non-standard PEM). Used to encrypt
    the unsealing private key before uploading it to the server during image registration.
  - `identity_pub_key`: Ed25519 public key (raw 32 bytes, non-standard PEM). Stable server signing
    key; to be baked into the guest initrd so the guest can verify artifacts received from the server
    without a separate network round-trip.

**Note**: This endpoint is public (no authentication required) and is used for TOFU during client
configuration. The CA certificate hash should be verified by the user before proceeding with
authentication.

**Error Responses**:
- `500 Internal Server Error`: Server error retrieving public information

**Example** (using curl):
```bash
# For self-signed certificates (development), use -k flag:
curl -k -X GET https://localhost:3000/v1/public/info --output public_info.json

# For production with valid certificates:
curl -X GET https://attest.example.com/v1/public/info --output public_info.json

# Or with a specific CA certificate:
curl --cacert ca.pem -X GET https://attest.example.com/v1/public/info --output public_info.json
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
5. Find attestation record by report.image_id, report.id_key_digest, report.auth_key_digest
6. Check if record is not disabled
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
- `GET/POST /v1/tokens`, `POST /v1/tokens/{id}/revoke`

**Note**: Attestation records are immutable. To make changes, delete the old record and create a new one.

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

**Response**: HTML page displaying record details (read-only)

**Note**: Attestation records are immutable. To make changes, delete this record and create a new one.

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

**Available Files**:
- `launch-config.json`: Launch configuration (vCPU model, count, guest policy)
- `id-block.bin`: ID-Block binary
- `id-auth.bin`: Auth-Block binary
- `firmware-code.fd`: Firmware image
- `vmlinuz`: Kernel binary
- `initrd.img`: Initrd image
- `kernel-params.txt`: Kernel parameters
- `artifacts.tar.gz`: Tarball with all files
- `artifacts.squashfs`: SquashFS image with all files

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

6. **Server Identity Key**: The server generates a stable Ed25519 signing keypair on first start and persists it at `/data/auth/identity.key` (private, PKCS#8 DER in PEM, mode 0400) and `/data/auth/identity.pub` (public, raw 32 bytes in PEM). The private key is used to sign artifacts sent to guests in RenewResponse messages. The public key is exposed via `GET /v1/public/info` and is meant to be baked into the guest initrd during image conversion, so the guest can verify artifact authenticity without trusting the network. Back up `identity.key` alongside `ingestion.key` - regenerating it would invalidate all previously prepared guest images.

5. **TOFU (Trust On First Use)**: Client configuration uses TOFU for secure server identity
   verification. During `config login`, the client fetches all three public values from
   `/v1/public/info` (CA cert, ingestion public key, identity public key), displays the CA
   certificate hash for user verification, and only proceeds after user confirmation. All three
   values are written to `~/.config/snpguard/` (ca.pem, ingestion.pub, identity.pub) and removed
   on `config logout`. This eliminates the need to manually provide CA certificates or public keys.

5. **Key Format**: All X25519 keys (unsealing and ingestion) use a non-standard PEM format (raw 32-byte keys wrapped in PEM). This is NOT standard PKCS#8 format. Standard tools like `openssl` may not recognize this format, but it works correctly with SnpGuard.
