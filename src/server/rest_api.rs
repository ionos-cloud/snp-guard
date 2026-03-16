use std::sync::Arc;

use crate::{auth, MAX_BODY_BYTES};
use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use prost::Message;

use crate::master_password::MasterAuth;
use crate::nonce;
use crate::service_core::ServiceState;
use common::snpguard::{
    AttestationRequest, CreateRecordRequest, CreateRecordResponse, DeleteRecordResponse,
    GetRecordResponse, ListRecordsResponse, NonceRequest, NonceResponse, RenewRequest,
    ToggleEnabledRequest, ToggleEnabledResponse,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const PROTO_CT: &str = "application/x-protobuf";

/// Validates that the string is a valid UUID (prevents path traversal via `..` in id).
fn is_valid_record_or_token_id(id: &str) -> bool {
    Uuid::parse_str(id).is_ok()
}

pub fn router(state: Arc<ServiceState>, master: Arc<MasterAuth>) -> Router {
    let auth_ctx = AuthCtx {
        state: state.clone(),
        master,
    };
    let public = Router::new()
        .route("/health", get(health))
        .route("/public/info", get(get_public_info))
        .route("/attest/nonce", post(attest_nonce))
        .route("/attest/report", post(attest_report))
        .route("/attest/renew", post(attest_renew))
        .with_state(state.clone());

    let management = Router::new()
        .route("/records", get(list_records).post(create_record))
        .route("/records/:id", get(get_record).delete(delete_record))
        .route("/records/:id/enable", post(enable_record))
        .route("/records/:id/disable", post(disable_record))
        .route("/records/:id/export/tar", get(export_tar))
        .route("/records/:id/export/squash", get(export_squash))
        .route("/tokens", get(list_tokens).post(create_token))
        .route("/tokens/:id/revoke", post(revoke_token))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            auth_ctx,
            management_auth,
        ));

    public
        .merge(management)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

#[derive(Serialize, Deserialize)]
struct PublicInfo {
    ca_cert: String,
    ingestion_pub_key: String,
    identity_pub_key: String,
}

async fn get_public_info(State(state): State<Arc<ServiceState>>) -> Response {
    // Read CA certificate
    let ca_cert = match std::fs::read_to_string(&state.data_paths.ca_cert) {
        Ok(cert) => cert,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"error":"Failed to read CA certificate: {}"}}"#,
                    e
                )))
                .unwrap();
        }
    };

    // Get ingestion public key
    let ingestion_pub_key = match state.ingestion_keys.get_public_key_pem() {
        Ok(pem) => pem,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"error":"Failed to get ingestion public key: {}"}}"#,
                    e
                )))
                .unwrap();
        }
    };

    // Get identity public key (Ed25519; to be baked into guest initrd)
    let identity_pub_key = match state.identity_key.get_public_key_pem() {
        Ok(pem) => pem,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"error":"Failed to get identity public key: {}"}}"#,
                    e
                )))
                .unwrap();
        }
    };

    let info = PublicInfo {
        ca_cert,
        ingestion_pub_key,
        identity_pub_key,
    };

    match serde_json::to_string(&info) {
        Ok(json) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Body::from(json))
            .unwrap(),
        Err(e) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("Content-Type", "application/json")
            .body(Body::from(format!(
                r#"{{"error":"Failed to serialize response: {}"}}"#,
                e
            )))
            .unwrap(),
    }
}

async fn health(State(state): State<Arc<ServiceState>>, headers: HeaderMap) -> Response {
    if let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            match crate::service_core::auth_token_valid(&state, token).await {
                Ok(true) => return StatusCode::OK.into_response(),
                Ok(false) | Err(_) => {
                    return proto_error(StatusCode::UNAUTHORIZED, "unauthorized");
                }
            }
        }
    }
    StatusCode::OK.into_response()
}

fn proto_response<M: Message>(msg: M) -> Response {
    let mut buf = Vec::new();
    msg.encode(&mut buf).expect("encode");
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", HeaderValue::from_static(PROTO_CT))
        .body(Body::from(buf))
        .unwrap()
}

fn proto_error(status: StatusCode, msg: &str) -> Response {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Body::from(msg.to_string()))
        .unwrap()
}

fn auth_header_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

#[derive(Clone)]
struct AuthCtx {
    state: Arc<ServiceState>,
    master: Arc<MasterAuth>,
}

async fn management_auth(
    State(ctx): State<AuthCtx>,
    req: axum::http::Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    let path = req.uri().path().to_string();
    let headers = req.headers();

    // Tokens endpoints require master password only
    let tokens_route = path.contains("/tokens");

    // Try bearer token for non-token routes
    if !tokens_route {
        if let Some(token) = auth_header_token(headers) {
            if let Ok(true) = crate::service_core::auth_token_valid(&ctx.state, &token).await {
                return next.run(req).await;
            }
        }
    }

    // Fallback to master password
    if auth::verify_master_from_header(headers, &ctx.master) {
        return next.run(req).await;
    }

    let mut resp = proto_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    resp.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"SnpGuard Management\""),
    );
    resp
}

async fn attest_nonce(State(state): State<Arc<ServiceState>>, body: Bytes) -> Response {
    let req = match NonceRequest::decode(&body[..]) {
        Ok(r) => r,
        Err(_) => return proto_error(StatusCode::BAD_REQUEST, "Failed to decode NonceRequest"),
    };
    let _ = req; // vm_id unused for stateless nonce
    let nonce_bytes = nonce::generate_nonce(&state.attestation_state.secret);
    proto_response(NonceResponse {
        nonce: nonce_bytes.to_vec(),
    })
}

async fn attest_renew(State(state): State<Arc<ServiceState>>, body: Bytes) -> Response {
    let req = match RenewRequest::decode(&body[..]) {
        Ok(r) => r,
        Err(_) => return proto_error(StatusCode::BAD_REQUEST, "Failed to decode RenewRequest"),
    };
    let resp = crate::service_core::renew_record_core(state, req).await;
    proto_response(resp)
}

async fn attest_report(State(state): State<Arc<ServiceState>>, body: Bytes) -> Response {
    let req = match AttestationRequest::decode(&body[..]) {
        Ok(r) => r,
        Err(_) => {
            return proto_error(
                StatusCode::BAD_REQUEST,
                "Failed to decode AttestationRequest",
            )
        }
    };

    let resp = crate::service_core::verify_report_core(state.clone(), req).await;
    proto_response(resp)
}

async fn list_records(State(state): State<Arc<ServiceState>>) -> Response {
    let records = match crate::service_core::list_records_core(&state).await {
        Ok(r) => r,
        Err(e) => return proto_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };
    proto_response(ListRecordsResponse { records })
}

async fn get_record(State(state): State<Arc<ServiceState>>, Path(id): Path<String>) -> Response {
    if !is_valid_record_or_token_id(&id) {
        return proto_error(StatusCode::BAD_REQUEST, "Invalid record id");
    }
    match crate::service_core::get_record_core(&state, id).await {
        Ok(opt) => proto_response(GetRecordResponse { record: opt }),
        Err(e) => proto_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn create_record(State(state): State<Arc<ServiceState>>, body: Bytes) -> Response {
    let req = match CreateRecordRequest::decode(&body[..]) {
        Ok(r) => r,
        Err(_) => {
            return proto_error(
                StatusCode::BAD_REQUEST,
                "Failed to decode CreateRecordRequest",
            )
        }
    };
    match crate::service_core::create_record_core(&state, req).await {
        Ok(id) => proto_response(CreateRecordResponse {
            id,
            error_message: None,
        }),
        Err(e) => proto_response(CreateRecordResponse {
            id: String::new(),
            error_message: Some(e),
        }),
    }
}

async fn delete_record(State(state): State<Arc<ServiceState>>, Path(id): Path<String>) -> Response {
    if !is_valid_record_or_token_id(&id) {
        return proto_error(StatusCode::BAD_REQUEST, "Invalid record id");
    }
    match crate::service_core::delete_record_core(&state, id).await {
        Ok(_) => proto_response(DeleteRecordResponse {
            success: true,
            error_message: None,
        }),
        Err(e) => proto_response(DeleteRecordResponse {
            success: false,
            error_message: Some(e),
        }),
    }
}

async fn enable_record(State(state): State<Arc<ServiceState>>, Path(id): Path<String>) -> Response {
    if !is_valid_record_or_token_id(&id) {
        return proto_error(StatusCode::BAD_REQUEST, "Invalid record id");
    }
    toggle_record(state, id, true).await
}

async fn disable_record(
    State(state): State<Arc<ServiceState>>,
    Path(id): Path<String>,
) -> Response {
    if !is_valid_record_or_token_id(&id) {
        return proto_error(StatusCode::BAD_REQUEST, "Invalid record id");
    }
    toggle_record(state, id, false).await
}

async fn export_tar(State(state): State<Arc<ServiceState>>, Path(id): Path<String>) -> Response {
    if !is_valid_record_or_token_id(&id) {
        return proto_error(StatusCode::BAD_REQUEST, "Invalid record id");
    }
    export_artifact(&state, &id, "artifacts.tar.gz").await
}

async fn export_squash(State(state): State<Arc<ServiceState>>, Path(id): Path<String>) -> Response {
    if !is_valid_record_or_token_id(&id) {
        return proto_error(StatusCode::BAD_REQUEST, "Invalid record id");
    }
    export_artifact(&state, &id, "artifacts.squashfs").await
}

async fn export_artifact(state: &Arc<ServiceState>, id: &str, filename: &str) -> Response {
    use axum::body::Body;
    use tokio_util::io::ReaderStream;

    let artifact_dir = match crate::service_core::get_current_artifact_dir(state, id).await {
        Ok(p) => p,
        Err(e) => return proto_error(StatusCode::NOT_FOUND, &e),
    };

    // Generate artifact archive
    let path = match crate::artifacts::generate_artifact(&artifact_dir, filename) {
        Ok(p) => p,
        Err(e) => return proto_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    match tokio::fs::File::open(path).await {
        Ok(file) => {
            let stream = ReaderStream::new(file);
            let body = Body::from_stream(stream);
            let content_disposition = format!("attachment; filename=\"{}\"", filename);
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                "Content-Type",
                HeaderValue::from_static("application/octet-stream"),
            );
            headers.insert(
                "Content-Disposition",
                HeaderValue::from_str(&content_disposition).unwrap(),
            );
            (headers, body).into_response()
        }
        Err(_) => proto_error(StatusCode::NOT_FOUND, "File not found"),
    }
}

async fn toggle_record(state: Arc<ServiceState>, id: String, enabled: bool) -> Response {
    let req = ToggleEnabledRequest { id };
    match crate::service_core::toggle_enabled_core(&state, req, enabled).await {
        Ok(enabled) => proto_response(ToggleEnabledResponse {
            enabled,
            error_message: None,
        }),
        Err(e) => proto_response(ToggleEnabledResponse {
            enabled: !enabled,
            error_message: Some(e),
        }),
    }
}

async fn list_tokens(State(state): State<Arc<ServiceState>>) -> Response {
    match crate::service_core::list_tokens(&state).await {
        Ok(tokens) => {
            // encode as protobuf? We don't have Token list message; return text for now
            let body = serde_json::to_vec(&tokens).unwrap_or_default();
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Body::from(body))
                .unwrap()
        }
        Err(e) => proto_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn create_token(State(state): State<Arc<ServiceState>>, body: Bytes) -> Response {
    // body: expected: label (string) and optional expires_at seconds
    // since epoch in plain text? For simplicity JSON
    #[derive(serde::Deserialize)]
    struct CreateReq {
        label: String,
        expires_at: Option<i64>,
    }
    let req: CreateReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return proto_error(
                StatusCode::BAD_REQUEST,
                "Invalid token create payload (json)",
            )
        }
    };
    let expires_at = req.expires_at.and_then(|ts| {
        chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0).map(|dt| dt.naive_utc())
    });
    match crate::service_core::generate_token(&state, req.label, expires_at).await {
        Ok((token_plain, info)) => {
            let resp = serde_json::json!({
                "token": token_plain,
                "id": info.id,
                "label": info.label,
                "created_at": info.created_at,
                "expires_at": info.expires_at,
                "revoked": info.revoked,
            });
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Body::from(resp.to_string()))
                .unwrap()
        }
        Err(e) => proto_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn revoke_token(State(state): State<Arc<ServiceState>>, Path(id): Path<String>) -> Response {
    if !is_valid_record_or_token_id(&id) {
        return proto_error(StatusCode::BAD_REQUEST, "Invalid token id");
    }
    match crate::service_core::revoke_token(&state, id).await {
        Ok(_) => proto_error(StatusCode::OK, "revoked"),
        Err(e) => proto_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}
