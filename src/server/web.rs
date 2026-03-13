use crate::artifacts;
use crate::auth;
use crate::ingestion_key;
use crate::service_core::{self, ServiceState, TokenInfo};
use askama::Template;
use axum::{
    body::Body,
    extract::{Extension, Form, Multipart, Path, Query},
    response::{Html, IntoResponse, Redirect},
};
use chrono::Duration;
use common::snpguard::AttestationRecord;
use std::sync::Arc;
use tokio_util::io::ReaderStream;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    vms: Vec<AttestationRecord>,
}

#[derive(Template)]
#[template(path = "create.html")]
struct CreateTemplate {}

#[derive(Template)]
#[template(path = "edit.html")]
struct EditTemplate {
    vm: AttestationRecord,
    has_pending: bool,
    pending_since_str: String,
    pending_kernel_params: String,
}

#[derive(serde::Deserialize, Default)]
pub struct DownloadParams {
    #[serde(default)]
    pub pending: bool,
}

#[derive(Template)]
#[template(path = "tokens.html")]
struct TokensTemplate {
    tokens: Vec<TokenInfo>,
    new_token: String,
    show_token: bool,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: String,
}

pub async fn index(Extension(state): Extension<Arc<ServiceState>>) -> impl IntoResponse {
    match service_core::list_records_core(&state).await {
        Ok(vms) => {
            let template = IndexTemplate { vms };
            match template.render() {
                Ok(html) => Html(html).into_response(),
                Err(e) => Html(format!("Template error: {}", e)).into_response(),
            }
        }
        Err(e) => Html(format!("Failed to load records: {}", e)).into_response(),
    }
}

pub async fn create_form() -> impl IntoResponse {
    let template = CreateTemplate {};
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => Html(format!("Template error: {}", e)).into_response(),
    }
}

pub async fn login_form() -> impl IntoResponse {
    let template = LoginTemplate {
        error: String::new(),
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => Html(format!("Template error: {}", e)).into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct LoginForm {
    password: String,
}

pub async fn login_submit(
    Extension(master): Extension<Arc<crate::master_password::MasterAuth>>,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    if crate::auth::verify_password(&master, &form.password) {
        let session = crate::auth::issue_session(&master);
        let mut resp = Redirect::to("/").into_response();
        resp.headers_mut().insert(
            axum::http::header::SET_COOKIE,
            format!("master_session={}; Path=/; HttpOnly; SameSite=Lax", session)
                .parse()
                .unwrap(),
        );
        resp
    } else {
        let template = LoginTemplate {
            error: "Invalid password".to_string(),
        };
        match template.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => Html(format!("Template error: {}", e)).into_response(),
        }
    }
}

fn max_upload_size(name: &str) -> Option<usize> {
    match name {
        "firmware" => Some(50 * 1024 * 1024), // 50 MB
        "kernel" => Some(50 * 1024 * 1024),   // 50 MB
        "initrd" => Some(150 * 1024 * 1024),  // 150 MB
        _ => None,
    }
}

pub async fn create_action(
    Extension(state): Extension<Arc<ServiceState>>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut os_name = String::new();
    let mut unsealing_private_key = String::new();
    let mut vcpus: u32 = 1;
    let mut vcpu_type = String::new();
    let mut kernel_params = String::new();
    let mut allowed_debug = false;
    let mut allowed_migrate_ma = false;
    let mut allowed_smt = true; // Default to true
    let mut min_tcb_bootloader = 0u32;
    let mut min_tcb_tee = 0u32;
    let mut min_tcb_snp = 0u32;
    let mut min_tcb_microcode = 0u32;
    let mut firmware: Option<Vec<u8>> = None;
    let mut kernel: Option<Vec<u8>> = None;
    let mut initrd: Option<Vec<u8>> = None;

    while let Some(field_res) = multipart.next_field().await.transpose() {
        let field = match field_res {
            Ok(f) => f,
            Err(e) => {
                return Html(format!(
                    "<h1>Error</h1><p>Failed to read form data: {}</p>",
                    e
                ))
                .into_response()
            }
        };

        let name = match field.name() {
            Some(n) => n.to_string(),
            None => continue,
        };
        if field.file_name().is_some() {
            let data = match field.bytes().await {
                Ok(d) => d,
                Err(e) => {
                    return Html(format!(
                        "<h1>Error</h1><p>Failed to read uploaded file '{}': {}</p>",
                        name, e
                    ))
                    .into_response()
                }
            };
            if data.is_empty() {
                continue;
            }

            // Enforce file size limits
            let max_size = max_upload_size(name.as_str());
            if max_size.is_none() {
                continue;
            }
            let max_size = max_size.unwrap();

            if data.len() > max_size {
                return Html(format!(
                    "<h1>File Too Large</h1><p>File '{}' exceeds maximum size of {} bytes</p>",
                    name, max_size
                ))
                .into_response();
            }

            match name.as_str() {
                "firmware" => firmware = Some(data.to_vec()),
                "kernel" => kernel = Some(data.to_vec()),
                "initrd" => initrd = Some(data.to_vec()),
                _ => {}
            }
        } else {
            let txt = match field.text().await {
                Ok(t) => t,
                Err(e) => {
                    return Html(format!(
                        "<h1>Error</h1><p>Failed to read field '{}': {}</p>",
                        name, e
                    ))
                    .into_response()
                }
            };
            match name.as_str() {
                "os_name" => os_name = txt,
                "unsealing_private_key" => unsealing_private_key = txt,
                "vcpus" => vcpus = txt.parse().unwrap_or(1),
                "vcpu_type" => vcpu_type = txt,
                "kernel_params" => kernel_params = txt,
                "allowed_debug" => allowed_debug = txt == "true",
                "allowed_migrate_ma" => allowed_migrate_ma = txt == "true",
                "allowed_smt" => allowed_smt = txt == "true",
                "min_tcb_bootloader" => min_tcb_bootloader = txt.parse().unwrap_or(0),
                "min_tcb_tee" => min_tcb_tee = txt.parse().unwrap_or(0),
                "min_tcb_snp" => min_tcb_snp = txt.parse().unwrap_or(0),
                "min_tcb_microcode" => min_tcb_microcode = txt.parse().unwrap_or(0),
                _ => {}
            }
        }
    }

    // Validate required fields
    if os_name.is_empty()
        || unsealing_private_key.is_empty()
        || firmware.is_none()
        || kernel.is_none()
        || initrd.is_none()
    {
        return Html("<h1>Error</h1><p>All fields are required</p>").into_response();
    }

    // Parse unsealing private key (non-standard PEM format - raw 32-byte key wrapped in PEM)
    let unsealing_key_pem = match pem::parse(&unsealing_private_key) {
        Ok(pem) => pem,
        Err(e) => {
            return Html(format!(
                "<h1>Error</h1><p>Failed to parse unsealing private key PEM: {}</p>",
                e
            ))
            .into_response()
        }
    };
    if unsealing_key_pem.tag() != "PRIVATE KEY" {
        return Html(
            "<h1>Error</h1><p>Invalid unsealing private key PEM tag (expected PRIVATE KEY)</p>"
                .to_string(),
        )
        .into_response();
    }
    let unsealing_key_bytes: [u8; 32] = match unsealing_key_pem.contents().try_into() {
        Ok(b) => b,
        Err(_) => {
            return Html(format!(
            "<h1>Error</h1><p>Invalid unsealing private key length (expected 32 bytes, got {})</p>",
            unsealing_key_pem.contents().len()
        ))
            .into_response()
        }
    };

    // Encrypt unsealing private key with ingestion public key
    let public_key_pem = match state.ingestion_keys.get_public_key_pem() {
        Ok(pem) => pem,
        Err(e) => {
            return Html(format!(
                "<h1>Error</h1><p>Failed to get ingestion public key: {}</p>",
                e
            ))
            .into_response()
        }
    };

    // Encrypt unsealing private key (32 bytes only) using the public key
    let unsealing_private_key_encrypted =
        match ingestion_key::encrypt_with_public_key(&public_key_pem, &unsealing_key_bytes) {
            Ok(encrypted) => encrypted,
            Err(e) => {
                return Html(format!(
                    "<h1>Error</h1><p>Failed to encrypt unsealing private key: {}</p>",
                    e
                ))
                .into_response()
            }
        };

    let req = common::snpguard::CreateRecordRequest {
        os_name,
        firmware: firmware.unwrap(),
        kernel: kernel.unwrap(),
        initrd: initrd.unwrap(),
        kernel_params,
        vcpus,
        vcpu_type,
        unsealing_private_key_encrypted,
        allowed_debug,
        allowed_migrate_ma,
        allowed_smt,
        min_tcb_bootloader,
        min_tcb_tee,
        min_tcb_snp,
        min_tcb_microcode,
    };
    match service_core::create_record_core(&state, req).await {
        Ok(_) => Redirect::to("/").into_response(),
        Err(e) => Html(format!("<h1>Error Creating Record</h1><p>{}</p>", e)).into_response(),
    }
}

pub async fn view_record(
    Extension(state): Extension<Arc<ServiceState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match service_core::get_record_core(&state, id).await {
        Ok(Some(vm)) => {
            let has_pending = vm.pending_since.is_some();
            let pending_since_str = vm
                .pending_since
                .and_then(|ts| chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0))
                .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_default();
            let pending_kernel_params = if has_pending {
                service_core::get_pending_kernel_params(&state, &vm.id)
                    .await
                    .unwrap_or_else(|| "(inherited from current)".to_string())
            } else {
                String::new()
            };
            let template = EditTemplate {
                vm,
                has_pending,
                pending_since_str,
                pending_kernel_params,
            };
            match template.render() {
                Ok(html) => Html(html).into_response(),
                Err(e) => Html(format!("Template error: {}", e)).into_response(),
            }
        }
        Ok(None) => Html("<h1>Not Found</h1><p>Record not found</p>").into_response(),
        Err(e) => {
            Html(format!("<h1>Error</h1><p>Failed to load record: {}</p>", e)).into_response()
        }
    }
}

pub async fn discard_pending(
    Extension(state): Extension<Arc<ServiceState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match service_core::discard_pending_core(&state, id.clone()).await {
        Ok(_) => Redirect::to(&format!("/view/{}", id)).into_response(),
        Err(e) => Html(format!(
            "<h1>Error</h1><p>Failed to discard pending renewal: {}</p>",
            e
        ))
        .into_response(),
    }
}

pub async fn toggle_enabled(
    Extension(state): Extension<Arc<ServiceState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Fetch current state to determine target
    let current = match service_core::get_record_core(&state, id.clone()).await {
        Ok(Some(vm)) => vm,
        Ok(None) => {
            return Html(format!("<h1>Error</h1><p>Record {} not found</p>", id)).into_response()
        }
        Err(e) => {
            return Html(format!("<h1>Error</h1><p>Failed to load record: {}</p>", e))
                .into_response()
        }
    };
    let target_enabled = !current.enabled;

    let req = common::snpguard::ToggleEnabledRequest { id: id.clone() };
    match service_core::toggle_enabled_core(&state, req, target_enabled).await {
        Ok(_) => Redirect::to("/").into_response(),
        Err(e) => Html(format!(
            "<h1>Error</h1><p>Failed to toggle enabled status: {}</p>",
            e
        ))
        .into_response(),
    }
}

pub async fn delete_action(
    Extension(state): Extension<Arc<ServiceState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match service_core::delete_record_core(&state, id).await {
        Ok(_) => Redirect::to("/").into_response(),
        Err(e) => Html(format!("<h1>Error Deleting Record</h1><p>{}</p>", e)).into_response(),
    }
}

pub async fn tokens_page(Extension(state): Extension<Arc<ServiceState>>) -> impl IntoResponse {
    match service_core::list_tokens(&state).await {
        Ok(tokens) => {
            let template = TokensTemplate {
                tokens,
                new_token: String::new(),
                show_token: false,
            };
            match template.render() {
                Ok(html) => Html(html).into_response(),
                Err(e) => Html(format!("Template error: {}", e)).into_response(),
            }
        }
        Err(e) => Html(format!("<h1>Error</h1><p>{}</p>", e)).into_response(),
    }
}

pub async fn create_token(
    Extension(state): Extension<Arc<ServiceState>>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut label = String::new();
    let mut expires_hours: Option<i64> = None;

    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap_or("").to_string();
        let txt = field.text().await.unwrap_or_default();
        match name.as_str() {
            "label" => label = txt,
            "expires_hours" => {
                let parsed = txt.trim();
                if !parsed.is_empty() {
                    if let Ok(h) = parsed.parse::<i64>() {
                        expires_hours = Some(h);
                    }
                }
            }
            _ => {}
        }
    }

    if label.is_empty() {
        return Html("<h1>Error</h1><p>Label is required</p>").into_response();
    }

    let expires_at = expires_hours.and_then(|h| {
        chrono::Utc::now()
            .naive_utc()
            .checked_add_signed(Duration::hours(h))
    });

    match service_core::generate_token(&state, label, expires_at).await {
        Ok((token_plain, _info)) => match service_core::list_tokens(&state).await {
            Ok(tokens) => {
                let template = TokensTemplate {
                    tokens,
                    new_token: token_plain,
                    show_token: true,
                };
                match template.render() {
                    Ok(html) => Html(html).into_response(),
                    Err(e) => Html(format!("Template error: {}", e)).into_response(),
                }
            }
            Err(e) => Html(format!("<h1>Error</h1><p>{}</p>", e)).into_response(),
        },
        Err(e) => Html(format!(
            "<h1>Error</h1><p>Failed to generate token: {}</p>",
            e
        ))
        .into_response(),
    }
}

pub async fn revoke_token(
    Extension(state): Extension<Arc<ServiceState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match service_core::revoke_token(&state, id).await {
        Ok(_) => Redirect::to("/tokens").into_response(),
        Err(e) => Html(format!(
            "<h1>Error</h1><p>Failed to revoke token: {}</p>",
            e
        ))
        .into_response(),
    }
}

pub async fn logout() -> impl IntoResponse {
    let mut resp = Redirect::to("/login").into_response();
    resp.headers_mut().append(
        axum::http::header::SET_COOKIE,
        auth::clear_session_cookie().parse().unwrap(),
    );
    resp
}

pub async fn download_artifact(
    Extension(state): Extension<Arc<ServiceState>>,
    Path((id, file_name)): Path<(String, String)>,
    Query(params): Query<DownloadParams>,
) -> impl IntoResponse {
    // Strip to bare filename to block both relative (../../) and absolute (/etc/)
    // path traversal.  Path::new().file_name() returns None for "." and "..".
    let file_name = match std::path::Path::new(&file_name)
        .file_name()
        .and_then(|n| n.to_str())
    {
        Some(n) => n.to_string(),
        None => return "Invalid filename".into_response(),
    };

    let artifact_dir = if params.pending {
        match service_core::get_pending_artifact_dir(&state, &id).await {
            Ok(p) => p,
            Err(e) => return format!("No pending renewal: {}", e).into_response(),
        }
    } else {
        match service_core::get_current_artifact_dir(&state, &id).await {
            Ok(p) => p,
            Err(e) => return format!("Record not found: {}", e).into_response(),
        }
    };

    // For archive formats (.tar.gz / .squashfs) regenerate on demand;
    // for plain files just resolve the path directly.
    let path = if file_name.ends_with(".tar.gz") || file_name.ends_with(".squashfs") {
        match artifacts::generate_artifact(&artifact_dir, &file_name) {
            Ok(p) => p,
            Err(e) => return format!("Failed to generate artifact: {}", e).into_response(),
        }
    } else {
        artifact_dir.join(&file_name)
    };

    match tokio::fs::File::open(path).await {
        Ok(file) => {
            let stream = ReaderStream::new(file);
            let body = Body::from_stream(stream);
            let content_disposition = format!("attachment; filename=\"{}\"", file_name);
            use axum::http::HeaderMap;
            let mut headers = HeaderMap::new();
            headers.insert("Content-Type", "application/octet-stream".parse().unwrap());
            headers.insert("Content-Disposition", content_disposition.parse().unwrap());
            (headers, body).into_response()
        }
        Err(_) => "File not found".into_response(),
    }
}
