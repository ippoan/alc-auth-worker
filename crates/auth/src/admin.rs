//! 会社の管理の内部口 (ユーザー・招待・SSO 設定・参加の申請)。rust-alc-api の `/api/admin/users*`・
//! `/api/admin/sso/configs`・`/api/access-requests*`・`/api/tenants/by-slug/{slug}` から移した
//! (Refs ippoan/rust-alc-api#680)。呼ぶのは auth-worker の管理画面と参加ページだけ。
//!
//! | method | path | 応答 |
//! |---|---|---|
//! | GET | `/internal/tenants/{tenant_id}/users` | 200 `{users:[{id,email,name,role,created_at}]}` |
//! | DELETE | `/internal/tenants/{tenant_id}/users/{user_id}` | 204 (無くても) |
//! | GET | `/internal/tenants/{tenant_id}/invitations` | 200 `{invitations:[{id,tenant_id,email,role,created_at}]}` |
//! | POST | `/internal/tenants/{tenant_id}/invitations` | 200 招待の 1 行 / 400 `invalid_email`・`invalid_role` / 409 `email_taken` (他社が招待済み) |
//! | DELETE | `/internal/tenants/{tenant_id}/invitations/{id}` | 204 (無くても) |
//! | GET | `/internal/tenants/{tenant_id}/sso-configs` | 200 `{configs:[{provider,client_id,external_org_id,enabled,woff_id,created_at,updated_at}]}` |
//! | PUT | `/internal/tenants/{tenant_id}/sso-configs/{provider}` | 200 設定の 1 行 / 400 `secret_required` (secret 無しで新規) / 409 `sso_config_conflict` (他社と同じ client_id・external_org_id) |
//! | DELETE | `/internal/tenants/{tenant_id}/sso-configs/{provider}` | 204 / 404 `sso_config_not_found` |
//! | GET | `/internal/tenant-by-slug/{slug}` | 200 `{found:true,id,name,slug}` / 404 `tenant_not_found` |
//! | POST | `/internal/access-requests` | 201 申請の 1 行 + `org_name` / 404 `tenant_not_found`・`user_not_found` |
//! | GET | `/internal/tenants/{tenant_id}/access-requests[?status=…]` | 200 `{requests:[{id,tenant_id,user_id,status,role,created_at}]}` (新しい順) |
//! | POST | `/internal/tenants/{tenant_id}/access-requests/{id}/approve` | 204 / 400 `invalid_role` / 404 `request_not_found` (無い・他社・pending でない) |
//! | POST | `/internal/tenants/{tenant_id}/access-requests/{id}/decline` | 204 / 404 `request_not_found` |
//!
//! 400 `invalid_id` は path の id が UUID でないとき、400 `invalid_body` は body の形が違うとき。
//! **認可は auth-worker** (管理者か・自分自身を消さないか・export の開発者か) で、ここは tenant を path で受けて
//! その会社の transaction (RLS) の中で読み書きする。SSO の client secret の暗号化も auth-worker で、ここは
//! 暗号文を保存するだけ (読み出しの口は暗号文を返さない)。共有 secret の照合は [`crate::internal`] の layer。

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

use crate::internal::{db_error, error, read_json, InternalState};
use crate::pg::{self, SsoConfigInput};

pub const USERS_PATH: &str = "/internal/tenants/{tenant_id}/users";
pub const USER_PATH: &str = "/internal/tenants/{tenant_id}/users/{user_id}";
pub const INVITATIONS_PATH: &str = "/internal/tenants/{tenant_id}/invitations";
pub const INVITATION_PATH: &str = "/internal/tenants/{tenant_id}/invitations/{id}";
pub const SSO_CONFIGS_PATH: &str = "/internal/tenants/{tenant_id}/sso-configs";
pub const SSO_CONFIG_PATH: &str = "/internal/tenants/{tenant_id}/sso-configs/{provider}";
pub const TENANT_BY_SLUG_PATH: &str = "/internal/tenant-by-slug/{slug}";
pub const CREATE_ACCESS_REQUEST_PATH: &str = "/internal/access-requests";
pub const ACCESS_REQUESTS_PATH: &str = "/internal/tenants/{tenant_id}/access-requests";
pub const APPROVE_PATH: &str = "/internal/tenants/{tenant_id}/access-requests/{id}/approve";
pub const DECLINE_PATH: &str = "/internal/tenants/{tenant_id}/access-requests/{id}/decline";

/// users.role・招待・参加の申請で受ける role (alc-migrations の 131 の CHECK と同じ 3 つ)
pub const ACCOUNT_ROLES: [&str; 3] = ["admin", "viewer", "payroll"];

pub fn admin_routes() -> Router<InternalState> {
    Router::new()
        .route(USERS_PATH, get(list_users))
        .route(USER_PATH, delete(delete_user))
        .route(INVITATIONS_PATH, get(list_invitations).post(invite))
        .route(INVITATION_PATH, delete(delete_invitation))
        .route(SSO_CONFIGS_PATH, get(list_sso))
        .route(SSO_CONFIG_PATH, put(save_sso).delete(delete_sso))
        .route(TENANT_BY_SLUG_PATH, get(tenant_by_slug))
        .route(CREATE_ACCESS_REQUEST_PATH, post(create_access_request))
        .route(ACCESS_REQUESTS_PATH, get(list_access_requests))
        .route(APPROVE_PATH, post(approve))
        .route(DECLINE_PATH, post(decline))
}

/// UUID でなければ 400 の語 `invalid_id`
fn parse_id(s: &str) -> Result<Uuid, &'static str> {
    s.parse().map_err(|_| "invalid_id")
}

fn parse_ids(a: &str, b: &str) -> Result<(Uuid, Uuid), &'static str> {
    Ok((parse_id(a)?, parse_id(b)?))
}

pub fn is_account_role(role: &str) -> bool {
    ACCOUNT_ROLES.contains(&role)
}

/// 招待の email (前後の空白を除いて、空でなく `@` を含む)。だめなら `None`
pub fn normalize_email(email: &str) -> Option<String> {
    let email = email.trim();
    (!email.is_empty() && email.contains('@')).then(|| email.to_owned())
}

// ---------- ユーザー ----------

async fn list_users(State(state): State<InternalState>, Path(tenant_id): Path<String>) -> Response {
    let tenant_id = match parse_id(&tenant_id) {
        Ok(t) => t,
        Err(code) => return error(StatusCode::BAD_REQUEST, code),
    };
    match pg::tenant_users(&mut *state.pg.lock().await, tenant_id).await {
        Ok(users) => Json(json!({ "users": users })).into_response(),
        Err(e) => db_error(&state, "users/list", &e),
    }
}

async fn delete_user(
    State(state): State<InternalState>,
    Path((tenant_id, user_id)): Path<(String, String)>,
) -> Response {
    let (tenant_id, user_id) = match parse_ids(&tenant_id, &user_id) {
        Ok(ids) => ids,
        Err(code) => return error(StatusCode::BAD_REQUEST, code),
    };
    match pg::delete_tenant_user(&mut *state.pg.lock().await, tenant_id, user_id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => db_error(&state, "users/delete", &e),
    }
}

// ---------- 招待 ----------

#[derive(Deserialize)]
struct InviteBody {
    email: String,
    role: Option<String>,
}

async fn list_invitations(
    State(state): State<InternalState>,
    Path(tenant_id): Path<String>,
) -> Response {
    let tenant_id = match parse_id(&tenant_id) {
        Ok(t) => t,
        Err(code) => return error(StatusCode::BAD_REQUEST, code),
    };
    match pg::tenant_invitations(&mut *state.pg.lock().await, tenant_id).await {
        Ok(invitations) => Json(json!({ "invitations": invitations })).into_response(),
        Err(e) => db_error(&state, "invitations/list", &e),
    }
}

async fn invite(
    State(state): State<InternalState>,
    Path(tenant_id): Path<String>,
    body: Body,
) -> Response {
    let tenant_id = match parse_id(&tenant_id) {
        Ok(t) => t,
        Err(code) => return error(StatusCode::BAD_REQUEST, code),
    };
    let b: InviteBody = match read_json(body).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Some(email) = normalize_email(&b.email) else {
        return error(StatusCode::BAD_REQUEST, "invalid_email");
    };
    // 移植元と同じく role の省略は admin
    let role = b.role.unwrap_or_else(|| "admin".to_owned());
    if !is_account_role(&role) {
        return error(StatusCode::BAD_REQUEST, "invalid_role");
    }
    match pg::upsert_invitation(&mut *state.pg.lock().await, tenant_id, email, role).await {
        Ok(Some(inv)) => Json(inv).into_response(),
        Ok(None) => error(StatusCode::CONFLICT, "email_taken"),
        Err(e) if e.code() == Some(&SqlState::FOREIGN_KEY_VIOLATION) => {
            error(StatusCode::NOT_FOUND, "tenant_not_found")
        }
        Err(e) => db_error(&state, "invitations/create", &e),
    }
}

async fn delete_invitation(
    State(state): State<InternalState>,
    Path((tenant_id, id)): Path<(String, String)>,
) -> Response {
    let (tenant_id, id) = match parse_ids(&tenant_id, &id) {
        Ok(ids) => ids,
        Err(code) => return error(StatusCode::BAD_REQUEST, code),
    };
    match pg::delete_invitation_by_id(&mut *state.pg.lock().await, tenant_id, id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => db_error(&state, "invitations/delete", &e),
    }
}

// ---------- SSO 設定 ----------

#[derive(Deserialize)]
struct SsoBody {
    client_id: String,
    /// auth-worker が暗号化した client secret。省略・null・空文字は「secret を変えない」
    client_secret_encrypted: Option<String>,
    external_org_id: String,
    woff_id: Option<String>,
    enabled: Option<bool>,
}

async fn list_sso(State(state): State<InternalState>, Path(tenant_id): Path<String>) -> Response {
    let tenant_id = match parse_id(&tenant_id) {
        Ok(t) => t,
        Err(code) => return error(StatusCode::BAD_REQUEST, code),
    };
    match pg::sso_configs(&mut *state.pg.lock().await, tenant_id).await {
        Ok(configs) => Json(json!({ "configs": configs })).into_response(),
        Err(e) => db_error(&state, "sso-configs/list", &e),
    }
}

async fn save_sso(
    State(state): State<InternalState>,
    Path((tenant_id, provider)): Path<(String, String)>,
    body: Body,
) -> Response {
    let tenant_id = match parse_id(&tenant_id) {
        Ok(t) => t,
        Err(code) => return error(StatusCode::BAD_REQUEST, code),
    };
    let b: SsoBody = match read_json(body).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let input = SsoConfigInput {
        provider,
        client_id: b.client_id,
        client_secret_encrypted: b.client_secret_encrypted.filter(|s| !s.is_empty()),
        external_org_id: b.external_org_id,
        woff_id: b.woff_id,
        enabled: b.enabled.unwrap_or(true),
    };
    match pg::save_sso_config(&mut *state.pg.lock().await, tenant_id, input).await {
        Ok(Some(row)) => Json(row).into_response(),
        Ok(None) => error(StatusCode::BAD_REQUEST, "secret_required"),
        // sso_provider_configs.tenant_id は tenants への外部キーを持たない (alc-migrations の 048)。
        // 会社の有無は呼び手 (auth-worker が JWT の会社を渡す) に任せる
        Err(e) if e.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
            error(StatusCode::CONFLICT, "sso_config_conflict")
        }
        Err(e) => db_error(&state, "sso-configs/save", &e),
    }
}

async fn delete_sso(
    State(state): State<InternalState>,
    Path((tenant_id, provider)): Path<(String, String)>,
) -> Response {
    let tenant_id = match parse_id(&tenant_id) {
        Ok(t) => t,
        Err(code) => return error(StatusCode::BAD_REQUEST, code),
    };
    match pg::delete_sso_config(&mut *state.pg.lock().await, tenant_id, provider).await {
        Ok(0) => error(StatusCode::NOT_FOUND, "sso_config_not_found"),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => db_error(&state, "sso-configs/delete", &e),
    }
}

// ---------- 参加の申請 ----------

#[derive(Deserialize)]
struct CreateRequestBody {
    org_slug: String,
    user_id: Uuid,
}

#[derive(Deserialize, Default)]
struct ApproveBody {
    role: Option<String>,
}

#[derive(Deserialize)]
struct StatusQuery {
    status: Option<String>,
}

async fn tenant_by_slug(State(state): State<InternalState>, Path(slug): Path<String>) -> Response {
    match pg::tenant_by_slug(&mut *state.pg.lock().await, slug).await {
        Ok(Some(t)) => Json(json!({
            "found": true,
            "id": t.id,
            "name": t.name,
            "slug": t.slug.unwrap_or_default(),
        }))
        .into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "tenant_not_found"),
        Err(e) => db_error(&state, "tenant-by-slug", &e),
    }
}

async fn create_access_request(State(state): State<InternalState>, body: Body) -> Response {
    let b: CreateRequestBody = match read_json(body).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    match pg::create_access_request(&mut *state.pg.lock().await, b.org_slug, b.user_id).await {
        Ok(Some((org_name, r))) => {
            let mut v = json!(r);
            v["org_name"] = json!(org_name);
            (StatusCode::CREATED, Json(v)).into_response()
        }
        Ok(None) => error(StatusCode::NOT_FOUND, "tenant_not_found"),
        Err(e) if e.code() == Some(&SqlState::FOREIGN_KEY_VIOLATION) => {
            error(StatusCode::NOT_FOUND, "user_not_found")
        }
        Err(e) => db_error(&state, "access-requests/create", &e),
    }
}

async fn list_access_requests(
    State(state): State<InternalState>,
    Path(tenant_id): Path<String>,
    query: Result<Query<StatusQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let tenant_id = match parse_id(&tenant_id) {
        Ok(t) => t,
        Err(code) => return error(StatusCode::BAD_REQUEST, code),
    };
    let Ok(Query(q)) = query else {
        return error(StatusCode::BAD_REQUEST, "invalid_query");
    };
    match pg::access_requests(&mut *state.pg.lock().await, tenant_id, q.status).await {
        Ok(requests) => Json(json!({ "requests": requests })).into_response(),
        Err(e) => db_error(&state, "access-requests/list", &e),
    }
}

async fn approve(
    State(state): State<InternalState>,
    Path((tenant_id, id)): Path<(String, String)>,
    body: Body,
) -> Response {
    let (tenant_id, id) = match parse_ids(&tenant_id, &id) {
        Ok(ids) => ids,
        Err(code) => return error(StatusCode::BAD_REQUEST, code),
    };
    // body は省略してよい (移植元と同じく role の省略は viewer)
    let b: ApproveBody = match axum::body::to_bytes(body, 4096).await {
        Ok(bytes) if bytes.is_empty() => ApproveBody::default(),
        Ok(bytes) => match serde_json::from_slice::<Option<ApproveBody>>(&bytes) {
            Ok(b) => b.unwrap_or_default(),
            Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_body"),
        },
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_body"),
    };
    let role = b.role.unwrap_or_else(|| "viewer".to_owned());
    if !is_account_role(&role) {
        return error(StatusCode::BAD_REQUEST, "invalid_role");
    }
    match pg::approve_access_request(&mut *state.pg.lock().await, tenant_id, id, role).await {
        Ok(0) => error(StatusCode::NOT_FOUND, "request_not_found"),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => db_error(&state, "access-requests/approve", &e),
    }
}

async fn decline(
    State(state): State<InternalState>,
    Path((tenant_id, id)): Path<(String, String)>,
) -> Response {
    let (tenant_id, id) = match parse_ids(&tenant_id, &id) {
        Ok(ids) => ids,
        Err(code) => return error(StatusCode::BAD_REQUEST, code),
    };
    match pg::decline_access_request(&mut *state.pg.lock().await, tenant_id, id).await {
        Ok(0) => error(StatusCode::NOT_FOUND, "request_not_found"),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => db_error(&state, "access-requests/decline", &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_roles_are_the_three() {
        for r in ["admin", "viewer", "payroll"] {
            assert!(is_account_role(r));
        }
        for r in ["member", "leave", "", "Admin"] {
            assert!(!is_account_role(r));
        }
    }

    #[test]
    fn email_is_trimmed_and_needs_an_at() {
        assert_eq!(
            normalize_email("  a@example.test "),
            Some("a@example.test".to_owned())
        );
        assert_eq!(normalize_email(""), None);
        assert_eq!(normalize_email("   "), None);
        assert_eq!(normalize_email("no-at"), None);
    }
}
