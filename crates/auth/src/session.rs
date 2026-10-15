//! staging の me・logout・my-orgs を alc-auth-worker が答えるための内部口 (Refs ohishi-exp/rust-leave-worker#1)。
//!
//! staging の tenant は alc-auth-worker + staging の DB が作る (STAGING_MODE) ので、Cloud Run staging の DB には無い。
//! 同じ DB を持つここが tenant の 1 行を返し、refresh token を消す。呼ぶのは auth-worker の staging だけ (c76)。
//!
//! | method | path | 応答 |
//! |---|---|---|
//! | GET | `/internal/tenants/{tenant_id}` | 200 `{id,name,slug,short_id}` / 404 `tenant_not_found` / 400 `invalid_id` |
//! | DELETE | `/internal/tenants/{tenant_id}/users/{user_id}/refresh-token` | 204 (該当が無くても) / 400 `invalid_id` |
//!
//! secret 不一致の 404 は本文が空、会社が無い 404 は本文に `tenant_not_found` が在る (呼び手は本文で読み分ける)。
//! identity ヘッダは読まない: tenant と user は path で受ける。共有 secret の照合は [`crate::internal`] の layer。

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use uuid::Uuid;

use crate::internal::{db_error, error, InternalState};
use crate::pg;

pub const TENANT_PATH: &str = "/internal/tenants/{tenant_id}";
pub const REFRESH_TOKEN_PATH: &str = "/internal/tenants/{tenant_id}/users/{user_id}/refresh-token";

pub fn session_routes() -> Router<InternalState> {
    Router::new()
        .route(TENANT_PATH, get(tenant))
        .route(REFRESH_TOKEN_PATH, delete(clear_refresh_token))
}

/// UUID でなければ 400 の語 `invalid_id`
fn parse_id(s: &str) -> Result<Uuid, &'static str> {
    s.parse().map_err(|_| "invalid_id")
}

async fn tenant(State(state): State<InternalState>, Path(tenant_id): Path<String>) -> Response {
    let tenant_id = match parse_id(&tenant_id) {
        Ok(t) => t,
        Err(code) => return error(StatusCode::BAD_REQUEST, code),
    };
    match pg::tenant_row(&mut *state.pg.lock().await, tenant_id).await {
        Ok(Some(row)) => Json(row).into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "tenant_not_found"),
        Err(e) => db_error(&state, "tenants/get", &e),
    }
}

async fn clear_refresh_token(
    State(state): State<InternalState>,
    Path((tenant_id, user_id)): Path<(String, String)>,
) -> Response {
    let (tenant_id, user_id) = match (parse_id(&tenant_id), parse_id(&user_id)) {
        (Ok(t), Ok(u)) => (t, u),
        (Err(code), _) | (_, Err(code)) => return error(StatusCode::BAD_REQUEST, code),
    };
    match pg::clear_refresh_token(&mut *state.pg.lock().await, tenant_id, user_id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => db_error(&state, "refresh-token/clear", &e),
    }
}
