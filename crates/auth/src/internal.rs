//! 機械用資格情報の内部口 (auth-worker が Service Binding で呼ぶ)。
//!
//! | method | path | 応答 |
//! |---|---|---|
//! | POST | `/internal/machine-credentials` | 201 `{}` / 400 / 409 (username の重複) / 404 `tenant_not_found` |
//! | GET | `/internal/machine-credentials?tenant_id=…[&purpose=…]` | 200 `{credentials:[…]}` (作った順。hash は返さない) / 400 |
//! | POST | `/internal/machine-credentials/{username}/revoke` | 200 `{revoked:true}` / 400 / 404 (その会社に無い) |
//! | POST | `/internal/machine-credentials/{username}/rotate` | 200 `{rotated:true}` (secret_hash を差し替える。旧 password は即失効) / 400 / 404 (失効済み・無い・他社) |
//! | GET | `/internal/machine-credentials/{username}` | 200 `{tenant_id,purpose,secret_hash,revoked}` / 404 (会社をまたいで照合) |
//!
//! ログインの口 (`/internal/auth/…`) は [`crate::login`]、ロールの付け外しの口 (`/internal/tenants/…`) は
//! [`crate::roles`] に在り、同じ router に載せて同じ layer で守る。
//!
//! **全部の口 (と当たらない path) を共有 secret (`X-Internal-Shared-Secret`、constant-time 比較) で守り、
//! 一致しなければ 404** (口が在ることも見せない。本文は当たらない path と同じ空)。tenant は body / query で受ける
//! (`X-Tenant-ID` は見ない。auth-worker が自分の認可を済ませてから呼ぶ)。
//!
//! この Worker は暗号処理を持たない: パスワードの生成と hash の計算・照合の比較は auth-worker 側。
//! 応答・ログは固定の語だけ (username・hash・secret は出さない。DB のエラーは SQLSTATE か種類の label)。

use std::sync::Arc;

use alc_worker_db::PgClient;
use axum::body::{Body, Bytes};
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::lock::Mutex;
use serde::de::DeserializeOwned;
use serde_json::json;
use tokio_postgres::error::SqlState;

use crate::creds::{
    check_create, check_list, check_rotate, valid_username, CreateInput, ListQuery, RevokeInput,
    RotateInput,
};
use crate::login::login_routes;
use crate::pg;
use crate::roles::role_routes;
use crate::secret::secret_matches;
use crate::session::session_routes;

pub const CREDENTIALS_PATH: &str = "/internal/machine-credentials";
const ONE_PATH: &str = "/internal/machine-credentials/{username}";
const REVOKE_PATH: &str = "/internal/machine-credentials/{username}/revoke";
const ROTATE_PATH: &str = "/internal/machine-credentials/{username}/rotate";
/// 共有 secret を載せるヘッダー (ippoan/rust-leave-worker の `/internal/ingest` と同じ名前)
pub const SECRET_HEADER: &str = "X-Internal-Shared-Secret";
/// body の大きさの上限 (入力は短い文字列 5 つまで)
const MAX_BODY_BYTES: usize = 4096;

/// ログの出し先 (worker は console、テストは Vec)
pub type LogSink = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Clone)]
pub struct InternalState {
    pub pg: Arc<Mutex<PgClient>>,
    /// Secrets Store の `INTERNAL_SHARED_SECRET`。取れなかった (`None`) なら全部 404
    pub secret: Option<Arc<str>>,
    pub log: LogSink,
    /// Google の初回ログインで会社を作ってよいか (staging だけ。決め方は [`crate::login::staging_mode`])
    pub staging_mode: bool,
}

pub fn internal_router(state: InternalState) -> Router {
    Router::new()
        .route(CREDENTIALS_PATH, post(create).get(list))
        .route(ONE_PATH, get(lookup))
        .route(REVOKE_PATH, post(revoke))
        .route(ROTATE_PATH, post(rotate))
        .merge(login_routes())
        .merge(role_routes())
        .merge(session_routes())
        // `layer` は当たらない path (fallback) にも掛かる: secret が無ければ口の有無も分からない
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_secret,
        ))
        .with_state(state)
}

async fn require_secret(State(state): State<InternalState>, req: Request, next: Next) -> Response {
    let given = req
        .headers()
        .get(SECRET_HEADER)
        .and_then(|v| v.to_str().ok());
    let expected = state.secret.as_deref().unwrap_or("");
    if !secret_matches(expected, given) {
        (state.log)("internal: unauthorized");
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(req).await
}

pub(crate) fn error(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({ "error": code }))).into_response()
}

fn not_found() -> Response {
    error(StatusCode::NOT_FOUND, "not_found")
}

pub(crate) fn db_error(state: &InternalState, what: &str, e: &tokio_postgres::Error) -> Response {
    (state.log)(&format!("{what}: {}", alc_worker_db::kind(e)));
    error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
}

/// body を JSON として読む。大きすぎる・JSON でない・形が違うは 400 `invalid_body`
pub(crate) async fn read_json<T: DeserializeOwned>(body: Body) -> Result<T, Response> {
    let bytes: Bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| error(StatusCode::BAD_REQUEST, "invalid_body"))?;
    serde_json::from_slice(&bytes).map_err(|_| error(StatusCode::BAD_REQUEST, "invalid_body"))
}

async fn create(State(state): State<InternalState>, body: Body) -> Response {
    let input: CreateInput = match read_json(body).await {
        Ok(i) => i,
        Err(r) => return r,
    };
    if let Err(code) = check_create(&input) {
        return error(StatusCode::BAD_REQUEST, code);
    }
    match pg::insert(&mut *state.pg.lock().await, input).await {
        Ok(_) => (StatusCode::CREATED, Json(json!({}))).into_response(),
        Err(e) if e.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
            error(StatusCode::CONFLICT, "username_taken")
        }
        Err(e) if e.code() == Some(&SqlState::FOREIGN_KEY_VIOLATION) => {
            error(StatusCode::NOT_FOUND, "tenant_not_found")
        }
        Err(e) => db_error(&state, "create", &e),
    }
}

async fn list(
    State(state): State<InternalState>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Response {
    let q = query.map(|Query(q)| q).unwrap_or_default();
    let (tenant_id, purpose) = match check_list(q) {
        Ok(v) => v,
        Err(code) => return error(StatusCode::BAD_REQUEST, code),
    };
    match pg::list(&mut *state.pg.lock().await, tenant_id, purpose).await {
        Ok(credentials) => Json(json!({ "credentials": credentials })).into_response(),
        Err(e) => db_error(&state, "list", &e),
    }
}

async fn revoke(
    State(state): State<InternalState>,
    Path(username): Path<String>,
    body: Body,
) -> Response {
    let input: RevokeInput = match read_json(body).await {
        Ok(i) => i,
        Err(r) => return r,
    };
    // 形の違う username は在りえない (DB の CHECK) ので引かずに 404
    if !valid_username(&username) {
        return not_found();
    }
    match pg::revoke(&mut *state.pg.lock().await, input.tenant_id, username).await {
        Ok(true) => Json(json!({ "revoked": true })).into_response(),
        Ok(false) => not_found(),
        Err(e) => db_error(&state, "revoke", &e),
    }
}

/// secret_hash を差し替える (username はそのまま。旧 password は即失効)。失効済み・無い・他社は 404。
/// rotate 前に発行済みの inbox のチケット (TTL 7 日) は username が有効かだけを見るので rotate 後も通る
/// (過去の PUT への印なので仕様)。
async fn rotate(
    State(state): State<InternalState>,
    Path(username): Path<String>,
    body: Body,
) -> Response {
    let input: RotateInput = match read_json(body).await {
        Ok(i) => i,
        Err(r) => return r,
    };
    if let Err(code) = check_rotate(&input) {
        return error(StatusCode::BAD_REQUEST, code);
    }
    if !valid_username(&username) {
        return not_found();
    }
    match pg::rotate(
        &mut *state.pg.lock().await,
        input.tenant_id,
        username,
        input.secret_hash,
    )
    .await
    {
        Ok(true) => Json(json!({ "rotated": true })).into_response(),
        Ok(false) => not_found(),
        Err(e) => db_error(&state, "rotate", &e),
    }
}

async fn lookup(State(state): State<InternalState>, Path(username): Path<String>) -> Response {
    if !valid_username(&username) {
        return not_found();
    }
    match pg::lookup(&mut *state.pg.lock().await, username).await {
        Ok(Some(found)) => Json(found).into_response(),
        Ok(None) => not_found(),
        Err(e) => db_error(&state, "lookup", &e),
    }
}
