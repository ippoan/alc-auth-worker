//! ログインの内部口 (auth-worker が Service Binding で呼ぶ。移植元は rust-alc-api の
//! `crates/alc-auth/src/internal.rs`。返す JSON の形は変えない — auth-worker が型で読む)。
//!
//! | method | path | 応答 |
//! |---|---|---|
//! | GET | `/internal/auth/sso-config?provider=…&domain=…` | 200 SSO 設定 / 404 `sso_config_not_found` / 400 |
//! | POST | `/internal/auth/users/upsert-google` | 200 user (8 列) + `slug` + `permissions` / 403 `no_tenant_for_email` / 400 |
//! | POST | `/internal/auth/refresh-token` | 204 / 400 |
//! | POST | `/internal/auth/users/upsert-lineworks` | 200 user (8 列) + `slug` + `permissions` / 400 |
//! | POST | `/internal/auth/users/upsert-line` | 200 user (8 列) + `slug` + `permissions` / 400 |
//! | GET | `/internal/auth/users/by-line-id?line_user_id=…` | 200 user (8 列) + `slug` + `permissions` / 200 `null` (無い) / 400 |
//! | POST | `/internal/auth/recipients/register-line` | 204 (重複も) / 400 |
//! | GET | `/internal/auth/recipients/by-line-id?line_user_id=…` | 200 `[{tenant_id,name}]` (会社をまたいで全部) / 400 |
//!
//! 共有 secret の照合は [`crate::internal`] の layer がこの口にも掛ける (一致しなければ本文の空の 404)。
//! Google の ID token の検証は auth-worker 側 (ここは検証済みの sub / email / name を受け取るだけ)。
//!
//! Google の初回ログインの会社は、招待 (email の完全一致) → email_domain の一致 → **STAGING_MODE のときだけ**
//! 会社を作る → それ以外は 403 の順に決める。role は招待の role、ほかは admin。
//! LINE・LINE WORKS の会社は body の `tenant_id` で、新規の role は **viewer 固定**。**STAGING_MODE のときだけ**
//! 先にその会社を在らせる (staging の DB は揮発し、SSO 設定の会社が消えていることがある)。
//! 応答・ログは固定の語だけ (email・hash を出さない)。

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use alc_worker_db::PgClient;

use crate::internal::{db_error, error, read_json, InternalState};
use crate::pg::{self, login_sql, RecipientTenant, SsoConfig, User};
use crate::roles::permissions_for;

pub const SSO_CONFIG_PATH: &str = "/internal/auth/sso-config";
pub const UPSERT_GOOGLE_PATH: &str = "/internal/auth/users/upsert-google";
pub const REFRESH_TOKEN_PATH: &str = "/internal/auth/refresh-token";
pub const UPSERT_LINEWORKS_PATH: &str = "/internal/auth/users/upsert-lineworks";
pub const UPSERT_LINE_PATH: &str = "/internal/auth/users/upsert-line";
pub const USER_BY_LINE_ID_PATH: &str = "/internal/auth/users/by-line-id";
pub const REGISTER_LINE_RECIPIENT_PATH: &str = "/internal/auth/recipients/register-line";
pub const RECIPIENTS_BY_LINE_ID_PATH: &str = "/internal/auth/recipients/by-line-id";

/// 招待が無く email_domain で会社が決まったときの role
const DOMAIN_ROLE: &str = "admin";

/// `STAGING_MODE` の値 (wrangler.toml の `[env.staging.vars]` にだけ在る) と、DB に Hyperdrive の段 (本番) で
/// 繋いだかから、会社の自動作成を許すかを決める。`"1"` だけが有効。
/// **Hyperdrive の段で有効なら `Err`** (本番で会社を作らせない。worker は全部の口を 500 にする)
pub fn staging_mode(var: Option<&str>, via_hyperdrive: bool) -> Result<bool, &'static str> {
    match (var == Some("1"), via_hyperdrive) {
        (true, true) => Err("STAGING_MODE on the production database"),
        (on, _) => Ok(on),
    }
}

/// JWT の組み立てに要る user と会社の slug (rust-alc-api の `InternalUserWithSlug` と同じ形) に、
/// 権限 (`permissions`。[`crate::roles::permissions_for`]。auth-worker が claim `perms` に詰める) を足したもの
#[derive(Debug, Serialize)]
pub struct UserWithSlug {
    #[serde(flatten)]
    pub user: User,
    pub slug: Option<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SsoConfigQuery {
    provider: String,
    domain: String,
}

#[derive(Debug, Deserialize)]
struct UpsertGoogleBody {
    google_sub: String,
    email: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct UpsertLineworksBody {
    tenant_id: Uuid,
    lineworks_id: String,
    email: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct UpsertLineBody {
    tenant_id: Uuid,
    line_user_id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct ByLineIdQuery {
    line_user_id: String,
}

#[derive(Debug, Deserialize)]
struct RegisterLineRecipientBody {
    tenant_id: Uuid,
    name: String,
    line_user_id: String,
}

#[derive(Debug, Deserialize)]
struct RefreshTokenBody {
    user_id: Uuid,
    /// hex(sha256(raw)) — auth-worker 側で作った hash (raw は載せない)
    refresh_hash: String,
    expires_at: DateTime<Utc>,
}

pub fn login_routes() -> Router<InternalState> {
    Router::new()
        .route(SSO_CONFIG_PATH, get(sso_config))
        .route(UPSERT_GOOGLE_PATH, post(upsert_google))
        .route(REFRESH_TOKEN_PATH, post(refresh_token))
        .route(UPSERT_LINEWORKS_PATH, post(upsert_lineworks))
        .route(UPSERT_LINE_PATH, post(upsert_line))
        .route(USER_BY_LINE_ID_PATH, get(user_by_line_id))
        .route(REGISTER_LINE_RECIPIENT_PATH, post(register_line_recipient))
        .route(RECIPIENTS_BY_LINE_ID_PATH, get(recipients_by_line_id))
}

async fn sso_config(
    State(state): State<InternalState>,
    query: Result<Query<SsoConfigQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(q)) = query else {
        return error(StatusCode::BAD_REQUEST, "invalid_query");
    };
    match pg::resolve_sso_config(&mut *state.pg.lock().await, q.provider, q.domain).await {
        Ok(Some(c)) => Json::<SsoConfig>(c).into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "sso_config_not_found"),
        Err(e) => db_error(&state, "sso-config", &e),
    }
}

async fn upsert_google(State(state): State<InternalState>, body: axum::body::Body) -> Response {
    let b: UpsertGoogleBody = match read_json(body).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    match upsert_google_user(&state, &mut *state.pg.lock().await, b).await {
        Ok(Some(u)) => Json(u).into_response(),
        Ok(None) => {
            (state.log)("upsert-google: no tenant for email");
            error(StatusCode::FORBIDDEN, "no_tenant_for_email")
        }
        Err(e) => db_error(&state, "upsert-google", &e),
    }
}

/// sub で既存の user を引き、無ければ会社と role を決めて作る。会社が決まらなければ `None` (403)
async fn upsert_google_user(
    state: &InternalState,
    pg: &mut PgClient,
    b: UpsertGoogleBody,
) -> Result<Option<UserWithSlug>, tokio_postgres::Error> {
    let user = match pg::find_user_by(pg, login_sql::USER_BY_GOOGLE_SUB, b.google_sub.clone())
        .await?
    {
        Some(u) => u,
        None => {
            // 移植元と同じ: '@' の後ろ (無ければ "default")
            let email_domain = b.email.split('@').nth(1).unwrap_or("default").to_owned();
            let invitation = pg::find_invitation_by_email(pg, b.email.clone()).await?;
            let (tenant_id, role) = match &invitation {
                Some(inv) => (inv.tenant_id, inv.role.clone()),
                None => match pg::find_tenant_by_email_domain(pg, email_domain.clone()).await? {
                    Some(t) => (t, DOMAIN_ROLE.to_owned()),
                    None if state.staging_mode => {
                        let t = pg::create_tenant_with_domain(pg, email_domain).await?;
                        (state.log)("upsert-google: staging tenant created");
                        (t, DOMAIN_ROLE.to_owned())
                    }
                    None => return Ok(None),
                },
            };
            let user = pg::insert_user(
                pg,
                tenant_id,
                login_sql::INSERT_GOOGLE_USER,
                vec![b.google_sub, b.email, b.name, role],
            )
            .await?;
            // 招待を使い済みにする。失敗は握りつぶす (login は通す。移植元と同じ)
            if let Some(inv) = invitation {
                let _ = pg::delete_invitation(pg, inv).await;
            }
            user
        }
    };
    with_slug(pg, user).await.map(Some)
}

/// 会社の slug と権限を添える。ロールは user の会社の transaction で読む (admin は読まずに `*`)
async fn with_slug(pg: &mut PgClient, user: User) -> Result<UserWithSlug, tokio_postgres::Error> {
    let slug = pg::tenant_slug(pg, user.tenant_id).await?;
    let roles = if user.role == "admin" {
        Vec::new()
    } else {
        pg::roles_of_user(pg, user.tenant_id, user.id).await?
    };
    let permissions = permissions_for(&user.role, &roles);
    Ok(UserWithSlug {
        user,
        slug,
        permissions,
    })
}

/// LINE・LINE WORKS の 1 つの id で既存の user を引き、無ければ body の会社に viewer で作る (STAGING_MODE なら先に
/// 会社を在らせる)。`texts[0]` が逆引きの鍵 (id)。既存の user は会社も role も変えずに返す
async fn upsert_by_id(
    state: &InternalState,
    pg: &mut PgClient,
    tenant_id: Uuid,
    find_sql: &'static str,
    insert_sql: &'static str,
    texts: Vec<String>,
) -> Result<UserWithSlug, tokio_postgres::Error> {
    if state.staging_mode {
        pg::ensure_tenant(pg, tenant_id).await?;
    }
    let user = match pg::find_user_by(pg, find_sql, texts[0].clone()).await? {
        Some(u) => u,
        None => pg::insert_user(pg, tenant_id, insert_sql, texts).await?,
    };
    with_slug(pg, user).await
}

async fn upsert_lineworks(State(state): State<InternalState>, body: axum::body::Body) -> Response {
    let b: UpsertLineworksBody = match read_json(body).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let texts = vec![b.lineworks_id, b.email, b.name];
    match upsert_by_id(
        &state,
        &mut *state.pg.lock().await,
        b.tenant_id,
        login_sql::USER_BY_LINEWORKS_ID,
        login_sql::INSERT_LINEWORKS_USER,
        texts,
    )
    .await
    {
        Ok(u) => Json(u).into_response(),
        Err(e) => db_error(&state, "upsert-lineworks", &e),
    }
}

async fn upsert_line(State(state): State<InternalState>, body: axum::body::Body) -> Response {
    let b: UpsertLineBody = match read_json(body).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    match upsert_by_id(
        &state,
        &mut *state.pg.lock().await,
        b.tenant_id,
        login_sql::USER_BY_LINE_USER_ID,
        login_sql::INSERT_LINE_USER,
        vec![b.line_user_id, b.name],
    )
    .await
    {
        Ok(u) => Json(u).into_response(),
        Err(e) => db_error(&state, "upsert-line", &e),
    }
}

/// LINE の user id で user を引く。無ければ 200 `null` (移植元と同じ。404 にしない)
async fn user_by_line_id(
    State(state): State<InternalState>,
    query: Result<Query<ByLineIdQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(q)) = query else {
        return error(StatusCode::BAD_REQUEST, "invalid_query");
    };
    let pg = &mut *state.pg.lock().await;
    let found = match pg::find_user_by(pg, login_sql::USER_BY_LINE_USER_ID, q.line_user_id).await {
        Ok(Some(u)) => with_slug(pg, u).await.map(Some),
        other => other.map(|_| None),
    };
    match found {
        Ok(u) => Json::<Option<UserWithSlug>>(u).into_response(),
        Err(e) => db_error(&state, "users/by-line-id", &e),
    }
}

async fn register_line_recipient(
    State(state): State<InternalState>,
    body: axum::body::Body,
) -> Response {
    let b: RegisterLineRecipientBody = match read_json(body).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    match pg::register_line_recipient(
        &mut *state.pg.lock().await,
        b.tenant_id,
        b.name,
        b.line_user_id,
    )
    .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => db_error(&state, "recipients/register-line", &e),
    }
}

async fn recipients_by_line_id(
    State(state): State<InternalState>,
    query: Result<Query<ByLineIdQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(q)) = query else {
        return error(StatusCode::BAD_REQUEST, "invalid_query");
    };
    match pg::find_recipients_by_line_user_id(&mut *state.pg.lock().await, q.line_user_id).await {
        Ok(rows) => Json::<Vec<RecipientTenant>>(rows).into_response(),
        Err(e) => db_error(&state, "recipients/by-line-id", &e),
    }
}

async fn refresh_token(State(state): State<InternalState>, body: axum::body::Body) -> Response {
    let b: RefreshTokenBody = match read_json(body).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    match pg::save_refresh_token(
        &mut *state.pg.lock().await,
        b.user_id,
        b.refresh_hash,
        b.expires_at,
    )
    .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => db_error(&state, "refresh-token", &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_mode_is_only_1_and_never_on_hyperdrive() {
        assert_eq!(staging_mode(Some("1"), false), Ok(true));
        assert_eq!(staging_mode(None, false), Ok(false));
        assert_eq!(staging_mode(Some("true"), false), Ok(false));
        assert_eq!(staging_mode(Some(""), false), Ok(false));
        assert_eq!(staging_mode(None, true), Ok(false));
        assert_eq!(staging_mode(Some("0"), true), Ok(false));
        assert!(staging_mode(Some("1"), true).is_err());
    }
}
