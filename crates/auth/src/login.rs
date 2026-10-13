//! ログインの内部口 (auth-worker が Service Binding で呼ぶ。移植元は rust-alc-api の
//! `crates/alc-auth/src/internal.rs`。返す JSON の形は変えない — auth-worker が型で読む)。
//!
//! | method | path | 応答 |
//! |---|---|---|
//! | GET | `/internal/auth/sso-config?provider=…&domain=…` | 200 SSO 設定 / 404 `sso_config_not_found` / 400 |
//! | POST | `/internal/auth/users/upsert-google` | 200 user (8 列) + `slug` / 403 `no_tenant_for_email` / 400 |
//! | POST | `/internal/auth/refresh-token` | 204 / 400 |
//!
//! 共有 secret の照合は [`crate::internal`] の layer がこの口にも掛ける (一致しなければ本文の空の 404)。
//! Google の ID token の検証は auth-worker 側 (ここは検証済みの sub / email / name を受け取るだけ)。
//!
//! Google の初回ログインの会社は、招待 (email の完全一致) → email_domain の一致 → **STAGING_MODE のときだけ**
//! 会社を作る → それ以外は 403 の順に決める。role は招待の role、ほかは admin。
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
use crate::pg::{self, SsoConfig, User};

pub const SSO_CONFIG_PATH: &str = "/internal/auth/sso-config";
pub const UPSERT_GOOGLE_PATH: &str = "/internal/auth/users/upsert-google";
pub const REFRESH_TOKEN_PATH: &str = "/internal/auth/refresh-token";

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

/// JWT の組み立てに要る user と会社の slug (rust-alc-api の `InternalUserWithSlug` と同じ形)
#[derive(Debug, Serialize)]
pub struct UserWithSlug {
    #[serde(flatten)]
    pub user: User,
    pub slug: Option<String>,
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
    let user = match pg::find_user_by_google_sub(pg, b.google_sub.clone()).await? {
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
            let user =
                pg::insert_google_user(pg, tenant_id, b.google_sub, b.email, b.name, role).await?;
            // 招待を使い済みにする。失敗は握りつぶす (login は通す。移植元と同じ)
            if let Some(inv) = invitation {
                let _ = pg::delete_invitation(pg, inv).await;
            }
            user
        }
    };
    let slug = pg::tenant_slug(pg, user.tenant_id).await?;
    Ok(Some(UserWithSlug { user, slug }))
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
