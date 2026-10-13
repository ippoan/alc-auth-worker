//! 機械用資格情報 (と、後でログイン) の内部口の Worker (Refs ohishi-exp/rust-leave-worker#1)。crates/auth の口
//! (`internal_router`、axum) を workers-rs (`http` / `axum` feature) に載せる。型は ippoan/rust-leave-worker・
//! ippoan/alc-vein-worker と同じ。DB への経路 (staging = alc-staging-db の DO、本番 = Hyperdrive) は
//! [`db::connect`] の 1 か所で出し分ける。
//!
//! **入口は auth-worker からの Service Binding だけ** (本番・staging とも `workers_dev` / `preview_urls` = false、
//! `routes` を持たない。wrangler.toml と scripts/check-exposure.sh が保証する)。口はすべて `/internal/…` で、
//! 共有 secret (`X-Internal-Shared-Secret`) が一致しなければ 404 (crates/auth の `internal`)。

// worker 本体は wasm32 専用。native の `cargo build` / `clippy` / `test` (workspace の root で打つもの) では空の crate にして、
// crates/auth だけを検査させる
#![cfg(target_arch = "wasm32")]

mod db;

use std::sync::Arc;

use auth::login::staging_mode;
use auth::{internal_router, InternalState, LogSink};
use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode};
use futures_util::lock::Mutex;
use tower_service::Service;
use worker::{console_error, event, Context, Env, HttpRequest, Result, WorkerVersionMetadata};

/// 内部口の共有 secret (Secrets Store の binding。`.get()` で実値にする)
const INTERNAL_SECRET_BINDING: &str = "INTERNAL_SHARED_SECRET";
/// Google の初回ログインで会社を作ってよいか (`"1"` で有効)。wrangler.toml の `[env.staging.vars]` にだけ置く
/// (scripts/check-exposure.sh が検査する)。Hyperdrive の段 (本番) で有効なら全部の口を 500 にする
const STAGING_MODE_VAR: &str = "STAGING_MODE";

/// 共有 secret の実値。取れなければ `None` (口は全部 404)
async fn internal_secret(env: &Env) -> Option<Arc<str>> {
    let store = env.secret_store(INTERNAL_SECRET_BINDING).ok()?;
    match store.get().await {
        Ok(Some(v)) => Some(Arc::from(v)),
        _ => {
            console_error!("auth: no {INTERNAL_SECRET_BINDING} value");
            None
        }
    }
}

fn log_sink() -> LogSink {
    Arc::new(|message| console_error!("auth: {message}"))
}

fn error_response(status: StatusCode, code: &str) -> Response<Body> {
    let mut resp = Response::new(Body::from(format!(r#"{{"error":"{code}"}}"#)));
    *resp.status_mut() = status;
    resp
}

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, _ctx: Context) -> Result<Response<Body>> {
    // 全リクエストで routing の前に繋ぐ (ippoan/rust-leave-worker と同じ)
    let db::Connected {
        client: pg,
        via_hyperdrive,
    } = match db::connect(&env).await {
        Ok(c) => c,
        Err(db::ConnectError::NotConfigured) => {
            console_error!("auth: {}", db::ConnectError::NotConfigured);
            return Ok(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "database_not_configured",
            ));
        }
        Err(e) => {
            console_error!("auth: {e}");
            return Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ));
        }
    };
    let staging_var = env.var(STAGING_MODE_VAR).ok().map(|v| v.to_string());
    let staging_mode = match staging_mode(staging_var.as_deref(), via_hyperdrive) {
        Ok(on) => on,
        Err(e) => {
            console_error!("auth: {e}");
            return Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ));
        }
    };
    let state = InternalState {
        pg: Arc::new(Mutex::new(pg)),
        secret: internal_secret(&env).await,
        log: log_sink(),
        staging_mode,
    };
    let mut resp = match internal_router(state).call(req).await {
        Ok(r) => r,
        Err(e) => match e {},
    };
    // どの版が応えたかを応答ヘッダーで分かるようにする。binding が取れなければ何も付けない
    if let Ok(meta) = env.get_binding::<WorkerVersionMetadata>("CF_VERSION_METADATA") {
        if let Ok(v) = HeaderValue::from_str(&meta.id()) {
            resp.headers_mut().insert("x-worker-version", v);
        }
        let tag = meta.tag();
        if !tag.is_empty() {
            if let Ok(v) = HeaderValue::from_str(&tag) {
                resp.headers_mut().insert("x-worker-tag", v);
            }
        }
    }
    Ok(resp)
}
