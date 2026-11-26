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
use worker::js_sys::{Object, Reflect};
use worker::wasm_bindgen::JsValue;
use worker::{
    console_error, event, Context, Env, HttpRequest, Result, SecretStore, WorkerVersionMetadata,
};

/// 内部口の共有 secret (Secrets Store の binding。`.get()` で実値にする)
const INTERNAL_SECRET_BINDING: &str = "INTERNAL_SHARED_SECRET";
/// Google の初回ログインで会社を作ってよいか (`"1"` で有効)。wrangler.toml の `[env.staging.vars]` にだけ置く
/// (scripts/check-exposure.sh が検査する)。Hyperdrive の段 (本番) で有効なら全部の口を 500 にする
const STAGING_MODE_VAR: &str = "STAGING_MODE";

/// 共有 secret の実値。取れなければ `None` (口は全部 404)。
///
/// `env.secret_store()` は使わない: prod の新しい版では binding の constructor 名が `"ServiceStub"` になり、
/// workers-rs 0.8.7 の `get_binding` の `"Fetcher"` 検査で Err になった (Refs ohishi-exp/nuxt-dtako-admin#1287)。
/// env から binding を直接取り出し、文字列でも `.get()` を持つものでも受ける (auth-worker の TS の `resolveSecret` と同じ)。
/// ログは種類の語と constructor 名だけ (値・長さ・先頭・hash は出さない)
async fn internal_secret(env: &Env) -> Option<Arc<str>> {
    let raw = match Reflect::get(env.as_ref(), &JsValue::from_str(INTERNAL_SECRET_BINDING)) {
        Ok(v) => v,
        Err(_) => {
            console_error!("auth: secret binding: reflect failed");
            return None;
        }
    };
    if raw.is_undefined() || raw.is_null() {
        console_error!("auth: secret binding: undefined");
        return None;
    }
    if let Some(s) = raw.as_string() {
        if s.is_empty() {
            console_error!("auth: secret get: empty (string form)");
            return None;
        }
        return Some(Arc::from(s));
    }
    // 失敗のログにだけ添える (成功のたびには出さない)
    let ctor = || Object::from(raw.clone()).constructor().name();
    match SecretStore::from(raw.clone()).get().await {
        Ok(Some(v)) if !v.is_empty() => Some(Arc::from(v)),
        Ok(Some(_)) => {
            console_error!("auth: secret get: empty (ctor={})", ctor());
            None
        }
        Ok(None) => {
            console_error!("auth: secret get: none (ctor={})", ctor());
            None
        }
        Err(e) => {
            console_error!("auth: secret get: {e} (ctor={})", ctor());
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
