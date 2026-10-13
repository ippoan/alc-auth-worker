//! alc-auth-worker の口の crate (Refs ohishi-exp/rust-leave-worker#1)。接続は持たない (worker が
//! [`internal::InternalState`] に差す)。
//!
//! - [`internal`] — 機械用資格情報の内部口 (共有 secret で守り、一致しなければ 404)
//! - [`login`] — ログインの内部口 (Google・refresh token・SSO 設定。同じ router・同じ共有 secret)
//! - [`creds`] — 入力の検証と応答の形 (純粋関数)
//! - [`secret`] — 共有 secret の constant-time 比較
//! - [`pg`] — SQL を流す 1 か所 (`tenant_tx` + `query_typed` 系だけ)

pub mod creds;
pub mod internal;
pub mod login;
pub mod pg;
pub mod secret;

pub use internal::{internal_router, InternalState, LogSink};
