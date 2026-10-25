//! alc-auth-worker の口の crate (Refs ohishi-exp/rust-leave-worker#1)。接続は持たない (worker が
//! [`internal::InternalState`] に差す)。
//!
//! - [`internal`] — 機械用資格情報の内部口 (共有 secret で守り、一致しなければ 404)
//! - [`login`] — ログインの内部口 (Google・LINE・LINE WORKS・refresh token・SSO 設定・LINE の受信者。同じ router・同じ共有 secret)
//! - [`roles`] — ロールの付け外しの口とロール → 権限の対応 (同じ router・同じ共有 secret)
//! - [`admin`] — 会社の管理の口 (ユーザー・招待・SSO 設定・参加の申請。同じ router・同じ共有 secret)
//! - [`creds`] — 入力の検証と応答の形 (純粋関数)
//! - [`secret`] — 共有 secret の constant-time 比較
//! - [`pg`] — SQL を流す 1 か所 (`tenant_tx` + `query_typed` 系だけ)

pub mod admin;
pub mod creds;
pub mod internal;
pub mod login;
pub mod pg;
pub mod roles;
pub mod secret;
pub mod session;

pub use internal::{internal_router, InternalState, LogSink};
