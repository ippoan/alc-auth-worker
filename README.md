# alc-auth-worker

ログインの内部口と機械用資格情報を DB (alc_api) で扱う Rust の Cloudflare Worker。auth-worker から Service Binding でだけ呼ばれる (workers_dev = false、route なし)。

内部口: `/internal/machine-credentials…` 5 本、ログイン `/internal/auth/…` 8 本、ロール 3 本、staging の me・logout・my-orgs 用の 2 本
(`GET /internal/tenants/{tenant_id}`・`DELETE /internal/tenants/{tenant_id}/users/{user_id}/refresh-token`。auth-worker の me・logout・my-orgs)、会社の管理の 13 本 (ユーザー・招待・SSO 設定・参加の申請。rust-alc-api から移植、`crates/auth/src/admin.rs`)。全部 `X-Internal-Shared-Secret` で守り、不一致は 404 (本文は空)。

Refs ohishi-exp/rust-leave-worker#1
