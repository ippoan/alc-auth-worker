# alc-auth-worker

機械用資格情報とログイン (Google・LINE・LINE WORKS・refresh token・SSO 設定・LINE の受信者) の内部口の Worker (Refs ohishi-exp/rust-leave-worker#1)。型は ippoan/rust-leave-worker と同じ。
直下 = Worker (wasm 専用)、`crates/auth/` = 口と検証。auth-worker (TS) から Service Binding でだけ呼ばれる。

## コマンド
```bash
bash scripts/check-exposure.sh && bash scripts/check-exposure-test.sh
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --target wasm32-unknown-unknown --release -- -D warnings
bash scripts/fetch-migrations.sh   # 版は scripts/ALC_MIGRATIONS_REV
AUTH_TEST_ADMIN_DATABASE_URL=postgresql://postgres:<pw>@127.0.0.1:<port>/postgres cargo test --workspace
worker-build --release && npx wrangler@4.144.0 deploy --dry-run
```
DB テストは使い捨ての postgres:17 へ。URL が無ければ失敗 (skip しない)。

## 規範
- 口は `/internal/machine-credentials…` の 5 本 (`crates/auth/src/internal.rs`) と、ログインの `/internal/auth/…` の 8 本
  (sso-config・users/upsert-google・refresh-token・users/upsert-lineworks・users/upsert-line・users/by-line-id・
  recipients/register-line・recipients/by-line-id。`crates/auth/src/login.rs`。返す JSON の形は移植元 rust-alc-api と同じ。
  users/by-line-id の無しは 200 `null`)。
  **全部 (と当たらない path) を共有 secret
  (`X-Internal-Shared-Secret`、constant-time 比較) で守り、一致しなければ 404** (本文は空)。tenant は body / query で受ける。
- **暗号処理を持たない**: パスワードの生成・hash の計算・照合の比較・Google の ID token の検証は auth-worker 側。
  ここは受け取った `secret_hash` / refresh token の hash を保存して返すだけ。
- 会社が決まる前の文は `tenant_tx(Uuid::nil())` の中で SECURITY DEFINER の関数 (`machine_credential_lookup()`・
  `find_user_by_google_sub()`・`find_user_by_lineworks_id()`・`find_user_by_line_user_id()`・`find_invitation_by_email()`・
  `find_recipient_by_line_user_id()`・`save_user_refresh_token()`・`resolve_sso_config()`) と、
  RLS の無い `tenants` の SELECT / INSERT だけ。ほかの文は `tenant_tx(<会社>)` の中で WHERE / VALUES にも tenant_id を明示する。
- role: Google の新規は招待の role、招待が無ければ admin (email_domain の一致・staging の作成)。LINE・LINE WORKS の新規は
  **viewer 固定**、既存の user は role も会社も変えない。取り違えるとテストが落ちる。
- 会社の自動作成 (Google の staging の作成・LINE / LINE WORKS の body の会社を在らせる) は `STAGING_MODE = "1"` のときだけ。**`wrangler.toml` の `[env.staging.vars]` にだけ**置く
  (トップレベル・他の env は `check-exposure.sh` が落とす)。Hyperdrive の段 (本番) で有効なら全部の口が 500 (`src/lib.rs`)。
- 公開範囲を弱めない: 本番・staging とも Service Binding だけ (どの env も `workers_dev`/`preview_urls` = false、route 無し)。
- DB の経路 (`src/db.rs`、上から見て最初にあるもの): staging は **DO の binding `STAGING_DB`** (別 Worker
  `alc-staging-db-staging` の `StagingDb` = PGlite。user は本番と同じ `alc_api_rt`) → 本番 Hyperdrive `AUTH_HYPERDRIVE`
  (設定は共有。新しい設定を作らない) → ローカル `DATABASE_URL`。VPC の段は持たない。
  binding が在るのに繋がらないときは次の段へ落とさず 500。DO の binding は **env.staging に 1 件だけ**
  (name/class_name/script_name 完全一致。トップレベル・他の env・migrations は禁止。`check-exposure.sh`)。
  Hyperdrive は本番だけ。`wrangler.toml` の表の順を変えない (新しい表は placement より後)。
- `INTERNAL_SHARED_SECRET` は既存の Secrets Store の secret を再利用する (secret を増やさない)。
- DB は `PgClient::tenant_tx` + `query_typed` 系だけ。SQL は `crates/auth/src/pg.rs` の 1 か所。
  名前付き prepared statement 禁止 (tests/ の superuser の側も `batch_execute` と `query_typed` だけ)。
- 応答・ログには固定の語だけ (username・email・hash・secret・生のエラー文を出さない)。
- `coverage_100.toml` の登録を外さない。CI の本数 (lib 9・api_db 32) はテストを足したら上げる。
- public repo: ホスト名・tenant UUID・個人情報を書かない。`v*` タグ = 本番 (Tag Release 手動)。
- kit の rev は直下 `Cargo.toml` の 1 か所 (ippoan/rust-leave-worker と同じ rev)。
