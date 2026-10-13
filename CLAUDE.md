# alc-auth-worker

機械用資格情報 (と、後でログイン) の内部口の Worker (Refs ohishi-exp/rust-leave-worker#1)。型は ippoan/rust-leave-worker と同じ。
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
- 口は `/internal/machine-credentials…` の 4 本だけ (`crates/auth/src/internal.rs`)。**全部 (と当たらない path) を共有 secret
  (`X-Internal-Shared-Secret`、constant-time 比較) で守り、一致しなければ 404** (本文は空)。tenant は body / query で受ける。
- **暗号処理を持たない**: パスワードの生成・hash の計算・照合の比較は auth-worker 側。ここは受け取った `secret_hash` を保存して返すだけ。
- 会社をまたぐのは照合 (`GET …/{username}`) だけで、`tenant_tx(Uuid::nil())` の中で SECURITY DEFINER の
  `machine_credential_lookup()` だけを呼ぶ。ほかの文は `tenant_tx(<会社>)` の中で WHERE / VALUES にも tenant_id を明示する。
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
- 応答・ログには固定の語だけ (username・hash・secret・生のエラー文を出さない)。
- `coverage_100.toml` の登録を外さない。CI の本数 (lib 7・api_db 13) はテストを足したら上げる。
- public repo: ホスト名・tenant UUID・個人情報を書かない。`v*` タグ = 本番 (Tag Release 手動)。
- kit の rev は直下 `Cargo.toml` の 1 か所 (ippoan/rust-leave-worker と同じ rev)。
