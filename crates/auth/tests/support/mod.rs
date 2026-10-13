//! 実 DB のテストの準備・接続 (ippoan/rust-leave-worker の tests/support/mod.rs の型。元は ippoan/alc-vein-worker の
//! tests/embedded/mod.rs と ippoan/alc-worker-kit の tests/support)。
//!
//! - **`AUTH_TEST_ADMIN_DATABASE_URL` が未設定なら失敗する** (skip して緑にしない)。値は準備用の superuser の
//!   接続文字列で、**使い捨ての DB (database 名 `postgres`) に向けること** (ロール・schema・全 migration を作る)。表示はしない
//! - 準備の SQL は ippoan/alc-migrations から版を固定して取る (`scripts/ALC_MIGRATIONS_REV`、
//!   `bash scripts/fetch-migrations.sh` が repo 直下の `.alc-migrations/` に取り出す)。**rev を書くのはそのファイルだけ**。
//!   流す順は init_local_db.sql → 空の `_sqlx_migrations` → migrations (1 ファイル 1 transaction) → local_app_grants.sql
//!   (alc-vein-worker の container/start.sh と同じ)
//! - 本体のテストは、表の所有者ではない・`NOSUPERUSER`・`NOBYPASSRLS` の `alc_api_app` で繋ぐ ([`app_client`] が毎回確かめる)。
//!   [`APP_PASSWORD`] は使い捨ての DB 専用の固定の文字列で、秘密ではない
//! - superuser の側も名前付き prepared statement を作らない (`batch_execute` と `query_typed` だけ)

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};

use alc_worker_db::PgClient;
use auth::internal::SECRET_HEADER;
use auth::{internal_router, InternalState};
use axum::body::Body;
use axum::http::Request;
use axum::Router;
use futures_util::lock::Mutex;
use tokio::sync::OnceCell;
use tokio_postgres::{Client, Config, NoTls};
use tower::ServiceExt;
use uuid::Uuid;

pub const ADMIN_URL_ENV: &str = "AUTH_TEST_ADMIN_DATABASE_URL";
pub const APP_ROLE: &str = "alc_api_app";
/// 使い捨ての DB 専用 (秘密ではない)
pub const APP_PASSWORD: &str = "auth-test-app-throwaway";
/// テストの共有 secret (使い捨てで、秘密ではない)
pub const SECRET: &str = "auth-test-internal-secret";
const SEARCH_PATH: &str = "-c search_path=alc_api,public";
/// 準備を直列にする advisory lock の鍵 (並列に走るテストの binary どうし)
const PREPARE_LOCK: i64 = 1_016_001;

fn migrations_dir() -> PathBuf {
    let dir = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.alc-migrations"
    ));
    assert!(
        dir.join("migrations").is_dir(),
        ".alc-migrations が無い。先に `bash scripts/fetch-migrations.sh` を流す"
    );
    dir
}

pub fn admin_config() -> Config {
    let url = std::env::var(ADMIN_URL_ENV).unwrap_or_else(|_| {
        panic!("{ADMIN_URL_ENV} が未設定。実 DB のテストは接続先が無ければ失敗させる (skip しない)")
    });
    url.parse()
        .unwrap_or_else(|_| panic!("{ADMIN_URL_ENV} が接続文字列として読めない"))
}

async fn raw_connect(config: &Config) -> Client {
    let (client, connection) = config
        .connect(NoTls)
        .await
        .unwrap_or_else(|_| panic!("{ADMIN_URL_ENV} の DB に繋げない"));
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

/// superuser の接続 (準備と、会社の作成・削除だけに使う)
pub async fn admin() -> Client {
    let mut config = admin_config();
    config.options(SEARCH_PATH);
    raw_connect(&config).await
}

/// 1 行 1 列の bool を名前なしの文で読む
async fn bool_of(client: &Client, sql: &str) -> bool {
    client.query_typed(sql, &[]).await.unwrap()[0].get(0)
}

/// 準備をプロセスの中で 1 回だけ流す。DB に既に `machine_credentials` が在れば (別の binary が流した) 何もしない
pub async fn prepare() {
    static PREPARED: OnceCell<()> = OnceCell::const_new();
    PREPARED
        .get_or_init(|| async {
            let su = admin().await;
            su.batch_execute(&format!("SELECT pg_advisory_lock({PREPARE_LOCK})"))
                .await
                .unwrap();
            let done = bool_of(
                &su,
                "SELECT to_regclass('alc_api.machine_credentials') IS NOT NULL",
            )
            .await;
            if !done {
                migrate(&su).await;
            }
            su.batch_execute(&format!("SELECT pg_advisory_unlock({PREPARE_LOCK})"))
                .await
                .unwrap();
            eprintln!("[auth-db] 実 DB で準備済み (migrations は {})", rev());
        })
        .await;
}

fn rev() -> String {
    std::fs::read_to_string(migrations_dir().join(".rev"))
        .unwrap()
        .trim()
        .to_owned()
}

async fn migrate(su: &Client) {
    let dir = migrations_dir();
    let read = |p: PathBuf| std::fs::read_to_string(p).unwrap();
    su.batch_execute(&read(dir.join("scripts/init_local_db.sql")))
        .await
        .unwrap();
    su.batch_execute("CREATE TABLE IF NOT EXISTS alc_api._sqlx_migrations (version BIGINT PRIMARY KEY, description TEXT NOT NULL, installed_on TIMESTAMPTZ NOT NULL DEFAULT now(), success BOOLEAN NOT NULL, checksum BYTEA NOT NULL, execution_time BIGINT NOT NULL)")
        .await
        .unwrap();
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir.join("migrations"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    files.sort();
    assert!(
        files.iter().any(|f| f
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with("_machine_credentials.sql")),
        "取り出した migrations に machine_credentials (173) が無い (scripts/ALC_MIGRATIONS_REV が古い)"
    );
    for file in files {
        let name = file.file_name().unwrap().to_owned();
        if let Err(e) = su
            .batch_execute(&format!("BEGIN;\n{}\n;COMMIT;", read(file)))
            .await
        {
            panic!("migration {name:?}: {:?}", e.code());
        }
    }
    su.batch_execute(&read(dir.join("scripts/local_app_grants.sql")))
        .await
        .unwrap();
    su.batch_execute(&format!(
        "ALTER ROLE {APP_ROLE} LOGIN PASSWORD '{APP_PASSWORD}'"
    ))
    .await
    .unwrap();
}

/// `alc_api_app` の接続 (worker と同じく `PgClient` に包む)。**superuser / BYPASSRLS / 表の所有者なら panic**
pub async fn app_client() -> PgClient {
    prepare().await;
    let mut config = admin_config();
    config.user(APP_ROLE).password(APP_PASSWORD);
    let client = raw_connect(&config).await;
    assert!(
        !bool_of(
            &client,
            "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user"
        )
        .await,
        "RLS を素通りするロールで繋いでいる"
    );
    assert!(
        !bool_of(
            &client,
            "SELECT tableowner = current_user FROM pg_tables \
             WHERE schemaname = 'alc_api' AND tablename = 'machine_credentials'"
        )
        .await,
        "表の所有者で繋いでいる"
    );
    PgClient::new(client)
}

/// 会社を 1 つ作る (superuser で。名前は乱数)
pub async fn tenant() -> Uuid {
    prepare().await;
    let id = Uuid::new_v4();
    admin()
        .await
        .batch_execute(&format!(
            "INSERT INTO alc_api.tenants (id, name) VALUES ('{id}', 'auth-test-{id}')"
        ))
        .await
        .unwrap();
    id
}

/// 会社を消す (superuser で。資格情報は ON DELETE CASCADE で消える)
pub async fn delete_tenant(id: Uuid) {
    admin()
        .await
        .batch_execute(&format!("DELETE FROM alc_api.tenants WHERE id = '{id}'"))
        .await
        .unwrap();
}

/// 乱数の username (`mc_` + 16 hex)
pub fn username() -> String {
    format!("mc_{}", &Uuid::new_v4().simple().to_string()[..16])
}

pub struct App {
    pub router: Router,
    pub logs: Arc<StdMutex<Vec<String>>>,
}

fn build(pg: PgClient, secret: Option<&str>) -> App {
    let logs = Arc::new(StdMutex::new(Vec::new()));
    let sink = logs.clone();
    let state = InternalState {
        pg: Arc::new(Mutex::new(pg)),
        secret: secret.map(Arc::from),
        log: Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_owned())),
    };
    App {
        router: internal_router(state),
        logs,
    }
}

/// 共有 secret が [`SECRET`] の口
pub async fn app() -> App {
    build(app_client().await, Some(SECRET))
}

/// worker が Secrets Store から secret を取れなかったときの口 (全部 404 になるはず)
pub async fn app_without_secret() -> App {
    build(app_client().await, None)
}

/// 接続が切れた口 (DB の失敗 = 500 の経路を通す)。superuser が backend を終わらせる
pub async fn broken_app() -> App {
    let mut pg = app_client().await;
    let pid = pg
        .tenant_tx(Uuid::nil(), move |tx| {
            Box::pin(async move {
                let row = tx.query_typed_one("SELECT pg_backend_pid()", &[]).await?;
                Ok(row.get::<_, i32>(0))
            })
        })
        .await
        .unwrap();
    assert!(
        bool_of(
            &admin().await,
            &format!("SELECT pg_terminate_backend({pid})")
        )
        .await
    );
    build(pg, Some(SECRET))
}

pub struct Got {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Got {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// 1 リクエストを打つ。`secret` が `None` なら共有 secret のヘッダーを付けない。`body` は生の bytes
pub async fn call_raw(
    app: &App,
    method: &str,
    uri: &str,
    secret: Option<&str>,
    body: Option<Vec<u8>>,
) -> Got {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(s) = secret {
        b = b.header(SECRET_HEADER, s);
    }
    let body = match body {
        Some(v) => {
            b = b.header("content-type", "application/json");
            Body::from(v)
        }
        None => Body::empty(),
    };
    let resp = app
        .router
        .clone()
        .oneshot(b.body(body).unwrap())
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    Got { status, body }
}

/// 正しい共有 secret 付きで 1 リクエストを打つ
pub async fn call(app: &App, method: &str, uri: &str, body: Option<serde_json::Value>) -> Got {
    call_raw(
        app,
        method,
        uri,
        Some(SECRET),
        body.map(|v| serde_json::to_vec(&v).unwrap()),
    )
    .await
}
