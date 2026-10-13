//! SQL を流す 1 か所。すべて `PgClient::tenant_tx` (transaction 単位の RLS) の中で、型付きの名前なしの文
//! (`query_typed` 系・`execute_typed`) だけを使う (Hyperdrive 経由では名前付き prepared statement で接続が切れる)。
//! RLS に加えて、会社の中の文は `tenant_id = <会社>` を WHERE / VALUES に明示する (所有者で繋いだときの備え)。

use alc_worker_db::{PgClient, TxOutput};
use chrono::{DateTime, Utc};
use futures_util::future::BoxFuture;
use serde::Serialize;
use tokio_postgres::error::SqlState;
use tokio_postgres::types::Type;
use tokio_postgres::{Error, Row};
use uuid::Uuid;

use crate::creds::{CreateInput, Lookup, Summary};

pub mod sql {
    pub const INSERT: &str = "INSERT INTO alc_api.machine_credentials \
         (username, tenant_id, purpose, label, secret_hash) VALUES ($1, $2, $3, $4, $5)";

    /// `$2` が NULL なら全用途。作った順 (同時刻は username 順)
    pub const LIST: &str = "SELECT username, purpose, label, created_at, revoked_at IS NOT NULL \
         FROM alc_api.machine_credentials \
         WHERE tenant_id = $1 AND ($2::text IS NULL OR purpose = $2) \
         ORDER BY created_at, username";

    /// 既に失効していれば revoked_at を変えない (行は当たるので 1 件)
    pub const REVOKE: &str = "UPDATE alc_api.machine_credentials \
         SET revoked_at = COALESCE(revoked_at, NOW()) WHERE username = $1 AND tenant_id = $2";

    /// 会社をまたぐ照合 (SECURITY DEFINER の関数。ippoan/alc-migrations の 173)
    pub const LOOKUP: &str = "SELECT tenant_id, purpose, secret_hash, revoked \
         FROM alc_api.machine_credential_lookup($1)";
}

impl TxOutput for Summary {}
impl TxOutput for Lookup {}

/// 1 行を入れる。username の重複は 23505、会社が無いのは 23503 (呼び手が SQLSTATE で出し分ける)
pub async fn insert(pg: &mut PgClient, c: CreateInput) -> Result<u64, Error> {
    pg.tenant_tx(c.tenant_id, move |tx| {
        Box::pin(async move {
            tx.execute_typed(
                sql::INSERT,
                &[
                    (&c.username, Type::TEXT),
                    (&c.tenant_id, Type::UUID),
                    (&c.purpose, Type::TEXT),
                    (&c.label, Type::TEXT),
                    (&c.secret_hash, Type::TEXT),
                ],
            )
            .await
        })
    })
    .await
}

pub async fn list(
    pg: &mut PgClient,
    tenant_id: Uuid,
    purpose: Option<String>,
) -> Result<Vec<Summary>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let rows = tx
                .query_typed(
                    sql::LIST,
                    &[(&tenant_id, Type::UUID), (&purpose, Type::TEXT)],
                )
                .await?;
            Ok(rows
                .iter()
                .map(|r| Summary {
                    username: r.get(0),
                    purpose: r.get(1),
                    label: r.get(2),
                    created_at: r.get(3),
                    revoked: r.get(4),
                })
                .collect())
        })
    })
    .await
}

/// 失効させる。その会社に無ければ false
pub async fn revoke(pg: &mut PgClient, tenant_id: Uuid, username: String) -> Result<bool, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let n = tx
                .execute_typed(
                    sql::REVOKE,
                    &[(&username, Type::TEXT), (&tenant_id, Type::UUID)],
                )
                .await?;
            Ok(n > 0)
        })
    })
    .await
}

/// username で 1 行 (会社をまたぐ)。会社が決まる前の照会なので nil の tenant の transaction で、
/// SECURITY DEFINER の関数だけを呼ぶ (ippoan/rust-leave-worker の `resolve_mailbox` と同じ形。
/// nil UUID はどの会社にも当たらない値で、RLS の表は 1 行も見えない)
pub async fn lookup(pg: &mut PgClient, username: String) -> Result<Option<Lookup>, Error> {
    pg.tenant_tx(Uuid::nil(), move |tx| {
        Box::pin(async move {
            let row = tx
                .query_typed_opt(sql::LOOKUP, &[(&username, Type::TEXT)])
                .await?;
            Ok(row.map(|r| Lookup {
                tenant_id: r.get(0),
                purpose: r.get(1),
                secret_hash: r.get(2),
                revoked: r.get(3),
            }))
        })
    })
    .await
}

// ---------- ログイン (Google・refresh token・SSO 設定) の部品。LINE 系の口 (後続) も使う ----------
//
// 会社が決まる前の照会 (users / 招待の逆引き・SSO 設定・refresh token の保存) は、上の `lookup` と同じく
// nil の tenant の transaction で SECURITY DEFINER の関数だけを呼ぶ。tenants は RLS の無い表で、email_domain での
// 照会と staging の会社の作成も nil の transaction で流す。users の INSERT・招待の DELETE・slug の取得は、
// その会社の transaction で tenant_id を VALUES / WHERE に明示する。

/// users の行のうち口が返す 8 列 (hash・refresh token の列は読まない)。順は [`user`] の map と同じ
macro_rules! user_columns {
    () => {
        "id, tenant_id, email, name, role, google_sub, lineworks_id, line_user_id"
    };
}

pub mod login_sql {
    /// Google の sub で users を逆引き (SECURITY DEFINER。ippoan/alc-migrations の 158)
    pub const USER_BY_GOOGLE_SUB: &str = concat!(
        "SELECT ",
        user_columns!(),
        " FROM alc_api.find_user_by_google_sub($1)"
    );

    /// 招待を email で逆引き (SECURITY DEFINER。158。email は一意)
    pub const INVITATION_BY_EMAIL: &str =
        "SELECT id, tenant_id, role FROM alc_api.find_invitation_by_email($1)";

    /// 招待を消す (使い済み)
    pub const DELETE_INVITATION: &str =
        "DELETE FROM alc_api.tenant_allowed_emails WHERE id = $1 AND tenant_id = $2";

    /// email_domain が一致する会社 (email_domain は一意でないので、作った順の最初の 1 つ)
    pub const TENANT_BY_EMAIL_DOMAIN: &str = "SELECT id FROM alc_api.tenants \
         WHERE email_domain = $1 ORDER BY created_at, id LIMIT 1";

    /// 会社を作る (staging だけ)。short_id は DEFAULT の乱数で、UNIQUE 違反なら呼び手が流し直す
    pub const INSERT_TENANT: &str =
        "INSERT INTO alc_api.tenants (name, email_domain) VALUES ($1, $1) RETURNING id";

    pub const TENANT_SLUG: &str = "SELECT slug FROM alc_api.tenants WHERE id = $1";

    pub const INSERT_GOOGLE_USER: &str = concat!(
        "INSERT INTO alc_api.users (tenant_id, google_sub, email, name, role) \
         VALUES ($1, $2, $3, $4, $5) RETURNING ",
        user_columns!()
    );

    /// refresh token の hash と期限を保存する (SECURITY DEFINER。158。引数は (user_id, hash, expires_at))
    pub const SAVE_REFRESH_TOKEN: &str = "SELECT alc_api.save_user_refresh_token($1, $2, $3)";

    /// SSO 設定 (SECURITY DEFINER。ippoan/alc-migrations の 174。external_org_id で完全一致し、
    /// 無ければ tenants.slug で引き直す)
    pub const RESOLVE_SSO_CONFIG: &str = "SELECT tenant_id, client_id, client_secret_encrypted, \
         external_org_id, woff_id FROM alc_api.resolve_sso_config($1, $2)";
}

/// users の 8 列 (auth-worker が JWT を組み立てる元。形は rust-alc-api の `InternalUser` と同じ)
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct User {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub name: String,
    pub role: String,
    pub google_sub: Option<String>,
    pub lineworks_id: Option<String>,
    pub line_user_id: Option<String>,
}

/// 招待 (tenant_allowed_emails) のうち口が使う列
#[derive(Debug, Clone, PartialEq)]
pub struct Invitation {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub role: String,
}

/// SSO 設定 (`client_secret_encrypted` は暗号化されたまま返す。復号は auth-worker 側)
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SsoConfig {
    pub tenant_id: Uuid,
    pub client_id: String,
    pub client_secret_encrypted: String,
    pub external_org_id: String,
    pub woff_id: Option<String>,
}

impl TxOutput for User {}
impl TxOutput for Invitation {}
impl TxOutput for SsoConfig {}

/// `user_columns!` の順の行を [`User`] にする
pub fn user(r: &Row) -> User {
    User {
        id: r.get(0),
        tenant_id: r.get(1),
        email: r.get(2),
        name: r.get(3),
        role: r.get(4),
        google_sub: r.get(5),
        lineworks_id: r.get(6),
        line_user_id: r.get(7),
    }
}

pub async fn find_user_by_google_sub(
    pg: &mut PgClient,
    google_sub: String,
) -> Result<Option<User>, Error> {
    pg.tenant_tx(Uuid::nil(), move |tx| {
        Box::pin(async move {
            let row = tx
                .query_typed_opt(login_sql::USER_BY_GOOGLE_SUB, &[(&google_sub, Type::TEXT)])
                .await?;
            Ok(row.as_ref().map(user))
        })
    })
    .await
}

pub async fn find_invitation_by_email(
    pg: &mut PgClient,
    email: String,
) -> Result<Option<Invitation>, Error> {
    pg.tenant_tx(Uuid::nil(), move |tx| {
        Box::pin(async move {
            let row = tx
                .query_typed_opt(login_sql::INVITATION_BY_EMAIL, &[(&email, Type::TEXT)])
                .await?;
            Ok(row.map(|r| Invitation {
                id: r.get(0),
                tenant_id: r.get(1),
                role: r.get(2),
            }))
        })
    })
    .await
}

/// 招待を消す (その会社の transaction で)。消えた行数を返す
pub async fn delete_invitation(pg: &mut PgClient, inv: Invitation) -> Result<u64, Error> {
    pg.tenant_tx(inv.tenant_id, move |tx| {
        Box::pin(async move {
            tx.execute_typed(
                login_sql::DELETE_INVITATION,
                &[(&inv.id, Type::UUID), (&inv.tenant_id, Type::UUID)],
            )
            .await
        })
    })
    .await
}

pub async fn find_tenant_by_email_domain(
    pg: &mut PgClient,
    email_domain: String,
) -> Result<Option<Uuid>, Error> {
    pg.tenant_tx(Uuid::nil(), move |tx| {
        Box::pin(async move {
            let row = tx
                .query_typed_opt(
                    login_sql::TENANT_BY_EMAIL_DOMAIN,
                    &[(&email_domain, Type::TEXT)],
                )
                .await?;
            Ok(row.map(|r| r.get(0)))
        })
    })
    .await
}

/// 会社を作る試行の回数 (short_id の衝突は続けて当たることが実質ない)
pub const TENANT_INSERT_ATTEMPTS: u32 = 16;

/// `f` を流し、UNIQUE 違反 (23505) なら `attempts` 回まで流し直す。最後の回の結果 (UNIQUE 違反を含む) と
/// UNIQUE 違反以外の結果はそのまま返す。`f` は毎回別の transaction を張る (失敗した transaction は使い回せない)
pub async fn retry_on_unique<T, F>(pg: &mut PgClient, attempts: u32, mut f: F) -> Result<T, Error>
where
    F: for<'a> FnMut(&'a mut PgClient) -> BoxFuture<'a, Result<T, Error>>,
{
    let mut left = attempts;
    loop {
        match f(pg).await {
            Err(e) if left > 1 && e.code() == Some(&SqlState::UNIQUE_VIOLATION) => left -= 1,
            r => return r,
        }
    }
}

/// email_domain を名前にした会社を作る (staging だけが呼ぶ)。short_id の衝突は
/// [`TENANT_INSERT_ATTEMPTS`] 回まで流し直す
pub async fn create_tenant_with_domain(
    pg: &mut PgClient,
    email_domain: String,
) -> Result<Uuid, Error> {
    retry_on_unique(pg, TENANT_INSERT_ATTEMPTS, |pg| {
        let email_domain = email_domain.clone();
        Box::pin(pg.tenant_tx(Uuid::nil(), move |tx| {
            Box::pin(async move {
                let row = tx
                    .query_typed_one(login_sql::INSERT_TENANT, &[(&email_domain, Type::TEXT)])
                    .await?;
                Ok(row.get(0))
            })
        }))
    })
    .await
}

/// 会社の slug (未設定・会社が無いは `None`)
pub async fn tenant_slug(pg: &mut PgClient, tenant_id: Uuid) -> Result<Option<String>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let row = tx
                .query_typed_opt(login_sql::TENANT_SLUG, &[(&tenant_id, Type::UUID)])
                .await?;
            Ok(row.and_then(|r| r.get(0)))
        })
    })
    .await
}

/// Google のログインで users の行を作る (その会社の transaction で)
pub async fn insert_google_user(
    pg: &mut PgClient,
    tenant_id: Uuid,
    google_sub: String,
    email: String,
    name: String,
    role: String,
) -> Result<User, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let row = tx
                .query_typed_one(
                    login_sql::INSERT_GOOGLE_USER,
                    &[
                        (&tenant_id, Type::UUID),
                        (&google_sub, Type::TEXT),
                        (&email, Type::TEXT),
                        (&name, Type::TEXT),
                        (&role, Type::TEXT),
                    ],
                )
                .await?;
            Ok(user(&row))
        })
    })
    .await
}

pub async fn save_refresh_token(
    pg: &mut PgClient,
    user_id: Uuid,
    refresh_hash: String,
    expires_at: DateTime<Utc>,
) -> Result<u64, Error> {
    pg.tenant_tx(Uuid::nil(), move |tx| {
        Box::pin(async move {
            tx.execute_typed(
                login_sql::SAVE_REFRESH_TOKEN,
                &[
                    (&user_id, Type::UUID),
                    (&refresh_hash, Type::TEXT),
                    (&expires_at, Type::TIMESTAMPTZ),
                ],
            )
            .await
        })
    })
    .await
}

pub async fn resolve_sso_config(
    pg: &mut PgClient,
    provider: String,
    domain: String,
) -> Result<Option<SsoConfig>, Error> {
    pg.tenant_tx(Uuid::nil(), move |tx| {
        Box::pin(async move {
            let row = tx
                .query_typed_opt(
                    login_sql::RESOLVE_SSO_CONFIG,
                    &[(&provider, Type::TEXT), (&domain, Type::TEXT)],
                )
                .await?;
            Ok(row.map(|r| SsoConfig {
                tenant_id: r.get(0),
                client_id: r.get(1),
                client_secret_encrypted: r.get(2),
                external_org_id: r.get(3),
                woff_id: r.get(4),
            }))
        })
    })
    .await
}
