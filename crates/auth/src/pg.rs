//! SQL を流す 1 か所。すべて `PgClient::tenant_tx` (transaction 単位の RLS) の中で、型付きの名前なしの文
//! (`query_typed` 系・`execute_typed`) だけを使う (Hyperdrive 経由では名前付き prepared statement で接続が切れる)。
//! RLS に加えて、会社の中の文は `tenant_id = <会社>` を WHERE / VALUES に明示する (所有者で繋いだときの備え)。

use alc_worker_db::{PgClient, TxOutput};
use chrono::{DateTime, Utc};
use futures_util::future::BoxFuture;
use serde::Serialize;
use tokio_postgres::error::SqlState;
use tokio_postgres::types::{ToSql, Type};
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

    /// 失効していない行だけ hash を差し替える (0 行 = 失効済み・無い・他社)
    pub const ROTATE: &str = "UPDATE alc_api.machine_credentials SET secret_hash = $3 \
         WHERE username = $1 AND tenant_id = $2 AND revoked_at IS NULL";

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

/// secret_hash を差し替える。失効済み・無い・他社なら false
pub async fn rotate(
    pg: &mut PgClient,
    tenant_id: Uuid,
    username: String,
    secret_hash: String,
) -> Result<bool, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let n = tx
                .execute_typed(
                    sql::ROTATE,
                    &[
                        (&username, Type::TEXT),
                        (&tenant_id, Type::UUID),
                        (&secret_hash, Type::TEXT),
                    ],
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

// ---------- ログイン (Google・LINE・LINE WORKS・refresh token・SSO 設定・LINE の受信者) の部品 ----------
//
// 会社が決まる前の照会 (users / 招待 / 受信者の逆引き・SSO 設定・refresh token の保存) は、上の `lookup` と同じく
// nil の tenant の transaction で SECURITY DEFINER の関数だけを呼ぶ。tenants は RLS の無い表で、email_domain での
// 照会と staging の会社の作成も nil の transaction で流す。users・受信者の INSERT・招待の DELETE・slug の取得は、
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

    /// LINE WORKS の id で users を逆引き (SECURITY DEFINER。158)
    pub const USER_BY_LINEWORKS_ID: &str = concat!(
        "SELECT ",
        user_columns!(),
        " FROM alc_api.find_user_by_lineworks_id($1)"
    );

    /// LINE の user id で users を逆引き (SECURITY DEFINER。121)
    pub const USER_BY_LINE_USER_ID: &str = concat!(
        "SELECT ",
        user_columns!(),
        " FROM alc_api.find_user_by_line_user_id($1)"
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

    /// 会社を id で在らせる (staging の LINE・LINE WORKS だけ。名前は移植元と同じ。在れば何もしない)。
    /// short_id は DEFAULT の乱数で、UNIQUE 違反なら呼び手が流し直す
    pub const ENSURE_TENANT: &str = "INSERT INTO alc_api.tenants (id, name) \
         VALUES ($1, 'LINE WORKS (staging auto)') ON CONFLICT (id) DO NOTHING";

    /// 会社の 1 行 (me と slug。RLS の tenants_policy は自分の会社の行だけ見せる)
    pub const TENANT_ROW: &str =
        "SELECT id, name, slug, short_id FROM alc_api.tenants WHERE id = $1";

    pub const INSERT_GOOGLE_USER: &str = concat!(
        "INSERT INTO alc_api.users (tenant_id, google_sub, email, name, role) \
         VALUES ($1, $2, $3, $4, $5) RETURNING ",
        user_columns!()
    );

    /// LINE WORKS の新規は role を viewer に固定する (昇格は招待 / 権限変更の画面から。移植元と同じ)
    pub const INSERT_LINEWORKS_USER: &str = concat!(
        "INSERT INTO alc_api.users (tenant_id, lineworks_id, email, name, role) \
         VALUES ($1, $2, $3, $4, 'viewer') RETURNING ",
        user_columns!()
    );

    /// LINE の新規も viewer 固定。email は無いので LINE の user id を入れる (移植元と同じ)
    pub const INSERT_LINE_USER: &str = concat!(
        "INSERT INTO alc_api.users (tenant_id, line_user_id, email, name, role) \
         VALUES ($1, $2, $2, $3, 'viewer') RETURNING ",
        user_columns!()
    );

    /// LINE の受信者を登録する (同じ会社の同じ LINE の user id は何もしない)
    pub const REGISTER_LINE_RECIPIENT: &str =
        "INSERT INTO alc_api.notify_recipients (tenant_id, name, provider, line_user_id) \
         VALUES ($1, $2, 'line', $3) \
         ON CONFLICT (tenant_id, line_user_id) WHERE line_user_id IS NOT NULL DO NOTHING";

    /// LINE の user id で有効な受信者を会社をまたいで逆引き (SECURITY DEFINER。081。複数の会社に居れば全部)
    pub const RECIPIENTS_BY_LINE_USER_ID: &str =
        "SELECT tenant_id, recipient_name FROM alc_api.find_recipient_by_line_user_id($1)";

    /// refresh token の hash と期限を NULL に戻す (logout 用。その会社の transaction で)
    pub const CLEAR_REFRESH_TOKEN: &str = "UPDATE alc_api.users \
         SET refresh_token_hash = NULL, refresh_token_expires_at = NULL \
         WHERE id = $1 AND tenant_id = $2";

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

/// LINE の受信者の逆引きの 1 行 (rust-alc-api の `RecipientTenant` と同じ形)
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RecipientTenant {
    pub tenant_id: Uuid,
    pub name: String,
}

impl TxOutput for User {}
impl TxOutput for RecipientTenant {}
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

/// 会社をまたいで users を 1 つの鍵で逆引きする。`sql` は `login_sql::USER_BY_*` (SECURITY DEFINER の関数)
pub async fn find_user_by(
    pg: &mut PgClient,
    sql: &'static str,
    key: String,
) -> Result<Option<User>, Error> {
    pg.tenant_tx(Uuid::nil(), move |tx| {
        Box::pin(async move {
            let row = tx.query_typed_opt(sql, &[(&key, Type::TEXT)]).await?;
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

/// 会社を id で在らせる (staging だけが呼ぶ)。short_id の衝突は [`TENANT_INSERT_ATTEMPTS`] 回まで流し直す
pub async fn ensure_tenant(pg: &mut PgClient, tenant_id: Uuid) -> Result<u64, Error> {
    retry_on_unique(pg, TENANT_INSERT_ATTEMPTS, |pg| {
        Box::pin(pg.tenant_tx(Uuid::nil(), move |tx| {
            Box::pin(async move {
                tx.execute_typed(login_sql::ENSURE_TENANT, &[(&tenant_id, Type::UUID)])
                    .await
            })
        }))
    })
    .await
}

/// 会社の 1 行 (`GET /internal/tenants/{tenant_id}`。rust-alc-api の me が読む列)
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TenantRow {
    pub id: Uuid,
    pub name: String,
    pub slug: Option<String>,
    pub short_id: String,
}

impl TxOutput for TenantRow {}

/// 会社の 1 行 (会社が無ければ `None`。その会社の transaction で)
pub async fn tenant_row(pg: &mut PgClient, tenant_id: Uuid) -> Result<Option<TenantRow>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let row = tx
                .query_typed_opt(login_sql::TENANT_ROW, &[(&tenant_id, Type::UUID)])
                .await?;
            Ok(row.map(|r| TenantRow {
                id: r.get(0),
                name: r.get(1),
                slug: r.get(2),
                short_id: r.get(3),
            }))
        })
    })
    .await
}

/// 会社の slug (未設定・会社が無いは `None`)
pub async fn tenant_slug(pg: &mut PgClient, tenant_id: Uuid) -> Result<Option<String>, Error> {
    Ok(tenant_row(pg, tenant_id).await?.and_then(|t| t.slug))
}

/// user の refresh token (hash と期限) を消す。消した行数 (無ければ 0。その会社の transaction で)
pub async fn clear_refresh_token(
    pg: &mut PgClient,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<u64, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            tx.execute_typed(
                login_sql::CLEAR_REFRESH_TOKEN,
                &[(&user_id, Type::UUID), (&tenant_id, Type::UUID)],
            )
            .await
        })
    })
    .await
}

/// ログインで users の行を作る (その会社の transaction で)。`sql` は `login_sql::INSERT_*_USER` で、
/// `$1` が会社、`$2` 以降が `texts` (どれも TEXT) の順
pub async fn insert_user(
    pg: &mut PgClient,
    tenant_id: Uuid,
    sql: &'static str,
    texts: Vec<String>,
) -> Result<User, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let mut params: Vec<(&(dyn ToSql + Sync), Type)> = vec![(&tenant_id, Type::UUID)];
            params.extend(texts.iter().map(|t| (t as &(dyn ToSql + Sync), Type::TEXT)));
            let row = tx.query_typed_one(sql, &params).await?;
            Ok(user(&row))
        })
    })
    .await
}

/// LINE の受信者を登録する (その会社の transaction で)。入った行数 (重複は 0)
pub async fn register_line_recipient(
    pg: &mut PgClient,
    tenant_id: Uuid,
    name: String,
    line_user_id: String,
) -> Result<u64, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            tx.execute_typed(
                login_sql::REGISTER_LINE_RECIPIENT,
                &[
                    (&tenant_id, Type::UUID),
                    (&name, Type::TEXT),
                    (&line_user_id, Type::TEXT),
                ],
            )
            .await
        })
    })
    .await
}

pub async fn find_recipients_by_line_user_id(
    pg: &mut PgClient,
    line_user_id: String,
) -> Result<Vec<RecipientTenant>, Error> {
    pg.tenant_tx(Uuid::nil(), move |tx| {
        Box::pin(async move {
            let rows = tx
                .query_typed(
                    login_sql::RECIPIENTS_BY_LINE_USER_ID,
                    &[(&line_user_id, Type::TEXT)],
                )
                .await?;
            Ok(rows
                .iter()
                .map(|r| RecipientTenant {
                    tenant_id: r.get(0),
                    name: r.get(1),
                })
                .collect())
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

// ---------- ロール (user_roles。ippoan/alc-migrations の 177) ----------
//
// 会社の中の表なので、必ずその会社の transaction で流し、tenant_id を WHERE / VALUES に明示する
// (`tenant_tx(Uuid::nil())` の中では RLS で 0 行になる)。

pub mod roles_sql {
    /// その user に付いたロール (role 順)
    pub const ROLES_OF_USER: &str = "SELECT role FROM alc_api.user_roles \
         WHERE tenant_id = $1 AND user_id = $2 ORDER BY role";

    /// 会社の中で 1 つ以上ロールを持つ user と、そのロール (user_id 順・role 順)
    pub const ROLES_OF_TENANT: &str = "SELECT user_id, array_agg(role ORDER BY role) \
         FROM alc_api.user_roles WHERE tenant_id = $1 GROUP BY user_id ORDER BY user_id";

    /// その会社に user が在るか (付ける前の確かめ)
    pub const USER_EXISTS: &str =
        "SELECT EXISTS (SELECT 1 FROM alc_api.users WHERE id = $1 AND tenant_id = $2)";

    /// 付ける (既に在れば何もしない)
    pub const GRANT_ROLE: &str = "INSERT INTO alc_api.user_roles (tenant_id, user_id, role) \
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING";

    /// 外す (無くても何もしない)
    pub const REVOKE_ROLE: &str = "DELETE FROM alc_api.user_roles \
         WHERE tenant_id = $1 AND user_id = $2 AND role = $3";
}

/// 会社の中のロールの一覧の 1 行
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UserRoles {
    pub user_id: Uuid,
    pub roles: Vec<String>,
}

impl TxOutput for UserRoles {}

/// その user に付いたロール (user の会社の transaction で)
pub async fn roles_of_user(
    pg: &mut PgClient,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<String>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let rows = tx
                .query_typed(
                    roles_sql::ROLES_OF_USER,
                    &[(&tenant_id, Type::UUID), (&user_id, Type::UUID)],
                )
                .await?;
            Ok(rows.iter().map(|r| r.get(0)).collect())
        })
    })
    .await
}

pub async fn roles_of_tenant(pg: &mut PgClient, tenant_id: Uuid) -> Result<Vec<UserRoles>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let rows = tx
                .query_typed(roles_sql::ROLES_OF_TENANT, &[(&tenant_id, Type::UUID)])
                .await?;
            Ok(rows
                .iter()
                .map(|r| UserRoles {
                    user_id: r.get(0),
                    roles: r.get(1),
                })
                .collect())
        })
    })
    .await
}

/// ロールを付ける。その会社に user が無ければ false (何も入れない)。既に付いていても true
pub async fn grant_role(
    pg: &mut PgClient,
    tenant_id: Uuid,
    user_id: Uuid,
    role: String,
) -> Result<bool, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let exists: bool = tx
                .query_typed_one(
                    roles_sql::USER_EXISTS,
                    &[(&user_id, Type::UUID), (&tenant_id, Type::UUID)],
                )
                .await?
                .get(0);
            if !exists {
                return Ok(false);
            }
            tx.execute_typed(
                roles_sql::GRANT_ROLE,
                &[
                    (&tenant_id, Type::UUID),
                    (&user_id, Type::UUID),
                    (&role, Type::TEXT),
                ],
            )
            .await?;
            Ok(true)
        })
    })
    .await
}

/// ロールを外す。消えた行数 (無ければ 0)
pub async fn revoke_role(
    pg: &mut PgClient,
    tenant_id: Uuid,
    user_id: Uuid,
    role: String,
) -> Result<u64, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            tx.execute_typed(
                roles_sql::REVOKE_ROLE,
                &[
                    (&tenant_id, Type::UUID),
                    (&user_id, Type::UUID),
                    (&role, Type::TEXT),
                ],
            )
            .await
        })
    })
    .await
}

// ---------- 会社の管理 (ユーザー・招待・SSO 設定・参加の申請。rust-alc-api の /api/admin/users・
// /api/admin/sso/configs・/api/access-requests・/api/tenants/by-slug から移した。Refs ippoan/rust-alc-api#680) ----------
//
// 会社の中の文はその会社の transaction で tenant_id を WHERE / VALUES に明示する。会社をまたぐのは slug での
// 会社の引き当て (RLS の無い tenants) と参加の申請の作成 (SECURITY DEFINER の `create_access_request()`) だけで、
// nil の tenant の transaction で流す。

pub mod admin_sql {
    pub const USERS: &str = "SELECT id, email, name, role, created_at FROM alc_api.users \
         WHERE tenant_id = $1 ORDER BY created_at, id";

    pub const DELETE_USER: &str = "DELETE FROM alc_api.users WHERE id = $1 AND tenant_id = $2";

    pub const INVITATIONS: &str = "SELECT id, tenant_id, email, role, created_at \
         FROM alc_api.tenant_allowed_emails WHERE tenant_id = $1 ORDER BY created_at, id";

    /// 招待を作る / 同じ会社の同じ email なら role だけ差し替える。email は会社をまたいで一意で、
    /// **他社の招待に当たったら書き換えずに 0 行** (移植元は他社の行の role を書き換えうる形だった)
    pub const UPSERT_INVITATION: &str =
        "INSERT INTO alc_api.tenant_allowed_emails (tenant_id, email, role) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (email) DO UPDATE SET role = EXCLUDED.role \
         WHERE alc_api.tenant_allowed_emails.tenant_id = EXCLUDED.tenant_id \
         RETURNING id, tenant_id, email, role, created_at";

    pub const DELETE_INVITATION_BY_ID: &str =
        "DELETE FROM alc_api.tenant_allowed_emails WHERE id = $1 AND tenant_id = $2";

    /// SSO 設定の一覧 (client_secret_encrypted は返さない)
    pub const SSO_CONFIGS: &str = "SELECT provider, client_id, external_org_id, enabled, woff_id, \
         created_at, updated_at FROM alc_api.sso_provider_configs WHERE tenant_id = $1 ORDER BY provider";

    pub const UPSERT_SSO_WITH_SECRET: &str = "INSERT INTO alc_api.sso_provider_configs \
         (tenant_id, provider, client_id, client_secret_encrypted, external_org_id, woff_id, enabled) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (tenant_id, provider) DO UPDATE SET \
         client_id = EXCLUDED.client_id, client_secret_encrypted = EXCLUDED.client_secret_encrypted, \
         external_org_id = EXCLUDED.external_org_id, woff_id = EXCLUDED.woff_id, \
         enabled = EXCLUDED.enabled, updated_at = NOW() \
         RETURNING provider, client_id, external_org_id, enabled, woff_id, created_at, updated_at";

    /// secret を渡さない保存は既存の行の更新だけ (client_secret_encrypted は NOT NULL で新規は作れない)
    pub const UPDATE_SSO_WITHOUT_SECRET: &str = "UPDATE alc_api.sso_provider_configs SET \
         client_id = $3, external_org_id = $4, woff_id = $5, enabled = $6, updated_at = NOW() \
         WHERE tenant_id = $1 AND provider = $2 \
         RETURNING provider, client_id, external_org_id, enabled, woff_id, created_at, updated_at";

    pub const DELETE_SSO: &str =
        "DELETE FROM alc_api.sso_provider_configs WHERE tenant_id = $1 AND provider = $2";

    /// slug で会社を引く (会社をまたぐ。RLS の無い tenants)
    pub const TENANT_BY_SLUG: &str = "SELECT id, name, slug FROM alc_api.tenants WHERE slug = $1";

    /// 参加の申請を作る (申請先は申請者の会社でないので SECURITY DEFINER。ippoan/alc-migrations の 158)
    pub const CREATE_ACCESS_REQUEST: &str =
        "SELECT id, tenant_id, user_id, status, role, created_at \
         FROM alc_api.create_access_request($1, $2)";

    /// `$2` が NULL なら全部の status。新しい順
    pub const ACCESS_REQUESTS: &str = "SELECT id, tenant_id, user_id, status, role, created_at \
         FROM alc_api.access_requests WHERE tenant_id = $1 AND ($2::text IS NULL OR status = $2) \
         ORDER BY created_at DESC, id";

    /// pending の申請だけ承認する (0 行 = 無い・他社・pending でない)
    pub const APPROVE_ACCESS_REQUEST: &str = "UPDATE alc_api.access_requests \
         SET status = 'approved', role = $1, updated_at = NOW() \
         WHERE id = $2 AND tenant_id = $3 AND status = 'pending'";

    pub const DECLINE_ACCESS_REQUEST: &str = "UPDATE alc_api.access_requests \
         SET status = 'declined', updated_at = NOW() \
         WHERE id = $1 AND tenant_id = $2 AND status = 'pending'";
}

/// 会社の user の 1 行 (`GET /internal/tenants/{tenant_id}/users`。移植元の `UserResponse` と同じ形)
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TenantUser {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

/// 招待の 1 行 (移植元の `TenantAllowedEmail` と同じ形)
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TenantInvitation {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

/// SSO 設定の 1 行 (移植元の `SsoConfigRow` と同じ形。client_secret_encrypted は持たない)
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SsoConfigRow {
    pub provider: String,
    pub client_id: String,
    pub external_org_id: String,
    pub enabled: bool,
    pub woff_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// SSO 設定の保存の入力 (`client_secret_encrypted` は auth-worker が暗号化したもの。`None` なら既存の行の更新だけ)
#[derive(Debug, Clone, PartialEq)]
pub struct SsoConfigInput {
    pub provider: String,
    pub client_id: String,
    pub client_secret_encrypted: Option<String>,
    pub external_org_id: String,
    pub woff_id: Option<String>,
    pub enabled: bool,
}

/// slug で引いた会社 (移植元の `TenantBySlugResponse` の中身)
#[derive(Debug, Clone, PartialEq)]
pub struct SlugTenant {
    pub id: Uuid,
    pub name: String,
    pub slug: Option<String>,
}

/// 参加の申請の 1 行 (移植元の `AccessRequestResponse` から org_name を除いた形)
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AccessRequest {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub status: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

impl TxOutput for TenantUser {}
impl TxOutput for TenantInvitation {}
impl TxOutput for SsoConfigRow {}
impl TxOutput for SlugTenant {}
impl TxOutput for AccessRequest {}

fn sso_config_row(r: &Row) -> SsoConfigRow {
    SsoConfigRow {
        provider: r.get(0),
        client_id: r.get(1),
        external_org_id: r.get(2),
        enabled: r.get(3),
        woff_id: r.get(4),
        created_at: r.get(5),
        updated_at: r.get(6),
    }
}

fn invitation_row(r: &Row) -> TenantInvitation {
    TenantInvitation {
        id: r.get(0),
        tenant_id: r.get(1),
        email: r.get(2),
        role: r.get(3),
        created_at: r.get(4),
    }
}

fn access_request_row(r: &Row) -> AccessRequest {
    AccessRequest {
        id: r.get(0),
        tenant_id: r.get(1),
        user_id: r.get(2),
        status: r.get(3),
        role: r.get(4),
        created_at: r.get(5),
    }
}

pub async fn tenant_users(pg: &mut PgClient, tenant_id: Uuid) -> Result<Vec<TenantUser>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let rows = tx
                .query_typed(admin_sql::USERS, &[(&tenant_id, Type::UUID)])
                .await?;
            Ok(rows
                .iter()
                .map(|r| TenantUser {
                    id: r.get(0),
                    email: r.get(1),
                    name: r.get(2),
                    role: r.get(3),
                    created_at: r.get(4),
                })
                .collect())
        })
    })
    .await
}

/// その会社の user を消す。消えた行数 (無い・他社は 0)
pub async fn delete_tenant_user(
    pg: &mut PgClient,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<u64, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            tx.execute_typed(
                admin_sql::DELETE_USER,
                &[(&user_id, Type::UUID), (&tenant_id, Type::UUID)],
            )
            .await
        })
    })
    .await
}

pub async fn tenant_invitations(
    pg: &mut PgClient,
    tenant_id: Uuid,
) -> Result<Vec<TenantInvitation>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let rows = tx
                .query_typed(admin_sql::INVITATIONS, &[(&tenant_id, Type::UUID)])
                .await?;
            Ok(rows.iter().map(invitation_row).collect())
        })
    })
    .await
}

/// 招待を作る / 同じ会社の同じ email の role を差し替える。他社が同じ email を招待していれば `None`
pub async fn upsert_invitation(
    pg: &mut PgClient,
    tenant_id: Uuid,
    email: String,
    role: String,
) -> Result<Option<TenantInvitation>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let row = tx
                .query_typed_opt(
                    admin_sql::UPSERT_INVITATION,
                    &[
                        (&tenant_id, Type::UUID),
                        (&email, Type::TEXT),
                        (&role, Type::TEXT),
                    ],
                )
                .await?;
            Ok(row.as_ref().map(invitation_row))
        })
    })
    .await
}

/// 招待を id で消す。消えた行数 (無い・他社は 0)
pub async fn delete_invitation_by_id(
    pg: &mut PgClient,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<u64, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            tx.execute_typed(
                admin_sql::DELETE_INVITATION_BY_ID,
                &[(&id, Type::UUID), (&tenant_id, Type::UUID)],
            )
            .await
        })
    })
    .await
}

pub async fn sso_configs(pg: &mut PgClient, tenant_id: Uuid) -> Result<Vec<SsoConfigRow>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let rows = tx
                .query_typed(admin_sql::SSO_CONFIGS, &[(&tenant_id, Type::UUID)])
                .await?;
            Ok(rows.iter().map(sso_config_row).collect())
        })
    })
    .await
}

/// SSO 設定を保存する。secret 無しで既存の行が無ければ `None` (新規には secret が要る)。
/// 他社と (provider, client_id) / (provider, external_org_id) が当たれば 23505 (呼び手が 409 にする)
pub async fn save_sso_config(
    pg: &mut PgClient,
    tenant_id: Uuid,
    c: SsoConfigInput,
) -> Result<Option<SsoConfigRow>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let row = match &c.client_secret_encrypted {
                Some(secret) => Some(
                    tx.query_typed_one(
                        admin_sql::UPSERT_SSO_WITH_SECRET,
                        &[
                            (&tenant_id, Type::UUID),
                            (&c.provider, Type::TEXT),
                            (&c.client_id, Type::TEXT),
                            (secret, Type::TEXT),
                            (&c.external_org_id, Type::TEXT),
                            (&c.woff_id, Type::TEXT),
                            (&c.enabled, Type::BOOL),
                        ],
                    )
                    .await?,
                ),
                None => {
                    tx.query_typed_opt(
                        admin_sql::UPDATE_SSO_WITHOUT_SECRET,
                        &[
                            (&tenant_id, Type::UUID),
                            (&c.provider, Type::TEXT),
                            (&c.client_id, Type::TEXT),
                            (&c.external_org_id, Type::TEXT),
                            (&c.woff_id, Type::TEXT),
                            (&c.enabled, Type::BOOL),
                        ],
                    )
                    .await?
                }
            };
            Ok(row.as_ref().map(sso_config_row))
        })
    })
    .await
}

/// SSO 設定を消す。消えた行数 (無い・他社は 0)
pub async fn delete_sso_config(
    pg: &mut PgClient,
    tenant_id: Uuid,
    provider: String,
) -> Result<u64, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            tx.execute_typed(
                admin_sql::DELETE_SSO,
                &[(&tenant_id, Type::UUID), (&provider, Type::TEXT)],
            )
            .await
        })
    })
    .await
}

/// slug で会社を引く (会社をまたぐので nil の tenant の transaction で)
pub async fn tenant_by_slug(pg: &mut PgClient, slug: String) -> Result<Option<SlugTenant>, Error> {
    pg.tenant_tx(Uuid::nil(), move |tx| {
        Box::pin(async move {
            let row = tx
                .query_typed_opt(admin_sql::TENANT_BY_SLUG, &[(&slug, Type::TEXT)])
                .await?;
            Ok(row.map(|r| SlugTenant {
                id: r.get(0),
                name: r.get(1),
                slug: r.get(2),
            }))
        })
    })
    .await
}

/// slug の会社への参加の申請を作る。会社が無ければ `None`。申請先は申請者の会社でないので、slug の引き当てと
/// 作成を 1 つの nil の tenant の transaction で流し、作成は SECURITY DEFINER の関数で行う。
/// user が無ければ 23503 (呼び手が 404 にする)
pub async fn create_access_request(
    pg: &mut PgClient,
    slug: String,
    user_id: Uuid,
) -> Result<Option<(String, AccessRequest)>, Error> {
    pg.tenant_tx(Uuid::nil(), move |tx| {
        Box::pin(async move {
            let Some(tenant) = tx
                .query_typed_opt(admin_sql::TENANT_BY_SLUG, &[(&slug, Type::TEXT)])
                .await?
            else {
                return Ok(None);
            };
            let (tenant_id, name): (Uuid, String) = (tenant.get(0), tenant.get(1));
            let row = tx
                .query_typed_one(
                    admin_sql::CREATE_ACCESS_REQUEST,
                    &[(&tenant_id, Type::UUID), (&user_id, Type::UUID)],
                )
                .await?;
            Ok(Some((name, access_request_row(&row))))
        })
    })
    .await
}

pub async fn access_requests(
    pg: &mut PgClient,
    tenant_id: Uuid,
    status: Option<String>,
) -> Result<Vec<AccessRequest>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let rows = tx
                .query_typed(
                    admin_sql::ACCESS_REQUESTS,
                    &[(&tenant_id, Type::UUID), (&status, Type::TEXT)],
                )
                .await?;
            Ok(rows.iter().map(access_request_row).collect())
        })
    })
    .await
}

/// pending の申請を承認する。変えた行数 (無い・他社・pending でないは 0)
pub async fn approve_access_request(
    pg: &mut PgClient,
    tenant_id: Uuid,
    id: Uuid,
    role: String,
) -> Result<u64, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            tx.execute_typed(
                admin_sql::APPROVE_ACCESS_REQUEST,
                &[
                    (&role, Type::TEXT),
                    (&id, Type::UUID),
                    (&tenant_id, Type::UUID),
                ],
            )
            .await
        })
    })
    .await
}

/// pending の申請を却下する。変えた行数 (無い・他社・pending でないは 0)
pub async fn decline_access_request(
    pg: &mut PgClient,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<u64, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            tx.execute_typed(
                admin_sql::DECLINE_ACCESS_REQUEST,
                &[(&id, Type::UUID), (&tenant_id, Type::UUID)],
            )
            .await
        })
    })
    .await
}
