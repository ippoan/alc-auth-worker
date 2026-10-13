//! SQL を流す 1 か所。すべて `PgClient::tenant_tx` (transaction 単位の RLS) の中で、型付きの名前なしの文
//! (`query_typed` 系・`execute_typed`) だけを使う (Hyperdrive 経由では名前付き prepared statement で接続が切れる)。
//! RLS に加えて、会社の中の文は `tenant_id = <会社>` を WHERE / VALUES に明示する (所有者で繋いだときの備え)。

use alc_worker_db::{PgClient, TxOutput};
use tokio_postgres::types::Type;
use tokio_postgres::Error;
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
