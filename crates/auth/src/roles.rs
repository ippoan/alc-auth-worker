//! ユーザーに付け外しするロールと、ロール → 権限の対応 (Refs ohishi-exp/rust-leave-worker#1)。
//!
//! 表 `alc_api.user_roles` (ippoan/alc-migrations の 177) は「どの user にどのロールが付いているか」だけを持ち、
//! ロール → 権限の対応はこの module の [`ROLE_PERMISSIONS`] に固定する。ログインの口 ([`crate::login`]) は
//! user と一緒に [`permissions_for`] の結果を `permissions` で返し、auth-worker が JWT の claim `perms` に詰める。
//! users.role (admin/viewer/payroll) は別物で変えない。admin は全権限 (`*`)。
//!
//! | method | path | 応答 |
//! |---|---|---|
//! | GET | `/internal/tenants/{tenant_id}/user-roles` | 200 `[{user_id,roles}]` (1 つ以上ロールを持つ user だけ) / 400 |
//! | PUT | `/internal/tenants/{tenant_id}/users/{user_id}/roles/{role}` | 204 (既に在っても) / 404 `user_not_found` / 400 |
//! | DELETE | `/internal/tenants/{tenant_id}/users/{user_id}/roles/{role}` | 204 (無くても) / 400 |
//!
//! 400 は tenant_id / user_id が UUID でない `invalid_id` と、[`ROLE_PERMISSIONS`] に無いロールの `unknown_role`。
//! 共有 secret の照合は [`crate::internal`] の layer がこの口にも掛ける。tenant は呼び手 (auth-worker が管理者の
//! JWT から取る) を信じ、その会社の transaction (RLS) の中で読み書きする。

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use uuid::Uuid;

use crate::internal::{db_error, error, InternalState};
use crate::pg::{self, UserRoles};

pub const TENANT_ROLES_PATH: &str = "/internal/tenants/{tenant_id}/user-roles";
pub const USER_ROLE_PATH: &str = "/internal/tenants/{tenant_id}/users/{user_id}/roles/{role}";

/// ロール → 権限。ロールを増やすときは alc-migrations の user_roles の CHECK も広げる
pub const ROLE_PERMISSIONS: &[(&str, &[&str])] = &[("leave", &["leave.use"])];

/// 全権限 (users.role が admin のとき)
pub const ALL_PERMISSIONS: &str = "*";

/// users.role が `admin` なら `["*"]`、それ以外は付いたロールを [`ROLE_PERMISSIONS`] で引いて重複なく並べる
/// (表に無いロールは無視)
pub fn permissions_for(role: &str, roles: &[String]) -> Vec<String> {
    if role == "admin" {
        return vec![ALL_PERMISSIONS.to_owned()];
    }
    let mut perms: Vec<String> = Vec::new();
    for r in roles {
        let Some((_, ps)) = ROLE_PERMISSIONS.iter().find(|(name, _)| name == r) else {
            continue;
        };
        for p in *ps {
            if !perms.iter().any(|q| q == p) {
                perms.push((*p).to_owned());
            }
        }
    }
    perms
}

pub fn is_known_role(role: &str) -> bool {
    ROLE_PERMISSIONS.iter().any(|(name, _)| *name == role)
}

pub fn role_routes() -> Router<InternalState> {
    Router::new()
        .route(TENANT_ROLES_PATH, get(list_roles))
        .route(USER_ROLE_PATH, put(grant).delete(revoke))
}

/// UUID でなければ 400 の語 `invalid_id`
fn parse_id(s: &str) -> Result<Uuid, &'static str> {
    s.parse().map_err(|_| "invalid_id")
}

/// path の (tenant_id, user_id, role) を確かめる。だめなら 400 の語
fn check_target(
    (tenant_id, user_id, role): (String, String, String),
) -> Result<(Uuid, Uuid, String), &'static str> {
    let (tenant_id, user_id) = (parse_id(&tenant_id)?, parse_id(&user_id)?);
    if !is_known_role(&role) {
        return Err("unknown_role");
    }
    Ok((tenant_id, user_id, role))
}

async fn list_roles(State(state): State<InternalState>, Path(tenant_id): Path<String>) -> Response {
    let tenant_id = match parse_id(&tenant_id) {
        Ok(t) => t,
        Err(code) => return error(StatusCode::BAD_REQUEST, code),
    };
    match pg::roles_of_tenant(&mut *state.pg.lock().await, tenant_id).await {
        Ok(rows) => Json::<Vec<UserRoles>>(rows).into_response(),
        Err(e) => db_error(&state, "user-roles", &e),
    }
}

async fn grant(
    State(state): State<InternalState>,
    Path(target): Path<(String, String, String)>,
) -> Response {
    let (tenant_id, user_id, role) = match check_target(target) {
        Ok(t) => t,
        Err(code) => return error(StatusCode::BAD_REQUEST, code),
    };
    match pg::grant_role(&mut *state.pg.lock().await, tenant_id, user_id, role).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "user_not_found"),
        Err(e) => db_error(&state, "roles/grant", &e),
    }
}

async fn revoke(
    State(state): State<InternalState>,
    Path(target): Path<(String, String, String)>,
) -> Response {
    let (tenant_id, user_id, role) = match check_target(target) {
        Ok(t) => t,
        Err(code) => return error(StatusCode::BAD_REQUEST, code),
    };
    match pg::revoke_role(&mut *state.pg.lock().await, tenant_id, user_id, role).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => db_error(&state, "roles/revoke", &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn admin_has_all_permissions() {
        assert_eq!(permissions_for("admin", &[]), s(&["*"]));
        assert_eq!(permissions_for("admin", &s(&["leave"])), s(&["*"]));
    }

    #[test]
    fn roles_map_to_permissions_without_duplicates() {
        assert_eq!(permissions_for("viewer", &s(&["leave"])), s(&["leave.use"]));
        assert_eq!(
            permissions_for("payroll", &s(&["leave", "leave"])),
            s(&["leave.use"])
        );
    }

    #[test]
    fn unknown_roles_and_empty_give_nothing() {
        assert!(permissions_for("viewer", &[]).is_empty());
        assert!(permissions_for("viewer", &s(&["nope"])).is_empty());
        assert_eq!(
            permissions_for("viewer", &s(&["nope", "leave"])),
            s(&["leave.use"])
        );
    }

    #[test]
    fn only_table_roles_are_known() {
        assert!(is_known_role("leave"));
        assert!(!is_known_role("admin"));
        assert!(!is_known_role(""));
    }
}
