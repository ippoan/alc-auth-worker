//! `GET /internal/rls-check` — テナントごとの行の出し分け (RLS) が、いま繋いでいる DB で効いているかを、
//! 固定の問い合わせで確かめる内部用の口 (W9、Refs ippoan/rust-alc-api#680。rust-alc-api の
//! `src/routes/rls_check.rs` (ippoan/auth-worker#605) を移したもの。応答の形は同じ)。
//!
//! migration を当てた後にオーナーが SQL エディタで手で見ていたもの (不変条件の検査 / 実行用ロールの
//! 属性 / 繋いでいるロール / 適用履歴) と、migration の履歴との食い違い (`drift`) を 1 回の呼び出しで返す。
//! 呼ぶのは auth-worker の MCP ツール `verify_rls` (Service Binding。ほかの口と同じ共有 secret の layer の配下)。
//!
//! 守ること (rust-alc-api と同じ):
//! - **引数を取らない。** extractor は `State` だけ。SQL・表名・テナントを受ける入口を足さない。
//! - **読み取りだけ。** transaction は [`crate::pg::read_only`] からだけ取る (`tenant_tx(Uuid::nil())` の最初に
//!   `SET TRANSACTION READ ONLY`)。kit の transaction は最後に COMMIT するが、読み取り専用なので何も書かない。
//! - **行のデータを返さない。** 返すのはカタログ由来のロール名・表名・関数名・真偽・件数だけ。
//!   `pg_stat_activity` から読む列は `usename` と件数だけ (接続元・問い合わせの本文は読まない)。
//! - **検査 SQL の写しを置かない。** 不変条件の検査は `alc_migrations::RLS_INVARIANTS_QUERY` を、
//!   状態は `alc_migrations::RLS_STATE_QUERY` をそのまま流す (加工・連結しない)。検査の題の一覧も
//!   `alc_migrations::RLS_INVARIANT_CHECKS` を使う。
//! - **期待する状態の写しを置かない。** `drift` は、同じ transaction で取った `state` を
//!   `alc_migrations::RLS_EXPECTED_STATE` (全 migration を 0 から当てた DB の状態) と比べたもの。
//! - **`ok` は `verdicts` (合否の内訳 4 つ) が全部 true のときだけ true。** 内訳は、違反 0 件
//!   (`invariants`) / ロールの属性 (`runtime_role`) / 適用履歴の一致 (`migrations`) / 履歴との
//!   食い違いが無い (`drift`)。`invariants.checks` は「何を検査したか」を確かめる材料で、合否には入れない。
//! - `state` は取れなければ null (主の結果を道連れにしない)。そのとき `drift` も null で、`verdicts.drift` は false。
//! - どの問い合わせも bind する値を持たない。
//!
//! **`migrations.binary_count` / `binary_max_version` は「この worker が組み込んだ alc-migrations の rev」**
//! (直下の `Cargo.toml` の `alc-migrations` の rev。rust-alc-api では backend の binary の rev だった)。
//! 本番に流した migration と揃えるには、alc-migrations の main に merge された rev へこの worker の rev を上げる。

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use serde_json::Value;

use crate::internal::{db_error, InternalState};
use crate::pg::{self, RlsSnapshot};

pub const RLS_CHECK_PATH: &str = "/internal/rls-check";

/// backend の実行用ロール (alc-migrations 158)。
const RUNTIME_ROLE: &str = "alc_api_rt";

#[derive(Debug, Serialize)]
pub struct RlsCheckResponse {
    /// `verdicts` の 4 つが全部 true のときだけ true
    pub ok: bool,
    pub verdicts: Verdicts,
    pub migrations: MigrationsStatus,
    pub runtime_role: RuntimeRoleStatus,
    pub connections: Vec<ConnectionCount>,
    pub owner_role_connected: bool,
    pub invariants: InvariantsStatus,
    /// `alc_api` schema のカタログの実物 (`alc_migrations::RLS_STATE_QUERY` の JSON をそのまま)。
    /// 取れなければ null。
    pub state: Option<Value>,
    /// `state` と `alc_migrations::RLS_EXPECTED_STATE` の食い違い。`state` が取れなければ null。
    pub drift: Option<Drift>,
}

/// 合否の内訳。`ok` はこの 4 つから計算する ([`Verdicts::ok`])。
#[derive(Debug, PartialEq, Serialize)]
pub struct Verdicts {
    /// 不変条件の違反が 0 件
    pub invariants: bool,
    /// 実行用ロールで繋いでいて、属性 4 つが全部 false
    pub runtime_role: bool,
    /// 適用履歴が binary と一致
    pub migrations: bool,
    /// 履歴との食い違いが無い (`drift` が取れていて `matches_expected`)
    pub drift: bool,
}

/// migration の履歴 (期待する状態) と実物の食い違い。
#[derive(Debug, PartialEq, Serialize)]
pub struct Drift {
    /// `tables`・`functions`・`unreadable` が空で、`views`・`sequences` が null
    pub matches_expected: bool,
    /// 状態か policy の名前が違う表・片方にしか無い表 (名前の昇順)
    pub tables: Vec<TableDrift>,
    /// 値が違う・片方にしか無い SECURITY DEFINER の関数 (署名の昇順)
    pub functions: Vec<FunctionDrift>,
    /// view の一覧が違うときだけ
    pub views: Option<ExpectedActual>,
    /// sequence の状態が違うときだけ
    pub sequences: Option<ExpectedActual>,
    /// 読めなかった箇所 (`expected.<key>` / `actual.<key>`。知らない key・壊れた形)。昇順。無ければ空
    pub unreadable: Vec<String>,
}

/// 表 1 つの食い違い。片方にしか無い表は、無い側の 2 つが null。
#[derive(Debug, PartialEq, Serialize)]
pub struct TableDrift {
    pub name: String,
    pub expected: Option<Value>,
    pub actual: Option<Value>,
    pub expected_policy_names: Option<Value>,
    pub actual_policy_names: Option<Value>,
}

/// 関数 1 つの食い違い。片方にしか無い関数は、無い側が null。
#[derive(Debug, PartialEq, Serialize)]
pub struct FunctionDrift {
    pub signature: String,
    pub expected: Option<Value>,
    pub actual: Option<Value>,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ExpectedActual {
    pub expected: Value,
    pub actual: Value,
}

#[derive(Debug, Serialize)]
pub struct MigrationsStatus {
    /// DB に適用済みの件数
    pub applied: i64,
    /// DB に適用済みの最大 version (1 件も無ければ 0)
    pub max_version: i64,
    /// この binary に埋め込まれた migration の件数
    pub binary_count: i64,
    /// この binary に埋め込まれた migration の最大 version
    pub binary_max_version: i64,
    pub matches_binary: bool,
}

#[derive(Debug, Serialize)]
pub struct RuntimeRoleStatus {
    pub current_user: String,
    pub is_runtime_role: bool,
    pub rolsuper: bool,
    pub rolbypassrls: bool,
    pub rolinherit: bool,
    pub member_of_table_owner: bool,
}

#[derive(Debug, Serialize)]
pub struct ConnectionCount {
    pub usename: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct InvariantsStatus {
    pub violation_count: i64,
    pub violations: Vec<InvariantViolation>,
    /// 流した検査の一覧と、検査ごとの違反の数 (違反が無くても毎回並ぶ)
    pub checks: Vec<InvariantCheck>,
}

#[derive(Debug, Serialize)]
pub struct InvariantCheck {
    pub check_no: i32,
    pub title: String,
    pub violations: i64,
}

#[derive(Debug, Serialize)]
pub struct InvariantViolation {
    pub check_no: i32,
    pub object: String,
    pub detail: String,
}

/// 合否の内訳。所有者ロールの接続の有無 (`owner_role_connected`) は入れない
/// (migration の job の実行中は所有者ロールが一時的に繋ぐ)。
/// `drift` が None (= `state` を取れなかった・期待する状態を読めなかった) なら `drift` は false。
fn verdicts(
    role: &RuntimeRoleStatus,
    violation_count: i64,
    matches_binary: bool,
    drift: Option<&Drift>,
) -> Verdicts {
    Verdicts {
        invariants: violation_count == 0,
        runtime_role: role.is_runtime_role
            && !role.rolsuper
            && !role.rolbypassrls
            && !role.rolinherit
            && !role.member_of_table_owner,
        migrations: matches_binary,
        drift: drift.is_some_and(|d| d.matches_expected),
    }
}

impl Verdicts {
    /// 全体の合否 = 内訳が全部 true。
    fn ok(&self) -> bool {
        self.invariants && self.runtime_role && self.migrations && self.drift
    }
}

/// 状態の JSON (`RLS_STATE_QUERY` の出力) の最上位の key。これ以外が在れば「読めなかった」に数える。
const STATE_KEYS: [&str; 6] = [
    "table_count",
    "tables",
    "policy_names",
    "views",
    "security_definer_functions",
    "sequences",
];

/// 状態の JSON の片側を、突き合わせの単位に開いたもの。
#[derive(Default)]
struct StateSide {
    /// 表の名前 → その表の状態
    tables: BTreeMap<String, Value>,
    /// 表の名前 → policy の名前の配列
    policy_names: BTreeMap<String, Value>,
    /// 署名 → 関数の値
    functions: BTreeMap<String, Value>,
    views: Value,
    sequences: Value,
}

/// `tables` (状態が同じ表をまとめた組の配列) を「表の名前 → その表の状態」に開く。
/// 表の状態 = 組の値から `names`・`count`・`owner` を除いたもの。**`owner` (所有者のロール名) は
/// 環境で違うので比べない** (期待する状態には元から無い)。出し分けに効く
/// `runtime_role_can_act_as_owner` は残る。形が違う・同じ表が 2 回出るなら None。
fn tables_by_name(tables: &Value) -> Option<BTreeMap<String, Value>> {
    let mut by_name = BTreeMap::new();
    for group in tables.as_array()? {
        let mut table_state = group.as_object()?.clone();
        let names = table_state.remove("names")?;
        table_state.remove("count");
        table_state.remove("owner");
        for name in names.as_array()? {
            let previous = by_name.insert(
                name.as_str()?.to_string(),
                Value::Object(table_state.clone()),
            );
            if previous.is_some() {
                return None;
            }
        }
    }
    Some(by_name)
}

/// `security_definer_functions` を「署名 → 残りの値」に開く。形が違う・同じ署名が 2 回出るなら None。
fn functions_by_signature(functions: &Value) -> Option<BTreeMap<String, Value>> {
    let mut by_signature = BTreeMap::new();
    for function in functions.as_array()? {
        let mut values = function.as_object()?.clone();
        let signature = values.remove("signature")?;
        let previous = by_signature.insert(signature.as_str()?.to_string(), Value::Object(values));
        if previous.is_some() {
            return None;
        }
    }
    Some(by_signature)
}

/// 状態の JSON の片側を開く。読めなかった箇所は `{label}.{key}` で `unreadable` に足し、
/// その箇所は空 (null) のまま返す (黙って一致にしない)。
fn read_state_side(label: &str, state: &Value, unreadable: &mut Vec<String>) -> StateSide {
    let mut side = StateSide::default();
    let Some(top) = state.as_object() else {
        unreadable.push(label.to_string());
        return side;
    };
    let mut bad: Vec<&str> = top
        .keys()
        .map(String::as_str)
        .filter(|key| !STATE_KEYS.contains(key))
        .collect();

    match top.get("table_count") {
        Some(count) if count.is_u64() => {}
        _ => bad.push("table_count"),
    }
    match top.get("tables").and_then(tables_by_name) {
        Some(tables) => side.tables = tables,
        None => bad.push("tables"),
    }
    match top.get("policy_names").and_then(Value::as_object) {
        Some(names) => side.policy_names = names.clone().into_iter().collect(),
        None => bad.push("policy_names"),
    }
    match top
        .get("security_definer_functions")
        .and_then(functions_by_signature)
    {
        Some(functions) => side.functions = functions,
        None => bad.push("security_definer_functions"),
    }
    match top.get("views") {
        Some(views) if views.is_array() => side.views = views.clone(),
        _ => bad.push("views"),
    }
    match top.get("sequences") {
        Some(sequences) if sequences.is_object() => side.sequences = sequences.clone(),
        _ => bad.push("sequences"),
    }

    unreadable.extend(bad.into_iter().map(|key| format!("{label}.{key}")));
    side
}

/// 期待する状態 (`expected`) と実物 (`actual`) を比べる。どちらも `RLS_STATE_QUERY` の出力の形。
///
/// 表は「組」ではなく表の単位で比べる (組の割れ方が違っても、表ごとの状態が同じなら一致)。
/// 配列 (`policies`・policy の名前・`runtime_role_privileges`) は SQL の側で並びが固定されているので、
/// 並べ替えずにそのまま比べる。
fn compute_drift(expected: &Value, actual: &Value) -> Drift {
    let mut unreadable = Vec::new();
    let expected = read_state_side("expected", expected, &mut unreadable);
    let actual = read_state_side("actual", actual, &mut unreadable);
    unreadable.sort();

    let table_names: BTreeSet<&String> = expected
        .tables
        .keys()
        .chain(expected.policy_names.keys())
        .chain(actual.tables.keys())
        .chain(actual.policy_names.keys())
        .collect();
    let tables: Vec<TableDrift> = table_names
        .into_iter()
        .map(|name| TableDrift {
            name: name.clone(),
            expected: expected.tables.get(name).cloned(),
            actual: actual.tables.get(name).cloned(),
            expected_policy_names: expected.policy_names.get(name).cloned(),
            actual_policy_names: actual.policy_names.get(name).cloned(),
        })
        .filter(|t| t.expected != t.actual || t.expected_policy_names != t.actual_policy_names)
        .collect();

    let signatures: BTreeSet<&String> = expected
        .functions
        .keys()
        .chain(actual.functions.keys())
        .collect();
    let functions: Vec<FunctionDrift> = signatures
        .into_iter()
        .map(|signature| FunctionDrift {
            signature: signature.clone(),
            expected: expected.functions.get(signature).cloned(),
            actual: actual.functions.get(signature).cloned(),
        })
        .filter(|f| f.expected != f.actual)
        .collect();

    let differing = |expected: Value, actual: Value| {
        (expected != actual).then_some(ExpectedActual { expected, actual })
    };
    let views = differing(expected.views, actual.views);
    let sequences = differing(expected.sequences, actual.sequences);

    Drift {
        matches_expected: tables.is_empty()
            && functions.is_empty()
            && views.is_none()
            && sequences.is_none()
            && unreadable.is_empty(),
        tables,
        functions,
        views,
        sequences,
        unreadable,
    }
}

/// 取れた `state` を応答に入れ、期待する状態 (`expected` = `RLS_EXPECTED_STATE` の JSON) と比べた
/// `drift` と、それを入れた `verdicts`・`ok` を計算し直す。
/// `expected` を読めなければ (起きないはず) `drift` は null のまま = `verdicts.drift` は false。
fn attach_state(response: &mut RlsCheckResponse, state: Option<Value>, expected: &str) {
    response.drift = state.as_ref().and_then(|actual| {
        let expected = serde_json::from_str::<Value>(expected).ok()?;
        Some(compute_drift(&expected, actual))
    });
    response.state = state;
    response.verdicts = verdicts(
        &response.runtime_role,
        response.invariants.violation_count,
        response.migrations.matches_binary,
        response.drift.as_ref(),
    );
    response.ok = response.verdicts.ok();
}

/// 検査の一覧に無い番号の違反に付ける題。
const UNLISTED_CHECK_TITLE: &str = "(一覧に無い検査)";

/// 検査の一覧 (`listed` = 番号と題) に、違反の数を番号ごとに数えて付ける。
/// 一覧に無い番号の違反は、番号の昇順で末尾に足す (数の合計 = 違反の行数)。
fn build_checks(listed: &[(i32, &str)], violations: &[InvariantViolation]) -> Vec<InvariantCheck> {
    let count = |check_no: i32| violations.iter().filter(|v| v.check_no == check_no).count() as i64;
    let mut checks: Vec<InvariantCheck> = listed
        .iter()
        .map(|&(check_no, title)| InvariantCheck {
            check_no,
            title: title.to_string(),
            violations: count(check_no),
        })
        .collect();

    let mut unlisted: Vec<i32> = violations
        .iter()
        .map(|v| v.check_no)
        .filter(|no| !listed.iter().any(|&(listed_no, _)| listed_no == *no))
        .collect();
    unlisted.sort_unstable();
    unlisted.dedup();
    checks.extend(unlisted.into_iter().map(|check_no| InvariantCheck {
        check_no,
        title: UNLISTED_CHECK_TITLE.to_string(),
        violations: count(check_no),
    }));
    checks
}

/// この binary に埋め込まれた migration の (件数, 最大 version)。
fn binary_migrations() -> (i64, i64) {
    let versions = alc_migrations::MIGRATOR
        .iter()
        .filter(|m| !m.migration_type.is_down_migration())
        .map(|m| m.version);
    versions.fold((0, 0), |(count, max), v| (count + 1, max.max(v)))
}

pub fn rls_check_routes() -> Router<InternalState> {
    Router::new().route(RLS_CHECK_PATH, get(rls_check))
}

/// 問い合わせの結果から応答を組み立てる (`state` と `drift` は [`attach_state`] で後から入れる。
/// それまで `verdicts.drift` と `ok` は false)。
fn build_response(snap: RlsSnapshot) -> (RlsCheckResponse, Option<Value>) {
    let (binary_count, binary_max_version) = binary_migrations();
    let matches_binary = snap.applied == binary_count && snap.max_version == binary_max_version;
    let runtime_role = RuntimeRoleStatus {
        is_runtime_role: snap.current_user == RUNTIME_ROLE,
        current_user: snap.current_user,
        rolsuper: snap.rolsuper,
        rolbypassrls: snap.rolbypassrls,
        rolinherit: snap.rolinherit,
        member_of_table_owner: snap.member_of_table_owner,
    };
    let connections = snap
        .connections
        .into_iter()
        .map(|(usename, count)| ConnectionCount { usename, count })
        .collect();
    let violations: Vec<InvariantViolation> = snap
        .violations
        .into_iter()
        .map(|(check_no, object, detail)| InvariantViolation {
            check_no,
            object,
            detail,
        })
        .collect();
    let violation_count = violations.len() as i64;
    let checks = build_checks(alc_migrations::RLS_INVARIANT_CHECKS, &violations);
    let verdicts = verdicts(&runtime_role, violation_count, matches_binary, None);
    let response = RlsCheckResponse {
        ok: verdicts.ok(),
        verdicts,
        migrations: MigrationsStatus {
            applied: snap.applied,
            max_version: snap.max_version,
            binary_count,
            binary_max_version,
            matches_binary,
        },
        runtime_role,
        connections,
        owner_role_connected: snap.owner_role_connected,
        invariants: InvariantsStatus {
            violation_count,
            violations,
            checks,
        },
        state: None,
        drift: None,
    };
    (response, snap.state)
}

async fn rls_check(State(state): State<InternalState>) -> Response {
    let snap = match pg::rls_snapshot(&mut *state.pg.lock().await).await {
        Ok(snap) => snap,
        // 本文には固定の語だけを載せる (SQL・カタログの中身を出さない)
        Err(e) => return db_error(&state, "rls-check", &e),
    };
    // 状態だけ取れなかったときは、種類の label を 1 行 (応答の state・drift は null)
    let log_state = |kind: &String| (state.log)(&format!("rls-check: state {kind}"));
    snap.state_error.iter().for_each(log_state);
    let (mut response, actual) = build_response(snap);
    attach_state(&mut response, actual, alc_migrations::RLS_EXPECTED_STATE);
    Json(response).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn healthy_role() -> RuntimeRoleStatus {
        RuntimeRoleStatus {
            current_user: RUNTIME_ROLE.to_string(),
            is_runtime_role: true,
            rolsuper: false,
            rolbypassrls: false,
            rolinherit: false,
            member_of_table_owner: false,
        }
    }

    fn keys(value: &Value) -> Vec<String> {
        let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        keys
    }

    /// 食い違いの無い `drift`
    fn matching_drift() -> Drift {
        compute_drift(&fixture_state(), &fixture_state())
    }

    /// 全部合格の内訳を作る材料 (ロール・違反の数・適用履歴の一致) に、`drift` だけ差し替えて渡す
    fn healthy_verdicts(drift: Option<&Drift>) -> Verdicts {
        verdicts(&healthy_role(), 0, true, drift)
    }

    fn response_with(role: RuntimeRoleStatus, violation_count: i64) -> RlsCheckResponse {
        let verdicts = verdicts(&role, violation_count, true, None);
        RlsCheckResponse {
            ok: verdicts.ok(),
            verdicts,
            migrations: MigrationsStatus {
                applied: 2,
                max_version: 3,
                binary_count: 2,
                binary_max_version: 3,
                matches_binary: true,
            },
            runtime_role: role,
            connections: vec![ConnectionCount {
                usename: RUNTIME_ROLE.to_string(),
                count: 3,
            }],
            owner_role_connected: false,
            invariants: InvariantsStatus {
                violation_count,
                violations: (0..violation_count).map(|_| violation(1)).collect(),
                checks: vec![InvariantCheck {
                    check_no: 1,
                    title: "t".to_string(),
                    violations: violation_count,
                }],
            },
            state: None,
            drift: None,
        }
    }

    // ---- verdicts と ok ----

    #[test]
    fn ok_only_when_all_four_verdicts_hold() {
        let drift = matching_drift();
        let all = healthy_verdicts(Some(&drift));
        assert_eq!(
            all,
            Verdicts {
                invariants: true,
                runtime_role: true,
                migrations: true,
                drift: true
            }
        );
        assert!(all.ok());
    }

    #[test]
    fn violations_fail_only_the_invariants_verdict() {
        let drift = matching_drift();
        let v = verdicts(&healthy_role(), 1, true, Some(&drift));
        assert_eq!(
            (v.invariants, v.runtime_role, v.migrations, v.drift),
            (false, true, true, true)
        );
        assert!(!v.ok());
    }

    #[test]
    fn role_problems_fail_only_the_runtime_role_verdict() {
        let not_runtime = RuntimeRoleStatus {
            current_user: "alc_api_app".to_string(),
            is_runtime_role: false,
            ..healthy_role()
        };
        let superuser = RuntimeRoleStatus {
            rolsuper: true,
            ..healthy_role()
        };
        let bypassrls = RuntimeRoleStatus {
            rolbypassrls: true,
            ..healthy_role()
        };
        let inherit = RuntimeRoleStatus {
            rolinherit: true,
            ..healthy_role()
        };
        let owner_member = RuntimeRoleStatus {
            member_of_table_owner: true,
            ..healthy_role()
        };
        let drift = matching_drift();
        for role in [not_runtime, superuser, bypassrls, inherit, owner_member] {
            let v = verdicts(&role, 0, true, Some(&drift));
            assert_eq!(
                (v.invariants, v.runtime_role, v.migrations, v.drift),
                (true, false, true, true),
            );
            assert!(!v.ok(), "{role:?}");
        }
    }

    #[test]
    fn binary_mismatch_fails_only_the_migrations_verdict() {
        let drift = matching_drift();
        let v = verdicts(&healthy_role(), 0, false, Some(&drift));
        assert_eq!(
            (v.invariants, v.runtime_role, v.migrations, v.drift),
            (true, true, false, true)
        );
        assert!(!v.ok());
    }

    #[test]
    fn drift_fails_only_the_drift_verdict() {
        let mut actual = fixture_state();
        actual["views"] = json!(["v1"]);
        let drift = compute_drift(&fixture_state(), &actual);
        assert!(!drift.matches_expected);
        let v = healthy_verdicts(Some(&drift));
        assert_eq!(
            (v.invariants, v.runtime_role, v.migrations, v.drift),
            (true, true, true, false)
        );
        assert!(!v.ok());
    }

    /// `drift` が取れていない (null) なら、検査できていないので不合格
    #[test]
    fn missing_drift_fails_the_drift_verdict() {
        let v = healthy_verdicts(None);
        assert_eq!(
            (v.invariants, v.runtime_role, v.migrations, v.drift),
            (true, true, true, false)
        );
        assert!(!v.ok());
    }

    // ---- attach_state (state → drift → verdicts → ok) ----

    #[test]
    fn attach_state_matching_expected_makes_ok() {
        let mut response = response_with(healthy_role(), 0);
        assert!(!response.ok, "state を入れる前は不合格");
        let expected = fixture_state().to_string();
        attach_state(&mut response, Some(fixture_state()), &expected);
        assert_eq!(response.state, Some(fixture_state()));
        assert_eq!(response.drift, Some(matching_drift()));
        assert!(response.verdicts.drift);
        assert!(response.ok);
    }

    #[test]
    fn attach_state_with_drift_is_not_ok_and_keeps_other_verdicts() {
        let mut response = response_with(healthy_role(), 0);
        let mut actual = fixture_state();
        actual["sequences"]["count"] = json!(3);
        attach_state(&mut response, Some(actual), &fixture_state().to_string());
        assert!(!response.drift.as_ref().unwrap().matches_expected);
        assert_eq!(
            response.verdicts,
            Verdicts {
                invariants: true,
                runtime_role: true,
                migrations: true,
                drift: false
            }
        );
        assert!(!response.ok);
    }

    /// `state` を取れなければ `drift` は null・`verdicts.drift` は false・`ok` は false
    #[test]
    fn attach_state_without_state_leaves_drift_null() {
        let mut response = response_with(healthy_role(), 0);
        attach_state(&mut response, None, &fixture_state().to_string());
        assert_eq!(response.state, None);
        assert_eq!(response.drift, None);
        assert!(!response.verdicts.drift);
        assert!(!response.ok);
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["state"].is_null());
        assert!(json["drift"].is_null());
        assert_eq!(json["verdicts"]["drift"], false);
    }

    /// 期待する状態が JSON として読めなければ、落とさずに `drift` を null にする (`state` は返す)
    #[test]
    fn attach_state_with_unparsable_expected_leaves_drift_null() {
        let mut response = response_with(healthy_role(), 0);
        attach_state(&mut response, Some(fixture_state()), "{ not json");
        assert_eq!(response.state, Some(fixture_state()));
        assert_eq!(response.drift, None);
        assert!(!response.verdicts.drift);
        assert!(!response.ok);
    }

    /// `ok` は、ほかの内訳が false なら `drift` が一致していても false (`ok` と `verdicts` が食い違わない)
    #[test]
    fn attach_state_keeps_ok_false_when_another_verdict_fails() {
        let mut response = response_with(healthy_role(), 2);
        attach_state(
            &mut response,
            Some(fixture_state()),
            &fixture_state().to_string(),
        );
        assert!(response.verdicts.drift);
        assert!(!response.verdicts.invariants);
        assert!(!response.ok);
    }

    /// 所有者ロールが繋いでいても ok は変わらない (`verdicts` は `owner_role_connected` を受けない)。
    #[test]
    fn owner_role_connected_does_not_affect_ok() {
        let mut response = response_with(healthy_role(), 0);
        response.owner_role_connected = true;
        attach_state(
            &mut response,
            Some(fixture_state()),
            &fixture_state().to_string(),
        );
        assert!(response.owner_role_connected);
        assert!(response.ok);
    }

    /// 応答の key は契約ちょうど (auth-worker の tool がこの形を読む)。
    #[test]
    fn response_keys_match_the_contract() {
        let mut response = response_with(healthy_role(), 1);
        let mut actual = fixture_state();
        actual["tables"][0]["rls_forced"] = json!(true);
        actual["security_definer_functions"][0]["public_can_execute"] = json!(true);
        actual["views"] = json!(["v1"]);
        actual["sequences"]["count"] = json!(3);
        attach_state(&mut response, Some(actual), &fixture_state().to_string());
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(
            keys(&json),
            [
                "connections",
                "drift",
                "invariants",
                "migrations",
                "ok",
                "owner_role_connected",
                "runtime_role",
                "state",
                "verdicts"
            ]
        );
        assert_eq!(
            keys(&json["verdicts"]),
            ["drift", "invariants", "migrations", "runtime_role"]
        );
        for (key, value) in json["verdicts"].as_object().unwrap() {
            assert!(value.is_boolean(), "{key}");
        }
        assert_eq!(
            keys(&json["drift"]),
            [
                "functions",
                "matches_expected",
                "sequences",
                "tables",
                "unreadable",
                "views"
            ]
        );
        assert_eq!(json["drift"]["matches_expected"], false);
        assert_eq!(
            keys(&json["drift"]["tables"][0]),
            [
                "actual",
                "actual_policy_names",
                "expected",
                "expected_policy_names",
                "name"
            ]
        );
        assert_eq!(
            keys(&json["drift"]["functions"][0]),
            ["actual", "expected", "signature"]
        );
        assert_eq!(keys(&json["drift"]["views"]), ["actual", "expected"]);
        assert_eq!(keys(&json["drift"]["sequences"]), ["actual", "expected"]);
        assert_eq!(json["drift"]["unreadable"], json!([]));
        assert_eq!(
            keys(&json["migrations"]),
            [
                "applied",
                "binary_count",
                "binary_max_version",
                "matches_binary",
                "max_version"
            ]
        );
        assert_eq!(
            keys(&json["runtime_role"]),
            [
                "current_user",
                "is_runtime_role",
                "member_of_table_owner",
                "rolbypassrls",
                "rolinherit",
                "rolsuper"
            ]
        );
        assert_eq!(keys(&json["connections"][0]), ["count", "usename"]);
        assert_eq!(
            keys(&json["invariants"]),
            ["checks", "violation_count", "violations"]
        );
        assert_eq!(
            keys(&json["invariants"]["checks"][0]),
            ["check_no", "title", "violations"]
        );
        assert!(json["invariants"]["checks"][0]["violations"].is_i64());
        assert!(json["state"].is_object());
        assert_eq!(
            keys(&json["invariants"]["violations"][0]),
            ["check_no", "detail", "object"]
        );
        assert!(json["migrations"]["applied"].is_i64());
        assert!(json["connections"][0]["count"].is_i64());
        assert!(json["invariants"]["violations"][0]["check_no"].is_i64());
    }

    // ---- compute_drift (fixture は架空の名前) ----

    fn tenant_policy() -> Value {
        json!({
            "command": "ALL",
            "permissive": true,
            "roles": ["public"],
            "using": "(tenant_id = current_tenant())",
            "with_check": "(tenant_id = current_tenant())"
        })
    }

    /// 表の組 1 つ (`owner` 無し = 期待する状態の形)
    fn group(names: &[&str], rls_forced: bool, policies: Value) -> Value {
        json!({
            "count": names.len(),
            "names": names,
            "rls_enabled": true,
            "rls_forced": rls_forced,
            "runtime_role_can_act_as_owner": false,
            "policies": policies,
            "runtime_role_privileges": ["SELECT", "INSERT", "UPDATE", "DELETE"]
        })
    }

    /// 表の状態 (組から `names`・`count` を除いたもの = `drift.tables[].expected` / `actual` の形)
    fn table_state(rls_forced: bool, policies: Value) -> Value {
        let mut state = group(&[], rls_forced, policies);
        let map = state.as_object_mut().unwrap();
        map.remove("names");
        map.remove("count");
        state
    }

    fn function(signature: &str, public_can_execute: bool) -> Value {
        json!({
            "signature": signature,
            "search_path": "alc_api",
            "runtime_role_can_execute": true,
            "public_can_execute": public_can_execute
        })
    }

    /// 表 3 つ (`table_x`・`table_y` は同じ組、`table_z` は policy 無し)・関数 2 つ・view 無し
    fn fixture_state() -> Value {
        json!({
            "table_count": 3,
            "tables": [
                group(&["table_x", "table_y"], false, json!([tenant_policy()])),
                group(&["table_z"], false, json!([]))
            ],
            "policy_names": {
                "table_x": ["p1"],
                "table_y": ["p1"],
                "table_z": []
            },
            "views": [],
            "security_definer_functions": [function("f(text)", false), function("g()", false)],
            "sequences": { "count": 2, "runtime_role_usage_missing": [] }
        })
    }

    fn drifted_table_names(drift: &Drift) -> Vec<&str> {
        drift.tables.iter().map(|t| t.name.as_str()).collect()
    }

    #[test]
    fn drift_is_empty_when_states_are_identical() {
        let drift = compute_drift(&fixture_state(), &fixture_state());
        assert_eq!(
            drift,
            Drift {
                matches_expected: true,
                tables: vec![],
                functions: vec![],
                views: None,
                sequences: None,
                unreadable: vec![],
            }
        );
    }

    /// `rls_forced` だけ違う表は、その表だけが載る (同じ組だった隣の表は載らない)
    #[test]
    fn drift_lists_only_the_table_whose_rls_forced_differs() {
        let mut actual = fixture_state();
        actual["table_count"] = json!(3);
        actual["tables"] = json!([
            group(&["table_x"], true, json!([tenant_policy()])),
            group(&["table_y"], false, json!([tenant_policy()])),
            group(&["table_z"], false, json!([]))
        ]);
        let drift = compute_drift(&fixture_state(), &actual);
        assert!(!drift.matches_expected);
        assert_eq!(
            drift.tables,
            [TableDrift {
                name: "table_x".to_string(),
                expected: Some(table_state(false, json!([tenant_policy()]))),
                actual: Some(table_state(true, json!([tenant_policy()]))),
                expected_policy_names: Some(json!(["p1"])),
                actual_policy_names: Some(json!(["p1"])),
            }]
        );
        assert!(drift.functions.is_empty());
        assert_eq!((drift.views, drift.sequences), (None, None));
        assert!(drift.unreadable.is_empty());
    }

    #[test]
    fn drift_lists_a_table_whose_policy_expression_differs() {
        let mut loose = tenant_policy();
        loose["using"] = json!("(tenant_id = something_else())");
        let mut actual = fixture_state();
        actual["tables"] = json!([
            group(&["table_x"], false, json!([tenant_policy()])),
            group(&["table_y"], false, json!([loose.clone()])),
            group(&["table_z"], false, json!([]))
        ]);
        let drift = compute_drift(&fixture_state(), &actual);
        assert!(!drift.matches_expected);
        assert_eq!(drifted_table_names(&drift), ["table_y"]);
        assert_eq!(
            drift.tables[0].actual,
            Some(table_state(false, json!([loose])))
        );
        assert_eq!(
            drift.tables[0].expected,
            Some(table_state(false, json!([tenant_policy()])))
        );
    }

    /// 状態は同じで policy の名前だけ違う表も載る
    #[test]
    fn drift_lists_a_table_whose_policy_names_differ() {
        let mut actual = fixture_state();
        actual["policy_names"]["table_y"] = json!(["p_renamed"]);
        let drift = compute_drift(&fixture_state(), &actual);
        assert!(!drift.matches_expected);
        assert_eq!(drifted_table_names(&drift), ["table_y"]);
        let table = &drift.tables[0];
        assert_eq!(table.expected, table.actual);
        assert_eq!(table.expected_policy_names, Some(json!(["p1"])));
        assert_eq!(table.actual_policy_names, Some(json!(["p_renamed"])));
    }

    /// 片方にしか無い表は、無い側の状態と policy の名前が null。名前の昇順で並ぶ
    #[test]
    fn drift_lists_tables_present_on_one_side_only() {
        let mut expected = fixture_state();
        expected["table_count"] = json!(4);
        expected["tables"][1] = group(&["table_only_expected", "table_z"], false, json!([]));
        expected["policy_names"]["table_only_expected"] = json!([]);
        let mut actual = fixture_state();
        actual["table_count"] = json!(4);
        actual["tables"][1] = group(&["table_a_only_actual", "table_z"], false, json!([]));
        actual["policy_names"]["table_a_only_actual"] = json!([]);

        let drift = compute_drift(&expected, &actual);
        assert!(!drift.matches_expected);
        assert_eq!(
            drift.tables,
            [
                TableDrift {
                    name: "table_a_only_actual".to_string(),
                    expected: None,
                    actual: Some(table_state(false, json!([]))),
                    expected_policy_names: None,
                    actual_policy_names: Some(json!([])),
                },
                TableDrift {
                    name: "table_only_expected".to_string(),
                    expected: Some(table_state(false, json!([]))),
                    actual: None,
                    expected_policy_names: Some(json!([])),
                    actual_policy_names: None,
                }
            ]
        );
        let json = serde_json::to_value(&drift).unwrap();
        assert!(json["tables"][0]["expected"].is_null());
        assert!(json["tables"][0]["expected_policy_names"].is_null());
        assert!(json["tables"][1]["actual"].is_null());
        assert!(json["tables"][1]["actual_policy_names"].is_null());
    }

    /// 実物にだけ `owner` が在る (期待する状態には無い) のは食い違いではない。所有者の名前が何でも同じ
    #[test]
    fn drift_ignores_owner() {
        for owner in ["role_a", "role_b"] {
            let mut actual = fixture_state();
            for group in actual["tables"].as_array_mut().unwrap() {
                group["owner"] = json!(owner);
            }
            let drift = compute_drift(&fixture_state(), &actual);
            assert!(drift.matches_expected, "{owner}: {drift:?}");
            assert!(drift.tables.is_empty());
        }
    }

    /// `owner` は読み飛ばすが、`runtime_role_can_act_as_owner` は比べる
    #[test]
    fn drift_compares_runtime_role_can_act_as_owner() {
        let mut actual = fixture_state();
        actual["tables"][1]["owner"] = json!("role_a");
        actual["tables"][1]["runtime_role_can_act_as_owner"] = json!(true);
        let drift = compute_drift(&fixture_state(), &actual);
        assert!(!drift.matches_expected);
        assert_eq!(drifted_table_names(&drift), ["table_z"]);
        let actual_state = drift.tables[0].actual.as_ref().unwrap();
        assert_eq!(actual_state["runtime_role_can_act_as_owner"], true);
        assert!(actual_state.get("owner").is_none(), "owner は載せない");
    }

    /// 組の割れ方が違っても (実物は 2 組・期待は 1 組)、表ごとの状態が同じなら食い違いではない
    #[test]
    fn drift_ignores_how_tables_are_grouped() {
        let mut actual = fixture_state();
        let mut first = group(&["table_x"], false, json!([tenant_policy()]));
        first["owner"] = json!("role_a");
        let mut second = group(&["table_y"], false, json!([tenant_policy()]));
        second["owner"] = json!("role_b");
        actual["tables"] = json!([first, second, group(&["table_z"], false, json!([]))]);
        let drift = compute_drift(&fixture_state(), &actual);
        assert!(drift.matches_expected, "{drift:?}");
    }

    #[test]
    fn drift_lists_functions_that_differ_or_exist_on_one_side_only() {
        let mut actual = fixture_state();
        actual["security_definer_functions"] = json!([
            function("a_only_actual()", false),
            function("f(text)", true)
        ]);
        let drift = compute_drift(&fixture_state(), &actual);
        assert!(!drift.matches_expected);
        let values = |public_can_execute: bool| {
            json!({
                "search_path": "alc_api",
                "runtime_role_can_execute": true,
                "public_can_execute": public_can_execute
            })
        };
        assert_eq!(
            drift.functions,
            [
                FunctionDrift {
                    signature: "a_only_actual()".to_string(),
                    expected: None,
                    actual: Some(values(false)),
                },
                FunctionDrift {
                    signature: "f(text)".to_string(),
                    expected: Some(values(false)),
                    actual: Some(values(true)),
                },
                FunctionDrift {
                    signature: "g()".to_string(),
                    expected: Some(values(false)),
                    actual: None,
                }
            ]
        );
        assert!(drift.tables.is_empty());
    }

    #[test]
    fn drift_reports_a_view_that_exists_only_in_actual() {
        let mut actual = fixture_state();
        actual["views"] = json!(["v1"]);
        let drift = compute_drift(&fixture_state(), &actual);
        assert!(!drift.matches_expected);
        assert_eq!(
            drift.views,
            Some(ExpectedActual {
                expected: json!([]),
                actual: json!(["v1"])
            })
        );
        assert_eq!(drift.sequences, None);
    }

    #[test]
    fn drift_reports_a_different_sequence_count() {
        let mut actual = fixture_state();
        actual["sequences"]["count"] = json!(3);
        let drift = compute_drift(&fixture_state(), &actual);
        assert!(!drift.matches_expected);
        assert_eq!(
            drift.sequences,
            Some(ExpectedActual {
                expected: json!({ "count": 2, "runtime_role_usage_missing": [] }),
                actual: json!({ "count": 3, "runtime_role_usage_missing": [] })
            })
        );
        assert_eq!(drift.views, None);
    }

    /// 知らない key は、ほかが全部同じでも一致にしない (どちらの側かを `unreadable` に出す)
    #[test]
    fn drift_does_not_match_with_unknown_top_level_keys() {
        let mut actual = fixture_state();
        actual["new_key"] = json!([]);
        let drift = compute_drift(&fixture_state(), &actual);
        assert!(!drift.matches_expected);
        assert_eq!(drift.unreadable, ["actual.new_key"]);
        assert!(drift.tables.is_empty() && drift.functions.is_empty());

        let mut expected = fixture_state();
        expected["new_key"] = json!([]);
        let drift = compute_drift(&expected, &actual);
        // 両側に在っても、読めない key は一致にしない
        assert!(!drift.matches_expected);
        assert_eq!(drift.unreadable, ["actual.new_key", "expected.new_key"]);
    }

    /// 壊れた形 (配列のはずが違う・key が無い・同じ表が 2 回出る・最上位が object でない) は一致にしない
    #[test]
    fn drift_does_not_match_with_broken_shapes() {
        let broken = |edit: fn(&mut Value)| {
            let mut actual = fixture_state();
            edit(&mut actual);
            compute_drift(&fixture_state(), &actual)
        };

        let drift = broken(|s| s["tables"] = json!({}));
        assert!(!drift.matches_expected);
        assert_eq!(drift.unreadable, ["actual.tables"]);

        let drift = broken(|s| s["tables"][0]["names"] = json!("table_x"));
        assert_eq!(drift.unreadable, ["actual.tables"]);

        let drift = broken(|s| s["tables"][1]["names"] = json!(["table_x"]));
        assert_eq!(drift.unreadable, ["actual.tables"], "同じ表が 2 回");

        let drift = broken(|s| s["policy_names"] = json!([]));
        assert_eq!(drift.unreadable, ["actual.policy_names"]);

        let drift = broken(|s| s["security_definer_functions"][0] = json!("f(text)"));
        assert_eq!(drift.unreadable, ["actual.security_definer_functions"]);

        let drift = broken(|s| s["security_definer_functions"][1]["signature"] = json!("f(text)"));
        assert_eq!(drift.unreadable, ["actual.security_definer_functions"],); // 同じ署名が 2 回

        let drift = broken(|s| s["views"] = json!(null));
        assert_eq!(drift.unreadable, ["actual.views"]);

        let drift = broken(|s| {
            s.as_object_mut().unwrap().remove("sequences");
        });
        assert_eq!(drift.unreadable, ["actual.sequences"]);

        let drift = broken(|s| s["table_count"] = json!("3"));
        assert_eq!(drift.unreadable, ["actual.table_count"]);

        // 両側が同じ壊れ方でも、一致にしない
        let drift = compute_drift(&json!([]), &json!([]));
        assert!(!drift.matches_expected);
        assert_eq!(drift.unreadable, ["actual", "expected"]);
        let drift = compute_drift(&json!({}), &json!({}));
        assert!(!drift.matches_expected);
        assert_eq!(drift.unreadable.len(), STATE_KEYS.len() * 2);
    }

    /// crate の期待する状態は JSON として読め、それ自身と比べて食い違いが無い
    /// (= 比較が、本物の形を「読めない」にしない)。`owner` は入っていない
    #[test]
    fn expected_state_from_the_crate_is_readable_and_matches_itself() {
        let expected: Value = serde_json::from_str(alc_migrations::RLS_EXPECTED_STATE).unwrap();
        let drift = compute_drift(&expected, &expected);
        assert_eq!(
            drift,
            Drift {
                matches_expected: true,
                tables: vec![],
                functions: vec![],
                views: None,
                sequences: None,
                unreadable: vec![],
            }
        );

        let mut keys = keys(&expected);
        keys.sort();
        let mut known: Vec<&str> = STATE_KEYS.to_vec();
        known.sort_unstable();
        assert_eq!(keys, known);

        let groups = expected["tables"].as_array().unwrap();
        assert!(!groups.is_empty());
        assert!(groups.iter().all(|g| g.get("owner").is_none()));
        let side = read_state_side("expected", &expected, &mut Vec::new());
        assert_eq!(
            side.tables.len() as u64,
            expected["table_count"].as_u64().unwrap()
        );
        let with_policy_names: Vec<&String> = side.policy_names.keys().collect();
        let with_state: Vec<&String> = side.tables.keys().collect();
        assert_eq!(with_policy_names, with_state);
    }

    // ---- build_checks ----

    fn violation(check_no: i32) -> InvariantViolation {
        InvariantViolation {
            check_no,
            object: format!("object {check_no}"),
            detail: "d".to_string(),
        }
    }

    fn numbers_and_counts(checks: &[InvariantCheck]) -> Vec<(i32, i64)> {
        checks.iter().map(|c| (c.check_no, c.violations)).collect()
    }

    /// 違反が無くても、一覧の検査が全部 (本物の一覧は番号 0 からの連番) 0 件で並ぶ
    #[test]
    fn checks_list_every_check_without_violations() {
        let checks = build_checks(alc_migrations::RLS_INVARIANT_CHECKS, &[]);
        let listed = alc_migrations::RLS_INVARIANT_CHECKS.len() as i32;
        assert!(listed > 0);
        let every_check_zero: Vec<(i32, i64)> = (0..listed).map(|no| (no, 0)).collect();
        assert_eq!(numbers_and_counts(&checks), every_check_zero);
        for (check, (_, title)) in checks.iter().zip(alc_migrations::RLS_INVARIANT_CHECKS) {
            assert_eq!(check.title, *title);
        }
    }

    /// 違反は該当の番号にだけ数が立つ
    #[test]
    fn checks_count_violations_per_check() {
        let violations = [violation(5), violation(1), violation(5), violation(5)];
        let checks = build_checks(alc_migrations::RLS_INVARIANT_CHECKS, &violations);
        let expected: Vec<(i32, i64)> = (0..alc_migrations::RLS_INVARIANT_CHECKS.len() as i32)
            .map(|no| match no {
                1 => (no, 1),
                5 => (no, 3),
                _ => (no, 0),
            })
            .collect();
        assert_eq!(numbers_and_counts(&checks), expected);
    }

    /// 一覧に無い番号の違反は、番号の昇順で末尾に足され、合計は違反の行数と合う
    #[test]
    fn checks_append_unlisted_numbers_and_sum_to_violation_count() {
        let listed = [(0, "zero"), (1, "one")];
        let violations = [
            violation(9),
            violation(1),
            violation(7),
            violation(9),
            violation(-1),
        ];
        let checks = build_checks(&listed, &violations);
        assert_eq!(
            numbers_and_counts(&checks),
            [(0, 0), (1, 1), (-1, 1), (7, 1), (9, 2)]
        );
        let titles: Vec<&str> = checks.iter().map(|c| c.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "zero",
                "one",
                UNLISTED_CHECK_TITLE,
                UNLISTED_CHECK_TITLE,
                UNLISTED_CHECK_TITLE
            ]
        );
        let total: i64 = checks.iter().map(|c| c.violations).sum();
        assert_eq!(total, violations.len() as i64);
    }

    /// 埋め込みの migration は 1 件以上で、最大 version は件数以上 (欠番が在るので等しいとは限らない)。
    #[test]
    fn binary_migrations_are_embedded() {
        let (count, max_version) = binary_migrations();
        assert!(count > 0);
        assert!(max_version >= count);
    }

    /// 問い合わせの結果から応答へ: 違反は検査ごとに数え、組み込んだ migration と適用履歴を比べる。
    /// 状態は `attach_state` に渡すために別に返す
    #[test]
    fn build_response_maps_the_snapshot() {
        let (binary_count, binary_max_version) = binary_migrations();
        let snap = RlsSnapshot {
            applied: binary_count,
            max_version: binary_max_version,
            current_user: RUNTIME_ROLE.to_string(),
            rolsuper: false,
            rolbypassrls: false,
            rolinherit: false,
            member_of_table_owner: false,
            connections: vec![("alc_api_rt".to_string(), 2)],
            owner_role_connected: true,
            violations: vec![(3, "table x".to_string(), "detail".to_string())],
            state: Some(json!({ "table_count": 0 })),
            state_error: None,
        };
        let (response, state) = build_response(snap);
        assert_eq!(state, Some(json!({ "table_count": 0 })));
        assert!(response.migrations.matches_binary);
        assert!(response.runtime_role.is_runtime_role);
        assert_eq!(response.connections[0].count, 2);
        assert!(response.owner_role_connected);
        assert_eq!(response.invariants.violation_count, 1);
        assert_eq!(response.invariants.violations[0].object, "table x");
        let three = response.invariants.checks.iter().find(|c| c.check_no == 3);
        assert_eq!(three.unwrap().violations, 1);
        assert_eq!(
            response.verdicts,
            Verdicts {
                invariants: false,
                runtime_role: true,
                migrations: true,
                drift: false,
            }
        );
        assert!(!response.ok);
    }
}
