//! 機械用資格情報の内部口 4 本を、口から実 DB (RLS が効く `alc_api_app`) まで通すテスト。
//! 接続先は `AUTH_TEST_ADMIN_DATABASE_URL` (未設定なら失敗する。tests/support/mod.rs)。

mod support;

use serde_json::{json, Value};
use support::{
    app, app_without_secret, broken_app, call, call_raw, delete_tenant, tenant, username, App,
    SECRET,
};
use uuid::Uuid;

const PATH: &str = "/internal/machine-credentials";
const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn body(username: &str, tenant_id: Uuid, label: &str) -> Value {
    json!({
        "username": username,
        "tenant_id": tenant_id,
        "purpose": "leave-scan",
        "label": label,
        "secret_hash": HASH,
    })
}

async fn create(a: &App, username: &str, tenant_id: Uuid, label: &str) -> support::Got {
    call(a, "POST", PATH, Some(body(username, tenant_id, label))).await
}

async fn list(a: &App, tenant_id: Uuid) -> Value {
    let got = call(a, "GET", &format!("{PATH}?tenant_id={tenant_id}"), None).await;
    assert_eq!(got.status, 200);
    got.json()
}

async fn lookup(a: &App, username: &str) -> support::Got {
    call(a, "GET", &format!("{PATH}/{username}"), None).await
}

async fn revoke(a: &App, username: &str, tenant_id: Uuid) -> support::Got {
    call(
        a,
        "POST",
        &format!("{PATH}/{username}/revoke"),
        Some(json!({ "tenant_id": tenant_id })),
    )
    .await
}

fn usernames(list: &Value) -> Vec<String> {
    list["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["username"].as_str().unwrap().to_owned())
        .collect()
}

/// 作る → 一覧 (hash を出さない) → 照合 → 失効 → 照合 (revoked) → 一覧 (revoked)
#[tokio::test]
async fn create_list_lookup_revoke() {
    let a = app().await;
    let t = tenant().await;
    let u = username();
    let got = create(&a, &u, t, "複合機 1F").await;
    assert_eq!(got.status, 201);
    assert_eq!(got.json(), json!({}));

    let l = list(&a, t).await;
    let creds = l["credentials"].as_array().unwrap();
    assert_eq!(creds.len(), 1);
    let c = creds[0].as_object().unwrap();
    let mut keys: Vec<_> = c.keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        ["created_at", "label", "purpose", "revoked", "username"]
    );
    assert_eq!(c["username"], json!(u));
    assert_eq!(c["purpose"], "leave-scan");
    assert_eq!(c["label"], "複合機 1F");
    assert_eq!(c["revoked"], false);
    assert!(c["created_at"].is_string());

    let got = lookup(&a, &u).await;
    assert_eq!(got.status, 200);
    assert_eq!(
        got.json(),
        json!({"tenant_id": t, "purpose": "leave-scan", "secret_hash": HASH, "revoked": false})
    );

    let got = revoke(&a, &u, t).await;
    assert_eq!(got.status, 200);
    assert_eq!(got.json(), json!({"revoked": true}));
    assert_eq!(lookup(&a, &u).await.json()["revoked"], true);
    assert_eq!(list(&a, t).await["credentials"][0]["revoked"], true);
}

/// 一覧は作った順で、purpose で絞れる。空なら空の配列
#[tokio::test]
async fn list_is_ordered_and_filtered() {
    let a = app().await;
    let t = tenant().await;
    assert_eq!(list(&a, t).await, json!({"credentials": []}));
    let (u1, u2) = (username(), username());
    assert_eq!(create(&a, &u1, t, "first").await.status, 201);
    assert_eq!(create(&a, &u2, t, "second").await.status, 201);
    assert_eq!(usernames(&list(&a, t).await), [u1.clone(), u2.clone()]);
    let got = call(
        &a,
        "GET",
        &format!("{PATH}?tenant_id={t}&purpose=leave-scan"),
        None,
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(usernames(&got.json()), [u1, u2]);
}

/// 失効の 2 回目も 200 で、revoked_at は最初の時刻のまま
#[tokio::test]
async fn revoke_twice_keeps_the_first_time() {
    let a = app().await;
    let t = tenant().await;
    let u = username();
    assert_eq!(create(&a, &u, t, "x").await.status, 201);
    assert_eq!(revoke(&a, &u, t).await.status, 200);
    let first = revoked_at(&u).await;
    assert_eq!(revoke(&a, &u, t).await.status, 200);
    assert_eq!(revoked_at(&u).await, first);
}

async fn revoked_at(username: &str) -> String {
    let su = support::admin().await;
    let rows = su
        .query_typed(
            "SELECT revoked_at::text FROM alc_api.machine_credentials WHERE username = $1",
            &[(&username, tokio_postgres::types::Type::TEXT)],
        )
        .await
        .unwrap();
    rows[0].get::<_, String>(0)
}

/// username の重複は 409 (別の会社でも)。最初の行は変わらない
#[tokio::test]
async fn duplicate_username_is_409() {
    let a = app().await;
    let (t1, t2) = (tenant().await, tenant().await);
    let u = username();
    assert_eq!(create(&a, &u, t1, "x").await.status, 201);
    for t in [t1, t2] {
        let got = create(&a, &u, t, "y").await;
        assert_eq!(got.status, 409);
        assert_eq!(got.json(), json!({"error": "username_taken"}));
    }
    assert_eq!(lookup(&a, &u).await.json()["tenant_id"], json!(t1));
}

/// 会社が無ければ 404 tenant_not_found (FK 違反)
#[tokio::test]
async fn unknown_tenant_is_404() {
    let a = app().await;
    let u = username();
    let got = create(&a, &u, Uuid::new_v4(), "x").await;
    assert_eq!(got.status, 404);
    assert_eq!(got.json(), json!({"error": "tenant_not_found"}));
    assert_eq!(lookup(&a, &u).await.status, 404);
}

/// 形の不正は 400 (DB に届かない)
#[tokio::test]
async fn bad_create_body_is_400() {
    let a = app().await;
    let t = tenant().await;
    let u = username();
    let with = |key: &str, v: Value| {
        let mut b = body(&u, t, "x");
        b[key] = v;
        b
    };
    let cases = [
        (with("username", json!("mc_XYZ")), "invalid_username"),
        (with("purpose", json!("other")), "invalid_purpose"),
        (with("label", json!("")), "invalid_label"),
        (with("label", json!("a".repeat(65))), "invalid_label"),
        (with("secret_hash", json!("abc")), "invalid_secret_hash"),
        (with("tenant_id", json!("not-a-uuid")), "invalid_body"),
        (json!({"username": u}), "invalid_body"),
    ];
    for (b, code) in cases {
        let got = call(&a, "POST", PATH, Some(b.clone())).await;
        assert_eq!(got.status, 400, "{b}");
        assert_eq!(got.json(), json!({ "error": code }), "{b}");
    }
    // JSON でない・大きすぎる
    for raw in [b"{".to_vec(), vec![b' '; 5000]] {
        let got = call_raw(&a, "POST", PATH, Some(SECRET), Some(raw)).await;
        assert_eq!(got.status, 400);
        assert_eq!(got.json(), json!({"error": "invalid_body"}));
    }
    assert_eq!(list(&a, t).await, json!({"credentials": []}));
}

/// 一覧の query の不正は 400
#[tokio::test]
async fn bad_list_query_is_400() {
    let a = app().await;
    let t = tenant().await;
    for (uri, code) in [
        (PATH.to_owned(), "invalid_tenant_id"),
        (format!("{PATH}?tenant_id=x"), "invalid_tenant_id"),
        (
            format!("{PATH}?tenant_id={t}&tenant_id={t}"),
            "invalid_tenant_id",
        ),
        (format!("{PATH}?tenant_id={t}&purpose=x"), "invalid_purpose"),
    ] {
        let got = call(&a, "GET", &uri, None).await;
        assert_eq!(got.status, 400, "{uri}");
        assert_eq!(got.json(), json!({ "error": code }), "{uri}");
    }
}

/// 失効の body の不正は 400、形の違う username・無い username は 404
#[tokio::test]
async fn revoke_errors() {
    let a = app().await;
    let t = tenant().await;
    let u = username();
    assert_eq!(create(&a, &u, t, "x").await.status, 201);
    let got = call(
        &a,
        "POST",
        &format!("{PATH}/{u}/revoke"),
        Some(json!({"tenant_id": "x"})),
    )
    .await;
    assert_eq!(got.status, 400);
    assert_eq!(got.json(), json!({"error": "invalid_body"}));
    for name in ["mc_XYZ".to_owned(), username()] {
        let got = revoke(&a, &name, t).await;
        assert_eq!(got.status, 404, "{name}");
        assert_eq!(got.json(), json!({"error": "not_found"}));
    }
    assert_eq!(lookup(&a, &u).await.json()["revoked"], false);
}

/// 照合: 形の違う username・無い username は 404
#[tokio::test]
async fn lookup_not_found() {
    let a = app().await;
    for name in ["mc_XYZ".to_owned(), username()] {
        let got = lookup(&a, &name).await;
        assert_eq!(got.status, 404, "{name}");
        assert_eq!(got.json(), json!({"error": "not_found"}));
    }
}

/// RLS: 別の会社の tenant_id では一覧に出ず、失効は 404 (行は変わらない)。照合は会社をまたいで引ける
#[tokio::test]
async fn other_tenant_cannot_see_or_revoke() {
    let a = app().await;
    let (mine, other) = (tenant().await, tenant().await);
    let u = username();
    assert_eq!(create(&a, &u, mine, "x").await.status, 201);
    assert_eq!(list(&a, other).await, json!({"credentials": []}));
    let got = revoke(&a, &u, other).await;
    assert_eq!(got.status, 404);
    assert_eq!(got.json(), json!({"error": "not_found"}));
    let got = lookup(&a, &u).await;
    assert_eq!(got.json()["tenant_id"], json!(mine));
    assert_eq!(got.json()["revoked"], false);
    assert_eq!(usernames(&list(&a, mine).await), [u]);
}

/// CASCADE: 会社を消すと資格情報も消え、照合は 404
#[tokio::test]
async fn deleting_tenant_cascades() {
    let a = app().await;
    let t = tenant().await;
    let u = username();
    assert_eq!(create(&a, &u, t, "x").await.status, 201);
    assert_eq!(lookup(&a, &u).await.status, 200);
    delete_tenant(t).await;
    let got = lookup(&a, &u).await;
    assert_eq!(got.status, 404);
    assert_eq!(got.json(), json!({"error": "not_found"}));
    assert_eq!(list(&a, t).await, json!({"credentials": []}));
}

/// 共有 secret が無い・違う・worker 側で取れない ときは、4 口とも (と当たらない path も) 404 で本文は空。DB にも届かない
#[tokio::test]
async fn wrong_secret_is_404_everywhere() {
    let a = app().await;
    let t = tenant().await;
    let u = username();
    assert_eq!(create(&a, &u, t, "x").await.status, 201);
    let v = username();
    let create_body = serde_json::to_vec(&body(&v, t, "x")).unwrap();
    let revoke_body = serde_json::to_vec(&json!({ "tenant_id": t })).unwrap();
    let requests: [(&str, String, Option<Vec<u8>>); 5] = [
        ("POST", PATH.to_owned(), Some(create_body)),
        ("GET", format!("{PATH}?tenant_id={t}"), None),
        ("POST", format!("{PATH}/{u}/revoke"), Some(revoke_body)),
        ("GET", format!("{PATH}/{u}"), None),
        ("GET", "/internal/nothing".to_owned(), None),
    ];
    let no_secret = app_without_secret().await;
    for (method, uri, b) in &requests {
        for (app, secret) in [
            (&a, None),
            (&a, Some("wrong")),
            (&a, Some("")),
            (&no_secret, Some(SECRET)),
            (&no_secret, Some("")),
        ] {
            let got = call_raw(app, method, uri, secret, b.clone()).await;
            assert_eq!(got.status, 404, "{method} {uri} {secret:?}");
            assert!(got.body.is_empty(), "{method} {uri} {secret:?}");
        }
    }
    assert!(a
        .logs
        .lock()
        .unwrap()
        .iter()
        .all(|l| l == "internal: unauthorized"));
    // 何も変わっていない
    assert_eq!(lookup(&a, &v).await.status, 404);
    assert_eq!(lookup(&a, &u).await.json()["revoked"], false);
}

/// DB の失敗は 500 internal_error で、ログは SQLSTATE / 種類の label だけ
#[tokio::test]
async fn db_failure_is_500() {
    let a = broken_app().await;
    let t = Uuid::new_v4();
    let u = username();
    for got in [
        create(&a, &u, t, "x").await,
        call(&a, "GET", &format!("{PATH}?tenant_id={t}"), None).await,
        revoke(&a, &u, t).await,
        lookup(&a, &u).await,
    ] {
        assert_eq!(got.status, 500);
        assert_eq!(got.json(), json!({"error": "internal_error"}));
    }
    let logs = a.logs.lock().unwrap().clone();
    assert_eq!(logs.len(), 4, "{logs:?}");
    for (log, what) in logs.iter().zip(["create", "list", "revoke", "lookup"]) {
        assert!(log.starts_with(&format!("{what}: ")), "{log}");
        assert!(!log.contains(&u), "{log}");
    }
}
