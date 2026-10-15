//! 機械用資格情報の内部口 5 本とログインの内部口 8 本とロールの付け外しの口 3 本を、口から実 DB (RLS が効く `alc_api_app`) まで通すテスト。
//! 接続先は `AUTH_TEST_ADMIN_DATABASE_URL` (未設定なら失敗する。tests/support/mod.rs)。

mod support;

use serde_json::{json, Value};
use support::{
    app, app_staging, app_without_secret, broken_app, call, call_raw, delete_tenant, tenant,
    username, App, SECRET,
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

const NEW_HASH: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

async fn rotate(a: &App, username: &str, tenant_id: Uuid, hash: &str) -> support::Got {
    call(
        a,
        "POST",
        &format!("{PATH}/{username}/rotate"),
        Some(json!({ "tenant_id": tenant_id, "secret_hash": hash })),
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

/// rotate: hash だけ新しくなり (username・purpose・会社はそのまま)、2 回目も通る
#[tokio::test]
async fn rotate_replaces_the_hash() {
    let a = app().await;
    let t = tenant().await;
    let u = username();
    assert_eq!(create(&a, &u, t, "x").await.status, 201);
    let got = rotate(&a, &u, t, NEW_HASH).await;
    assert_eq!(got.status, 200);
    assert_eq!(got.json(), json!({"rotated": true}));
    assert_eq!(
        lookup(&a, &u).await.json(),
        json!({"tenant_id": t, "purpose": "leave-scan", "secret_hash": NEW_HASH, "revoked": false})
    );
    assert_eq!(rotate(&a, &u, t, HASH).await.status, 200);
    assert_eq!(lookup(&a, &u).await.json()["secret_hash"], HASH);
}

/// rotate の失敗: 失効済み・他社・無い・形の違う username は 404 (hash は変わらない)、body の不正は 400
#[tokio::test]
async fn rotate_errors() {
    let a = app().await;
    let (t, other) = (tenant().await, tenant().await);
    let (u, dead) = (username(), username());
    assert_eq!(create(&a, &u, t, "x").await.status, 201);
    assert_eq!(create(&a, &dead, t, "x").await.status, 201);
    assert_eq!(revoke(&a, &dead, t).await.status, 200);
    for (name, tenant_id) in [
        (dead.clone(), t),
        (u.clone(), other),
        (username(), t),
        ("mc_XYZ".to_owned(), t),
    ] {
        let got = rotate(&a, &name, tenant_id, NEW_HASH).await;
        assert_eq!(got.status, 404, "{name}");
        assert_eq!(got.json(), json!({"error": "not_found"}));
    }
    assert_eq!(lookup(&a, &u).await.json()["secret_hash"], HASH);
    assert_eq!(lookup(&a, &dead).await.json()["secret_hash"], HASH);
    let uri = format!("{PATH}/{u}/rotate");
    for (b, code) in [
        (
            json!({"tenant_id": t, "secret_hash": "x"}),
            "invalid_secret_hash",
        ),
        (
            json!({"tenant_id": t, "secret_hash": NEW_HASH.to_uppercase()}),
            "invalid_secret_hash",
        ),
        (
            json!({"tenant_id": "x", "secret_hash": NEW_HASH}),
            "invalid_body",
        ),
        (json!({"tenant_id": t}), "invalid_body"),
    ] {
        let got = call(&a, "POST", &uri, Some(b)).await;
        assert_eq!(got.status, 400);
        assert_eq!(got.json(), json!({ "error": code }));
    }
    assert_eq!(lookup(&a, &u).await.json()["secret_hash"], HASH);
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

/// 共有 secret が無い・違う・worker 側で取れない ときは、18 口とも (と当たらない path も) 404 で本文は空。DB にも届かない
#[tokio::test]
async fn wrong_secret_is_404_everywhere() {
    let a = app().await;
    let t = tenant().await;
    let u = username();
    assert_eq!(create(&a, &u, t, "x").await.status, 201);
    let v = username();
    let create_body = serde_json::to_vec(&body(&v, t, "x")).unwrap();
    let revoke_body = serde_json::to_vec(&json!({ "tenant_id": t })).unwrap();
    let rotate_body =
        serde_json::to_vec(&json!({ "tenant_id": t, "secret_hash": NEW_HASH })).unwrap();
    let google_body = serde_json::to_vec(&google_body(&gsub(), "x@example.test")).unwrap();
    let refresh_body = serde_json::to_vec(&refresh_body(Uuid::new_v4())).unwrap();
    let line_id = line_user_id();
    let lw = serde_json::to_vec(&lineworks_body(t, &line_id, "x@example.test")).unwrap();
    let line = serde_json::to_vec(&line_body(t, &line_id)).unwrap();
    let reg = serde_json::to_vec(&recipient_body(t, &line_id, "x")).unwrap();
    let role_path = format!("/internal/tenants/{t}/users/{}/roles/leave", Uuid::new_v4());
    let session_user = Uuid::new_v4();
    let requests: [(&str, String, Option<Vec<u8>>); 19] = [
        ("POST", PATH.to_owned(), Some(create_body)),
        ("GET", format!("{PATH}?tenant_id={t}"), None),
        ("POST", format!("{PATH}/{u}/revoke"), Some(revoke_body)),
        ("POST", format!("{PATH}/{u}/rotate"), Some(rotate_body)),
        ("GET", format!("{PATH}/{u}"), None),
        ("GET", format!("{SSO}?provider=lineworks&domain=x"), None),
        ("POST", GOOGLE.to_owned(), Some(google_body)),
        ("POST", REFRESH.to_owned(), Some(refresh_body)),
        ("POST", LINEWORKS.to_owned(), Some(lw)),
        ("POST", LINE.to_owned(), Some(line)),
        (
            "GET",
            format!("{USER_BY_LINE}?line_user_id={line_id}"),
            None,
        ),
        ("POST", REGISTER.to_owned(), Some(reg)),
        ("GET", format!("{RECIPIENTS}?line_user_id={line_id}"), None),
        ("GET", format!("/internal/tenants/{t}/user-roles"), None),
        ("PUT", role_path.clone(), None),
        ("DELETE", role_path, None),
        ("GET", format!("/internal/tenants/{t}"), None),
        ("DELETE", refresh_of(t, session_user), None),
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
    assert_eq!(line_rows(&line_id).await, (0, 0));
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
        rotate(&a, &u, t, NEW_HASH).await,
        lookup(&a, &u).await,
        call(
            &a,
            "GET",
            &format!("{SSO}?provider=lineworks&domain=x"),
            None,
        )
        .await,
        google(&a, &u, "u@example.test").await,
        call(&a, "POST", REFRESH, Some(refresh_body(t))).await,
        call(
            &a,
            "POST",
            LINEWORKS,
            Some(lineworks_body(t, &u, "u@example.test")),
        )
        .await,
        call(&a, "POST", LINE, Some(line_body(t, &u))).await,
        call(&a, "GET", &format!("{USER_BY_LINE}?line_user_id={u}"), None).await,
        call(&a, "POST", REGISTER, Some(recipient_body(t, &u, "x"))).await,
        call(&a, "GET", &format!("{RECIPIENTS}?line_user_id={u}"), None).await,
        call(&a, "GET", &roles_of(t), None).await,
        call(&a, "PUT", &role_of(t, Uuid::new_v4(), "leave"), None).await,
        call(&a, "DELETE", &role_of(t, Uuid::new_v4(), "leave"), None).await,
        call(&a, "GET", &format!("/internal/tenants/{t}"), None).await,
        call(&a, "DELETE", &refresh_of(t, Uuid::new_v4()), None).await,
    ] {
        assert_eq!(got.status, 500);
        assert_eq!(got.json(), json!({"error": "internal_error"}));
    }
    let logs = a.logs.lock().unwrap().clone();
    assert_eq!(logs.len(), 18, "{logs:?}");
    let whats = [
        "create",
        "list",
        "revoke",
        "rotate",
        "lookup",
        "sso-config",
        "upsert-google",
        "refresh-token",
        "upsert-lineworks",
        "upsert-line",
        "users/by-line-id",
        "recipients/register-line",
        "recipients/by-line-id",
        "user-roles",
        "roles/grant",
        "roles/revoke",
        "tenants/get",
        "refresh-token/clear",
    ];
    for (log, what) in logs.iter().zip(whats) {
        assert!(log.starts_with(&format!("{what}: ")), "{log}");
        assert!(!log.contains(&u), "{log}");
        assert!(!log.contains("example.test"), "{log}");
    }
}

// ---------- ログインの口 (Google・refresh token・SSO 設定) ----------

const SSO: &str = "/internal/auth/sso-config";
const GOOGLE: &str = "/internal/auth/users/upsert-google";
const REFRESH: &str = "/internal/auth/refresh-token";
const REFRESH_HASH: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

fn gsub() -> String {
    format!("gsub-{}", Uuid::new_v4().simple())
}

/// 乱数のドメイン (どの会社の email_domain とも当たらない)
fn domain() -> String {
    format!("d{}.example.test", Uuid::new_v4().simple())
}

fn google_body(sub: &str, email: &str) -> Value {
    json!({ "google_sub": sub, "email": email, "name": "Google User" })
}

fn refresh_body(user_id: Uuid) -> Value {
    json!({ "user_id": user_id, "refresh_hash": REFRESH_HASH, "expires_at": "2030-01-02T03:04:05Z" })
}

async fn google(a: &App, sub: &str, email: &str) -> support::Got {
    call(a, "POST", GOOGLE, Some(google_body(sub, email))).await
}

/// superuser で文を流す (準備と確認だけ)
async fn su_exec(sql: &str) {
    support::admin().await.batch_execute(sql).await.unwrap();
}

/// superuser で 1 行 1 列の数を読む
async fn su_count(sql: &str) -> i64 {
    support::admin().await.query_typed(sql, &[]).await.unwrap()[0].get(0)
}

/// 会社の email_domain と slug を変える
async fn set_tenant(t: Uuid, email_domain: Option<&str>, slug: Option<&str>) {
    let q = |v: Option<&str>| v.map_or("NULL".to_owned(), |v| format!("'{v}'"));
    su_exec(&format!(
        "UPDATE alc_api.tenants SET email_domain = {}, slug = {} WHERE id = '{t}'",
        q(email_domain),
        q(slug)
    ))
    .await;
}

async fn invite(t: Uuid, email: &str, role: &str) {
    su_exec(&format!(
        "INSERT INTO alc_api.tenant_allowed_emails (tenant_id, email, role) VALUES ('{t}', '{email}', '{role}')"
    ))
    .await;
}

fn keys(v: &Value) -> Vec<String> {
    let mut k: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

/// Google: 招待の email の初回ログインは、招待の会社・招待の role (email_domain が別の会社に当たっても招待が先) で作り、
/// 招待は消える。返す形は user の 8 列 + slug
#[tokio::test]
async fn google_invitation_creates_user_with_invited_role() {
    let a = app().await;
    let (invited, by_domain) = (tenant().await, tenant().await);
    let d = domain();
    set_tenant(invited, None, Some(&format!("slug-{invited}"))).await;
    set_tenant(by_domain, Some(&d), None).await;
    let email = format!("someone@{d}");
    invite(invited, &email, "viewer").await;
    let sub = gsub();

    let got = google(&a, &sub, &email).await;
    assert_eq!(got.status, 200);
    let u = got.json();
    assert_eq!(
        keys(&u),
        [
            "email",
            "google_sub",
            "id",
            "line_user_id",
            "lineworks_id",
            "name",
            "permissions",
            "role",
            "slug",
            "tenant_id"
        ]
    );
    assert_eq!(u["tenant_id"], json!(invited));
    assert_eq!(u["role"], "viewer", "招待の role で作る (admin にしない)");
    assert_eq!(u["google_sub"], json!(sub));
    assert_eq!(u["email"], json!(email));
    assert_eq!(u["name"], "Google User");
    assert_eq!(u["lineworks_id"], Value::Null);
    assert_eq!(u["line_user_id"], Value::Null);
    assert_eq!(u["slug"], json!(format!("slug-{invited}")));
    let left = su_count(&format!(
        "SELECT count(*) FROM alc_api.tenant_allowed_emails WHERE email = '{email}'"
    ))
    .await;
    assert_eq!(left, 0, "招待は使い済みで消える");
}

/// Google: 招待の role は payroll も admin もそのまま写す
#[tokio::test]
async fn google_invitation_role_is_copied() {
    let a = app().await;
    let t = tenant().await;
    for role in ["payroll", "admin"] {
        let email = format!("{role}@{}", domain());
        invite(t, &email, role).await;
        let got = google(&a, &gsub(), &email).await;
        assert_eq!(got.status, 200);
        assert_eq!(got.json()["role"], role);
        assert_eq!(got.json()["tenant_id"], json!(t));
    }
}

/// Google: 既存の user (sub の一致) はそのまま返す (email / name / role は書き換えず、行も増えない)
#[tokio::test]
async fn google_existing_user_is_returned_as_is() {
    let a = app().await;
    let t = tenant().await;
    let d = domain();
    set_tenant(t, Some(&d), None).await;
    let sub = gsub();
    let first = google(&a, &sub, &format!("a@{d}")).await.json();
    assert_eq!(first["role"], "admin");
    su_exec(&format!(
        "UPDATE alc_api.users SET role = 'viewer' WHERE id = '{}'",
        first["id"].as_str().unwrap()
    ))
    .await;
    let renamed =
        json!({ "google_sub": sub, "email": "other@other.example.test", "name": "Renamed" });
    let got = call(&a, "POST", GOOGLE, Some(renamed)).await;
    assert_eq!(got.status, 200);
    let again = got.json();
    assert_eq!(again["id"], first["id"]);
    assert_eq!(again["role"], "viewer");
    assert_eq!(again["email"], json!(format!("a@{d}")));
    assert_eq!(again["name"], "Google User");
    assert_eq!(again["slug"], Value::Null);
    let rows = su_count(&format!(
        "SELECT count(*) FROM alc_api.users WHERE google_sub = '{sub}'"
    ))
    .await;
    assert_eq!(rows, 1);
}

/// Google: 招待が無く email_domain が会社に当たれば、その会社の admin
#[tokio::test]
async fn google_email_domain_match_is_admin() {
    let a = app().await;
    let t = tenant().await;
    let d = domain();
    set_tenant(t, Some(&d), Some(&format!("slug-{t}"))).await;
    let got = google(&a, &gsub(), &format!("someone@{d}")).await;
    assert_eq!(got.status, 200);
    assert_eq!(got.json()["tenant_id"], json!(t));
    assert_eq!(got.json()["role"], "admin");
    assert_eq!(got.json()["slug"], json!(format!("slug-{t}")));
}

/// Google: 招待も email_domain の一致も無ければ、本番 (STAGING_MODE 無効) は 403 で、会社も user も作らない。
/// ログに email を出さない
#[tokio::test]
async fn google_without_tenant_is_403_in_production() {
    let a = app().await;
    let d = domain();
    let sub = gsub();
    let got = google(&a, &sub, &format!("nobody@{d}")).await;
    assert_eq!(got.status, 403);
    assert_eq!(got.json(), json!({"error": "no_tenant_for_email"}));
    let tenants = su_count(&format!(
        "SELECT count(*) FROM alc_api.tenants WHERE email_domain = '{d}'"
    ))
    .await;
    assert_eq!(tenants, 0);
    let users = su_count(&format!(
        "SELECT count(*) FROM alc_api.users WHERE google_sub = '{sub}'"
    ))
    .await;
    assert_eq!(users, 0);
    assert_eq!(
        *a.logs.lock().unwrap(),
        ["upsert-google: no tenant for email"]
    );
}

/// Google: STAGING_MODE では、会社 (名前・email_domain = ドメイン) を作ってその admin にする。
/// 同じドメインの 2 人目は、作った会社に email_domain で当たる
#[tokio::test]
async fn google_without_tenant_creates_tenant_in_staging() {
    let a = app_staging().await;
    let d = domain();
    let got = google(&a, &gsub(), &format!("first@{d}")).await;
    assert_eq!(got.status, 200);
    let first = got.json();
    assert_eq!(first["role"], "admin");
    let t = first["tenant_id"].as_str().unwrap().to_owned();
    let made = su_count(&format!(
        "SELECT count(*) FROM alc_api.tenants WHERE id = '{t}' AND name = '{d}' AND email_domain = '{d}'"
    ))
    .await;
    assert_eq!(made, 1);
    let second = google(&a, &gsub(), &format!("second@{d}")).await.json();
    assert_eq!(second["tenant_id"].as_str().unwrap(), t);
    assert_eq!(second["role"], "admin");
    assert_eq!(
        *a.logs.lock().unwrap(),
        ["upsert-google: staging tenant created"]
    );
}

/// STAGING_MODE でも、招待・email_domain の一致が先 (会社を作らない)
#[tokio::test]
async fn google_staging_prefers_invitation_and_domain() {
    let a = app_staging().await;
    let t = tenant().await;
    let d = domain();
    set_tenant(t, Some(&d), None).await;
    let email = format!("inv@{}", domain());
    invite(t, &email, "viewer").await;
    let by_invitation = google(&a, &gsub(), &email).await.json();
    assert_eq!(by_invitation["tenant_id"], json!(t));
    assert_eq!(by_invitation["role"], "viewer");
    let by_domain = google(&a, &gsub(), &format!("x@{d}")).await.json();
    assert_eq!(by_domain["tenant_id"], json!(t));
    assert_eq!(by_domain["role"], "admin");
    assert!(a.logs.lock().unwrap().is_empty());
}

/// 会社の作成の再試行: UNIQUE 違反は回数まで流し直し、最後の UNIQUE 違反はそのまま返す。
/// ほかのエラーと成功は流し直さない
#[tokio::test]
async fn retry_on_unique_counts_attempts() {
    use alc_worker_db::PgClient;
    use auth::pg::retry_on_unique;
    use futures_util::future::BoxFuture;

    /// 1 文を nil の tenant の transaction で流す
    fn attempt(
        pg: &mut PgClient,
        sql: String,
    ) -> BoxFuture<'_, Result<u64, tokio_postgres::Error>> {
        Box::pin(pg.tenant_tx(Uuid::nil(), move |tx| {
            Box::pin(async move { tx.execute_typed(&sql, &[]).await })
        }))
    }

    let mut pg = support::app_client().await;
    let t = tenant().await;
    let dup = format!("INSERT INTO alc_api.tenants (id, name) VALUES ('{t}', 'dup')");
    let mut calls = 0;
    // ずっと UNIQUE 違反 → 3 回で止まり 23505
    let e = retry_on_unique(&mut pg, 3, |pg| {
        calls += 1;
        attempt(pg, dup.clone())
    })
    .await
    .unwrap_err();
    assert_eq!(alc_worker_db::kind(&e), "23505");
    assert_eq!(calls, 3);
    // 2 回目で通る
    calls = 0;
    let n = retry_on_unique(&mut pg, 3, |pg| {
        calls += 1;
        let sql = if calls == 2 { "SELECT 1" } else { &dup };
        attempt(pg, sql.to_owned())
    })
    .await
    .unwrap();
    assert_eq!((n, calls), (1, 2));
    // UNIQUE 違反でなければ流し直さない
    calls = 0;
    let e = retry_on_unique(&mut pg, 3, |pg| {
        calls += 1;
        attempt(pg, "SELECT 1 / 0".to_owned())
    })
    .await
    .unwrap_err();
    assert_eq!((alc_worker_db::kind(&e).as_str(), calls), ("22012", 1));
}

/// refresh token: 渡した user の行だけに hash と期限を書き、204。無い user も 204 (移植元と同じ)
#[tokio::test]
async fn refresh_token_is_saved_for_the_given_user_only() {
    let a = app().await;
    let t = tenant().await;
    let d = domain();
    set_tenant(t, Some(&d), None).await;
    let target = google(&a, &gsub(), &format!("a@{d}")).await.json();
    let other = google(&a, &gsub(), &format!("b@{d}")).await.json();
    let id = target["id"].as_str().unwrap();
    let got = call(&a, "POST", REFRESH, Some(refresh_body(id.parse().unwrap()))).await;
    assert_eq!(got.status, 204);
    assert!(got.body.is_empty());
    let saved = su_count(&format!(
        "SELECT count(*) FROM alc_api.users WHERE id = '{id}' AND refresh_token_hash = '{REFRESH_HASH}' \
         AND refresh_token_expires_at = '2030-01-02T03:04:05Z'"
    ))
    .await;
    assert_eq!(saved, 1);
    let untouched = su_count(&format!(
        "SELECT count(*) FROM alc_api.users WHERE id = '{}' AND refresh_token_hash IS NULL",
        other["id"].as_str().unwrap()
    ))
    .await;
    assert_eq!(untouched, 1);
    let got = call(&a, "POST", REFRESH, Some(refresh_body(Uuid::new_v4()))).await;
    assert_eq!(got.status, 204);
}

/// SSO 設定: external_org_id の完全一致 → 無ければ slug で引き直す → provider 違い・無効・無いは 404
#[tokio::test]
async fn sso_config_exact_slug_and_not_found() {
    let a = app().await;
    let (t, disabled) = (tenant().await, tenant().await);
    let slug = format!("slug-{t}");
    set_tenant(t, None, Some(&slug)).await;
    let org = format!("org-{t}");
    su_exec(&format!(
        "INSERT INTO alc_api.sso_provider_configs \
         (tenant_id, provider, client_id, client_secret_encrypted, external_org_id, woff_id) \
         VALUES ('{t}', 'lineworks', 'cid-{t}', 'enc-{t}', '{org}', 'woff-{t}'); \
         INSERT INTO alc_api.sso_provider_configs \
         (tenant_id, provider, client_id, client_secret_encrypted, external_org_id, enabled) \
         VALUES ('{disabled}', 'lineworks', 'cid-{disabled}', 'enc', 'org-{disabled}', false)"
    ))
    .await;
    let want = json!({
        "tenant_id": t,
        "client_id": format!("cid-{t}"),
        "client_secret_encrypted": format!("enc-{t}"),
        "external_org_id": org,
        "woff_id": format!("woff-{t}"),
    });
    for d in [&org, &slug] {
        let got = call(
            &a,
            "GET",
            &format!("{SSO}?provider=lineworks&domain={d}"),
            None,
        )
        .await;
        assert_eq!(got.status, 200, "{d}");
        assert_eq!(got.json(), want, "{d}");
    }
    for uri in [
        format!("{SSO}?provider=google&domain={org}"),
        format!("{SSO}?provider=lineworks&domain=org-{disabled}"),
        format!("{SSO}?provider=lineworks&domain=nothing-{t}"),
    ] {
        let got = call(&a, "GET", &uri, None).await;
        assert_eq!(got.status, 404, "{uri}");
        assert_eq!(
            got.json(),
            json!({"error": "sso_config_not_found"}),
            "{uri}"
        );
    }
}

/// ログインの口の入力の不正は 400 (DB に届かない)
#[tokio::test]
async fn bad_login_input_is_400() {
    let a = app().await;
    for uri in [
        SSO.to_owned(),
        format!("{SSO}?provider=lineworks"),
        format!("{SSO}?domain=x"),
        USER_BY_LINE.to_owned(),
        format!("{USER_BY_LINE}?line=x"),
        RECIPIENTS.to_owned(),
        format!("{RECIPIENTS}?line=x"),
    ] {
        let got = call(&a, "GET", &uri, None).await;
        assert_eq!(got.status, 400, "{uri}");
        assert_eq!(got.json(), json!({"error": "invalid_query"}), "{uri}");
    }
    let bodies = [
        (GOOGLE, json!({"google_sub": "x", "email": "y"})),
        (
            REFRESH,
            json!({"user_id": "x", "refresh_hash": "h", "expires_at": "2030-01-01T00:00:00Z"}),
        ),
        (
            REFRESH,
            json!({"user_id": Uuid::new_v4(), "refresh_hash": "h", "expires_at": "tomorrow"}),
        ),
        (
            LINEWORKS,
            json!({"tenant_id": Uuid::new_v4(), "lineworks_id": "x", "name": "n"}),
        ),
        (
            LINE,
            json!({"tenant_id": "x", "line_user_id": "x", "name": "n"}),
        ),
        (LINE, json!({"line_user_id": "x", "name": "n"})),
        (REGISTER, json!({"tenant_id": Uuid::new_v4(), "name": "n"})),
    ];
    for (path, b) in bodies {
        let got = call(&a, "POST", path, Some(b.clone())).await;
        assert_eq!(got.status, 400, "{b}");
        assert_eq!(got.json(), json!({"error": "invalid_body"}), "{b}");
    }
    let got = call_raw(&a, "POST", REFRESH, Some(SECRET), Some(b"{".to_vec())).await;
    assert_eq!(got.status, 400);
    assert!(a.logs.lock().unwrap().is_empty());
}

// ---------- ログインの口 (LINE・LINE WORKS・LINE の受信者) ----------

const LINEWORKS: &str = "/internal/auth/users/upsert-lineworks";
const LINE: &str = "/internal/auth/users/upsert-line";
const USER_BY_LINE: &str = "/internal/auth/users/by-line-id";
const REGISTER: &str = "/internal/auth/recipients/register-line";
const RECIPIENTS: &str = "/internal/auth/recipients/by-line-id";

fn line_user_id() -> String {
    format!("U{}", Uuid::new_v4().simple())
}

fn lineworks_body(t: Uuid, id: &str, email: &str) -> Value {
    json!({ "tenant_id": t, "lineworks_id": id, "email": email, "name": "LW User" })
}

fn line_body(t: Uuid, id: &str) -> Value {
    json!({ "tenant_id": t, "line_user_id": id, "name": "LINE User" })
}

fn recipient_body(t: Uuid, id: &str, name: &str) -> Value {
    json!({ "tenant_id": t, "line_user_id": id, "name": name })
}

/// その LINE の user id の (users の行数, 受信者の行数) を superuser で数える
async fn line_rows(id: &str) -> (i64, i64) {
    (
        su_count(&format!(
            "SELECT count(*) FROM alc_api.users WHERE line_user_id = '{id}'"
        ))
        .await,
        su_count(&format!(
            "SELECT count(*) FROM alc_api.notify_recipients WHERE line_user_id = '{id}'"
        ))
        .await,
    )
}

/// superuser で、その user の role を変える (既存の user の role を口が書き換えないことの確かめ)
async fn set_role(user: &Value, role: &str) {
    su_exec(&format!(
        "UPDATE alc_api.users SET role = '{role}' WHERE id = '{}'",
        user["id"].as_str().unwrap()
    ))
    .await;
}

/// refresh token を保存して 204 と、DB に入ったことを確かめる (ログインの最後の手。移植元の runtime_role_test と同じ組み合わせ)
async fn assert_refresh_saved(a: &App, user: &Value) {
    let id = user["id"].as_str().unwrap();
    let got = call(a, "POST", REFRESH, Some(refresh_body(id.parse().unwrap()))).await;
    assert_eq!(got.status, 204);
    let saved = su_count(&format!(
        "SELECT count(*) FROM alc_api.users WHERE id = '{id}' AND refresh_token_hash = '{REFRESH_HASH}'"
    ))
    .await;
    assert_eq!(saved, 1);
}

/// LINE WORKS: 新規は body の会社に viewer で作る (返す形は user の 8 列 + slug)。既存 (id の一致) は、
/// 会社・role・email・name を変えずに返す (別の会社の tenant_id が来ても)。refresh token はどちらの後にも保存できる
#[tokio::test]
async fn lineworks_new_is_viewer_then_existing_is_kept() {
    let a = app().await;
    let (t, other) = (tenant().await, tenant().await);
    set_tenant(t, None, Some(&format!("slug-{t}"))).await;
    let id = line_user_id();
    let email = format!("lw@{}", domain());
    let got = call(&a, "POST", LINEWORKS, Some(lineworks_body(t, &id, &email))).await;
    assert_eq!(got.status, 200);
    let created = got.json();
    assert_eq!(
        keys(&created),
        [
            "email",
            "google_sub",
            "id",
            "line_user_id",
            "lineworks_id",
            "name",
            "permissions",
            "role",
            "slug",
            "tenant_id"
        ]
    );
    assert_eq!(created["tenant_id"], json!(t));
    assert_eq!(
        created["role"], "viewer",
        "LINE WORKS の新規は viewer (admin にしない)"
    );
    assert_eq!(created["lineworks_id"], json!(id));
    assert_eq!(created["email"], json!(email));
    assert_eq!(created["name"], "LW User");
    assert_eq!(created["google_sub"], Value::Null);
    assert_eq!(created["line_user_id"], Value::Null);
    assert_eq!(created["slug"], json!(format!("slug-{t}")));
    assert_refresh_saved(&a, &created).await;

    set_role(&created, "admin").await;
    let renamed = json!({ "tenant_id": other, "lineworks_id": id, "email": "o@other.example.test", "name": "Renamed" });
    let got = call(&a, "POST", LINEWORKS, Some(renamed)).await;
    assert_eq!(got.status, 200);
    let again = got.json();
    assert_eq!(again["id"], created["id"]);
    assert_eq!(again["tenant_id"], json!(t));
    assert_eq!(again["role"], "admin", "既存の user の role は変えない");
    assert_eq!(again["email"], json!(email));
    assert_eq!(again["name"], "LW User");
    assert_refresh_saved(&a, &again).await;
    let rows = su_count(&format!(
        "SELECT count(*) FROM alc_api.users WHERE lineworks_id = '{id}'"
    ))
    .await;
    assert_eq!(rows, 1);
    assert!(a.logs.lock().unwrap().is_empty());
}

/// LINE: 新規は body の会社に viewer で作り、email には LINE の user id が入る (移植元と同じ)。
/// 既存は会社・role・name を変えずに返す。by-line-id は同じ形で引け、無い id は 200 `null`
#[tokio::test]
async fn line_new_is_viewer_then_existing_is_kept() {
    let a = app().await;
    let (t, other) = (tenant().await, tenant().await);
    let id = line_user_id();
    let by_id = format!("{USER_BY_LINE}?line_user_id={id}");
    let got = call(&a, "GET", &by_id, None).await;
    assert_eq!(got.status, 200, "無いは 404 にしない");
    assert_eq!(got.body, b"null");

    let got = call(&a, "POST", LINE, Some(line_body(t, &id))).await;
    assert_eq!(got.status, 200);
    let created = got.json();
    assert_eq!(created["tenant_id"], json!(t));
    assert_eq!(
        created["role"], "viewer",
        "LINE の新規は viewer (admin にしない)"
    );
    assert_eq!(created["line_user_id"], json!(id));
    assert_eq!(created["email"], json!(id));
    assert_eq!(created["name"], "LINE User");
    assert_eq!(created["google_sub"], Value::Null);
    assert_eq!(created["lineworks_id"], Value::Null);
    assert_eq!(created["slug"], Value::Null);
    assert_refresh_saved(&a, &created).await;

    set_role(&created, "payroll").await;
    set_tenant(t, None, Some(&format!("slug-{t}"))).await;
    let renamed = json!({ "tenant_id": other, "line_user_id": id, "name": "Renamed" });
    let again = call(&a, "POST", LINE, Some(renamed)).await.json();
    assert_eq!(again["id"], created["id"]);
    assert_eq!(again["tenant_id"], json!(t));
    assert_eq!(again["role"], "payroll", "既存の user の role は変えない");
    assert_eq!(again["name"], "LINE User");
    assert_eq!(again["slug"], json!(format!("slug-{t}")));
    assert_refresh_saved(&a, &again).await;
    assert_eq!(line_rows(&id).await, (1, 0));

    let got = call(&a, "GET", &by_id, None).await;
    assert_eq!(got.status, 200);
    assert_eq!(got.json(), again, "by-line-id は upsert-line と同じ形");
    assert!(a.logs.lock().unwrap().is_empty());
}

/// 本番 (STAGING_MODE 無効) では会社を作らない: 無い会社の tenant_id は FK 違反で 500 (移植元と同じ)、
/// 会社も user も増えない。ログは SQLSTATE だけ
#[tokio::test]
async fn line_unknown_tenant_is_500_in_production() {
    let a = app().await;
    let t = Uuid::new_v4();
    let (id, lw) = (line_user_id(), line_user_id());
    let got = call(&a, "POST", LINE, Some(line_body(t, &id))).await;
    assert_eq!(got.status, 500);
    assert_eq!(got.json(), json!({"error": "internal_error"}));
    let got = call(
        &a,
        "POST",
        LINEWORKS,
        Some(lineworks_body(t, &lw, "a@example.test")),
    )
    .await;
    assert_eq!(got.status, 500);
    let tenants = su_count(&format!(
        "SELECT count(*) FROM alc_api.tenants WHERE id = '{t}'"
    ))
    .await;
    assert_eq!(tenants, 0);
    assert_eq!(line_rows(&id).await, (0, 0));
    assert_eq!(
        *a.logs.lock().unwrap(),
        ["upsert-line: 23503", "upsert-lineworks: 23503"]
    );
}

/// STAGING_MODE では、無い会社を先に在らせて (名前は移植元と同じ) その viewer を作る。在る会社は名前を変えない
#[tokio::test]
async fn line_unknown_tenant_is_ensured_in_staging() {
    let a = app_staging().await;
    let (missing, existing) = (Uuid::new_v4(), tenant().await);
    for (path, t, b) in [
        (LINE, missing, line_body(missing, &line_user_id())),
        (
            LINEWORKS,
            missing,
            lineworks_body(missing, &line_user_id(), "a@example.test"),
        ),
        (LINE, existing, line_body(existing, &line_user_id())),
    ] {
        let got = call(&a, "POST", path, Some(b)).await;
        assert_eq!(got.status, 200, "{path}");
        assert_eq!(got.json()["tenant_id"], json!(t));
        assert_eq!(got.json()["role"], "viewer");
    }
    let made = su_count(&format!(
        "SELECT count(*) FROM alc_api.tenants WHERE id = '{missing}' AND name = 'LINE WORKS (staging auto)'"
    ))
    .await;
    assert_eq!(made, 1);
    let kept = su_count(&format!(
        "SELECT count(*) FROM alc_api.tenants WHERE id = '{existing}' AND name = 'auth-test-{existing}'"
    ))
    .await;
    assert_eq!(kept, 1);
    assert!(a.logs.lock().unwrap().is_empty());
}

/// 受信者: 登録は 204、同じ会社の重複も 204 で何もしない (名前も変えない)。逆引きは会社をまたいで全部返し、
/// 無効な受信者・無い id は出さない
#[tokio::test]
async fn line_recipients_register_and_lookup() {
    let a = app().await;
    let (t1, t2) = (tenant().await, tenant().await);
    let id = line_user_id();
    for (t, name) in [(t1, "first"), (t1, "second"), (t2, "other")] {
        let got = call(&a, "POST", REGISTER, Some(recipient_body(t, &id, name))).await;
        assert_eq!(got.status, 204);
        assert!(got.body.is_empty());
    }
    assert_eq!(line_rows(&id).await, (0, 2));
    let got = call(&a, "GET", &format!("{RECIPIENTS}?line_user_id={id}"), None).await;
    assert_eq!(got.status, 200);
    let mut rows = got.json().as_array().unwrap().clone();
    rows.sort_by_key(|r| r["tenant_id"].as_str().unwrap().to_owned());
    let mut want = vec![
        json!({"tenant_id": t1, "name": "first"}),
        json!({"tenant_id": t2, "name": "other"}),
    ];
    want.sort_by_key(|r| r["tenant_id"].as_str().unwrap().to_owned());
    assert_eq!(rows, want);

    su_exec(&format!(
        "UPDATE alc_api.notify_recipients SET enabled = false WHERE tenant_id = '{t2}' AND line_user_id = '{id}'"
    ))
    .await;
    let got = call(&a, "GET", &format!("{RECIPIENTS}?line_user_id={id}"), None).await;
    assert_eq!(got.json(), json!([{"tenant_id": t1, "name": "first"}]));
    let got = call(
        &a,
        "GET",
        &format!("{RECIPIENTS}?line_user_id={}", line_user_id()),
        None,
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(got.json(), json!([]));
    assert!(a.logs.lock().unwrap().is_empty());
}

/// RLS: 口の INSERT の文 (users・受信者) は、別の会社の transaction からは入らず (42501)、
/// 別の会社の transaction からは入った行が見えない
#[tokio::test]
async fn line_inserts_are_bound_by_rls() {
    use alc_worker_db::PgClient;
    use auth::pg::login_sql;
    use tokio_postgres::types::Type;

    async fn run(
        pg: &mut PgClient,
        as_tenant: Uuid,
        sql: &'static str,
        t: Uuid,
        id: String,
    ) -> Result<u64, tokio_postgres::Error> {
        pg.tenant_tx(as_tenant, move |tx| {
            Box::pin(async move {
                let name = "x".to_owned();
                if sql == login_sql::INSERT_LINE_USER {
                    tx.query_typed(
                        sql,
                        &[(&t, Type::UUID), (&id, Type::TEXT), (&name, Type::TEXT)],
                    )
                    .await
                    .map(|r| r.len() as u64)
                } else {
                    tx.execute_typed(
                        sql,
                        &[(&t, Type::UUID), (&name, Type::TEXT), (&id, Type::TEXT)],
                    )
                    .await
                }
            })
        })
        .await
    }

    async fn visible(pg: &mut PgClient, as_tenant: Uuid, id: String) -> i64 {
        pg.tenant_tx(as_tenant, move |tx| {
            Box::pin(async move {
                let row = tx
                    .query_typed_one(
                        "SELECT (SELECT count(*) FROM alc_api.users WHERE line_user_id = $1) \
                         + (SELECT count(*) FROM alc_api.notify_recipients WHERE line_user_id = $1)",
                        &[(&id, Type::TEXT)],
                    )
                    .await?;
                Ok(row.get::<_, i64>(0))
            })
        })
        .await
        .unwrap()
    }

    let mut pg = support::app_client().await;
    let (mine, other) = (tenant().await, tenant().await);
    let id = line_user_id();
    for sql in [
        login_sql::INSERT_LINE_USER,
        login_sql::REGISTER_LINE_RECIPIENT,
    ] {
        let e = run(&mut pg, other, sql, mine, id.clone())
            .await
            .unwrap_err();
        assert_eq!(alc_worker_db::kind(&e), "42501", "{sql}");
        assert_eq!(run(&mut pg, mine, sql, mine, id.clone()).await.unwrap(), 1);
    }
    assert_eq!(line_rows(&id).await, (1, 1));
    assert_eq!(visible(&mut pg, mine, id.clone()).await, 2);
    assert_eq!(visible(&mut pg, other, id.clone()).await, 0);
}

// ---------- ロールの付け外しの口とログインの permissions ----------

fn roles_of(t: Uuid) -> String {
    format!("/internal/tenants/{t}/user-roles")
}

fn role_of(t: impl std::fmt::Display, user: impl std::fmt::Display, role: &str) -> String {
    format!("/internal/tenants/{t}/users/{user}/roles/{role}")
}

/// LINE で新しい user を作って返す (viewer)
async fn line_user(a: &App, t: Uuid) -> Value {
    let got = call(a, "POST", LINE, Some(line_body(t, &line_user_id()))).await;
    assert_eq!(got.status, 200);
    got.json()
}

async fn grant(a: &App, t: Uuid, user: &Value) -> support::Got {
    let id = user["id"].as_str().unwrap();
    call(a, "PUT", &role_of(t, id, "leave"), None).await
}

async fn role_rows(user: &Value) -> i64 {
    su_count(&format!(
        "SELECT count(*) FROM alc_api.user_roles WHERE user_id = '{}'",
        user["id"].as_str().unwrap()
    ))
    .await
}

/// user を返す 4 口は、付いたロールの権限を `permissions` で返す (無ければ空)。LINE・LINE WORKS・Google の viewer
#[tokio::test]
async fn login_returns_permissions_from_roles() {
    let a = app().await;
    let t = tenant().await;

    let line = line_user(&a, t).await;
    assert_eq!(line["permissions"], json!([]));
    assert_eq!(grant(&a, t, &line).await.status, 204);
    let id = line["line_user_id"].as_str().unwrap();
    let again = call(&a, "POST", LINE, Some(line_body(t, id))).await.json();
    assert_eq!(again["permissions"], json!(["leave.use"]));
    let by_id = call(
        &a,
        "GET",
        &format!("{USER_BY_LINE}?line_user_id={id}"),
        None,
    )
    .await;
    assert_eq!(by_id.json()["permissions"], json!(["leave.use"]));

    let lw_id = line_user_id();
    let lw = lineworks_body(t, &lw_id, "lw@example.test");
    let created = call(&a, "POST", LINEWORKS, Some(lw.clone())).await.json();
    assert_eq!(created["permissions"], json!([]));
    assert_eq!(grant(&a, t, &created).await.status, 204);
    let again = call(&a, "POST", LINEWORKS, Some(lw)).await.json();
    assert_eq!(again["permissions"], json!(["leave.use"]));

    let email = format!("v@{}", domain());
    invite(t, &email, "viewer").await;
    let sub = gsub();
    let created = google(&a, &sub, &email).await.json();
    assert_eq!(created["role"], "viewer");
    assert_eq!(created["permissions"], json!([]));
    assert_eq!(grant(&a, t, &created).await.status, 204);
    let again = google(&a, &sub, &email).await.json();
    assert_eq!(again["permissions"], json!(["leave.use"]));
    assert!(a.logs.lock().unwrap().is_empty());
}

/// admin は全権限 `*` (ロールが付いていても同じ)
#[tokio::test]
async fn admin_permissions_are_all() {
    let a = app().await;
    let t = tenant().await;
    let d = domain();
    set_tenant(t, Some(&d), None).await;
    let sub = gsub();
    let email = format!("a@{d}");
    let created = google(&a, &sub, &email).await.json();
    assert_eq!(created["role"], "admin");
    assert_eq!(created["permissions"], json!(["*"]));
    assert_eq!(
        grant(&a, t, &created).await.status,
        204,
        "admin に付けても拒まない"
    );
    assert_eq!(role_rows(&created).await, 1);
    assert_eq!(
        google(&a, &sub, &email).await.json()["permissions"],
        json!(["*"])
    );
}

/// 付ける (2 回でも 1 行) → 一覧 (ロールを持つ user だけ) → 外す (無くても 204)
#[tokio::test]
async fn roles_put_list_delete() {
    let a = app().await;
    let t = tenant().await;
    let (u1, u2) = (line_user(&a, t).await, line_user(&a, t).await);
    assert_eq!(call(&a, "GET", &roles_of(t), None).await.json(), json!([]));

    for _ in 0..2 {
        let got = grant(&a, t, &u1).await;
        assert_eq!(got.status, 204);
        assert!(got.body.is_empty());
    }
    assert_eq!(role_rows(&u1).await, 1);
    let got = call(&a, "GET", &roles_of(t), None).await;
    assert_eq!(got.status, 200);
    assert_eq!(
        got.json(),
        json!([{ "user_id": u1["id"], "roles": ["leave"] }])
    );

    assert_eq!(grant(&a, t, &u2).await.status, 204);
    let mut want = vec![
        json!({ "user_id": u1["id"], "roles": ["leave"] }),
        json!({ "user_id": u2["id"], "roles": ["leave"] }),
    ];
    want.sort_by_key(|v| v["user_id"].as_str().unwrap().to_owned());
    assert_eq!(
        call(&a, "GET", &roles_of(t), None).await.json(),
        json!(want)
    );

    let path = role_of(t, u1["id"].as_str().unwrap(), "leave");
    for _ in 0..2 {
        let got = call(&a, "DELETE", &path, None).await;
        assert_eq!(got.status, 204);
        assert!(got.body.is_empty());
    }
    assert_eq!(role_rows(&u1).await, 0);
    assert_eq!(
        call(&a, "GET", &roles_of(t), None).await.json(),
        json!([{ "user_id": u2["id"], "roles": ["leave"] }])
    );
    // 別の会社の一覧には出ない
    assert_eq!(
        call(&a, "GET", &roles_of(tenant().await), None)
            .await
            .json(),
        json!([])
    );
    assert!(a.logs.lock().unwrap().is_empty());
}

/// 未知のロール・UUID でない id は 400、別の会社 / 無い user に付けるのは 404 (行は入らない)。
/// 別の会社からは外せない
#[tokio::test]
async fn roles_errors() {
    let a = app().await;
    let (t, other) = (tenant().await, tenant().await);
    let u = line_user(&a, t).await;
    let id = u["id"].as_str().unwrap();

    for method in ["PUT", "DELETE"] {
        for (path, code) in [
            (role_of(t, id, "admin"), "unknown_role"),
            (role_of(t, id, "Leave"), "unknown_role"),
            (role_of("x", id, "leave"), "invalid_id"),
            (role_of(t, "x", "leave"), "invalid_id"),
        ] {
            let got = call(&a, method, &path, None).await;
            assert_eq!(got.status, 400, "{method} {path}");
            assert_eq!(got.json(), json!({ "error": code }), "{method} {path}");
        }
    }
    let got = call(&a, "GET", "/internal/tenants/x/user-roles", None).await;
    assert_eq!(got.status, 400);
    assert_eq!(got.json(), json!({ "error": "invalid_id" }));

    for path in [
        role_of(other, id, "leave"),
        role_of(t, Uuid::new_v4(), "leave"),
    ] {
        let got = call(&a, "PUT", &path, None).await;
        assert_eq!(got.status, 404, "{path}");
        assert_eq!(got.json(), json!({ "error": "user_not_found" }));
    }
    assert_eq!(role_rows(&u).await, 0);
    assert_eq!(grant(&a, t, &u).await.status, 204);
    let got = call(&a, "DELETE", &role_of(other, id, "leave"), None).await;
    assert_eq!(got.status, 204);
    assert_eq!(role_rows(&u).await, 1, "別の会社からは外せない");
    assert!(a.logs.lock().unwrap().is_empty());
}

// ---------- staging の me・logout の口 (tenant の読み出しと refresh token の削除) ----------

fn refresh_of(t: impl std::fmt::Display, user: impl std::fmt::Display) -> String {
    format!("/internal/tenants/{t}/users/{user}/refresh-token")
}

/// tenant の 1 行: 4 項目で返す (slug 未設定は null)。無い会社は本文つきの 404、UUID でなければ 400
#[tokio::test]
async fn tenant_get_returns_row_or_404() {
    let a = app().await;
    let t = tenant().await;
    let got = call(&a, "GET", &format!("/internal/tenants/{t}"), None).await;
    assert_eq!(got.status, 200);
    let v = got.json();
    assert_eq!(keys(&v), ["id", "name", "short_id", "slug"]);
    assert_eq!(v["id"], json!(t));
    assert_eq!(v["slug"], Value::Null);
    assert!(!v["name"].as_str().unwrap().is_empty());
    assert!(!v["short_id"].as_str().unwrap().is_empty());
    set_tenant(t, None, Some(&format!("slug-{t}"))).await;
    let got = call(&a, "GET", &format!("/internal/tenants/{t}"), None).await;
    assert_eq!(got.json()["slug"], json!(format!("slug-{t}")));

    let got = call(
        &a,
        "GET",
        &format!("/internal/tenants/{}", Uuid::new_v4()),
        None,
    )
    .await;
    assert_eq!(got.status, 404);
    assert_eq!(got.json(), json!({"error": "tenant_not_found"}));
    let got = call(&a, "GET", "/internal/tenants/not-a-uuid", None).await;
    assert_eq!(got.status, 400);
    assert_eq!(got.json(), json!({"error": "invalid_id"}));
}

/// refresh token の削除: 自分の会社の user の 2 列だけ NULL にして 204。別の会社の user・無い user・UUID でない id
#[tokio::test]
async fn refresh_token_delete_clears_only_own_tenant_user() {
    let a = app().await;
    let (t1, t2) = (tenant().await, tenant().await);
    let (d1, d2) = (domain(), domain());
    set_tenant(t1, Some(&d1), None).await;
    set_tenant(t2, Some(&d2), None).await;
    let u1 = google(&a, &gsub(), &format!("a@{d1}")).await.json();
    let u1b = google(&a, &gsub(), &format!("b@{d1}")).await.json();
    let u2 = google(&a, &gsub(), &format!("c@{d2}")).await.json();
    let ids = [&u1, &u1b, &u2].map(|u| u["id"].as_str().unwrap().to_owned());
    for id in &ids {
        let got = call(&a, "POST", REFRESH, Some(refresh_body(id.parse().unwrap()))).await;
        assert_eq!(got.status, 204);
    }
    async fn set(id: &str) -> i64 {
        su_count(&format!(
            "SELECT count(*) FROM alc_api.users WHERE id = '{id}' \
             AND refresh_token_hash IS NOT NULL AND refresh_token_expires_at IS NOT NULL"
        ))
        .await
    }
    // 別の会社の path では変わらない (該当 0 件でも 204)
    let got = call(&a, "DELETE", &refresh_of(t2, &ids[0]), None).await;
    assert_eq!(got.status, 204);
    assert!(got.body.is_empty());
    assert_eq!(set(&ids[0]).await, 1);
    // 正しい会社: 対象の user だけ消える
    let got = call(&a, "DELETE", &refresh_of(t1, &ids[0]), None).await;
    assert_eq!(got.status, 204);
    assert!(got.body.is_empty());
    assert_eq!(set(&ids[0]).await, 0);
    assert_eq!(set(&ids[1]).await, 1);
    assert_eq!(set(&ids[2]).await, 1);
    // 無い user も 204
    let got = call(&a, "DELETE", &refresh_of(t1, Uuid::new_v4()), None).await;
    assert_eq!(got.status, 204);
    for path in [refresh_of("x", &ids[0]), refresh_of(t1, "x")] {
        let got = call(&a, "DELETE", &path, None).await;
        assert_eq!(got.status, 400, "{path}");
        assert_eq!(got.json(), json!({"error": "invalid_id"}));
    }
}
