//! 機械用資格情報の内部口 4 本とログインの内部口 3 本を、口から実 DB (RLS が効く `alc_api_app`) まで通すテスト。
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

/// 共有 secret が無い・違う・worker 側で取れない ときは、7 口とも (と当たらない path も) 404 で本文は空。DB にも届かない
#[tokio::test]
async fn wrong_secret_is_404_everywhere() {
    let a = app().await;
    let t = tenant().await;
    let u = username();
    assert_eq!(create(&a, &u, t, "x").await.status, 201);
    let v = username();
    let create_body = serde_json::to_vec(&body(&v, t, "x")).unwrap();
    let revoke_body = serde_json::to_vec(&json!({ "tenant_id": t })).unwrap();
    let google_body = serde_json::to_vec(&google_body(&gsub(), "x@example.test")).unwrap();
    let refresh_body = serde_json::to_vec(&refresh_body(Uuid::new_v4())).unwrap();
    let requests: [(&str, String, Option<Vec<u8>>); 8] = [
        ("POST", PATH.to_owned(), Some(create_body)),
        ("GET", format!("{PATH}?tenant_id={t}"), None),
        ("POST", format!("{PATH}/{u}/revoke"), Some(revoke_body)),
        ("GET", format!("{PATH}/{u}"), None),
        ("GET", format!("{SSO}?provider=lineworks&domain=x"), None),
        ("POST", GOOGLE.to_owned(), Some(google_body)),
        ("POST", REFRESH.to_owned(), Some(refresh_body)),
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
        call(
            &a,
            "GET",
            &format!("{SSO}?provider=lineworks&domain=x"),
            None,
        )
        .await,
        google(&a, &u, "u@example.test").await,
        call(&a, "POST", REFRESH, Some(refresh_body(t))).await,
    ] {
        assert_eq!(got.status, 500);
        assert_eq!(got.json(), json!({"error": "internal_error"}));
    }
    let logs = a.logs.lock().unwrap().clone();
    assert_eq!(logs.len(), 7, "{logs:?}");
    let whats = [
        "create",
        "list",
        "revoke",
        "lookup",
        "sso-config",
        "upsert-google",
        "refresh-token",
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
