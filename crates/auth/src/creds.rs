//! 機械用資格情報の入力の検証と応答の形 (純粋関数)。
//!
//! 形は DB の CHECK (ippoan/alc-migrations の 173 `machine_credentials`) と auth-worker の `lib/machine-credential.ts`
//! と同じ。DB に投げる前にここで 400 にする (CHECK 違反を 500 にしない)。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// 用途の allowlist (DB の CHECK と同じ。足すときは migration と一緒に)
pub const PURPOSES: &[&str] = &["leave-scan"];
/// label の最大の字数 (DB の `char_length(label) BETWEEN 1 AND 64`)
pub const LABEL_MAX_CHARS: usize = 64;

/// `POST /internal/machine-credentials` の body
#[derive(Debug, Deserialize)]
pub struct CreateInput {
    pub username: String,
    pub tenant_id: Uuid,
    pub purpose: String,
    pub label: String,
    /// password の sha256 の hex (計算は auth-worker 側。ここは保存するだけ)
    pub secret_hash: String,
}

/// `POST /internal/machine-credentials/{username}/revoke` の body
#[derive(Debug, Deserialize)]
pub struct RevokeInput {
    pub tenant_id: Uuid,
}

/// `POST /internal/machine-credentials/{username}/rotate` の body
#[derive(Debug, Deserialize)]
pub struct RotateInput {
    pub tenant_id: Uuid,
    /// 新しい password の sha256 の hex (計算は auth-worker 側)
    pub secret_hash: String,
}

/// `GET /internal/machine-credentials` の query (形の検証は [`check_list`])
#[derive(Debug, Default, Deserialize)]
pub struct ListQuery {
    pub tenant_id: Option<String>,
    pub purpose: Option<String>,
}

/// 一覧の 1 行 (secret_hash は返さない)
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Summary {
    pub username: String,
    pub purpose: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
}

/// 照合用の 1 行 (会社をまたいで username で引いたもの。比較は auth-worker 側)
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Lookup {
    pub tenant_id: Uuid,
    pub purpose: String,
    pub secret_hash: String,
    pub revoked: bool,
}

/// `mc_` + 16 桁の小文字の hex
pub fn valid_username(s: &str) -> bool {
    s.len() == 19 && s.starts_with("mc_") && is_lower_hex(&s[3..])
}

pub fn valid_purpose(s: &str) -> bool {
    PURPOSES.contains(&s)
}

/// 1〜64 字 (DB の `char_length` と同じく、byte ではなく字で数える)
pub fn valid_label(s: &str) -> bool {
    (1..=LABEL_MAX_CHARS).contains(&s.chars().count())
}

/// sha256 の hex = 64 桁の小文字の hex
pub fn valid_secret_hash(s: &str) -> bool {
    s.len() == 64 && is_lower_hex(s)
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// 作成の body の検証。不正なら 400 の本文の語
pub fn check_create(input: &CreateInput) -> Result<(), &'static str> {
    if !valid_username(&input.username) {
        return Err("invalid_username");
    }
    if !valid_purpose(&input.purpose) {
        return Err("invalid_purpose");
    }
    if !valid_label(&input.label) {
        return Err("invalid_label");
    }
    if !valid_secret_hash(&input.secret_hash) {
        return Err("invalid_secret_hash");
    }
    Ok(())
}

/// rotate の body の検証 (tenant_id は型で UUID。secret_hash の形だけ)
pub fn check_rotate(input: &RotateInput) -> Result<(), &'static str> {
    if !valid_secret_hash(&input.secret_hash) {
        return Err("invalid_secret_hash");
    }
    Ok(())
}

/// 一覧の query の検証: tenant_id は必須の UUID、purpose は在れば allowlist のもの
pub fn check_list(q: ListQuery) -> Result<(Uuid, Option<String>), &'static str> {
    let tenant_id = q
        .tenant_id
        .as_deref()
        .and_then(|t| Uuid::parse_str(t).ok())
        .ok_or("invalid_tenant_id")?;
    if let Some(p) = &q.purpose {
        if !valid_purpose(p) {
            return Err("invalid_purpose");
        }
    }
    Ok((tenant_id, q.purpose))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn input() -> CreateInput {
        CreateInput {
            username: "mc_0123456789abcdef".into(),
            tenant_id: Uuid::nil(),
            purpose: "leave-scan".into(),
            label: "複合機 1F".into(),
            secret_hash: HASH.into(),
        }
    }

    #[test]
    fn username_shape() {
        assert!(valid_username("mc_0123456789abcdef"));
        assert!(!valid_username("mc_0123456789ABCDEF"));
        assert!(!valid_username("mc_0123456789abcde"));
        assert!(!valid_username("mc_0123456789abcdef0"));
        assert!(!valid_username("xx_0123456789abcdef"));
        assert!(!valid_username("mc_0123456789abcdeg"));
        // 19 byte でも ASCII でない字は通さない
        assert!(!valid_username("mc_0123456789abcd\u{e9}"));
        assert!(!valid_username(""));
    }

    #[test]
    fn purpose_is_allowlisted() {
        assert!(valid_purpose("leave-scan"));
        assert!(!valid_purpose("Leave-scan"));
        assert!(!valid_purpose(""));
    }

    #[test]
    fn label_is_counted_in_chars() {
        assert!(valid_label("a"));
        assert!(valid_label(&"あ".repeat(64)));
        assert!(!valid_label(&"あ".repeat(65)));
        assert!(!valid_label(""));
    }

    #[test]
    fn secret_hash_shape() {
        assert!(valid_secret_hash(HASH));
        assert!(!valid_secret_hash(&HASH.to_uppercase()));
        assert!(!valid_secret_hash(&HASH[1..]));
        assert!(!valid_secret_hash(&format!("{HASH}0")));
    }

    #[test]
    fn create_reports_the_first_bad_field() {
        assert_eq!(check_create(&input()), Ok(()));
        let bad = |f: fn(&mut CreateInput)| {
            let mut i = input();
            f(&mut i);
            check_create(&i)
        };
        assert_eq!(bad(|i| i.username = "x".into()), Err("invalid_username"));
        assert_eq!(bad(|i| i.purpose = "x".into()), Err("invalid_purpose"));
        assert_eq!(bad(|i| i.label = String::new()), Err("invalid_label"));
        assert_eq!(
            bad(|i| i.secret_hash = "x".into()),
            Err("invalid_secret_hash")
        );
    }

    #[test]
    fn rotate_checks_the_hash() {
        let r = |h: &str| {
            check_rotate(&RotateInput {
                tenant_id: Uuid::nil(),
                secret_hash: h.into(),
            })
        };
        assert_eq!(r(HASH), Ok(()));
        assert_eq!(r("x"), Err("invalid_secret_hash"));
        assert_eq!(r(&HASH.to_uppercase()), Err("invalid_secret_hash"));
    }

    #[test]
    fn list_query() {
        let id = Uuid::from_u128(1);
        let t = &id.to_string();
        let q = |tenant: Option<&str>, purpose: Option<&str>| {
            check_list(ListQuery {
                tenant_id: tenant.map(str::to_owned),
                purpose: purpose.map(str::to_owned),
            })
        };
        assert_eq!(q(Some(t), None), Ok((id, None)));
        assert_eq!(
            q(Some(t), Some("leave-scan")),
            Ok((id, Some("leave-scan".into())))
        );
        assert_eq!(q(Some(t), Some("x")), Err("invalid_purpose"));
        assert_eq!(q(None, None), Err("invalid_tenant_id"));
        assert_eq!(q(Some("x"), None), Err("invalid_tenant_id"));
    }
}
