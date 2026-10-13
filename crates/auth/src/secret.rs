//! 共有 secret (`X-Internal-Shared-Secret`) の照合 (ippoan/rust-leave-worker の `crates/leave/src/ingest.rs` の
//! `secret_matches` の写し)。

/// 共有 secret を constant-time で比べる (長さの違いも同じ時間の比較で吸収する)。
/// 期待値が空 (Secrets Store から取れなかった)・ヘッダーが無い・空なら常に false
pub fn secret_matches(expected: &str, given: Option<&str>) -> bool {
    let Some(given) = given else { return false };
    if expected.is_empty() || given.is_empty() {
        return false;
    }
    let (a, b) = (expected.as_bytes(), given.as_bytes());
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_compared_exactly() {
        assert!(secret_matches("s3cret", Some("s3cret")));
        assert!(!secret_matches("s3cret", Some("s3cre")));
        assert!(!secret_matches("s3cret", Some("s3cretx")));
        assert!(!secret_matches("s3cret", Some("S3cret")));
        assert!(!secret_matches("s3cret", None));
        assert!(!secret_matches("s3cret", Some("")));
        assert!(!secret_matches("", Some("")));
        assert!(!secret_matches("", Some("x")));
    }
}
