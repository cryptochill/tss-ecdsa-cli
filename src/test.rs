#[cfg(test)]
mod tests {
    use crate::ecdsa::{run_pubkey_or_sign};

    #[test]
    fn test_pubkey() {
        let key_file_path = "src/tss-test-1.store";
        let path = "1/2/3";
        let expected_pubkey_x = "e891363052c09185814e92ce7a1a1946631dc53d058a01176fcf27a66b5674c2";
        let expected_pubkey_y = "cfbe0a84b7f7c49b5bb2a48999a761fc6c5dd6526aa79a58d4029865ef7d4a17";
        let params: Vec<&str> = Vec::new();
        let pub_key = run_pubkey_or_sign("pubkey", key_file_path, path, "", "".to_string(), params);

        assert_eq!(pub_key.get("x").unwrap(), expected_pubkey_x);
        assert_eq!(pub_key.get("y").unwrap(), expected_pubkey_y);
    }

}