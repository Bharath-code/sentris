use sha2::{Digest, Sha256};

/// Genesis previous hash for the first record in the cryptographic chain (64 zeros).
pub const GENESIS_PREVIOUS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Standard HMAC-SHA256 implementation (RFC 2104).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let hashed_key = hasher.finalize();
        key_block[..32].copy_from_slice(&hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    let mut inner_hasher = Sha256::new();
    inner_hasher.update(ipad);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    outer_hasher.update(opad);
    outer_hasher.update(inner_hash);
    let outer_hash = outer_hasher.finalize();

    outer_hash.into()
}

/// HMAC key for the audit chain: `SENTRIS_AUDIT_SALT` (CI), else a random per-user key kept outside the repo (0600).
/// It is never derived from guessable inputs such as the repo path or username.
pub fn get_audit_salt() -> Result<Vec<u8>, crate::error::SentrisError> {
    if let Ok(salt) = std::env::var("SENTRIS_AUDIT_SALT") {
        if !salt.is_empty() {
            return Ok(salt.into_bytes());
        }
    }
    crate::keystore::key("audit")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc4231_hmac_sha256() {
        // RFC 4231 Test Case 1
        let key_1 = vec![0x0bu8; 20];
        let data_1 = b"Hi There";
        let hmac_1 = hmac_sha256(&key_1, data_1);
        assert_eq!(
            hex::encode(hmac_1),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );

        // RFC 4231 Test Case 2
        let key_2 = b"Jefe";
        let data_2 = b"what do ya want for nothing?";
        let hmac_2 = hmac_sha256(key_2, data_2);
        assert_eq!(
            hex::encode(hmac_2),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );

        // RFC 4231 Test Case 6 (key larger than block size 64 bytes)
        let key_6 = vec![0xaau8; 131];
        let data_6 = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let hmac_6 = hmac_sha256(&key_6, data_6);
        assert_eq!(
            hex::encode(hmac_6),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }
}
