pub mod certs;
pub mod client;
pub mod config;
pub mod crypto;
pub mod identity;
pub mod tsa;
pub mod verify;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Re-exports
pub use certs::{kamusm_root_cas, update_certs, auto_update_certs, certs_cache_path};

pub use client::{send_credit_request, send_timestamp_request};
pub use config::{ConfigData, load_config, save_config, config_path, mask_password};
pub use identity::build_identity;
pub use tsa::{compute_file_digest, build_tsa_request};
pub use verify::{
    is_valid_timestamp_response, extract_pkcs7, extract_text_from_asn1,
    parse_credits_from_body, verify_timestamp, VerifyResult
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_aes_cbc() {
        let key = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let iv = b"1234567890abcdef"; // 16 bytes
        let plaintext = b"Hello, KamuSM!";
        
        let ciphertext = crypto::encrypt_aes_cbc(key, iv, plaintext).unwrap();
        let decrypted = crypto::decrypt_aes_cbc(key, iv, &ciphertext).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_key_derivation() {
        let password = "mysecretpassword";
        let salt = b"saltsaltsaltsalt";
        let key = crypto::derive_key(password, salt, 100);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_build_tsa_request() {
        let digest = vec![0x42; 32];
        let req = build_tsa_request(&digest, "sha256").unwrap();
        assert!(!req.is_empty());
    }

    #[test]
    fn test_build_identity() {
        let digest = vec![0x42; 32];
        let identity = build_identity(123456, "secret", &digest, 100).unwrap();
        assert!(!identity.is_empty());
    }
}
