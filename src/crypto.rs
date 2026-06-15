use aes::Aes256;
use cbc::{Encryptor, Decryptor};
use aes::cipher::{block_padding::Pkcs7, KeyIvInit, BlockEncryptMut, BlockDecryptMut};
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// Derives a key using PBKDF2-HMAC-SHA256.
pub fn derive_key(password: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut key = vec![0u8; 32];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, iterations, &mut key)
        .expect("HMAC can be initialized with any key length");
    key
}

/// Encrypts data using AES-256-CBC with PKCS#7 padding.
pub fn encrypt_aes_cbc(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let enc = Aes256CbcEnc::new_from_slices(key, iv)
        .map_err(|e| format!("Anahtar veya IV uzunluğu geçersiz: {:?}", e))?;
    let ciphertext = enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    Ok(ciphertext)
}

/// Decrypts data using AES-256-CBC with PKCS#7 padding.
pub fn decrypt_aes_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let dec = Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|e| format!("Anahtar veya IV uzunluğu geçersiz: {:?}", e))?;
    let plaintext = dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| format!("Şifre çözme hatası (padding geçersiz olabilir): {:?}", e))?;
    Ok(plaintext)
}
