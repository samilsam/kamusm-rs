use der::Encode;
use der::asn1::OctetStringRef;
use rand::RngCore;

#[derive(Clone, Debug, der::Sequence)]
pub struct EsyaReqEx<'a> {
    pub user_id: u32,
    pub salt: OctetStringRef<'a>,
    pub iteration_count: u32,
    pub iv: OctetStringRef<'a>,
    pub encrypted_message_imprint: OctetStringRef<'a>,
}

/// Creates the identity header for KamuSM authentication.
/// Returns a hex string of the DER-encoded ASN.1 structure.
pub fn build_identity(customer_id: u32, password: &str, message_imprint: &[u8], iterations: i32) -> Result<String, String> {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);
    let salt = iv;

    let key = crate::crypto::derive_key(password, &salt, iterations as u32);
    let ciphertext = crate::crypto::encrypt_aes_cbc(&key, &iv, message_imprint)?;

    let token = EsyaReqEx {
        user_id: customer_id,
        salt: OctetStringRef::new(&salt).map_err(|e| format!("ASN.1 salt hatası: {:?}", e))?,
        iteration_count: iterations as u32,
        iv: OctetStringRef::new(&iv).map_err(|e| format!("ASN.1 IV hatası: {:?}", e))?,
        encrypted_message_imprint: OctetStringRef::new(&ciphertext).map_err(|e| format!("ASN.1 ciphertext hatası: {:?}", e))?,
    };

    let der_bytes = token.to_der()
        .map_err(|e| format!("ASN.1 DER kodlama hatası: {:?}", e))?;

    Ok(hex::encode(der_bytes))
}
