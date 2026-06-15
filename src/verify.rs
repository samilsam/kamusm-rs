use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use x509_certificate::CapturedX509Certificate;
use cryptographic_message_syntax::SignedData;

const PKCS7_SIGNED_DATA_OID: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VerifyResult {
    #[serde(rename = "gecerli")]
    pub valid: bool,
    #[serde(rename = "imzalayan", skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(rename = "tarih", skip_serializing_if = "Option::is_none")]
    pub date: Option<DateTime<Utc>>,
    #[serde(rename = "sertifika_gecerlilik", skip_serializing_if = "Option::is_none")]
    pub cert_not_after: Option<DateTime<Utc>>,
    #[serde(rename = "hata", skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Checks if the response body contains a PKCS#7 SignedData OID.
pub fn is_valid_timestamp_response(body: &[u8]) -> bool {
    body.windows(PKCS7_SIGNED_DATA_OID.len()).any(|w| w == PKCS7_SIGNED_DATA_OID)
}

/// Extracts the PKCS#7 SignedData structure from the response body.
pub fn extract_pkcs7(buf: &[u8]) -> Option<Vec<u8>> {
    let pos = buf.windows(PKCS7_SIGNED_DATA_OID.len()).position(|w| w == PKCS7_SIGNED_DATA_OID)?;
    
    let start_search = if pos >= 16 { pos - 16 } else { 0 };
    
    for i in (start_search..=pos).rev() {
        if buf[i] != 0x30 {
            continue;
        }
        
        if i + 1 >= buf.len() {
            continue;
        }
        
        let len_byte = buf[i + 1];
        let total_len: usize;
        
        if len_byte & 0x80 == 0 {
            total_len = (len_byte as usize) + 2;
        } else {
            let num_bytes = (len_byte & 0x7F) as usize;
            if num_bytes == 0 || i + 1 + num_bytes >= buf.len() {
                continue;
            }
            if num_bytes > 4 {
                continue;
            }
            let mut l = 0usize;
            for &b in &buf[i + 2 .. i + 2 + num_bytes] {
                l = (l << 8) | (b as usize);
            }
            total_len = l + 2 + num_bytes;
        }
        
        if i + total_len <= buf.len() && pos < i + total_len {
            return Some(buf[i .. i + total_len].to_vec());
        }
    }
    
    None
}

/// Scans the body for ASN.1 string types and extracts printable text.
pub fn extract_text_from_asn1(body: &[u8]) -> Vec<String> {
    let mut texts = Vec::new();
    let mut i = 0;
    
    while i < body.len().saturating_sub(2) {
        let tag = body[i];
        let length = body[i + 1] as usize;
        
        match tag {
            0x0C | 0x13 | 0x14 | 0x16 | 0x19 | 0x1A | 0x1B | 0x1C => {
                if length > 0 && i + 2 + length <= body.len() {
                    let text_bytes = &body[i + 2 .. i + 2 + length];
                    if let Ok(text) = std::str::from_utf8(text_bytes) {
                        let trimmed = string_trim_space(text);
                        if !trimmed.is_empty() && is_ascii_printable(&trimmed) {
                            texts.push(trimmed);
                        }
                    }
                    i += 2 + length;
                } else {
                    i += 1;
                }
            }
            _ => {
                i += 1;
            }
        }
    }
    
    texts
}

fn is_ascii_printable(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii() && (c.is_alphanumeric() || c.is_ascii_punctuation() || c.is_ascii_whitespace()))
}

fn string_trim_space(s: &str) -> String {
    let mut result = Vec::new();
    for &b in s.as_bytes() {
        if (0x20..=0x7E).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r' {
            result.push(b);
        }
    }
    
    let trimmed = String::from_utf8_lossy(&result);
    trimmed.trim().to_string()
}

/// Parses the balance/credits count from the response body.
pub fn parse_credits_from_body(body: &[u8]) -> Option<u32> {
    let body_str = String::from_utf8_lossy(body);
    let mut digits = String::new();
    for c in body_str.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else if !digits.is_empty() {
            break;
        }
    }
    if digits.is_empty() {
        None
    } else {
        digits.parse::<u32>().ok()
    }
}

/// Verifies the PKCS#7 SignedData in the given DER data against KamuSM root CA certificates.
pub fn verify_timestamp(der_data: &[u8]) -> Result<VerifyResult, String> {
    let p7 = SignedData::parse_ber(der_data)
        .map_err(|e| format!("PKCS#7 ayrıştırma hatası: {:?}", e))?;

    // 1. Verify signatures inside CMS structure
    for signer in p7.signers() {
        if let Err(e) = signer.verify_signature_with_signed_data(&p7) {
            return Ok(VerifyResult {
                valid: false,
                signer: None,
                date: None,
                cert_not_after: None,
                error: Some(format!("imza doğrulama başarısız: {:?}", e)),
            });
        }
    }

    // 2. Load the root CAs
    let roots = crate::certs::kamusm_root_cas();
    
    // 3. For each signer, verify its certificate chain to a root CA
    let mut signer_name = None;
    let mut cert_not_after = None;
    for signer in p7.signers() {
        let (signer_issuer, signer_serial) = match signer.certificate_issuer_and_serial() {
            Some(val) => val,
            None => {
                return Ok(VerifyResult {
                    valid: false,
                    signer: None,
                    date: None,
                    cert_not_after: None,
                    error: Some("İmzalayan sertifikasının yayıncı ve seri numarası bulunamadı".to_string()),
                });
            }
        };

        // Find signer's certificate in the CMS certificates
        let mut signer_cert = None;
        for cert in p7.certificates() {
            if cert.issuer_name() == signer_issuer && cert.serial_number_asn1() == signer_serial {
                signer_cert = Some(cert);
                break;
            }
        }

        let signer_cert = match signer_cert {
            Some(cert) => cert,
            None => {
                return Ok(VerifyResult {
                    valid: false,
                    signer: None,
                    date: None,
                    cert_not_after: None,
                    error: Some("İmzalayan sertifikası PKCS#7 paketi içinde bulunamadı".to_string()),
                });
            }
        };

        // Get signer's common name
        if signer_name.is_none() {
            signer_name = signer_cert.subject_common_name();
        }

        // Get signer's certificate expiration time
        if cert_not_after.is_none() {
            cert_not_after = Some(signer_cert.validity_not_after());
        }

        // Verify the certificate chain
        if let Err(e) = verify_chain(signer_cert, &p7, &roots) {
            return Ok(VerifyResult {
                valid: false,
                signer: signer_name,
                date: None,
                cert_not_after,
                error: Some(format!("sertifika zinciri doğrulanamadı: {}", e)),
            });
        }
    }

    Ok(VerifyResult {
        valid: true,
        signer: signer_name,
        date: Some(Utc::now()),
        cert_not_after,
        error: None,
    })
}

fn verify_chain(
    cert: &CapturedX509Certificate,
    p7: &SignedData,
    roots: &[CapturedX509Certificate]
) -> Result<(), String> {
    let mut current_cert = cert.clone();

    // Prevent infinite loop (max 10 steps)
    for _ in 0..10 {
        // Check if current_cert is signed by any of the trusted roots
        for root in roots {
            if current_cert.issuer_name() == root.subject_name() {
                if current_cert.verify_signed_by_certificate(root).is_ok() {
                    return Ok(());
                }
            }
        }

        // Check if self-signed but not in roots
        if current_cert.subject_name() == current_cert.issuer_name() {
            return Err("Sertifika zinciri güvenilmeyen bir kök sertifikada sonlanıyor".to_string());
        }

        // Search for the issuer in the CMS intermediate certificates
        let mut issuer_found = false;
        for intermediate in p7.certificates() {
            if current_cert.issuer_name() == intermediate.subject_name() {
                if current_cert.verify_signed_by_certificate(intermediate).is_ok() {
                    current_cert = intermediate.clone();
                    issuer_found = true;
                    break;
                }
            }
        }

        if !issuer_found {
            return Err("Sertifikanın yayıncısı (issuer) bulunamadı".to_string());
        }
    }

    Err("Sertifika zinciri çok uzun veya döngüsel".to_string())
}
