use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use x509_certificate::CapturedX509Certificate;
use cryptographic_message_syntax::SignedData;
use xmltree::Element;
use xml_canonicalization::Canonicalizer;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::Digest;

const PKCS7_SIGNED_DATA_OID: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VerifyResult {
    #[serde(rename = "gecerli")]
    pub valid: bool,
    #[serde(rename = "imzalayan", skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(rename = "ad_soyad", skip_serializing_if = "Option::is_none")]
    pub ad_soyad: Option<String>,
    #[serde(rename = "tc_no", skip_serializing_if = "Option::is_none")]
    pub tc_no: Option<String>,
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
                ad_soyad: None,
                tc_no: None,
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
                    ad_soyad: None,
                    tc_no: None,
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
                    ad_soyad: None,
                    tc_no: None,
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
                ad_soyad: None,
                tc_no: None,
                date: None,
                cert_not_after,
                error: Some(format!("sertifika zinciri doğrulanamadı: {}", e)),
            });
        }
    }

    Ok(VerifyResult {
        valid: true,
        signer: signer_name,
        ad_soyad: None,
        tc_no: None,
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

/// Helper to decode bytes from UTF-16 LE
pub fn decode_utf16_le(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() % 2 != 0 {
        return Err("UTF-16 LE verisi çift sayıda bayt içermelidir.".to_string());
    }
    let u16_chars: Vec<u16> = bytes.chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16(&u16_chars).map_err(|e| format!("UTF-16 LE dönüştürme hatası: {:?}", e))
}

/// Helper to decode bytes from UTF-16 BE
pub fn decode_utf16_be(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() % 2 != 0 {
        return Err("UTF-16 BE verisi çift sayıda bayt içermelidir.".to_string());
    }
    let u16_chars: Vec<u16> = bytes.chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16(&u16_chars).map_err(|e| format!("UTF-16 BE dönüştürme hatası: {:?}", e))
}

/// Helper to decode ISO-8859-9 (Turkish Latin-5)
pub fn decode_iso_8859_9(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len());
    for &b in bytes {
        let c = match b {
            0xDE => 'Ş',
            0xFE => 'ş',
            0xD0 => 'Ğ',
            0xF0 => 'ğ',
            0xDD => 'İ',
            0xFD => 'ı',
            _ => b as char,
        };
        result.push(c);
    }
    result
}

/// Helper to parse XML content bytes into a UTF-8 String, detecting encoding (UTF-8, UTF-16, ISO-8859-9)
pub fn decode_xml_content(xml_content: &[u8]) -> Result<String, String> {
    if xml_content.starts_with(&[0xFE, 0xFF]) {
        decode_utf16_be(&xml_content[2..])
    } else if xml_content.starts_with(&[0xFF, 0xFE]) {
        decode_utf16_le(&xml_content[2..])
    } else {
        let raw_bytes = if xml_content.starts_with(&[0xEF, 0xBB, 0xBF]) {
            &xml_content[3..]
        } else {
            xml_content
        };
        match std::str::from_utf8(raw_bytes) {
            Ok(s) => Ok(s.to_string()),
            Err(_) => Ok(decode_iso_8859_9(raw_bytes)),
        }
    }
}

/// XML Enveloped Signature (XML-DSig) doğrulamasını gerçekleştirir.
pub fn verify_eimza_xml(xml_content: &[u8]) -> Result<VerifyResult, String> {
    // 1. XML'i ayrıştır (encoding tespiti ile)
    let xml_str = decode_xml_content(xml_content)?;
    let mut root = Element::parse(xml_str.as_bytes())
        .map_err(|e| format!("XML ayrıştırılamadı: {:?}", e))?;

    // 2. ds:Signature elemanını bul ve root'tan çıkar (enveloped signature transform)
    let mut sig_elem = None;
    let mut sig_idx = None;
    for (idx, node) in root.children.iter().enumerate() {
        if let xmltree::XMLNode::Element(el) = node {
            if el.name == "Signature" {
                sig_idx = Some(idx);
                sig_elem = Some(el.clone());
                break;
            }
        }
    }

    let sig_elem = sig_elem.ok_or_else(|| "XML dosyasında 'Signature' elemanı bulunamadı.".to_string())?;
    
    // İmza elemanını root'tan çıkaralım
    if let Some(idx) = sig_idx {
        root.children.remove(idx);
    }

    // İmzalanmamış XML içeriğini canonicalize et ve özetini (digest) hesapla
    let mut unsigned_xml_bytes = Vec::new();
    root.write(&mut unsigned_xml_bytes)
        .map_err(|e| format!("XML yazma hatası: {:?}", e))?;

    let unsigned_xml_str = std::str::from_utf8(&unsigned_xml_bytes)
        .map_err(|e| format!("Geçersiz UTF-8 XML verisi: {:?}", e))?;

    let mut unsigned_canon = Vec::new();
    Canonicalizer::read_from_str(unsigned_xml_str)
        .write_to_writer(std::io::Cursor::new(&mut unsigned_canon))
        .canonicalize(true)
        .map_err(|e| format!("Kanonikalizasyon hatası: {:?}", e))?;

    let computed_digest = sha2::Sha256::digest(&unsigned_canon);
    let computed_digest_b64 = STANDARD.encode(computed_digest);

    // 3. ds:Signature altındaki elemanları çıkar
    // ds:SignedInfo
    let signed_info_el = sig_elem.get_child("SignedInfo")
        .ok_or_else(|| "Signature altında SignedInfo bulunamadı.".to_string())?;

    // ds:SignatureValue
    let sig_val_el = sig_elem.get_child("SignatureValue")
        .ok_or_else(|| "Signature altında SignatureValue bulunamadı.".to_string())?;
    let sig_val_b64 = sig_val_el.get_text()
        .ok_or_else(|| "SignatureValue içeriği boş.".to_string())?;
    let sig_bytes = STANDARD.decode(sig_val_b64.trim().replace("\n", "").replace("\r", "").replace(" ", ""))
        .map_err(|e| format!("Geçersiz base64 imza değeri: {:?}", e))?;

    // ds:KeyInfo / ds:X509Data / ds:X509Certificate
    let key_info_el = sig_elem.get_child("KeyInfo")
        .ok_or_else(|| "Signature altında KeyInfo bulunamadı.".to_string())?;
    let x509_data_el = key_info_el.get_child("X509Data")
        .ok_or_else(|| "KeyInfo altında X509Data bulunamadı.".to_string())?;
    let x509_cert_el = x509_data_el.get_child("X509Certificate")
        .ok_or_else(|| "X509Data altında X509Certificate bulunamadı.".to_string())?;
    let cert_b64 = x509_cert_el.get_text()
        .ok_or_else(|| "X509Certificate içeriği boş.".to_string())?;
    let cert_der = STANDARD.decode(cert_b64.trim().replace("\n", "").replace("\r", "").replace(" ", ""))
        .map_err(|e| format!("Geçersiz base64 sertifika verisi: {:?}", e))?;

    // ds:SignedInfo / ds:Reference / ds:DigestValue
    let ref_el = signed_info_el.get_child("Reference")
        .ok_or_else(|| "SignedInfo altında Reference bulunamadı.".to_string())?;
    let digest_val_el = ref_el.get_child("DigestValue")
        .ok_or_else(|| "Reference altında DigestValue bulunamadı.".to_string())?;
    let expected_digest_b64 = digest_val_el.get_text()
        .ok_or_else(|| "DigestValue içeriği boş.".to_string())?;

    // Orijinal içerik özetini doğrula
    if computed_digest_b64 != expected_digest_b64.trim().replace("\n", "").replace("\r", "").replace(" ", "") {
        return Ok(VerifyResult {
            valid: false,
            signer: None,
            ad_soyad: None,
            tc_no: None,
            date: None,
            cert_not_after: None,
            error: Some("Dosya içeriği özeti (DigestValue) eşleşmiyor. Dosya değiştirilmiş veya bozulmuş olabilir.".to_string()),
        });
    }

    // 4. SignedInfo elementini kanonikal hale getir
    let mut signed_info_bytes = Vec::new();
    let mut signed_info_clone = signed_info_el.clone();
    if !signed_info_clone.attributes.contains_key("xmlns:ds") {
        signed_info_clone.attributes.insert("xmlns:ds".to_string(), "http://www.w3.org/2000/09/xmldsig#".to_string());
    }
    signed_info_clone.write(&mut signed_info_bytes)
        .map_err(|e| format!("SignedInfo yazma hatası: {:?}", e))?;

    let signed_info_str = std::str::from_utf8(&signed_info_bytes)
        .map_err(|e| format!("Geçersiz UTF-8 SignedInfo verisi: {:?}", e))?;

    let mut signed_info_canon = Vec::new();
    Canonicalizer::read_from_str(signed_info_str)
        .write_to_writer(std::io::Cursor::new(&mut signed_info_canon))
        .canonicalize(true)
        .map_err(|e| format!("SignedInfo kanonikalizasyon hatası: {:?}", e))?;

    // 5. Sertifikayı ayrıştır ve imzayı doğrula
    let cert = CapturedX509Certificate::from_der(cert_der.clone())
        .map_err(|e| format!("Sertifika ayrıştırılamadı: {:?}", e))?;

    let cert_details = crate::certs::read_cert_details(&cert_der)
        .map_err(|e| format!("Sertifika detayları okunamadı: {:?}", e))?;

    match cert.verify_signed_data(&signed_info_canon, &sig_bytes) {
        Ok(_) => {
            Ok(VerifyResult {
                valid: true,
                signer: Some(cert_details.subject),
                ad_soyad: cert_details.ad_soyad,
                tc_no: cert_details.tc_no,
                date: Some(Utc::now()),
                cert_not_after: Some(cert_details.not_after),
                error: None,
            })
        }
        Err(e) => {
            Ok(VerifyResult {
                valid: false,
                signer: Some(cert_details.subject),
                ad_soyad: cert_details.ad_soyad,
                tc_no: cert_details.tc_no,
                date: None,
                cert_not_after: Some(cert_details.not_after),
                error: Some(format!("İmza doğrulama başarısız: {:?}", e)),
            })
        }
    }
}

/// Detached (Ham) E-İmza doğrulamasını gerçekleştirir.
pub fn verify_eimza_detached(
    original_data: &[u8],
    signature_bytes: &[u8],
    cert_der_or_pem: &[u8],
) -> Result<VerifyResult, String> {
    let cert = CapturedX509Certificate::from_der(cert_der_or_pem.to_vec())
        .or_else(|_| CapturedX509Certificate::from_pem(cert_der_or_pem))
        .map_err(|e| format!("Sertifika ayrıştırılamadı: {:?}", e))?;

    let der_bytes = cert.encode_der()
        .map_err(|e| format!("Sertifika DER kodlaması alınamadı: {:?}", e))?;

    let cert_details = crate::certs::read_cert_details(&der_bytes)
        .map_err(|e| format!("Sertifika detayları okunamadı: {:?}", e))?;

    match cert.verify_signed_data(original_data, signature_bytes) {
        Ok(_) => {
            Ok(VerifyResult {
                valid: true,
                signer: Some(cert_details.subject),
                ad_soyad: cert_details.ad_soyad,
                tc_no: cert_details.tc_no,
                date: Some(Utc::now()),
                cert_not_after: Some(cert_details.not_after),
                error: None,
            })
        }
        Err(e) => {
            Ok(VerifyResult {
                valid: false,
                signer: Some(cert_details.subject),
                ad_soyad: cert_details.ad_soyad,
                tc_no: cert_details.tc_no,
                date: None,
                cert_not_after: Some(cert_details.not_after),
                error: Some(format!("İmza doğrulama başarısız: {:?}", e)),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_utf8_bom() {
        let mut data = vec![0xEF, 0xBB, 0xBF];
        data.extend_from_slice(b"<root>\xc5\x9fehir</root>"); // "şehir" in UTF-8
        let decoded = decode_xml_content(&data).unwrap();
        assert_eq!(decoded, "<root>şehir</root>");
    }

    #[test]
    fn test_decode_utf16_le() {
        let utf16_le_bom = &[0xFF, 0xFE];
        // "<root>şehir</root>" in UTF-16 LE
        let utf16_data = [
            0x3C, 0x00, // <
            0x72, 0x00, // r
            0x6F, 0x00, // o
            0x6F, 0x00, // o
            0x74, 0x00, // t
            0x3E, 0x00, // >
            0x5F, 0x01, // ş (U+015F)
            0x65, 0x00, // e
            0x68, 0x00, // h
            0x69, 0x00, // i
            0x72, 0x00, // r
            0x3C, 0x00, // <
            0x2F, 0x00, // /
            0x72, 0x00, // r
            0x6F, 0x00, // o
            0x6F, 0x00, // o
            0x74, 0x00, // t
            0x3E, 0x00, // >
        ];
        let mut data = utf16_le_bom.to_vec();
        data.extend_from_slice(&utf16_data);

        let decoded = decode_xml_content(&data).unwrap();
        assert_eq!(decoded, "<root>şehir</root>");
    }

    #[test]
    fn test_decode_utf16_be() {
        let utf16_be_bom = &[0xFE, 0xFF];
        // "<root>şehir</root>" in UTF-16 BE
        let utf16_data = [
            0x00, 0x3C, // <
            0x00, 0x72, // r
            0x00, 0x6F, // o
            0x00, 0x6F, // o
            0x00, 0x74, // t
            0x00, 0x3E, // >
            0x01, 0x5F, // ş (U+015F)
            0x00, 0x65, // e
            0x00, 0x68, // h
            0x00, 0x69, // i
            0x00, 0x72, // r
            0x00, 0x3C, // <
            0x00, 0x2F, // /
            0x00, 0x72, // r
            0x00, 0x6F, // o
            0x00, 0x6F, // o
            0x00, 0x74, // t
            0x00, 0x3E, // >
        ];
        let mut data = utf16_be_bom.to_vec();
        data.extend_from_slice(&utf16_data);

        let decoded = decode_xml_content(&data).unwrap();
        assert_eq!(decoded, "<root>şehir</root>");
    }

    #[test]
    fn test_decode_iso_8859_9() {
        // "<root>şehir</root>" in ISO-8859-9
        // ş in ISO-8859-9 is 0xFE
        let raw_data = b"<root>\xfeehir</root>";
        let decoded = decode_xml_content(raw_data).unwrap();
        assert_eq!(decoded, "<root>şehir</root>");
    }
}

