use x509_certificate::CapturedX509Certificate;
use std::path::PathBuf;
use std::fs;
use std::collections::HashSet;
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose::STANDARD};


pub const KAMUSM_ROOT_CA_V7: &str = "-----BEGIN CERTIFICATE-----
MIICqjCCAjCgAwIBAgIHAOHOlcAEqjAKBggqhkjOPQQDAzCBmjELMAkGA1UEBhMC
VFIxEDAOBgNVBAgMB0tvY2FlbGkxNTAzBgNVBAoMLFTDnELEsFRBSyBCxLBMR0VN
IEthbXUgU2VydGlmaWthc3lvbiBNZXJrZXppMUIwQAYDVQQDDDlLYW11IFNNIEvD
tmsgU2VydGlmaWthIEhpem1ldCBTYcSfbGF5xLFjxLFzxLEgLSBTw7xyw7xtIDcw
HhcNMjUwOTI0MTE1MzM5WhcNMzUwOTIyMTE1MzM5WjCBmjELMAkGA1UEBhMCVFIx
EDAOBgNVBAgMB0tvY2FlbGkxNTAzBgNVBAoMLFTDnELEsFRBSyBCxLBMR0VNIEth
bXUgU2VydGlmaWthc3lvbiBNZXJrZXppMUIwQAYDVQQDDDlLYW11IFNNIEvDtmsg
U2VydGlmaWthIEhpem1ldCBTYcSfbGF5xLFjxLFzxLEgLSBTw7xyw7xtIDcwdjAQ
BgcqhkjOPQIBBgUrgQQAIgNiAATZDyFTF9DDVtoTZsUrC/leLuLRX4/+/pCvxQtk
3zOlx0S7cwdKGGTBI5PRXMcwAiX/ErPKroloXD3csBkrFWVe9l6/VMwUFku34MIi
N1zyTxoZLiIGLtis4giT2QCnNIKjQjBAMB0GA1UdDgQWBBQRTnHT4zu2wGgvnoRl
npMjS5imnTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjO
PQQDAwNoADBlAjBryUMTwaZSRGdvTlPFVGFQfaQFDkgw44RNMskwio+9KqOQynoA
CgBx2in+sgBQrkQCMQCNVlO92uuYxNwhW3ZDNSePr0uJTRV78Du1qRTRjqp6nO/r
HqhhcClEXcOQxy4P62U=
-----END CERTIFICATE-----";

pub const KAMUSM_ROOT_CA_V6: &str = "-----BEGIN CERTIFICATE-----
MIIDATCCAoigAwIBAgIHAO0duC4B1jAKBggqhkjOPQQDAzCBxjELMAkGA1UEBhMC
VFIxGDAWBgNVBAcMD0dlYnplIC0gS29jYWVsaTFHMEUGA1UECgw+VMO8cmtpeWUg
QmlsaW1zZWwgdmUgVGVrbm9sb2ppayBBcmHFn3TEsXJtYSBLdXJ1bXUgLSBUw5xC
xLBUQUsxEDAOBgNVBAsMB0LEsExHRU0xQjBABgNVBAMMOUthbXUgU00gS8O2ayBT
ZXJ0aWZpa2EgSGl6bWV0IFNhxJ9sYXnEsWPEsXPEsSAtIFPDvHLDvG0gNjAeFw0x
OTA4MDkxNjI1MDhaFw0yOTA4MDYxNjI1MDhaMIHGMQswCQYDVQQGEwJUUjEYMBYG
A1UEBwwPR2ViemUgLSBLb2NhZWxpMUcwRQYDVQQKDD5Uw7xya2l5ZSBCaWxpbXNl
bCB2ZSBUZWtub2xvamlrIEFyYcWfdMSxcm1hIEt1cnVtdSAtIFTDnELEsFRBSzEQ
MA4GA1UECwwHQsSwTEdFTTFCMEAGA1UEAww5S2FtdSBTTSBLw7ZrIFNlcnRpZmlr
YSBIaXptZXQgU2HEn2xhecSxY8Sxc8SxIC0gU8O8csO8bSA2MHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAEF/tnulb6R1MBEV53a+nlFTP1RhOih+24haYwXvIJdkNbMtji
qo2BNsS2z8YFunOF0OIT7lDcjmiXQN5aQ8qRIMP/xECh8sy/mvfepOepKEl1wqVB
XVz5rm/ywyW6gbz7o0IwQDAdBgNVHQ4EFgQUMMvWgRAjLJ9EMg/gunvxicLAOdow
DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwMDZwAw
ZAIwZl/Z0ic/i+LzKE2nGaAHO93ebWMBXKtHyxOyUbDjTa9AGh610Up8e8IOMCVZ
UPSUAjB7BJ+eeCX9QQXbDMVKr04rcpOo9iNVVLSD2uT2bNEQqJX8b8upRr7+TFmf
szwiaJk=
-----END CERTIFICATE-----";

pub const KAMUSM_ROOT_CA_V5: &str = "-----BEGIN CERTIFICATE-----
MIIEUDCCAzigAwIBAgIGLLmOuQDFMA0GCSqGSIb3DQEBCwUAMIHGMQswCQYDVQQG
EwJUUjEYMBYGA1UEBwwPR2ViemUgLSBLb2NhZWxpMUcwRQYDVQQKDD5Uw7xya2l5
ZSBCaWxpbXNlbCB2ZSBUZWtub2xvamlrIEFyYcWfdMSxcm1hIEt1cnVtdSAtIFTD
nELEsFRBSzEQMA4GA1UECwwHQsSwTEdFTTFCMEAGA1UEAww5S2FtdSBTTSBLw7Zr
IFNlcnRpZmlrYSBIaXptZXQgU2HEn2xhecSxY8Sxc8SxIC0gU8O8csO8bSA1MB4X
DTEzMDExNTEyNTEzNFoXDTIzMDExMzEyNTEzNFowgcYxCzAJBgNVBAYTAlRSMRgw
FgYDVQQHDA9HZWJ6ZSAtIEtvY2FlbGkxRzBFBgNVBAoMPlTDvHJraXllIEJpbGlt
c2VsIHZlIFRla25vbG9qaWsgQXJhxZ90xLFybWEgS3VydW11IC0gVMOcQsSwVEFL
MRAwDgYDVQQLDAdCxLBMR0VNMUIwQAYDVQQDDDlLYW11IFNNIEvDtmsgU2VydGlm
aWthIEhpem1ldCBTYcSfbGF5xLFjxLFzxLEgLSBTw7xyw7xtIDUwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCCSM0RI3Xw85mYyKteRLO7FqoilGq0gQrm
MmAbndhJfn9pGEKEFdTNssGhXK+XDS297NljUyV80TBGq1IRCbNxYUmJacfbaZvr
52cfePO/tZLIVHwAwMFnMQjt3k6MKO/Og4L0z9mHiS2GqkjsFrRVMAikXQk15kqp
1z9BJZ9+EpZwdks8ZP5xpX0Sm4L9CjkeAMhR6T9zl3kYEX/eTF3///YErdcLdx1Q
J1wxuC0U3lbvzS8g7UZIhutUPYlciJvNux3fN9yIXyEXDWx2J7PSWb7Y9rN9Yaf0
4dIR1R6C9anGaail9oD/WPT9d/wSq8SUMaIwWSOZFO1cmEx6LBldAgMBAAGjQjBA
MB0GA1UdDgQWBBQ36zcA9xW9U3vMic5x8TT94hamAjAOBgNVHQ8BAf8EBAMCAQYw
DwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAdUpvROJnInv27yby
LJ56sVJinVcvUH0BP229jvw9jKr1GTZ1SkfQmAypYqtfmT+IYDf1T0HvVQQgJ/SJ
SwZfM1XV3y/G32bgRSGKtAX/n0Y9nQesyRB3Y+2KEETQigJ6oP26+Y0/7xBIvlMB
CSgTwAj8rwNqrMOVj7TfA9t4LZJmG/JvV0gaFtlTtRL4Ib8JFH3iUfqU0K+qAyUH
pQcyqc2pyuMPWeLn/K7v9AM+tsg4ltYxIfz2TQkrsE2dyKmNIQVZuK3RQDPPf2+z
vA3pJ+DUIrucTvD417fTVy0NPetxTTQWKmEqcMw4tSRWSe/M7K1Q/8hM+cvANgOc
8GAhIg==
-----END CERTIFICATE-----";

pub const KAMUSM_ROOT_CA_V4: &str = "-----BEGIN CERTIFICATE-----
MIIESzCCAzOgAwIBAgIBdTANBgkqhkiG9w0BAQUFADCBxjELMAkGA1UEBhMCVFIx
GDAWBgNVBAcMD0dlYnplIC0gS29jYWVsaTFHMEUGA1UECgw+VMO8cmtpeWUgQmls
aW1zZWwgdmUgVGVrbm9sb2ppayBBcmHFn3TEsXJtYSBLdXJ1bXUgLSBUw5xCxLBU
QUsxEDAOBgNVBAsMB0LEsExHRU0xQjBABgNVBAMMOUthbXUgU00gS8O2ayBTZXJ0
aWZpa2EgSGl6bWV0IFNhxJ9sYXnEsWPEsXPEsSAtIFPDvHLDvG0gNDAeFw0xMjA1
MTExNDM2MjlaFw0yMjA1MDkxNDM2MjlaMIHGMQswCQYDVQQGEwJUUjEYMBYGA1UE
BwwPR2ViemUgLSBLb2NhZWxpMUcwRQYDVQQKDD5Uw7xya2l5ZSBCaWxpbXNlbCB2
ZSBUZWtub2xvamlrIEFyYcWfdMSxcm1hIEt1cnVtdSAtIFTDnELEsFRBSzEQMA4G
A1UECwwHQsSwTEdFTTFCMEAGA1UEAww5S2FtdSBTTSBLw7ZrIFNlcnRpZmlrYSBI
aXptZXQgU2HEn2xhecSxY8Sxc8SxIC0gU8O8csO8bSA0MIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAgDOnZauxvvkOqKLdiYJUCy3ZBDZpAROdnI/NDHGz
7ggMwuRFHKCPwRo3I8NHMraJ7wYSUId+82W6+n/HRagxrvcg2U66vOcFHs9wWDP3
8tAVhXhXqzjLvr2u9Ad1x05fT3X6n5cDyds688GCFmiMZHPyWFgd/EHXBN/dIbCU
6aoIORT2RkCeW8PDoA7GBtUjYa39nwwiTfK5jWDLaHtQSU9i+xTuXLoNOvzPmhfc
uWLaEJEfAfPwngPE+goDD0lEosW+Aq7Z5xzV4x0n8aWNlvu1gE5zSX4sZUFYWub4
SW0TdcbBv6kHndv6WXexK0OmQK8O/2tMKjvp+msJObMg7QIDAQABo0IwQDAdBgNV
HQ4EFgQUOtCH1kqqep9MqWyJ/3Mm//frSb0wDgYDVR0PAQH/BAQDAgEGMA8GA1Ud
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBABx5IjRsx0PZN6/VgQSc6AKT
DxdRFHqgefrlUYOfMyTJRfnL/eUYZVHHVnmcC1MZpSeUqRM+x90A7oHNsJynIWK1
hZ1lU0mm2rQ9jfdGnjt8mu2yYbcbOe/Ps3fHu4VZqxwUuxTR2pXNvQVjPEc+wWWJ
QLvCz6sFZTkaP1iN5mo3sf/vqu8jO8Vg90BTunkkOdvrCjQzWICcZd9kZeowxm5R
Llu8tEVfOoMGLuJRQF6F5oY28lTqNLhfnytKBikaXgx5apHakqVpL+h+UvqwHnMj
+Yzc83xy1RRpWDBQnLx0Ah//EKWt6pWNJBuEPsTQdlxRqeE1wyNzSdp1E8LKSO8=
-----END CERTIFICATE-----";

pub fn certs_cache_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "Kullanıcı ev dizini bulunamadı".to_string())?;
    Ok(home.join(".kamusm-rs-certs.pem"))
}

pub fn load_cached_root_cas() -> Vec<CapturedX509Certificate> {
    let mut certs = Vec::new();
    if let Ok(path) = certs_cache_path() {
        if let Ok(pem_content) = fs::read_to_string(&path) {
            let mut start = 0;
            while let Some(start_idx) = pem_content[start..].find("-----BEGIN CERTIFICATE-----") {
                let actual_start = start + start_idx;
                if let Some(end_idx) = pem_content[actual_start..].find("-----END CERTIFICATE-----") {
                    let actual_end = actual_start + end_idx + 25; // Length of "-----END CERTIFICATE-----"
                    let pem_block = &pem_content[actual_start..actual_end];
                    if let Ok(cert) = CapturedX509Certificate::from_pem(pem_block.as_bytes()) {
                        certs.push(cert);
                    }
                    start = actual_end;
                } else {
                    break;
                }
            }
        }
    }
    certs
}

fn cert_to_pem(der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let mut pem = String::new();
    pem.push_str("-----BEGIN CERTIFICATE-----\n");
    let chars: Vec<char> = b64.chars().collect();
    for chunk in chars.chunks(64) {
        let line: String = chunk.iter().collect();
        pem.push_str(&line);
        pem.push_str("\n");
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

fn parse_root_certs_from_xml(xml: &str) -> Vec<String> {
    let mut certs = Vec::new();
    let mut pos = 0;
    while let Some(start_idx) = xml[pos..].find("<koksertifika>") {
        let actual_start = pos + start_idx;
        if let Some(end_idx) = xml[actual_start..].find("</koksertifika>") {
            let actual_end = actual_start + end_idx;
            let chunk = &xml[actual_start..actual_end];
            if let Some(val_start_idx) = chunk.find("<mValue>") {
                let val_start = val_start_idx + 8;
                if let Some(val_end_idx) = chunk[val_start..].find("</mValue>") {
                    let val_end = val_start + val_end_idx;
                    let b64_raw = &chunk[val_start..val_end];
                    let b64: String = b64_raw.chars().filter(|c| !c.is_whitespace()).collect();
                    certs.push(b64);
                }
            }
            pos = actual_end + 15; // length of "</koksertifika>"
        } else {
            break;
        }
    }
    certs
}

pub fn update_certs(force: bool) -> Result<usize, String> {
    // 1. Download XML
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP istemci oluşturulamadı: {}", e))?;
    
    let resp = client.get("https://sertifikalar.kamusm.gov.tr/depo/SertifikaDeposu.xml")
        .send()
        .map_err(|e| format!("Sertifika deposu indirilemedi: {}", e))?;
        
    let xml_content = resp.text()
        .map_err(|e| format!("Yanıt metni okunamadı: {}", e))?;
        
    // 2. Parse XML
    let b64_certs = parse_root_certs_from_xml(&xml_content);
    if b64_certs.is_empty() {
        return Err("XML dosyasında kök sertifika bulunamadı".to_string());
    }
    
    // 3. Process certificates & filter by subject common name
    let mut parsed_certs = Vec::new();
    for b64 in b64_certs {
        if let Ok(der_bytes) = STANDARD.decode(&b64) {
            if let Ok(cert) = CapturedX509Certificate::from_der(der_bytes) {
                let cn = cert.subject_common_name().unwrap_or_default();
                if cn.contains("Kamu SM") || cn.contains("KamuSM") {
                    parsed_certs.push(cert);
                }
            }
        }
    }
    
    if parsed_certs.is_empty() {
        return Err("XML dosyasında Kamu SM kök sertifikası bulunamadı".to_string());
    }
    
    // 4. Deduplicate list of unique certificates (embedded + downloaded)
    let mut embedded_certs = Vec::new();
    for pem_str in &[KAMUSM_ROOT_CA_V7, KAMUSM_ROOT_CA_V6, KAMUSM_ROOT_CA_V5, KAMUSM_ROOT_CA_V4] {
        if let Ok(cert) = CapturedX509Certificate::from_pem(pem_str.as_bytes()) {
            embedded_certs.push(cert);
        }
    }
    
    let current_cached = load_cached_root_cas();
    
    let mut seen_fingerprints = HashSet::new();
    for cert in &embedded_certs {
        if let Ok(der) = cert.encode_der() {
            seen_fingerprints.insert(Sha256::digest(&der).to_vec());
        }
    }
    
    let mut current_cached_fingerprints = HashSet::new();
    for cert in &current_cached {
        if let Ok(der) = cert.encode_der() {
            let fp = Sha256::digest(&der).to_vec();
            seen_fingerprints.insert(fp.clone());
            current_cached_fingerprints.insert(fp);
        }
    }
    
    let mut has_new = false;
    let mut all_unique_new_certs = current_cached.clone();
    
    for cert in parsed_certs {
        if let Ok(der) = cert.encode_der() {
            let fp = Sha256::digest(&der).to_vec();
            if seen_fingerprints.insert(fp.clone()) {
                has_new = true;
                all_unique_new_certs.push(cert);
            }
        }
    }
    
    let path = certs_cache_path()?;
    if has_new || force || !path.exists() {
        let mut pem_content = String::new();
        for cert in &all_unique_new_certs {
            if let Ok(der) = cert.encode_der() {
                pem_content.push_str(&cert_to_pem(&der));
            }
        }
        
        fs::write(&path, pem_content)
            .map_err(|e| format!("Sertifika önbellek dosyası yazılamadı: {}", e))?;
            
        let added_count = all_unique_new_certs.len().saturating_sub(current_cached.len());
        Ok(added_count)
    } else {
        Ok(0)
    }
}

pub fn auto_update_certs() -> Result<(), String> {
    let path = certs_cache_path()?;
    let should_update = if !path.exists() {
        true
    } else {
        if let Ok(metadata) = fs::metadata(&path) {
            if let Ok(modified) = metadata.modified() {
                if let Ok(elapsed) = modified.elapsed() {
                    elapsed.as_secs() > 604_800 // 7 gün
                } else {
                    true
                }
            } else {
                true
            }
        } else {
            true
        }
    };
    
    if should_update {
        eprintln!("Kök sertifikalar kontrol ediliyor...");
        match update_certs(false) {
            Ok(added) => {
                if added > 0 {
                    eprintln!("Yeni kök sertifikalar indirildi ve kaydedildi ({} yeni sertifika).", added);
                } else {
                    // Touch the file to update its modification time
                    if let Ok(content) = fs::read(&path) {
                        let _ = fs::write(&path, content);
                    }
                }
            }
            Err(e) => {
                eprintln!("Uyarı: Kök sertifikalar güncellenemedi (çevrimdışı veya sunucu hatası). Mevcut sertifikalar kullanılacak. Hata: {}", e);
            }
        }
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct CertDetails {
    #[serde(rename = "konu")]
    pub subject: String,
    #[serde(rename = "yayinlayan")]
    pub issuer: String,
    #[serde(rename = "baslangic_tarihi")]
    pub not_before: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "bitis_tarihi")]
    pub not_after: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "gecerli")]
    pub is_valid: bool,
}

pub fn read_cert_details(bytes: &[u8]) -> Result<CertDetails, String> {
    let cert = CapturedX509Certificate::from_pem(bytes)
        .or_else(|_| CapturedX509Certificate::from_der(bytes.to_vec()))
        .map_err(|e| format!("Sertifika dosyası ayrıştırılamadı (PEM veya DER formatı bekleniyordu): {:?}", e))?;

    let subject = cert.subject_common_name().unwrap_or_else(|| "Bilinmeyen Konu".to_string());
    let issuer = cert.issuer_common_name().unwrap_or_else(|| "Bilinmeyen Yayıncı".to_string());
    let not_before = cert.validity_not_before();
    let not_after = cert.validity_not_after();
    let is_valid = cert.time_constraints_valid(None);

    Ok(CertDetails {
        subject,
        issuer,
        not_before,
        not_after,
        is_valid,
    })
}


pub fn kamusm_root_cas() -> Vec<CapturedX509Certificate> {
    let mut certs = Vec::new();
    
    for pem_str in &[KAMUSM_ROOT_CA_V7, KAMUSM_ROOT_CA_V6, KAMUSM_ROOT_CA_V5, KAMUSM_ROOT_CA_V4] {
        if let Ok(cert) = CapturedX509Certificate::from_pem(pem_str.as_bytes()) {
            certs.push(cert);
        }
    }
    
    let cached = load_cached_root_cas();
    
    let mut seen = HashSet::new();
    let mut unique_certs = Vec::new();
    
    for cert in certs.into_iter().chain(cached.into_iter()) {
        if let Ok(der) = cert.encode_der() {
            let hash = Sha256::digest(&der).to_vec();
            if seen.insert(hash) {
                unique_certs.push(cert);
            }
        }
    }
    
    unique_certs
}


#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use sha1::Sha1;

    #[test]
    fn print_cert_details() {
        let certs = [
            ("Sürüm 4", KAMUSM_ROOT_CA_V4),
            ("Sürüm 5", KAMUSM_ROOT_CA_V5),
            ("Sürüm 6", KAMUSM_ROOT_CA_V6),
            ("Sürüm 7", KAMUSM_ROOT_CA_V7),
        ];

        for (name, pem_str) in certs {
            let pem_obj = pem::parse(pem_str).unwrap();
            let der = pem_obj.contents();

            let sha256_hash = Sha256::digest(der);
            let sha1_hash = Sha1::digest(der);

            let cert = CapturedX509Certificate::from_pem(pem_str.as_bytes()).unwrap();
            let common_name = cert.subject_common_name().unwrap_or_default();
            
            println!("--- {} ---", name);
            println!("Common Name: {}", common_name);
            println!("SHA-256: {}", hex::encode(sha256_hash));
            println!("SHA-1:   {}", hex::encode(sha1_hash));
        }
    }

    #[test]
    fn test_xml_parsing() {
        let dummy_xml = r#"
        <depo>
            <koksertifikalar>
                <koksertifika>
                    <mKokSertifikaNo>1</mKokSertifikaNo>
                    <mValue>
                        dGVzdGNlcnQx
                    </mValue>
                </koksertifika>
                <koksertifika>
                    <mKokSertifikaNo>2</mKokSertifikaNo>
                    <mValue>dGVzdGNlcnQy</mValue>
                </koksertifika>
            </koksertifikalar>
        </depo>
        "#;

        let parsed = parse_root_certs_from_xml(dummy_xml);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], "dGVzdGNlcnQx");
        assert_eq!(parsed[1], "dGVzdGNlcnQy");
    }

    #[test]
    fn test_read_cert_details() {
        let details = read_cert_details(KAMUSM_ROOT_CA_V7.as_bytes()).unwrap();
        assert!(details.subject.contains("Kamu SM Kök Sertifika"));
        assert!(details.issuer.contains("Kamu SM Kök Sertifika"));
        assert_eq!(details.not_before.format("%Y-%m-%d").to_string(), "2025-09-24");
        assert_eq!(details.not_after.format("%Y-%m-%d").to_string(), "2035-09-22");
    }

    #[test]
    fn test_cert_to_pem() {
        let der = b"testDERdata";
        let pem_str = cert_to_pem(der);
        assert!(pem_str.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem_str.contains("dGVzdERFUmRhdGE="));
        assert!(pem_str.trim().ends_with("-----END CERTIFICATE-----"));
    }
}

