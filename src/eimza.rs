use std::path::{Path};
use std::sync::{OnceLock, Mutex};
use std::io::Cursor;
use libloading::Library;
use cryptoki::context::{Pkcs11, CInitializeArgs, CInitializeFlags};
use cryptoki::session::{UserType};
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use xmltree::{Element, XMLNode};
use xml_canonicalization::Canonicalizer;
use crate::certs::{CertDetails, read_cert_details};

static LOADED_LIBS: OnceLock<Mutex<Vec<Library>>> = OnceLock::new();

/// Manually calls C_Initialize(NULL_PTR) on a PKCS#11 library using libloading.
/// This is required for drivers like akisp11.dll which reject non-null pInitArgs with CKR_ARGUMENTS_BAD.
pub fn init_pkcs11_library_manually(module_path: &str) -> Result<(), String> {
    unsafe {
        let lib = Library::new(module_path)
            .map_err(|e| format!("Kütüphane yüklenemedi: {:?}", e))?;
        
        let c_initialize: libloading::Symbol<unsafe extern "C" fn(*mut std::ffi::c_void) -> usize> = lib.get(b"C_Initialize")
            .map_err(|e| format!("C_Initialize sembolü bulunamadı: {:?}", e))?;
        
        let rv = c_initialize(std::ptr::null_mut());
        
        // 0 is CKR_OK, 0x00000191 is CKR_CRYPTOKI_ALREADY_INITIALIZED
        if rv != 0 && rv != 0x00000191 {
            return Err(format!("C_Initialize başarısız (Hata Kodu: 0x{:X})", rv));
        }

        // Store the library to keep it resident in memory
        let libs_mutex = LOADED_LIBS.get_or_init(|| Mutex::new(Vec::<Library>::new()));
        if let Ok(mut libs) = libs_mutex.lock() {
            libs.push(lib);
        }
    }
    Ok(())
}


#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct EImzaTokenInfo {
    #[serde(rename = "slot_id")]
    pub slot_id: u64,
    #[serde(rename = "etiket")]
    pub label: String,
    #[serde(rename = "uretici")]
    pub manufacturer_id: String,
    #[serde(rename = "model")]
    pub model: String,
    #[serde(rename = "seri_no")]
    pub serial_number: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct EImzaResult {
    #[serde(rename = "token")]
    pub token: EImzaTokenInfo,
    #[serde(rename = "sertifikalar")]
    pub certificates: Vec<CertDetails>,
}

/// Detects the path of the AKİS PKCS#11 driver based on the OS.
pub fn detect_pkcs11_module() -> Option<String> {
    if let Ok(val) = std::env::var("KAMUSM_PKCS11_MODULE") {
        if Path::new(&val).exists() {
            return Some(val);
        }
    }

    let paths = if cfg!(target_os = "windows") {
        vec![
            "C:\\Windows\\System32\\akisp11.dll",
            "C:\\Windows\\SysWOW64\\akisp11.dll",
        ]
    } else if cfg!(target_os = "macos") {
        vec![
            "/usr/local/lib/libakisp11.dylib",
            "/usr/lib/libakisp11.dylib",
            "/Library/Java/Extensions/libakisp11.dylib",
        ]
    } else {
        // Linux / Ubuntu
        vec![
            "/usr/lib/libakisp11.so",
            "/usr/lib64/libakisp11.so",
            "/usr/local/lib/libakisp11.so",
        ]
    };

    for path in paths {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

/// Lists all slots containing active tokens (smart cards).
pub fn list_eimza_tokens(module_path: &str) -> Result<Vec<EImzaTokenInfo>, String> {
    // Try manual C_Initialize(NULL) bypass for akisp11 and similar drivers
    let manual_init = init_pkcs11_library_manually(module_path);

    let pkcs11 = Pkcs11::new(module_path)
        .map_err(|e| format!("PKCS#11 modülü yüklenemedi ({}): {:?}", module_path, e))?;

    if manual_init.is_err() {
        pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .or_else(|e| {
                let err_str = format!("{:?}", e);
                if err_str.contains("CRYPTOKI_ALREADY_INITIALIZED") {
                    Ok(())
                } else {
                    Err(format!("PKCS#11 kütüphanesi başlatılamadı: {:?}", e))
                }
            })?;
    }

    let slots = pkcs11.get_slots_with_token()
        .map_err(|e| format!("Slot listesi alınamadı: {:?}", e))?;

    let mut token_infos = Vec::new();
    for slot in slots {
        let (label, manufacturer_id, model, serial_number) = match pkcs11.get_token_info(slot) {
            Ok(info) => {
                let label = info.label().trim().to_string();
                let manufacturer_id = info.manufacturer_id().trim().to_string();
                let model = info.model().trim().to_string();
                let serial_number = info.serial_number().trim().to_string();
                (label, manufacturer_id, model, serial_number)
            }
            Err(_) => {
                (
                    format!("E-İmza Token {}", slot.id()),
                    "KamuSM / TÜBİTAK".to_string(),
                    "AKİS Smart Card".to_string(),
                    "Bilinmiyor".to_string(),
                )
            }
        };
        token_infos.push(EImzaTokenInfo {
            slot_id: slot.id(),
            label,
            manufacturer_id,
            model,
            serial_number,
        });
    }

    Ok(token_infos)
}

/// Reads certificate details from all active E-Signature tokens.
/// If `pin` is provided, logs into the token before searching for certificates.
pub fn read_eimza_certs(module_path: &str, pin: Option<&str>) -> Result<Vec<EImzaResult>, String> {
    // Try manual C_Initialize(NULL) bypass for akisp11 and similar drivers
    let manual_init = init_pkcs11_library_manually(module_path);

    let pkcs11 = Pkcs11::new(module_path)
        .map_err(|e| format!("PKCS#11 modülü yüklenemedi ({}): {:?}", module_path, e))?;

    if manual_init.is_err() {
        pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .or_else(|e| {
                let err_str = format!("{:?}", e);
                if err_str.contains("CRYPTOKI_ALREADY_INITIALIZED") {
                    Ok(())
                } else {
                    Err(format!("PKCS#11 kütüphanesi başlatılamadı: {:?}", e))
                }
            })?;
    }

    let slots = pkcs11.get_slots_with_token()
        .map_err(|e| format!("Slot listesi alınamadı: {:?}", e))?;

    let mut results = Vec::new();
    for slot in slots {
        let (label, manufacturer_id, model, serial_number) = match pkcs11.get_token_info(slot) {
            Ok(info) => {
                let label = info.label().trim().to_string();
                let manufacturer_id = info.manufacturer_id().trim().to_string();
                let model = info.model().trim().to_string();
                let serial_number = info.serial_number().trim().to_string();
                (label, manufacturer_id, model, serial_number)
            }
            Err(_) => {
                (
                    format!("E-İmza Token {}", slot.id()),
                    "KamuSM / TÜBİTAK".to_string(),
                    "AKİS Smart Card".to_string(),
                    "Bilinmiyor".to_string(),
                )
            }
        };
        
        let slot_info = EImzaTokenInfo {
            slot_id: slot.id(),
            label,
            manufacturer_id,
            model,
            serial_number,
        };

            let session = pkcs11.open_ro_session(slot)
                .map_err(|e| format!("Oturum açılamadı (Slot: {}): {:?}", slot.id(), e))?;

            // Gerekirse PIN ile oturum aç
            if let Some(pin_str) = pin {
                let pin_secret = secrecy::SecretBox::new(Box::<str>::from(pin_str));
                session.login(UserType::User, Some(&pin_secret))
                    .map_err(|e| format!("PIN ile giriş yapılamadı (Slot: {}): {:?}", slot.id(), e))?;
            }

            // Sertifikaları ara
            let template = vec![Attribute::Class(ObjectClass::CERTIFICATE)];
            let cert_handles = session.find_objects(&template)
                .map_err(|e| format!("Sertifika arama başarısız (Slot: {}): {:?}", slot.id(), e))?;

            let mut certs = Vec::new();
            for handle in cert_handles {
                if let Ok(attrs) = session.get_attributes(handle, &[AttributeType::Value]) {
                    for attr in attrs {
                        if let Attribute::Value(der_bytes) = attr {
                            if let Ok(details) = read_cert_details(&der_bytes) {
                                certs.push(details);
                            }
                        }
                    }
                }
            }

            results.push(EImzaResult {
                token: slot_info,
                certificates: certs,
            });

            if pin.is_some() {
                let _ = session.logout();
            }
        }

    Ok(results)
}

struct EImzaSessionContext {
    #[allow(dead_code)]
    pkcs11: Pkcs11,
    session: cryptoki::session::Session,
    selected_key_handle: ObjectHandle,
    cert_der: Vec<u8>,
}

fn open_eimza_signing_session(
    module_path: &str,
    pin: Option<&str>,
) -> Result<EImzaSessionContext, String> {
    let manual_init = init_pkcs11_library_manually(module_path);

    let pkcs11 = Pkcs11::new(module_path)
        .map_err(|e| format!("PKCS#11 modülü yüklenemedi ({}): {:?}", module_path, e))?;

    if manual_init.is_err() {
        pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .or_else(|e| {
                let err_str = format!("{:?}", e);
                if err_str.contains("CRYPTOKI_ALREADY_INITIALIZED") {
                    Ok(())
                } else {
                    Err(format!("PKCS#11 kütüphanesi başlatılamadı: {:?}", e))
                }
            })?;
    }

    let slots = pkcs11.get_slots_with_token()
        .map_err(|e| format!("Slot listesi alınamadı: {:?}", e))?;

    if slots.is_empty() {
        return Err("Takılı USB E-İmza (Akıllı Kart) bulunamadı.".to_string());
    }

    // Use the first slot with token
    let slot = slots[0];

    let session = pkcs11.open_rw_session(slot)
        .map_err(|e| format!("Oturum açılamadı (Slot: {}): {:?}", slot.id(), e))?;

    // PIN is required for signing
    let pin_str = pin.ok_or_else(|| "E-İmza imzalama işlemi için PIN kodu gereklidir.".to_string())?;
    let pin_secret = secrecy::SecretBox::new(Box::<str>::from(pin_str));
    session.login(UserType::User, Some(&pin_secret))
        .map_err(|e| format!("PIN ile giriş yapılamadı (Slot: {}): {:?}", slot.id(), e))?;

    // Find all private keys
    let key_template = vec![Attribute::Class(ObjectClass::PRIVATE_KEY)];
    let key_handles = session.find_objects(&key_template)
        .map_err(|e| format!("Özel anahtarlar bulunamadı: {:?}", e))?;

    if key_handles.is_empty() {
        let _ = session.logout();
        return Err("Kartta özel anahtar bulunamadı.".to_string());
    }

    // Find all certificates
    let cert_template = vec![Attribute::Class(ObjectClass::CERTIFICATE)];
    let cert_handles = session.find_objects(&cert_template)
        .map_err(|e| format!("Sertifikalar bulunamadı: {:?}", e))?;

    if cert_handles.is_empty() {
        let _ = session.logout();
        return Err("Kartta sertifika bulunamadı.".to_string());
    }

    // Match private key and certificate using CKA_ID
    let mut selected_key_handle = key_handles[0];
    let mut selected_cert_handle = cert_handles[0];
    let mut found_pair = false;
    for cert_handle in &cert_handles {
        if let Ok(cert_attrs) = session.get_attributes(*cert_handle, &[AttributeType::Id]) {
            if let Some(Attribute::Id(cert_id)) = cert_attrs.first() {
                for &key_handle in &key_handles {
                    if let Ok(key_attrs) = session.get_attributes(key_handle, &[AttributeType::Id]) {
                        if let Some(Attribute::Id(key_id)) = key_attrs.first() {
                            if cert_id == key_id {
                                selected_key_handle = key_handle;
                                selected_cert_handle = *cert_handle;
                                found_pair = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        if found_pair {
            break;
        }
    }

    // Get certificate DER bytes
    let cert_attrs = session.get_attributes(selected_cert_handle, &[AttributeType::Value])
        .map_err(|e| {
            let _ = session.logout();
            format!("Sertifika verisi alınamadı: {:?}", e)
        })?;
    
    let cert_der = match cert_attrs.first() {
        Some(Attribute::Value(bytes)) => bytes.clone(),
        _ => {
            let _ = session.logout();
            return Err("Sertifika DER baytları bulunamadı.".to_string());
        }
    };

    Ok(EImzaSessionContext {
        pkcs11,
        session,
        selected_key_handle,
        cert_der,
    })
}

/// Signs the given data using the PKCS#11 token's private key.
pub fn sign_eimza_data(
    module_path: &str,
    pin: Option<&str>,
    data: &[u8],
) -> Result<(Vec<u8>, String), String> {
    let ctx = open_eimza_signing_session(module_path, pin)?;

    use cryptoki::mechanism::Mechanism;
    
    let mechanisms_to_try = vec![
        (Mechanism::Ecdsa, "ECDSA", true),
        (Mechanism::Sha256RsaPkcs, "SHA256-RSA-PKCS", false),
        (Mechanism::RsaPkcs, "RSA-PKCS", true),
    ];

    let mut sign_err = String::new();
    for (mech, label, use_hash) in mechanisms_to_try {
        let data_to_sign = if use_hash {
            use sha2::Digest;
            let hash = sha2::Sha256::digest(data);
            hash.to_vec()
        } else {
            data.to_vec()
        };

        match ctx.session.sign(&mech, ctx.selected_key_handle, &data_to_sign) {
            Ok(sig) => {
                let _ = ctx.session.logout();
                return Ok((sig, label.to_string()));
            }
            Err(e) => {
                sign_err = format!("imza başarısız ({}): {:?}", label, e);
            }
        }
    }

    let _ = ctx.session.logout();
    Err(format!("İmzalama hatası: {}", sign_err))
}

/// Signs the given XML data as enveloped XML-DSig using the PKCS#11 token's private key.
pub fn sign_eimza_xml(
    module_path: &str,
    pin: Option<&str>,
    xml_content: &[u8],
) -> Result<String, String> {
    let ctx = open_eimza_signing_session(module_path, pin)?;

    // Parse the original XML
    let xml_str = std::str::from_utf8(xml_content)
        .map_err(|e| format!("Geçersiz UTF-8 XML verisi: {:?}", e))?;
    
    let mut root = Element::parse(xml_content)
        .map_err(|e| format!("XML ayrıştırılamadı: {:?}", e))?;

    // Canonicalize the original XML
    let mut original_canon = Vec::new();
    Canonicalizer::read_from_str(xml_str)
        .write_to_writer(Cursor::new(&mut original_canon))
        .canonicalize(true)
        .map_err(|e| format!("Kanonikalizasyon hatası: {:?}", e))?;

    // Compute SHA-256 hash of original canonical XML
    use sha2::Digest;
    let digest_value = sha2::Sha256::digest(&original_canon);
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let digest_value_b64 = STANDARD.encode(digest_value);

    // Get certificate Base64
    let cert_b64 = STANDARD.encode(&ctx.cert_der);

    // Determine mechanism
    use cryptoki::mechanism::Mechanism;
    let mechanisms_to_try = vec![
        (Mechanism::Ecdsa, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", true),
        (Mechanism::Sha256RsaPkcs, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", false),
        (Mechanism::RsaPkcs, "http://www.w3.org/2000/09/xmldsig#rsa-sha256", true),
    ];

    let mut signature_bytes = None;
    let mut used_algorithm_uri = "";

    for (mech, algorithm_uri, use_hash) in mechanisms_to_try {
        // Build SignedInfo XML
        let mut signed_info = Element::new("ds:SignedInfo");
        signed_info.attributes.insert("xmlns:ds".to_string(), "http://www.w3.org/2000/09/xmldsig#".to_string());

        let mut canon_method = Element::new("ds:CanonicalizationMethod");
        canon_method.attributes.insert("Algorithm".to_string(), "http://www.w3.org/TR/2001/REC-xml-c14n-20010315".to_string());
        signed_info.children.push(XMLNode::Element(canon_method));

        let mut sig_method = Element::new("ds:SignatureMethod");
        sig_method.attributes.insert("Algorithm".to_string(), algorithm_uri.to_string());
        signed_info.children.push(XMLNode::Element(sig_method));

        let mut reference = Element::new("ds:Reference");
        reference.attributes.insert("URI".to_string(), "".to_string());

        let mut transforms = Element::new("ds:Transforms");
        let mut transform1 = Element::new("ds:Transform");
        transform1.attributes.insert("Algorithm".to_string(), "http://www.w3.org/2000/09/xmldsig#enveloped-signature".to_string());
        transforms.children.push(XMLNode::Element(transform1));

        let mut transform2 = Element::new("ds:Transform");
        transform2.attributes.insert("Algorithm".to_string(), "http://www.w3.org/TR/2001/REC-xml-c14n-20010315".to_string());
        transforms.children.push(XMLNode::Element(transform2));

        reference.children.push(XMLNode::Element(transforms));

        let mut digest_method = Element::new("ds:DigestMethod");
        digest_method.attributes.insert("Algorithm".to_string(), "http://www.w3.org/2001/04/xmlenc#sha256".to_string());
        reference.children.push(XMLNode::Element(digest_method));

        let mut digest_value_elem = Element::new("ds:DigestValue");
        digest_value_elem.children.push(XMLNode::Text(digest_value_b64.clone()));
        reference.children.push(XMLNode::Element(digest_value_elem));

        signed_info.children.push(XMLNode::Element(reference));

        // Serialize and canonicalize SignedInfo
        let mut signed_info_bytes = Vec::new();
        if signed_info.write(&mut signed_info_bytes).is_err() {
            continue;
        }
        
        let signed_info_str = match std::str::from_utf8(&signed_info_bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        
        let mut signed_info_canon = Vec::new();
        if Canonicalizer::read_from_str(signed_info_str)
            .write_to_writer(Cursor::new(&mut signed_info_canon))
            .canonicalize(true)
            .is_err() {
            continue;
        }

        let data_to_sign = if use_hash {
            let hash = sha2::Sha256::digest(&signed_info_canon);
            hash.to_vec()
        } else {
            signed_info_canon.clone()
        };

        if let Ok(sig) = ctx.session.sign(&mech, ctx.selected_key_handle, &data_to_sign) {
            signature_bytes = Some(sig);
            used_algorithm_uri = algorithm_uri;
            break;
        }
    }

    let signature_bytes = signature_bytes.ok_or_else(|| {
        let _ = ctx.session.logout();
        "Hiçbir XML imzalama mekanizması çalışmadı.".to_string()
    })?;

    let _ = ctx.session.logout();

    let signature_b64 = STANDARD.encode(signature_bytes);

    // Build the final Signature element
    let mut signature_elem = Element::new("ds:Signature");
    signature_elem.attributes.insert("xmlns:ds".to_string(), "http://www.w3.org/2000/09/xmldsig#".to_string());
    signature_elem.attributes.insert("Id".to_string(), "signature".to_string());

    let mut signed_info = Element::new("ds:SignedInfo");
    
    let mut canon_method = Element::new("ds:CanonicalizationMethod");
    canon_method.attributes.insert("Algorithm".to_string(), "http://www.w3.org/TR/2001/REC-xml-c14n-20010315".to_string());
    signed_info.children.push(XMLNode::Element(canon_method));

    let mut sig_method = Element::new("ds:SignatureMethod");
    sig_method.attributes.insert("Algorithm".to_string(), used_algorithm_uri.to_string());
    signed_info.children.push(XMLNode::Element(sig_method));

    let mut reference = Element::new("ds:Reference");
    reference.attributes.insert("URI".to_string(), "".to_string());

    let mut transforms = Element::new("ds:Transforms");
    let mut transform1 = Element::new("ds:Transform");
    transform1.attributes.insert("Algorithm".to_string(), "http://www.w3.org/2000/09/xmldsig#enveloped-signature".to_string());
    transforms.children.push(XMLNode::Element(transform1));

    let mut transform2 = Element::new("ds:Transform");
    transform2.attributes.insert("Algorithm".to_string(), "http://www.w3.org/TR/2001/REC-xml-c14n-20010315".to_string());
    transforms.children.push(XMLNode::Element(transform2));

    reference.children.push(XMLNode::Element(transforms));

    let mut digest_method = Element::new("ds:DigestMethod");
    digest_method.attributes.insert("Algorithm".to_string(), "http://www.w3.org/2001/04/xmlenc#sha256".to_string());
    reference.children.push(XMLNode::Element(digest_method));

    let mut digest_value_elem = Element::new("ds:DigestValue");
    digest_value_elem.children.push(XMLNode::Text(digest_value_b64));
    reference.children.push(XMLNode::Element(digest_value_elem));

    signed_info.children.push(XMLNode::Element(reference));

    signature_elem.children.push(XMLNode::Element(signed_info));

    let mut sig_val_elem = Element::new("ds:SignatureValue");
    sig_val_elem.children.push(XMLNode::Text(signature_b64));
    signature_elem.children.push(XMLNode::Element(sig_val_elem));

    let mut key_info = Element::new("ds:KeyInfo");
    let mut x509_data = Element::new("ds:X509Data");
    let mut x509_cert = Element::new("ds:X509Certificate");
    x509_cert.children.push(XMLNode::Text(cert_b64));
    x509_data.children.push(XMLNode::Element(x509_cert));
    key_info.children.push(XMLNode::Element(x509_data));
    signature_elem.children.push(XMLNode::Element(key_info));

    root.children.push(XMLNode::Element(signature_elem));

    let mut output = Vec::new();
    let trimmed_xml = xml_str.trim();
    let has_decl = trimmed_xml.starts_with("<?xml") || trimmed_xml.starts_with("<?XML");
    if has_decl {
        output.extend_from_slice(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    }
    root.write(&mut output).map_err(|e| format!("XML yazma hatası: {:?}", e))?;

    String::from_utf8(output).map_err(|e| format!("UTF-8 dönüşüm hatası: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_pkcs11_module_env() {
        let temp_dir = std::env::temp_dir();
        let ext = if cfg!(target_os = "windows") {
            "dll"
        } else if cfg!(target_os = "macos") {
            "dylib"
        } else {
            "so"
        };
        let temp_file = temp_dir.join(format!("test_akisp11_xyz.{}", ext));
        std::fs::write(&temp_file, b"").unwrap();
        
        std::env::set_var("KAMUSM_PKCS11_MODULE", temp_file.to_str().unwrap());
        assert_eq!(detect_pkcs11_module(), Some(temp_file.to_str().unwrap().to_string()));

        std::env::set_var("KAMUSM_PKCS11_MODULE", "non_existent_file_xyz.dll");
        if let Some(path) = detect_pkcs11_module() {
            assert_ne!(path, "non_existent_file_xyz.dll");
        }
        
        std::fs::remove_file(temp_file).ok();
        std::env::remove_var("KAMUSM_PKCS11_MODULE");
    }

    #[test]
    fn test_real_akis_init() {
        if let Some(path) = detect_pkcs11_module() {
            let manual_res = init_pkcs11_library_manually(&path);
            assert!(manual_res.is_ok());

            let pkcs11 = Pkcs11::new(&path).unwrap();
            let slots = pkcs11.get_slots_with_token();
            assert!(slots.is_ok());
        }
    }

    #[test]
    fn test_xml_canonicalization_and_parsing() {
        let xml = r#"<root>  <child>hello</child>  </root>"#;
        
        let mut canon = Vec::new();
        let canon_res = Canonicalizer::read_from_str(xml)
            .write_to_writer(Cursor::new(&mut canon))
            .canonicalize(true);
        assert!(canon_res.is_ok());
        
        let parsed = Element::parse(xml.as_bytes());
        assert!(parsed.is_ok());
    }
}

