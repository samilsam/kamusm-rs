#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn get_pkcs11_module() -> Result<String, String> {
    kamusm_rs::detect_pkcs11_module().ok_or_else(|| {
        "PKCS#11 sürücü modülü (akisp11.dll/so/dylib) bulunamadı. Kart okuyucu sürücüsünün (AKİS) kurulu olduğundan emin olun.".to_string()
    })
}

#[tauri::command]
fn list_tokens() -> Result<Vec<kamusm_rs::EImzaTokenInfo>, String> {
    let module_path = get_pkcs11_module()?;
    kamusm_rs::list_eimza_tokens(&module_path)
}

#[tauri::command]
fn login_with_eimza(pin: Option<String>) -> Result<Vec<kamusm_rs::EImzaResult>, String> {
    let module_path = get_pkcs11_module()?;
    let pin_ref = pin.as_deref().filter(|s| !s.is_empty());
    kamusm_rs::read_eimza_certs(&module_path, pin_ref)
}

#[tauri::command]
fn sign_file(
    file_path: String,
    is_xml: bool,
    pin: String,
    output_path: Option<String>,
) -> Result<String, String> {
    let module_path = get_pkcs11_module()?;
    let data = std::fs::read(&file_path)
        .map_err(|e| format!("Dosya okunamadı: {:?}", e))?;

    if is_xml {
        let signed_xml = kamusm_rs::sign_eimza_xml(&module_path, Some(&pin), &data)?;
        let out_path = output_path.unwrap_or_else(|| {
            let path = std::path::Path::new(&file_path);
            let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
            parent.join(format!("{}_imzali.xml", stem)).to_string_lossy().into_owned()
        });
        std::fs::write(&out_path, signed_xml.as_bytes())
            .map_err(|e| format!("İmzalı XML kaydedilemedi: {:?}", e))?;
        Ok(out_path)
    } else {
        let (sig_bytes, _mechanism) = kamusm_rs::sign_eimza_data(&module_path, Some(&pin), &data)?;
        let out_path = output_path.unwrap_or_else(|| {
            format!("{}.sig", file_path)
        });
        std::fs::write(&out_path, &sig_bytes)
            .map_err(|e| format!("İmza dosyası kaydedilemedi: {:?}", e))?;
        Ok(out_path)
    }
}

#[tauri::command]
fn verify_file(
    file_path: String,
    is_xml: bool,
    original_path: Option<String>,
    sig_path: Option<String>,
    cert_path: Option<String>,
) -> Result<kamusm_rs::VerifyResult, String> {
    if is_xml {
        let data = std::fs::read(&file_path)
            .map_err(|e| format!("İmzalı XML dosyası okunamadı: {:?}", e))?;
        kamusm_rs::verify_eimza_xml(&data)
    } else {
        let orig_p = original_path.ok_or_else(|| "Orijinal dosya yolu gereklidir.".to_string())?;
        let sig_p = sig_path.unwrap_or(file_path);
        let cert_p = cert_path.ok_or_else(|| "Sertifika dosyası (.pem/.der) gereklidir.".to_string())?;

        let original_data = std::fs::read(&orig_p)
            .map_err(|e| format!("Orijinal dosya okunamadı: {:?}", e))?;
        let signature_bytes = std::fs::read(&sig_p)
            .map_err(|e| format!("İmza dosyası okunamadı: {:?}", e))?;
        let cert_bytes = std::fs::read(&cert_p)
            .map_err(|e| format!("Sertifika dosyası okunamadı: {:?}", e))?;

        kamusm_rs::verify_eimza_detached(&original_data, &signature_bytes, &cert_bytes)
    }
}

#[tauri::command]
fn select_file(title: String) -> Option<String> {
    let path = rfd::FileDialog::new()
        .set_title(&title)
        .pick_file()?;
    Some(path.to_string_lossy().into_owned())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            list_tokens,
            login_with_eimza,
            sign_file,
            verify_file,
            select_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
