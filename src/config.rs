use std::fs;
use std::path::PathBuf;
use rand::RngCore;
use serde::{Serialize, Deserialize};

const CONFIG_FILE_NAME: &str = ".kamusm-rs.conf";
const CONFIG_SALT_PHRASE: &str = "kamusm-go-config-salt";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConfigData {
    pub sunucu: String,
    #[serde(rename = "musteriNo")]
    pub musteri_no: u64,
    pub parola: String,

    pub hash: String,
    pub iterasyon: i32,
}

pub fn config_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "Kullanıcı ev dizini bulunamadı".to_string())?;
    Ok(home.join(CONFIG_FILE_NAME))
}

fn machine_key(salt: &[u8]) -> Result<Vec<u8>, String> {
    let username = whoami::username();
    let hostname = hostname::get()
        .map_err(|e| format!("Hostname alınamadı: {:?}", e))?
        .to_string_lossy()
        .into_owned();

    let source = format!("{}{}{}", hostname, username, CONFIG_SALT_PHRASE);
    Ok(crate::crypto::derive_key(&source, salt, 100_000))
}

pub fn save_config(cfg: &ConfigData) -> Result<(), String> {
    let json_data = serde_json::to_vec(cfg)
        .map_err(|e| format!("JSON kodlama hatası: {:?}", e))?;

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let key = machine_key(&salt)?;
    let ciphertext = crate::crypto::encrypt_aes_cbc(&key, &iv, &json_data)?;

    let mut file_data = Vec::with_capacity(32 + ciphertext.len());
    file_data.extend_from_slice(&salt);
    file_data.extend_from_slice(&iv);
    file_data.extend_from_slice(&ciphertext);

    let path = config_path()?;
    
    fs::write(&path, file_data)
        .map_err(|e| format!("Yapılandırma dosyası yazılamadı: {:?}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(&path) {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            let _ = fs::set_permissions(&path, permissions);
        }
    }

    Ok(())
}

pub fn load_config() -> Result<ConfigData, String> {
    let path = config_path()?;
    let file_data = fs::read(&path)
        .map_err(|e| format!("Yapılandırma dosyası okunamadı: {:?}", e))?;

    if file_data.len() < 33 {
        return Err("Yapılandırma dosyası bozuk".to_string());
    }

    let salt = &file_data[0..16];
    let iv = &file_data[16..32];
    let ciphertext = &file_data[32..];

    let key = machine_key(salt)?;
    let json_data = crate::crypto::decrypt_aes_cbc(&key, iv, ciphertext)?;

    let cfg: ConfigData = serde_json::from_slice(&json_data)
        .map_err(|e| format!("Yapılandırma ayrıştırılamadı: {:?}", e))?;

    Ok(cfg)
}

pub fn mask_password(p: &str) -> String {
    if p.len() <= 3 {
        "***".to_string()
    } else {
        format!("{}****", &p[..3])
    }
}
