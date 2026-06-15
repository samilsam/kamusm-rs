use clap::{Parser, Subcommand};
use kamusm_rs::{
    load_config, save_config, mask_password, ConfigData,
    build_identity, build_tsa_request, compute_file_digest,
    send_credit_request, send_timestamp_request,
    is_valid_timestamp_response, extract_pkcs7, extract_text_from_asn1,
    parse_credits_from_body, verify_timestamp, VERSION, config_path,
    update_certs, auto_update_certs
};
use std::path::Path;
use std::fs;
use std::process;
use chrono::Utc;
use sha1::Digest;

#[derive(Parser, Debug)]
#[command(name = "kamusm-rs", about = "kamusm-rs - KamuSM Zaman Damgası İstemcisi", version = VERSION)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// \"identity\" başlığı oluştur
    #[command(name = "kimlik")]
    Kimlik {
        #[arg(long = "musteri-no")]
        musteri_no: Option<u32>,
        #[arg(long = "parola")]
        parola: Option<String>,
        #[arg(long = "ozet-hex")]
        ozet_hex: Option<String>,
        #[arg(long = "zaman")]
        zaman: Option<u64>,
        #[arg(long = "iterasyon", default_value_t = 100)]
        iterasyon: i32,
        #[arg(long = "json")]
        json: bool,
    },
    /// Zaman damgası isteği gönder
    #[command(name = "gonder")]
    Gonder {
        #[arg(long = "sunucu")]
        sunucu: Option<String>,
        #[arg(long = "musteri-no")]
        musteri_no: Option<u32>,
        #[arg(long = "parola")]
        parola: Option<String>,
        #[arg(long = "dosya")]
        dosya: Option<String>,
        #[arg(long = "ozet-hex")]
        ozet_hex: Option<String>,
        #[arg(long = "hash", default_value = "sha256")]
        hash: String,
        #[arg(long = "iterasyon", default_value_t = 100)]
        iterasyon: i32,
        #[arg(long = "json")]
        json: bool,
        #[arg(long = "dogrula")]
        dogrula: bool,
    },
    /// Bakiyeyi kontrol et
    #[command(name = "bakiye")]
    Bakiye {
        #[arg(long = "sunucu")]
        sunucu: Option<String>,
        #[arg(long = "musteri-no")]
        musteri_no: Option<u32>,
        #[arg(long = "parola")]
        parola: Option<String>,
        #[arg(long = "iterasyon", default_value_t = 100)]
        iterasyon: i32,
        #[arg(long = "zaman")]
        zaman: Option<u64>,
        #[arg(long = "json")]
        json: bool,
    },
    /// Zaman damgası dosyasını doğrula
    #[command(name = "dogrula")]
    Dogrula {
        #[arg(long = "dosya")]
        dosya: String,
        #[arg(long = "json")]
        json: bool,
    },
    /// Bağlantı bilgilerini şifreli kaydet
    #[command(name = "ayar-kaydet")]
    AyarKaydet {
        #[arg(long = "sunucu")]
        sunucu: String,
        #[arg(long = "musteri-no")]
        musteri_no: u32,
        #[arg(long = "parola")]
        parola: String,
        #[arg(long = "hash", default_value = "sha256")]
        hash: String,
        #[arg(long = "iterasyon", default_value_t = 100)]
        iterasyon: i32,
    },
    /// Kayıtlı ayarları göster
    #[command(name = "ayar-goster")]
    AyarGoster,
    /// Versiyon bilgisini göster
    #[command(name = "versiyon")]
    Versiyon,
    /// Kök sertifikaları TÜBİTAK KamuSM deposundan güncelle
    #[command(name = "sertifika-guncelle")]
    SertifikaGuncelle {
        #[arg(long = "zorla")]
        zorla: bool,
    },
}

fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::Kimlik {
            musteri_no,
            parola,
            ozet_hex,
            zaman,
            iterasyon,
            json,
        } => {
            run_identity(musteri_no, parola, ozet_hex, zaman, iterasyon, json);
        }
        Commands::Gonder {
            sunucu,
            musteri_no,
            parola,
            dosya,
            ozet_hex,
            hash,
            iterasyon,
            json,
            dogrula,
        } => {
            run_send(sunucu, musteri_no, parola, dosya, ozet_hex, hash, iterasyon, json, dogrula);
        }
        Commands::Bakiye {
            sunucu,
            musteri_no,
            parola,
            iterasyon,
            zaman,
            json,
        } => {
            run_credits(sunucu, musteri_no, parola, iterasyon, zaman, json);
        }
        Commands::Dogrula { dosya, json } => {
            run_verify(dosya, json);
        }
        Commands::AyarKaydet {
            sunucu,
            musteri_no,
            parola,
            hash,
            iterasyon,
        } => {
            run_save_config(sunucu, musteri_no, parola, hash, iterasyon);
        }
        Commands::AyarGoster => {
            run_show_config();
        }
        Commands::Versiyon => {
            println!("kamusm-rs {}", VERSION);
        }
        Commands::SertifikaGuncelle { zorla } => {
            run_update_certs(zorla);
        }
    }
}

fn apply_config_defaults(
    sunucu: &mut Option<String>,
    musteri_no: &mut Option<u32>,
    parola: &mut Option<String>,
    hash: &mut String,
    iterasyon: &mut i32,
) {
    if let Ok(cfg) = load_config() {
        if sunucu.is_none() && !cfg.sunucu.is_empty() {
            *sunucu = Some(cfg.sunucu);
        }
        if musteri_no.is_none() && cfg.musteri_no != 0 {
            *musteri_no = Some(cfg.musteri_no);
        }
        if parola.is_none() && !cfg.parola.is_empty() {
            *parola = Some(cfg.parola);
        }
        if hash == "sha256" && !cfg.hash.is_empty() {
            *hash = cfg.hash;
        }
        if *iterasyon == 100 && cfg.iterasyon != 0 {
            *iterasyon = cfg.iterasyon;
        }
    }
}

fn run_identity(
    mut musteri_no: Option<u32>,
    mut parola: Option<String>,
    ozet_hex: Option<String>,
    zaman: Option<u64>,
    mut iterasyon: i32,
    json: bool,
) {
    let mut dummy_sunucu = None;
    let mut dummy_hash = "sha256".to_string();
    apply_config_defaults(&mut dummy_sunucu, &mut musteri_no, &mut parola, &mut dummy_hash, &mut iterasyon);

    let customer_id = musteri_no.unwrap_or_else(|| fatal("--musteri-no parametresi gereklidir"));
    let password = parola.unwrap_or_else(|| fatal("--parola parametresi gereklidir"));
    if iterasyon < 1 {
        fatal("--iterasyon değeri en az 1 olmalıdır");
    }

    let digest = if let Some(hex_str) = ozet_hex {
        hex::decode(&hex_str).unwrap_or_else(|e| fatal(&format!("Geçersiz hex özet: {:?}", e)))
    } else if let Some(ts) = zaman {
        let s = format!("{}{}", customer_id, ts);
        let hash = sha1::Sha1::digest(s.as_bytes());
        hash.to_vec()
    } else {
        fatal("--ozet-hex veya --zaman parametrelerinden biri sağlanmalıdır");
    };

    match build_identity(customer_id, &password, &digest, iterasyon) {
        Ok(identity) => {
            if json {
                print_json(&serde_json::json!({ "identity": identity }));
            } else {
                println!("{}", identity);
            }
        }
        Err(e) => fatal(&format!("Identity oluşturulamadı: {}", e)),
    }
}

fn run_send(
    mut sunucu: Option<String>,
    mut musteri_no: Option<u32>,
    mut parola: Option<String>,
    dosya: Option<String>,
    ozet_hex: Option<String>,
    mut hash_alg: String,
    mut iterasyon: i32,
    json: bool,
    dogrula: bool,
) {
    apply_config_defaults(&mut sunucu, &mut musteri_no, &mut parola, &mut hash_alg, &mut iterasyon);

    if dogrula {
        let _ = auto_update_certs();
    }

    let server_url = sunucu.unwrap_or_else(|| fatal("--sunucu parametresi gereklidir"));
    let customer_id = musteri_no.unwrap_or_else(|| fatal("--musteri-no parametresi gereklidir"));
    let password = parola.unwrap_or_else(|| fatal("--parola parametresi gereklidir"));
    if iterasyon < 1 {
        fatal("--iterasyon değeri en az 1 olmalıdır");
    }

    let digest: Vec<u8>;
    let output_filename: String;

    if let Some(file_path) = dosya {
        digest = compute_file_digest(&file_path, &hash_alg)
            .unwrap_or_else(|e| fatal(&format!("Dosya hash'i hesaplanamadı: {}", e)));
        
        let path = Path::new(&file_path);
        let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        output_filename = parent.join(format!("{}_zd.der", stem)).to_string_lossy().into_owned();
    } else if let Some(hex_str) = ozet_hex {
        digest = hex::decode(&hex_str).unwrap_or_else(|e| fatal(&format!("Geçersiz hex özet: {:?}", e)));
        let ts = Utc::now().timestamp();
        output_filename = format!("zd_{}.der", ts);
    } else {
        fatal("--dosya veya --ozet-hex parametrelerinden biri sağlanmalıdır");
    }

    let der = build_tsa_request(&digest, &hash_alg)
        .unwrap_or_else(|e| fatal(&format!("TSA isteği oluşturulamadı: {}", e)));

    let identity = build_identity(customer_id, &password, &digest, iterasyon)
        .unwrap_or_else(|e| fatal(&format!("Identity oluşturulamadı: {}", e)));

    match send_timestamp_request(&server_url, &identity, &der) {
        Ok((status, body)) => {
            if is_valid_timestamp_response(&body) {
                let p7_data = extract_pkcs7(&body).unwrap_or(body);
                if let Err(e) = fs::write(&output_filename, &p7_data) {
                    fatal(&format!("Yanıt yazılamadı: {:?}", e));
                }

                if json {
                    let mut result = serde_json::json!({
                        "durum": status,
                        "basarili": true,
                        "dosya": output_filename
                    });

                    if dogrula {
                        let saved_data = fs::read(&output_filename).unwrap_or_default();
                        match verify_timestamp(&saved_data) {
                            Ok(vr) => {
                                result.as_object_mut().unwrap().insert("dogrulama".to_string(), serde_json::to_value(vr).unwrap());
                            }
                            Err(e) => {
                                result.as_object_mut().unwrap().insert("dogrulama".to_string(), serde_json::json!({ "gecerli": false, "hata": e }));
                            }
                        }
                    }
                    print_json(&result);
                } else {
                    println!("Yanıt durumu: {}", status);
                    println!("Çıkarılan PKCS#7 SignedData {} dosyasına kaydedildi", output_filename);

                    if dogrula {
                        let saved_data = fs::read(&output_filename).unwrap_or_default();
                        match verify_timestamp(&saved_data) {
                            Ok(vr) => {
                                if vr.valid {
                                    println!("Doğrulama başarılı");
                                    if let Some(signer) = vr.signer {
                                        println!("  İmzalayan: {}", signer);
                                    }
                                } else {
                                    println!("Doğrulama başarısız: {}", vr.error.unwrap_or_default());
                                }
                            }
                            Err(e) => {
                                println!("Doğrulama hatası: {}", e);
                            }
                        }
                    }
                }
            } else {
                let texts = extract_text_from_asn1(&body);

                if json {
                    let mut result = serde_json::json!({
                        "durum": status,
                        "basarili": false
                    });
                    if !texts.is_empty() {
                        result.as_object_mut().unwrap().insert("hatalar".to_string(), serde_json::to_value(texts).unwrap());
                    } else {
                        let text = String::from_utf8_lossy(&body).trim().to_string();
                        if is_printable_string(&text) {
                            result.as_object_mut().unwrap().insert("hatalar".to_string(), serde_json::json!([text]));
                        } else {
                            if let Err(e) = fs::write(&output_filename, &body) {
                                fatal(&format!("Yanıt yazılamadı: {:?}", e));
                            }
                            result.as_object_mut().unwrap().insert("dosya".to_string(), serde_json::json!(output_filename));
                        }
                    }
                    print_json(&result);
                } else {
                    println!("Yanıt durumu: {}", status);
                    println!("Hata yanıtı alındı (HTTP {})", status);
                    if !texts.is_empty() {
                        println!("Hata mesajları:");
                        for text in texts {
                            println!("  {}", text);
                        }
                    } else {
                        let text = String::from_utf8_lossy(&body).trim().to_string();
                        if is_printable_string(&text) {
                            println!("Yanıt gövdesi (metin):\n{}", text);
                        } else {
                            if let Err(e) = fs::write(&output_filename, &body) {
                                fatal(&format!("Yanıt yazılamadı: {:?}", e));
                            }
                            println!("Binary hata yanıtı {} dosyasına kaydedildi", output_filename);
                        }
                    }
                }
            }
        }
        Err(e) => fatal(&format!("İstek gönderilemedi: {}", e)),
    }
}

fn run_credits(
    mut sunucu: Option<String>,
    mut musteri_no: Option<u32>,
    mut parola: Option<String>,
    mut iterasyon: i32,
    zaman: Option<u64>,
    json: bool,
) {
    let mut dummy_hash = "sha256".to_string();
    apply_config_defaults(&mut sunucu, &mut musteri_no, &mut parola, &mut dummy_hash, &mut iterasyon);

    let server_url = sunucu.unwrap_or_else(|| fatal("--sunucu parametresi gereklidir"));
    let customer_id = musteri_no.unwrap_or_else(|| fatal("--musteri-no parametresi gereklidir"));
    let password = parola.unwrap_or_else(|| fatal("--parola parametresi gereklidir"));
    if iterasyon < 1 {
        fatal("--iterasyon değeri en az 1 olmalıdır");
    }

    let ts = zaman.unwrap_or_else(|| chrono::Utc::now().timestamp_millis() as u64);

    let s = format!("{}{}", customer_id, ts);
    let hash = sha1::Sha1::digest(s.as_bytes());
    let digest = hash.to_vec();

    let identity = build_identity(customer_id, &password, &digest, iterasyon)
        .unwrap_or_else(|e| fatal(&format!("Identity oluşturulamadı: {}", e)));

    match send_credit_request(&server_url, &identity, customer_id, ts) {
        Ok((status, content_type, body)) => {
            if json {
                let mut result = serde_json::json!({ "durum": status });
                if content_type.starts_with("application/timestamp-reply") {
                    if let Some(credits) = parse_credits_from_body(&body) {
                        result.as_object_mut().unwrap().insert("bakiye".to_string(), serde_json::json!(credits));
                    } else {
                        let text = String::from_utf8_lossy(&body).trim().to_string();
                        result.as_object_mut().unwrap().insert("hata".to_string(), serde_json::json!(text));
                    }
                } else {
                    let text = String::from_utf8_lossy(&body).trim().to_string();
                    result.as_object_mut().unwrap().insert("hata".to_string(), serde_json::json!(text));
                }
                print_json(&result);
            } else {
                println!("Yanıt durumu: {}", status);
                if content_type.starts_with("application/timestamp-reply") {
                    if let Some(credits) = parse_credits_from_body(&body) {
                        println!("Kalan zaman damgası bakiyesi: {}", credits);
                    } else {
                        let text = String::from_utf8_lossy(&body).trim().to_string();
                        if is_printable_string(&text) {
                            println!("Yanıt gövdesi (metin):\n{}", text);
                        } else {
                            if let Err(e) = fs::write("timestamp_resp.der", &body) {
                                fatal(&format!("Yanıt yazılamadı: {:?}", e));
                            }
                            println!("Binary yanıt; timestamp_resp.der dosyasına kaydedildi");
                        }
                    }
                } else {
                    println!("Content-Type: {}", content_type);
                    let text = String::from_utf8_lossy(&body).trim().to_string();
                    if is_printable_string(&text) {
                        println!("Yanıt gövdesi (metin):\n{}", text);
                    } else {
                        if let Err(e) = fs::write("timestamp_resp.der", &body) {
                            fatal(&format!("Yanıt yazılamadı: {:?}", e));
                        }
                        println!("Binary yanıt; timestamp_resp.der dosyasına kaydedildi");
                    }
                }
            }
        }
        Err(e) => fatal(&format!("Bakiye kontrolü isteği gönderilemedi: {}", e)),
    }
}

fn run_verify(dosya: String, json: bool) {
    let _ = auto_update_certs();
    let data = fs::read(&dosya).unwrap_or_else(|e| fatal(&format!("Dosya okunamadı: {:?}", e)));


    match verify_timestamp(&data) {
        Ok(vr) => {
            if json {
                print_json(&vr);
            } else if vr.valid {
                println!("Doğrulama başarılı");
                if let Some(signer) = vr.signer {
                    println!("  İmzalayan: {}", signer);
                }
            } else {
                println!("Doğrulama başarısız: {}", vr.error.unwrap_or_default());
            }
        }
        Err(e) => {
            if json {
                print_json(&serde_json::json!({ "gecerli": false, "hata": e }));
            } else {
                fatal(&format!("Doğrulama hatası: {}", e));
            }
        }
    }
}

fn run_save_config(sunucu: String, musteri_no: u32, parola: String, hash: String, iterasyon: i32) {
    if iterasyon < 1 {
        fatal("--iterasyon değeri en az 1 olmalıdır");
    }

    let cfg = ConfigData {
        sunucu,
        musteri_no,
        parola,
        hash,
        iterasyon,
    };

    match save_config(&cfg) {
        Ok(()) => {
            let path = config_path().unwrap();
            println!("Ayarlar şifreli olarak kaydedildi: {}", path.to_string_lossy());
        }
        Err(e) => fatal(&format!("Ayarlar kaydedilemedi: {}", e)),
    }
}

fn run_show_config() {
    match load_config() {
        Ok(cfg) => {
            println!("Kayıtlı ayarlar:");
            println!("  Sunucu:     {}", cfg.sunucu);
            println!("  Müşteri No: {}", cfg.musteri_no);
            println!("  Parola:     {}", mask_password(&cfg.parola));
            println!("  Hash:       {}", cfg.hash);
            println!("  İterasyon:  {}", cfg.iterasyon);
        }
        Err(e) => fatal(&format!("Ayarlar okunamadı: {}", e)),
    }
}

fn is_printable_string(s: &str) -> bool {
    s.as_bytes().iter().all(|&b| {
        (0x20..=0x7E).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t'
    })
}

fn fatal(msg: &str) -> ! {
    eprintln!("Hata: {}", msg);
    process::exit(1);
}

fn print_json<T: serde::Serialize>(v: &T) {
    if let Ok(json_str) = serde_json::to_string_pretty(v) {
        println!("{}", json_str);
    }
}

fn run_update_certs(force: bool) {
    println!("TÜBİTAK Kamu SM Kök Sertifikaları deposundan güncelleniyor...");
    match update_certs(force) {
        Ok(added) => {
            if added > 0 {
                println!("Güncelleme tamamlandı: {} yeni kök sertifika önbelleğe kaydedildi.", added);
            } else {
                println!("Sertifikalar zaten güncel. Herhangi bir değişiklik yapılmadı.");
            }
        }
        Err(e) => {
            fatal(&format!("Sertifika güncelleme hatası: {}", e));
        }
    }
}

