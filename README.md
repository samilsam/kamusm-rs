# kamusm-rs

TÜBİTAK BİLGEM tarafından işletilen [Kamu SM](https://kamusm.bilgem.tubitak.gov.tr/) zaman damgası sunucuları ile iletişim kuran CLI aracı ve Rust kütüphanesi. Kamu SM altyapısı üzerinden RFC 3161 uyumlu zaman damgası almak, bakiye sorgulamak, kimlik doğrulama başlığı üretmek ve zaman damgası doğrulamak için kullanılır.

Tamamen Rust dilinde yazılmıştır, Windows ve Unix platformlarında ek bir C kütüphanesi (OpenSSL vb.) gerektirmeden çalışır.

## Kurulum

### CLI (Komut Satırı)

Kaynak koddan derleyerek kurmak için:

```bash
git clone https://github.com/KilimcininKorOglu/kamusm-rs.git
cd kamusm-rs
cargo install --path .
```

Derleme sonrasında `kamusm_rs` CLI binary dosyası kurulacaktır.

### Kütüphane

Rust projenize `Cargo.toml` üzerinden bağımlılık olarak ekleyebilirsiniz:

```toml
[dependencies]
kamusm_rs = { git = "https://github.com/KilimcininKorOglu/kamusm-rs.git" }
```

## Hızlı Başlangıç

### CLI

İlk kullanımda KamuSM müşteri numarası ve parolanızı şifreli ayar dosyasına kaydedin:

```bash
kamusm_rs ayar-kaydet \
    --sunucu http://zd.kamusm.gov.tr \
    --musteri-no 123456 \
    --parola "sifre"
```

Ayar kaydedildikten sonra, parametre belirtmeden işlem yapabilirsiniz:

```bash
kamusm_rs gonder --dosya belge.pdf --dogrula
kamusm_rs bakiye
```

Başarılı sonuçta `belge_zd.der` dosyası oluşturulur ve Kamu SM kök sertifikaları ile otomatik olarak doğrulanır.

### Kütüphane Kullanımı

```rust
use kamusm_rs::{compute_file_digest, build_tsa_request, build_identity, send_timestamp_request, verify_timestamp};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Dosyanın özet değerini (digest) hesaplayın
    let digest = compute_file_digest("belge.pdf", "sha256")?;

    // 2. RFC 3161 istek DER paketini oluşturun
    let der = build_tsa_request(&digest, "sha256")?;

    // 3. Kamu SM kimlik doğrulama belirtecini üretin
    let identity = build_identity(123456, "sifre", &digest, 100)?;

    // 4. İsteği gönderin
    let (status, body) = send_timestamp_request("http://zd.kamusm.gov.tr", &identity, &der)?;

    println!("HTTP Durumu: {}", status);

    // 5. Yanıtı doğrulayın
    if kamusm_rs::is_valid_timestamp_response(&body) {
        let p7_data = kamusm_rs::extract_pkcs7(&body).unwrap_or(body);
        let result = verify_timestamp(&p7_data)?;
        println!("Doğrulama: {:?}", result);
    }
    
    Ok(())
}
```

---

## Komutlar

### gonder

Belirtilen dosya veya özet değeri için zaman damgası ister.

```bash
# Dosyadan zaman damgası alma ve otomatik doğrulama
kamusm_rs gonder --dosya DOSYA [--hash sha256] [--dogrula]

# Hex özetten zaman damgası alma
kamusm_rs gonder --ozet-hex HEX_DEGERI [--hash sha256]

# Ayar dosyası kullanmadan doğrudan parametrelerle çalıştırma
kamusm_rs gonder --sunucu URL --musteri-no ID --parola PAROLA --dosya DOSYA
```

`--dosya` kullanıldığında çıktı, girdi dosyasının yanına `{ad}_zd.der` olarak kaydedilir. `--ozet-hex` kullanıldığında ise çalışılan dizine `zd_{unix_epoch}.der` olarak kaydedilir.

### bakiye

Hesabınızdaki kalan zaman damgası bakiyesini sorgular.

```bash
kamusm_rs bakiye
```

Örnek Çıktı:
```
Yanıt durumu: 200
Kalan zaman damgası bakiyesi: 847
```

### dogrula

Daha önce alınmış bir zaman damgası dosyasını (`.der`) gömülü Kamu SM kök sertifikalarına (v4-v7) karşı doğrular.

```bash
kamusm_rs dogrula --dosya belge_zd.der
```

Örnek Çıktı:
```
Doğrulama başarılı
  İmzalayan: Kamu SM Zaman Damgasi Sunucusu S2
```

### kimlik

Sunucuya gönderilecek `identity` HTTP başlığını üretir (Hata ayıklama ve entegrasyon amacıyla kullanılır).

```bash
kamusm_rs kimlik --musteri-no ID --parola PAROLA --ozet-hex HEX_DEGERI
```

### ayar-kaydet

Bağlantı bilgilerini makine kimliğinizle şifreleyerek `~/.kamusm-rs.conf` dosyasına kaydeder.

```bash
kamusm_rs ayar-kaydet \
    --sunucu http://zd.kamusm.gov.tr \
    --musteri-no 123456 \
    --parola "sifre"
```

### ayar-goster

Kaydedilmiş ayarları görüntüler (parola maskelenmiş olarak gösterilir).

```bash
kamusm_rs ayar-goster
```

### sertifika-guncelle

TÜBİTAK Kamu SM Kök Sertifikaları deposundan güncel kök sertifikaları çeker ve yerel önbelleğe (`~/.kamusm-rs-certs.pem`) kaydeder.

```bash
# Otomatik kontrolden bağımsız olarak sertifikaları depodan zorla güncelle
kamusm_rs sertifika-guncelle --zorla
```

Zaman damgası gönderme (`gonder`) ve doğrulama (`dogrula`) komutları çalışırken, eğer yerel önbellek dosyası yoksa veya 7 günden eski ise sistem otomatik olarak depodan güncellemeleri arka planda çeker ve sessizce/uyarıyla günceller.

---


## JSON Çıktı Desteği

`kimlik`, `gonder`, `bakiye` ve `dogrula` komutları, otomasyonlar için `--json` parametresini destekler:

```bash
kamusm_rs bakiye --json
```

Çıktı:
```json
{
  "durum": 200,
  "bakiye": 847
}
```

---

## Kütüphane API Referansı

| Fonksiyon | Açıklama |
|---|---|
| `build_identity` | KamuSM `identity` HTTP başlığını üretir. |
| `build_tsa_request` | RFC 3161 TimeStampReq DER yapısı oluşturur. |
| `compute_file_digest` | Dosyanın SHA-1 veya SHA-256 özetini hesaplar. |
| `send_timestamp_request` | Zaman damgası isteğini gönderir. |
| `send_credit_request` | Bakiye sorgusunu gönderir. |
| `is_valid_timestamp_response` | Yanıtın geçerli bir zaman damgası içerip içermediğini kontrol eder. |
| `extract_pkcs7` | Yanıttan PKCS#7 SignedData yapısını çıkarır. |
| `extract_text_from_asn1` | ASN.1 yapısındaki metinsel hata mesajlarını ayıklar. |
| `parse_credits_from_body` | Yanıttan bakiye sayısını ayrıştırır. |
| `verify_timestamp` | PKCS#7 imzasını KamuSM kök sertifikalarıyla doğrular. |
| `kamusm_root_cas` | Gömülü ve önbellekteki KamuSM kök sertifika havuzunu döndürür. |
| `update_certs` | Kök sertifikaları TÜBİTAK deposundan indirip günceller. |
| `auto_update_certs` | Önbellek süresi dolmuşsa veya dosya yoksa sertifikaları otomatik günceller. |
| `certs_cache_path` | Sertifika önbellek dosyasının yolunu döndürür. |
| `save_config` | Konfigürasyonu şifreli kaydeder. |
| `load_config` | Şifreli konfigürasyonu okur ve çözer. |
| `config_path` | Konfigürasyon dosyasının yolunu döndürür. |


---

## Güvenlik ve Şifreleme Detayları

- **Config Şifreleme**: `~/.kamusm-rs.conf` dosyası AES-256-CBC ile şifrelenir. Şifreleme anahtarı yerel makine kimliğinden (hostname + kullanıcı adı) ve dosyaya özel rastgele 16 byte salt değerinden PBKDF2-SHA256 (100.000 iterasyon) ile türetilir. Dosya Unix sistemlerinde `0600` izinleriyle korunur.
- **Güvenli API**: Rust sürümü, harici OpenSSL yüklemesi gerektirmeyen saf Rust kriptografi araçları üzerine kurulmuştur, bu sayede sistem bağımlılıklarından kaynaklanan zafiyetler ve derleme sorunları en aza indirilmiştir.
