# kamusm-rs

TÜBİTAK BİLGEM tarafından işletilen [Kamu SM](https://kamusm.bilgem.tubitak.gov.tr/) zaman damgası sunucuları ile iletişim kuran CLI aracı ve Rust kütüphanesi. Kamu SM altyapısı üzerinden RFC 3161 uyumlu zaman damgası almak, bakiye sorgulamak, kimlik doğrulama başlığı üretmek, zaman damgası doğrulamak ve USB E-İmza (akıllı kart) ile dijital imza işlemleri gerçekleştirmek için kullanılır.

Tamamen Rust dilinde yazılmıştır, Windows, Linux ve macOS platformlarında harici bir C kütüphanesi (OpenSSL vb.) gerektirmeden çalışır.

## Kurulum

### CLI (Komut Satırı)

Kaynak koddan derleyerek kurmak için:

```bash
git clone https://github.com/zinderud/kamusm-rs.git
cd kamusm-rs
cargo install --path .
```

Derleme sonrasında `kamusm_rs` CLI aracı komut satırınıza kurulacaktır.

### Kütüphane

Rust projenize `Cargo.toml` üzerinden bağımlılık olarak ekleyebilirsiniz:

```toml
[dependencies]
kamusm_rs = { git = "https://github.com/zinderud/kamusm-rs.git" }
```

---

## Hızlı Başlangıç (Zaman Damgası)

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

---

## USB E-İmza (Akıllı Kart) Kullanımı ve İşlemleri

`kamusm-rs`, USB portuna bağlı akıllı kart ve token sürücülerini (TÜBİTAK AKİS ve uyumlu PKCS#11 sürücüleri) otomatik olarak tarayarak platform bağımsız imzalama desteği sunar. Aşağıda e-imza işlemlerinin tüm detayları, kurulum adımları ve kütüphane entegrasyonu açıklanmıştır.

### 1. Ön Hazırlık ve Sürücü Kurulumu
E-İmza işlemlerini gerçekleştirebilmek için bilgisayarınızda e-imza sürücüsünün (genellikle TÜBİTAK KamuSM tarafından sağlanan **AKİS**) kurulu olması gerekir:
- **Windows**: KamuSM veya e-imza sağlayıcınızdan AKİS Yönetici Paketini yükleyin. Kurulum sonucunda `akisp11.dll` dosyası `C:\Windows\System32\` veya `C:\Windows\SysWOW64\` dizininde bulunmalıdır.
- **Linux (Ubuntu)**: AKİS paketini kurduğunuzda sürücü genellikle `/usr/lib/libakisp11.so` veya `/usr/local/lib/libakisp11.so` yollarına yerleşir.
- **macOS**: Sürücü dosyası `/usr/local/lib/libakisp11.dylib` veya `/Library/Java/Extensions/libakisp11.dylib` yollarında olmalıdır.

*Varsayılan olarak `kamusm-rs` bu yolları otomatik olarak tarar. Sürücünüz farklı bir dizindeyse, komutlara `--modul <sürücü_yolu>` parametresini geçebilir veya `KAMUSM_PKCS11_MODULE` çevre değişkenini ayarlayabilirsiniz.*

### 2. Kart Algılama ve Sertifika Sorgulama (`eimza-bilgi`)
USB e-imza kartının bilgisayar tarafından tanınıp tanınmadığını ve içerisindeki sertifikanın geçerlilik durumunu kontrol etmek için kullanılır:
```bash
kamusm_rs eimza-bilgi
```
- **PIN'siz Çalıştırma**: Komutu doğrudan çalıştırıp PIN girmeden geçerseniz, sadece takılı kart ve okuyucu bilgileri listelenir.
- **PIN ile Çalıştırma**: PIN kodunuzu girerek (veya `--pin 12345` parametresiyle geçerek) akıllı karta oturum açabilir ve içindeki imza sertifikalarının geçerlilik tarihi, yayıncı ve konu (CN) bilgilerini listeleyebilirsiniz.
- **Toleranslı Sürücü Bağlantısı**: TÜBİTAK AKİS kartlarının sürüm bilgilerini sayısal olmayan karakterlerle dönerek `cryptoki` kütüphanesini kırma (Internal `ParseIntError`) hatası giderilmiştir. Sürücüden bu tür hatalı bilgiler alınsa bile kartlar başarıyla tespit edilecektir.

### 3. Dijital İmzalama İşlemleri (`eimza-imzala`)
`eimza-imzala` komutu, akıllı kartınızdaki özel anahtarı (private key) ve sertifikayı kullanarak iki farklı formatta imzalama yapabilir:

#### A. Ham (Raw) Veri İmzalama
Bir belgenin veya dosyanın (PDF, TXT, resim vb.) ham kriptografik imzasını üretmek ve doğrulamak için kullanılır:
```bash
kamusm_rs eimza-imzala --dosya belge.pdf --cikis imza.sig
```
**Çalışma Mekanizması:**
1. Dosya içeriği ikili (binary) olarak okunur.
2. Dosyanın SHA-256 özeti (digest) hesaplanır.
3. Akıllı karttaki imza anahtarı otomatik olarak tespit edilir ve bu hash değeri kartın içinde imzalanır (kart modeline göre ECDSA veya RSA algoritmaları otomatik olarak denenir).
4. Çıkan imza baytları `.sig` uzantısıyla diske kaydedilir.

#### B. XML Enveloped Dijital İmzalama (XML-DSig)
GİB e-Arşiv raporları ve resmi kurumlara gönderilen standart XML belgelerini imzalamak için kullanılır. Bu imza türü W3C XML-DSig standardına tam uyumludur:
```bash
kamusm_rs eimza-imzala --dosya earsiv.xml --xml --cikis imzali_earsiv.xml
```
**Çalışma Mekanizması (Adım Adım):**
1. Orijinal XML içeriği okunur ve XML standartlarına uygun şekilde kanonikalize (C14N) edilir.
2. Kanonikal XML'in SHA-256 özeti hesaplanarak Base64 formatına çevrilir.
3. Standart bir `<ds:SignedInfo>` bloğu oluşturulur ve içerisine az önce hesaplanan digest değeri yerleştirilir.
4. Bu `<ds:SignedInfo>` bloğu tekrar C14N ile kanonikalize edilir ve akıllı kartın içerisindeki özel anahtar ile imzalanır.
5. İmza sonucu elde edilen baytlar Base64 formatında `<ds:SignatureValue>` içine yazılır.
6. Kartın genel anahtar sertifikası (public certificate) DER formatından Base64'e kodlanarak `<ds:KeyInfo>` içerisine yerleştirilir.
7. Oluşturulan tüm `<ds:Signature>` bloğu, orijinal XML belgesinin root elementinin (en dıştaki etiket) **en son çocuğu** olarak XML ağacına eklenir ve dosya kaydedilir.

---

### 4. Kütüphane (Programmatik) Entegrasyon Örneği

E-İmza işlemlerini kendi Rust uygulamanızda kütüphane olarak kullanmak için örnek kod:

```rust
use std::fs;
use kamusm_rs::{detect_pkcs11_module, sign_eimza_data, sign_eimza_xml};

fn main() -> Result<(), String> {
    // 1. Sürücü yolunu tespit edin
    let module_path = detect_pkcs11_module()
        .ok_or("AKİS PKCS#11 sürücüsü bulunamadı.")?;

    let pin = "123456"; // Akıllı kart şifreniz
    let data_to_sign = b"Merhaba Dunya!";

    // 2. Ham veri imzalama
    let (sig_bytes, mechanism) = sign_eimza_data(&module_path, Some(pin), data_to_sign)?;
    println!("Ham İmza Boyutu: {}, Mekanizma: {}", sig_bytes.len(), mechanism);

    // 3. XML imzalama
    let xml_content = b"<belge><veri>Test</veri></belge>";
    let signed_xml = sign_eimza_xml(&module_path, Some(pin), xml_content)?;
    println!("İmzalanmış XML:\n{}", signed_xml);

    Ok(())
}
```

---

## Tüm CLI Komutları

### `gonder`
Belirtilen dosya veya özet değeri için zaman damgası ister.
```bash
kamusm_rs gonder --dosya DOSYA [--hash sha256] [--dogrula]
```

### `bakiye`
Zaman damgası hesabınızdaki kalan bakiyeyi sorgular.
```bash
kamusm_rs bakiye
```

### `dogrula`
Daha önce alınmış zaman damgası dosyasını (`.der`) Kamu SM kök sertifikalarıyla doğrular.
```bash
kamusm_rs dogrula --dosya belge_zd.der
```

### `ayar-kaydet`
Zaman damgası sunucu bilgilerini şifreli olarak yerel ayar dosyasına (`~/.kamusm-rs.conf`) kaydeder.
```bash
kamusm_rs ayar-kaydet --sunucu URL --musteri-no ID --parola PAROLA
```

### `sertifika-guncelle`
TÜBİTAK Kamu SM Kök Sertifikaları deposundan güncel sertifikaları çekerek önbelleği günceller.
```bash
kamusm_rs sertifika-guncelle --zorla
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
| `verify_timestamp` | PKCS#7 imzasını KamuSM kök sertifikalarıyla doğrular. |
| `detect_pkcs11_module` | İşletim sistemine göre PKCS#11 modül (akisp11) yolunu tespit eder. |
| `list_eimza_tokens` | Takılı olan USB token/akıllı kartların slot ve etiket bilgilerini listeler. |
| `read_eimza_certs` | Karttaki sertifikaları ve geçerlilik tarihlerini ayrıştırıp okur. |
| `sign_eimza_data` | Verilen ham veriyi karttaki özel anahtar ile imzalar. |
| `sign_eimza_xml` | XML belgesini karttaki anahtar ve sertifika ile enveloped XML-DSig standardında imzalar. |
| `save_config` | Konfigürasyonu şifreli kaydeder. |
| `load_config` | Şifreli konfigürasyonu okur ve çözer. |

---

## Güvenlik ve Şifreleme Detayları

- **Şifreli Ayar Dosyası**: `~/.kamusm-rs.conf` dosyası AES-256-CBC ile şifrelenir. Şifreleme anahtarı yerel makine kimliğinden (hostname + kullanıcı adı) PBKDF2-SHA256 (100.000 iterasyon) ile türetilir. Dosya Unix sistemlerinde `0600` izinleriyle korunur.
- **PIN Güvenliği**: Akıllı kart PIN kodları hiçbir şekilde saklanmaz, diske yazılmaz ve terminal üzerinden güvenli bellek alanlarında (`secrecy` kasası) geçici olarak tutulur.
- **Harici Bağımlılık Yok**: Harici C-kütüphanelerine (OpenSSL veya libxml2 gibi) bağımlılık olmadan saf Rust kriptografi araçları ve XML araçları üzerine kurulmuştur, bu sayede taşınabilirlik en üst düzeydedir.
