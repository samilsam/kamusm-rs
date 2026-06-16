# Kamu SM E-İmza Demo Uygulaması (Tauri v2)

Bu proje, `kamusm-rs` Rust kütüphanesini kullanarak akıllı kart (e-imza) entegrasyonu sağlayan modern, hızlı ve güvenli bir masaüstü demo uygulamasıdır. **Tauri v2** ile Vanilla HTML, CSS ve JavaScript mimarisi üzerinde inşa edilmiştir.

---

## 🚀 Ne Yaptık? (Uygulanan Özellikler)

Uygulama, e-imza kartınız ile etkileşime geçebilmeniz, sertifikalarınızı sorgulayabilmeniz ve güvenli imzalama/doğrulama işlemleri yapabilmeniz için aşağıdaki yeteneklerle donatılmıştır:

1. **Modern Tasarım (Glassmorphism)**: 
   - Outfit yazı tipi, koyu tema, göz yormayan renk paleti, yarı saydam cam efektleri ve yumuşak mikro-animasyonlar içeren premium bir arayüz tasarlanmıştır.

2. **Akıllı Kart Algılama ve Bağlantı**:
   - KamuSM/TÜBİTAK akıllı kart okuyucularını ve takılı donanımları (`akisp11` sürücüsü aracılığıyla) otomatik olarak algılar ve listeler.

3. **PIN Girişi ve Kişisel Bilgiler**:
   - Akıllı kart şifreniz (PIN) ile giriş yaparak kart içerisindeki imza sertifikalarını okur.
   - Sertifika sahibinin **Ad Soyad** ve **T.C. Kimlik Numarası** bilgilerini doğrudan sertifikadan ayrıştırarak profil ekranında görüntüler.
   - Sertifikanın geçerlilik tarihini (başlangıç/bitiş) listeler ve son kullanma tarihine kalan gün sayısına göre dinamik uyarı kutuları (Yeşil/Sarı/Kırmızı) üretir.

4. **Güvenli Dosya İmzalama**:
   - İki farklı imza formatını destekler:
     - **XML Enveloped (XML-DSig)**: Seçtiğiniz XML dosyasının içine gömülü (enveloped) imza ekler. Çıktı dosyasını `{dosya_adi}_imzali.xml` olarak kaydeder.
     - **Detached / Raw Signature (.sig)**: Seçilen herhangi bir dosyanın ham RSA/ECDSA imza özetini çıkartır ve `{dosya_adi}.sig` olarak kaydeder.

5. **Akıllı İmza Doğrulama (Encoding Desteğiyle)**:
   - İmzalı XML veya Detached (.sig) dosyalarının geçerliliğini denetler.
   - **Gelişmiş Kodlama Tespiti**: XML dosyaları okunurken karşılaşılan UTF-8 BOM, UTF-16 LE/BE ve Türkçe karakterlerden kaynaklanan ISO-8859-9 (Latin-5) kodlama uyumsuzluklarını otomatik olarak tespit eder, UTF-8'e dönüştürür ve hatasız ayrıştırır.
   - İmza geçerli ise imzalayan kişinin **Ad Soyad**, **T.C. Kimlik No**, **Sertifika Son Kullanma Tarihi** ve **Doğrulama Zamanını** raporlar.

---

## 🛠️ Sistem Gereksinimleri

Uygulamanın akıllı kart okuyucunuzla haberleşebilmesi için sisteminizde ilgili sürücülerin yüklü olması gerekir:

- **Windows**: [AKİS (Akıllı Kart İşletim Sistemi) Sürücüleri](https://akis.tubitak.gov.tr/) bilgisayarınızda yüklü olmalıdır. (Uygulama varsayılan olarak `C:\Windows\System32\akisp11.dll` yolundaki kütüphaneyi arar).
- **macOS / Linux**: İlgili işletim sistemlerine ait AKİS sürücü paketleri kurulmalıdır (kütüphane `/usr/local/lib/libakisp11.dylib` veya `/usr/lib/libakisp11.so` yollarını tarar).
- **Node.js**: Arayüz bağımlılıklarını kurmak için Node.js (v18+) gereklidir.
- **Rust**: Tauri backend derlemesi için bilgisayarınızda Rust kurulu olmalıdır.

---

## ⚙️ Kurulum ve Çalıştırma

Projeyi yerel ortamınızda çalıştırmak için aşağıdaki adımları sırasıyla uygulayın:

### 1. Bağımlılıkları Yükleyin
`demo` dizini içerisinde terminali açarak Node.js paketlerini yükleyin:
```bash
npm install
```

### 2. Geliştirme Sunucusunu Başlatın
Tauri geliştirme modunu başlatmak için aşağıdaki komutu çalıştırın. Bu komut hem frontend tarafını derleyecek hem de yerel masaüstü penceresini açacaktır:
```bash
npm run tauri dev
```

### 3. Prodüksiyon Sürümünü Paketleyin (İsteğe Bağlı)
Uygulamayı tek başına çalışabilir bir masaüstü uygulaması (.exe / .dmg / .deb) olarak paketlemek için:
```bash
npm run tauri build
```

---

## 📖 Kullanım Rehberi

### Adım 1: Giriş Yap
1. Akıllı kart okuyucunuzu bilgisayara takın ve içine e-imza kartınızı yerleştirin.
2. Giriş Yap ekranındaki yenileme butonuna basarak kartınızı bulun.
3. Akıllı kart PIN şifrenizi girerek **Giriş Yap** butonuna tıklayın.

### Adım 2: Bilgilerinizi İnceleyin
- Giriş yapıldıktan sonra **Kullanıcı Bilgileri** sekmesi aktifleşecektir.
- Bu sekmede kart donanım bilgilerinizle birlikte adınız, soyadınız, T.C. kimlik numaranız ve sertifikanızın bitiş tarihleri gösterilir.

### Adım 3: Dosya İmzalama
- **Dosya İmzala** sekmesine gidin.
- İmza formatınızı seçin (XML veya Detached).
- İmzalamak istediğiniz dosyayı seçerek **Dosyayı Güvenli Olarak İmzala** butonuna tıklayın. Çıktı dosyası orijinal dosyanın bulunduğu dizine kaydedilecektir.

### Adım 4: İmza Doğrulama
- **İmza Doğrula** sekmesine gidin.
- **XML** seçtiyseniz: Sadece imzalanmış XML dosyasını seçin.
- **Detached** seçtiyseniz: Orijinal imzasız dosyayı, oluşturulan `.sig` imza dosyasını ve imzalayanın `.pem/.der` formatındaki sertifikasını seçin.
- **Doğrula** butonuna bastığınızda imza geçerliliği, dosya bütünlüğü ve sertifika sahibi detayları ekranda yeşil veya kırmızı kutu halinde listelenecektir.
