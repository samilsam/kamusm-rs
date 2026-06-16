const { invoke } = window.__TAURI__.core;

// State
let activeToken = null;
let activeCerts = [];
let sessionPin = "";
let currentSignFormat = "xml";
let currentVerifyFormat = "xml";

// DOM Elements
let tabButtons;
let tabPanes;
let selectTokens;
let btnRefreshTokens;
let inputPin;
let btnLogin;
let loginStatusContainer;

// Profile elements
let navProfile;
let navSign;
let cardManufacturer;
let cardModel;
let cardSerial;
let cardLabel;
let userFullname;
let userTckn;
let certTableBody;
let expiryWarningContainer;

// Sign elements
let inputSignFile;
let btnBrowseSign;
let btnSign;
let signStatusContainer;
let signFormatToggle;

// Verify elements
let verifyFormatToggle;
let verifyXmlBlock;
let verifyRawBlock;
let inputVerifyXmlFile;
let btnBrowseVerifyXml;
let inputVerifyRawOrig;
let btnBrowseVerifyRawOrig;
let inputVerifyRawSig;
let btnBrowseVerifyRawSig;
let inputVerifyRawCert;
let btnBrowseVerifyRawCert;
let btnVerify;
let verifyStatusContainer;

// Helpers
function showStatus(container, type, title, message) {
  let icon = "";
  if (type === "success") {
    icon = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>`;
  } else if (type === "error") {
    icon = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>`;
  } else if (type === "warning") {
    icon = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>`;
  } else {
    icon = `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>`;
  }

  container.innerHTML = `
    <div class="alert-box alert-${type}">
      ${icon}
      <div class="alert-box-content">
        <span class="alert-box-title">${title}</span>
        <span class="alert-box-desc">${message}</span>
      </div>
    </div>
  `;
}

function showLoader(container, text) {
  container.innerHTML = `
    <div class="loader-container">
      <div class="spinner"></div>
      <span class="loader-text">${text}</span>
    </div>
  `;
}

function clearStatus(container) {
  container.innerHTML = "";
}

// Format Date helpers
function formatDate(isoString) {
  if (!isoString) return "-";
  const date = new Date(isoString);
  return date.toLocaleString("tr-TR", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

// Navigation logic
function switchTab(tabId) {
  tabButtons.forEach(btn => {
    if (btn.getAttribute("data-tab") === tabId) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });

  tabPanes.forEach(pane => {
    if (pane.id === tabId) {
      pane.classList.add("active");
    } else {
      pane.classList.remove("active");
    }
  });
}

// E-Imza Tokens loading
async function refreshTokens() {
  selectTokens.innerHTML = `<option value="">Kartlar aranıyor...</option>`;
  try {
    const tokens = await invoke("list_tokens");
    selectTokens.innerHTML = "";
    
    if (tokens.length === 0) {
      selectTokens.innerHTML = `<option value="">Takılı E-İmza kartı bulunamadı</option>`;
      showStatus(loginStatusContainer, "warning", "Kart Bulunamadı", "Lütfen USB E-İmza kartınızın bilgisayara takılı olduğunu kontrol edin.");
      return;
    }
    
    tokens.forEach((token, idx) => {
      const opt = document.createElement("option");
      opt.value = token.slot_id;
      opt.textContent = `${token.etiket} (Slot: ${token.slot_id}, Model: ${token.model})`;
      if (idx === 0) {
        opt.selected = true;
      }
      selectTokens.appendChild(opt);
    });
    
    clearStatus(loginStatusContainer);
  } catch (err) {
    selectTokens.innerHTML = `<option value="">Kart tarama hatası</option>`;
    showStatus(loginStatusContainer, "error", "Sürücü / Kart Hatası", err);
  }
}

// Login & Read certs
async function handleLogin() {
  const pin = inputPin.value.trim();
  if (!pin) {
    showStatus(loginStatusContainer, "error", "Giriş Hatası", "Lütfen akıllı kart PIN kodunuzu girin.");
    return;
  }

  showLoader(loginStatusContainer, "E-İmza kartı sorgulanıyor, lütfen bekleyin...");
  
  try {
    const results = await invoke("login_with_eimza", { pin });
    
    if (results.length === 0 || !results[0].sertifikalar || results[0].sertifikalar.length === 0) {
      showStatus(loginStatusContainer, "error", "Sertifika Hatası", "Kart içinde okunabilir sertifika bulunamadı. PIN kodunun doğruluğundan emin olun.");
      return;
    }

    // Success login
    const result = results[0];
    activeToken = result.token;
    activeCerts = result.sertifikalar;
    sessionPin = pin; // Store for signing

    // Update Profile View
    cardManufacturer.textContent = activeToken.uretici || "-";
    cardModel.textContent = activeToken.model || "-";
    cardSerial.textContent = activeToken.seri_no || "-";
    cardLabel.textContent = activeToken.etiket || "-";

    const primaryCert = activeCerts[0];
    if (primaryCert) {
      userFullname.textContent = primaryCert.ad_soyad || primaryCert.konu || "-";
      userTckn.textContent = primaryCert.tc_no || "-";
    } else {
      userFullname.textContent = "-";
      userTckn.textContent = "-";
    }

    // Fill Certs table
    certTableBody.innerHTML = "";
    activeCerts.forEach(cert => {
      const row = document.createElement("tr");
      
      const cnTd = document.createElement("td");
      cnTd.textContent = cert.konu || "-";
      
      const caTd = document.createElement("td");
      caTd.textContent = cert.yayinlayan || "-";
      
      const beforeTd = document.createElement("td");
      beforeTd.textContent = formatDate(cert.baslangic_tarihi);
      
      const afterTd = document.createElement("td");
      afterTd.textContent = formatDate(cert.bitis_tarihi);
      
      const statusTd = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = cert.gecerli ? "badge badge-success" : "badge badge-error";
      badge.textContent = cert.gecerli ? "GEÇERLİ" : "SÜRESİ DOLMUŞ";
      statusTd.appendChild(badge);

      row.appendChild(cnTd);
      row.appendChild(caTd);
      row.appendChild(beforeTd);
      row.appendChild(afterTd);
      row.appendChild(statusTd);
      
      certTableBody.appendChild(row);
    });

    // Check certificate expiration soon warning (less than 30 days)
    const expiryDate = new Date(primaryCert.bitis_tarihi);
    const now = new Date();
    const diffTime = expiryDate - now;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    if (!primaryCert.gecerli || diffDays <= 0) {
      showStatus(expiryWarningContainer, "error", "Sertifika Süresi Dolmuş", `E-İmza sertifikanızın geçerlilik süresi dolmuştur. Lütfen sertifikanızı yenileyin.`);
    } else if (diffDays <= 30) {
      showStatus(expiryWarningContainer, "warning", "Sertifika Süresi Yakında Doluyor", `E-İmza sertifikanızın son kullanma tarihine sadece ${diffDays} gün kalmıştır.`);
    } else {
      showStatus(expiryWarningContainer, "success", "Sertifika Durumu Aktif", `E-İmza sertifikanız güvenle kullanılabilir. Son kullanma tarihine daha ${diffDays} gün bulunmaktadır.`);
    }

    // Enable navigation views
    navProfile.classList.remove("disabled");
    navSign.classList.remove("disabled");

    clearStatus(loginStatusContainer);
    inputPin.value = ""; // Clear input for safety
    
    // Switch to profile view
    switchTab("tab-profile");
    
  } catch (err) {
    showStatus(loginStatusContainer, "error", "Giriş Başarısız", err);
  }
}

// File Dialog Picker Helper
async function browseFile(title, inputEl) {
  try {
    const path = await invoke("select_file", { title });
    if (path) {
      inputEl.value = path;
    }
  } catch (err) {
    console.error("Dosya seçici hatası:", err);
  }
}

// File Sign Handler
async function handleSign() {
  const filePath = inputSignFile.value;
  if (!filePath) {
    showStatus(signStatusContainer, "error", "Hata", "Lütfen imzalanacak bir dosya seçin.");
    return;
  }

  showLoader(signStatusContainer, "Dosya e-imza ile imzalanıyor. Lütfen kartınızı çıkarmayın...");

  try {
    const isXml = currentSignFormat === "xml";
    const outPath = await invoke("sign_file", {
      filePath,
      isXml,
      pin: sessionPin,
      outputPath: null
    });

    showStatus(signStatusContainer, "success", "Dosya İmzalandı", `Dosya başarıyla imzalandı.<br/>Çıktı dosyası:<br/><strong>${outPath}</strong>`);
  } catch (err) {
    showStatus(signStatusContainer, "error", "İmzalama Hatası", err);
  }
}

// File Verification Handler
async function handleVerify() {
  const isXml = currentVerifyFormat === "xml";
  
  let filePath = "";
  let originalPath = null;
  let sigPath = null;
  let certPath = null;

  if (isXml) {
    filePath = inputVerifyXmlFile.value;
    if (!filePath) {
      showStatus(verifyStatusContainer, "error", "Hata", "Lütfen doğrulanacak imzalı XML dosyasını seçin.");
      return;
    }
  } else {
    originalPath = inputVerifyRawOrig.value;
    filePath = inputVerifyRawSig.value; // set file_path to the signature file
    certPath = inputVerifyRawCert.value;
    
    if (!originalPath || !filePath || !certPath) {
      showStatus(verifyStatusContainer, "error", "Eksik Dosya", "Detached doğrulaması için orijinal dosya, imza dosyası (.sig) ve sertifika dosyası seçilmelidir.");
      return;
    }
  }

  showLoader(verifyStatusContainer, "İmza doğrulanıyor...");

  try {
    const result = await invoke("verify_file", {
      filePath,
      isXml,
      originalPath,
      sigPath,
      certPath
    });

    if (result.gecerli) {
      let message = `İmza doğrulaması başarıyla tamamlandı. Dosya bütünlüğü korunmaktadır.<br/><br/>`;
      if (result.imzalayan) {
        message += `<strong>Sertifika Konusu:</strong> ${result.imzalayan}<br/>`;
      }
      if (result.ad_soyad) {
        message += `<strong>İmzalayan (Ad Soyad):</strong> ${result.ad_soyad}<br/>`;
      }
      if (result.tc_no) {
        message += `<strong>T.C. Kimlik No:</strong> ${result.tc_no}<br/>`;
      }
      if (result.sertifika_gecerlilik) {
        message += `<strong>Sertifika Son Kullanma Tarihi:</strong> ${formatDate(result.sertifika_gecerlilik)}<br/>`;
      }
      if (result.tarih) {
        message += `<strong>Doğrulama Zamanı:</strong> ${formatDate(result.tarih)}`;
      }
      showStatus(verifyStatusContainer, "success", "İmza Geçerli (BAŞARILI)", message);
    } else {
      let errorMsg = result.hata || "İmza veya sertifika geçersiz.";
      showStatus(verifyStatusContainer, "error", "İmza Geçersiz (BAŞARISIZ)", `Doğrulama başarısız.<br/><strong>Hata Nedeni:</strong> ${errorMsg}`);
    }
  } catch (err) {
    showStatus(verifyStatusContainer, "error", "Doğrulama Hatası", err);
  }
}

// DOM Setup
window.addEventListener("DOMContentLoaded", () => {
  // Elements binding
  tabButtons = document.querySelectorAll(".nav-button");
  tabPanes = document.querySelectorAll(".tab-pane");
  selectTokens = document.querySelector("#select-tokens");
  btnRefreshTokens = document.querySelector("#btn-refresh-tokens");
  inputPin = document.querySelector("#input-pin");
  btnLogin = document.querySelector("#btn-login");
  loginStatusContainer = document.querySelector("#login-status-container");

  navProfile = document.querySelector("#nav-profile");
  navSign = document.querySelector("#nav-sign");
  cardManufacturer = document.querySelector("#card-manufacturer");
  cardModel = document.querySelector("#card-model");
  cardSerial = document.querySelector("#card-serial");
  cardLabel = document.querySelector("#card-label");
  userFullname = document.querySelector("#user-fullname");
  userTckn = document.querySelector("#user-tckn");
  certTableBody = document.querySelector("#cert-table-body");
  expiryWarningContainer = document.querySelector("#expiry-warning-container");

  inputSignFile = document.querySelector("#input-sign-file");
  btnBrowseSign = document.querySelector("#btn-browse-sign");
  btnSign = document.querySelector("#btn-sign");
  signStatusContainer = document.querySelector("#sign-status-container");
  signFormatToggle = document.querySelector("#sign-format-toggle");

  verifyFormatToggle = document.querySelector("#verify-format-toggle");
  verifyXmlBlock = document.querySelector("#verify-xml-block");
  verifyRawBlock = document.querySelector("#verify-raw-block");
  inputVerifyXmlFile = document.querySelector("#input-verify-xml-file");
  btnBrowseVerifyXml = document.querySelector("#btn-browse-verify-xml");
  inputVerifyRawOrig = document.querySelector("#input-verify-raw-orig");
  btnBrowseVerifyRawOrig = document.querySelector("#btn-browse-verify-raw-orig");
  inputVerifyRawSig = document.querySelector("#input-verify-raw-sig");
  btnBrowseVerifyRawSig = document.querySelector("#btn-browse-verify-raw-sig");
  inputVerifyRawCert = document.querySelector("#input-verify-raw-cert");
  btnBrowseVerifyRawCert = document.querySelector("#btn-browse-verify-raw-cert");
  btnVerify = document.querySelector("#btn-verify");
  verifyStatusContainer = document.querySelector("#verify-status-container");

  // Init card scanning
  refreshTokens();

  // Tab switching click handlers
  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const tabId = btn.getAttribute("data-tab");
      switchTab(tabId);
    });
  });

  // Refresh tokens click
  btnRefreshTokens.addEventListener("click", refreshTokens);

  // Login click
  btnLogin.addEventListener("click", handleLogin);

  // Sign File Picker
  btnBrowseSign.addEventListener("click", () => {
    browseFile("İmzalanacak Dosyayı Seçin", inputSignFile);
  });

  // Sign Format Toggle
  signFormatToggle.querySelectorAll(".toggle-option").forEach(btn => {
    btn.addEventListener("click", () => {
      signFormatToggle.querySelectorAll(".toggle-option").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentSignFormat = btn.getAttribute("data-value");
      clearStatus(signStatusContainer);
    });
  });

  // Sign Button Click
  btnSign.addEventListener("click", handleSign);

  // Verify Format Toggle
  verifyFormatToggle.querySelectorAll(".toggle-option").forEach(btn => {
    btn.addEventListener("click", () => {
      verifyFormatToggle.querySelectorAll(".toggle-option").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentVerifyFormat = btn.getAttribute("data-value");
      clearStatus(verifyStatusContainer);

      if (currentVerifyFormat === "xml") {
        verifyXmlBlock.style.display = "block";
        verifyRawBlock.style.display = "none";
      } else {
        verifyXmlBlock.style.display = "none";
        verifyRawBlock.style.display = "block";
      }
    });
  });

  // Verify File Pickers
  btnBrowseVerifyXml.addEventListener("click", () => {
    browseFile("İmzalı XML Dosyasını Seçin", inputVerifyXmlFile);
  });

  btnBrowseVerifyRawOrig.addEventListener("click", () => {
    browseFile("Orijinal Dosyayı Seçin", inputVerifyRawOrig);
  });

  btnBrowseVerifyRawSig.addEventListener("click", () => {
    browseFile("İmza Dosyasını (.sig) Seçin", inputVerifyRawSig);
  });

  btnBrowseVerifyRawCert.addEventListener("click", () => {
    browseFile("Sertifika Dosyasını (.pem/.der/.crt) Seçin", inputVerifyRawCert);
  });

  // Verify Button Click
  btnVerify.addEventListener("click", handleVerify);
});
