<div align="center">
<img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge"/>
<img src="https://img.shields.io/badge/AI-Ollama%20Local-orange?style=for-the-badge&logo=ollama"/>
<img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge"/>
🦅 AtmacaIOC Yerel
Siber Güvenlik Analistleri için Geliştirilmiş, Yerel Çalışan IOC Analiz ve AI Log Analizi Platformu
Tek dosya · Sıfır konfigürasyon · Lokalde çalışan · Dışarıya veri göndermeyen

</div>
💡 Neden Yaptım?
Bir SOC analisti olarak her gün onlarca IP, hash ve domain analiz etmek zorunda kalıyordum. Her seferinde farklı platformları — AbuseIPDB, VirusTotal, Shodan, MalwareBazaar — tek tek açıp manuel sorgulama yapmak hem zaman kaybettiriyor hem de özellikle hassas iç log verilerini kopyalayıp çevrimiçi araçlara yapıştırırken ciddi bir güvenlik riski oluşturuyordu.
AtmacaIOC bu sorunu çözmek için geliştirildi:

🔍 IOC sorgularını tek ekrandan, birden fazla servise paralel göndererek saniyeler içinde sonuç alıyorum
🤖 İç ağ loglarını, OT/ICS olaylarını, EDR alarmlarını ve firewall kayıtlarını tamamen lokalde çalışan bir AI modeline (Ollama) göndererek SOC bildirimine dönüştürüyorum — hiçbir veri dışarı çıkmıyor
📚 Günlük işlerde sürekli ihtiyaç duyduğum referans bilgileri (port listesi, MITRE ATT&CK teknikleri, Windows Event ID'leri, IR adımları, SOC komutları) tek uygulamada hızlıca erişilebilir hale getirdim


🖥️ Ekran Görüntüleri
<div align="center">
IOC Analizi — Paralel SorgulamaAI Log Analizi — LokaldeVirusTotal gauge grafikleri, zararlı motor listeleriFortigate, EDR, OT/ICS, Windows Event SOC bildirimi
</div>

✨ Özellikler
🔍 IOC Analizi — 9 Farklı Servis, Tek Ekran
Bir IP, hash veya domain girildiğinde desteklenen tüm servislere eş zamanlı sorgu gönderilir. Her sonuç ayrı bir sekmede zengin HTML çıktısıyla gösterilir.
ServisDesteklenen TiplerÜcretsiz APIAbuseIPDBIP✅ARINIP✅ (anahtar gerektirmez)ShodanIP, Domain✅GreyNoiseIP, Domain✅OTX AlienVaultIP, Domain, MD5, SHA1, SHA256✅VirusTotalIP, Domain, MD5, SHA1, SHA256✅MalwareBazaarMD5, SHA1, SHA256✅ (anahtar opsiyonel)HybridAnalysisMD5, SHA1, SHA256✅URLScan.ioDomain✅ (anahtar opsiyonel)
Her sorgu sonucu görsel olarak zenginleştirilmiş çıktıyla gelir:

📊 Dairesel gauge grafikler — AbuseIPDB güven skoru, OTX pulse sayısı, VT zararlı motor oranı
📊 Bar chart — VirusTotal motor dağılımı (zararlı / şüpheli / temiz / tespit yok)
🔴 Renkli kart tasarımı — zararlıysa kırmızı, temizse yeşil MalwareBazaar kartları
🦠 ClamAV, YARA, sandbox sonuçları — OTX analysis endpoint'inden
🔗 Detay linkleri — her servis için doğrudan sayfa bağlantısı

🤖 Yerel AI Log Analizi — Ollama Entegrasyonu
Loglarınız dışarıya hiç çıkmaz. Ollama aracılığıyla bilgisayarınızda çalışan bir LLM modeline gönderilir, tüm işlem yereldir.
Desteklenen log tipleri ve özelleştirilmiş promptlar:
Analiz TipiNeler Yapılır🔥 Fortigate / Firewall Trafiksrcip, dstip, DNAT, honeypot/gerçek sistem ayrımı, ülke bazlı risk🏭 OT/ICS/SCADAPLC iletişimi, error code çözümleme, Siemens S7comm, Modbus, MITRE ICS🦅 EDR (CrowdStrike/Defender/Sentinel)IOA analizi, davranışsal ML tespiti, karantina aksiyon raporu📋 Windows Event / AccelOps / SIEMSubject vs Target ayrımı, şifre sıfırlama, grup ekleme, brute force🔧 Firewall Policy ChangeAdd/Edit/Delete işlemi, hangi kullanıcı, hangi policy, hangi değişiklik🔍 Genel GüvenlikHer türlü log için temel analiz
Her analiz sonucu şu yapıda gelir:
📋 SOC BİLDİRİMİ   — kopyalanabilir, hazır bildirim metni
🎯 ÖZET            — 2-3 cümle teknik özet
📍 Kaynak ve Hedef — IP, MAC, hostname, DNAT detayları
📊 TESPİT EDİLEN VERİLER — tüm log alanları tabloda
⚠️ GÜVENLİK DEĞERLENDİRMESİ — DÜŞÜK / ORTA / YÜKSEK / KRİTİK
🔍 NE OLDU?        — adım adım teknik açıklama
🛡️ ÖNERİLEN AKSIYONLAR — somut müdahale adımları

Önerilen modeller: ollama pull qwen2.5:14b (en iyi) · ollama pull mistral (hızlı) · ollama pull llama3.1:8b

🛡️ SOC Analist Referans Kütüphanesi
Günlük analist iş akışında hızlı başvuru için kapsamlı bir referans sekmesi. Her bilgi aranabilir, tek tıkla kopyalanabilir.
<details>
<summary><b>🔌 Portlar (35+ kayıt)</b></summary>
Renkli risk sınıflandırmasıyla kritik portlar: FTP, SSH, Telnet, SMB (EternalBlue), RDP (BlueKeep), Metasploit reverse shell portları, OT/SCADA portları (Modbus 502, S7 102, DNP3 20000, BACnet 47808) ve daha fazlası.
</details>
<details>
<summary><b>📋 Windows Event ID'leri (33 kayıt) + Linux Log Kaynakları</b></summary>
4624/4625 oturum, 4688 proses, 4698 zamanlanmış görev, 4740 hesap kilitleme, 4768/4769 Kerberos (Kerberoasting), 4776 NTLM, 7045 yeni servis, PowerShell remote oturum ve daha fazlası. Linux tarafında auth.log, audit.log, .bash_history gibi kritik log kaynakları.
</details>
<details>
<summary><b>⌨️ SIEM/Platform Komutları</b></summary>
QRadar, Splunk, Wazuh, LogSign ve Genel SSH olmak üzere 5 platform için hazır komutlar. Servis durumu, canlı log takibi, disk kullanımı, agent listesi, cluster sağlığı gibi 60+ komut. Her biri tek tıkla panoya kopyalanabilir.
</details>
<details>
<summary><b>🪟 Windows CMD / PowerShell Komutları (30 kayıt)</b></summary>
netstat -ano, schtasks /query, wmic startup, cmdkey /list, Get-NetTCPConnection gibi forensic ve incident response komutları.
</details>
<details>
<summary><b>🎯 MITRE ATT&CK Teknikleri (24 teknik)</b></summary>
Initial Access'ten Impact'e kadar tüm taktikler: T1190, T1566, T1059, T1053, T1003 (Mimikatz), T1110 (Brute Force), T1486 (Ransomware) ve daha fazlası. ID'ye tıkla, kopyala.
</details>
<details>
<summary><b>🚨 Incident Response Adımları (NIST SP 800-61)</b></summary>
Hazırlık → Tespit & Analiz → Kontrol Altına Alma → Temizleme → Kurtarma → Lessons Learned. Her adım için somut kontrol listesi.
</details>
<details>
<summary><b>⚠️ Severity Seviyeleri, 🔎 Google Dorks, 🧰 SOC Araçları, 🧩 Chrome Eklentileri</b></summary>
P1-P5 öncelik seviyeleri · RFC 5424 Syslog · IOC hızlı kontrol checklist · 50+ Google Dork (config dosyaları, dizin listeleme, admin panel, GitHub sızıntısı) · Nmap, Volatility, Autopsy, Wireshark, Burp Suite gibi SOC araç kütüphanesi · Wappalyzer, Shodan, Netcraft gibi Chrome güvenlik eklentileri.
</details>
<details>
<summary><b>🔐 Password Generator</b></summary>
Kriptografik olarak güvenli parola üretici. Uzunluk, karakter seti (a-z, A-Z, 0-9, özel karakterler) seçilebilir.
</details>

🔐 API Anahtarları — Güvenli Saklama
API anahtarları hiçbir zaman kod içine, .env dosyasına veya harici bir sunucuya yazılmaz.
İşletim sisteminin kimlik bilgisi yöneticisinde saklanır:
PlatformDepolama YeriWindowsWindows Credential ManagermacOSKeychainLinuxSecret Service (GNOME Keyring / KWallet)
keyring kütüphanesi aracılığıyla sağlanan bu yöntem sayesinde anahtarlar sadece sizin kullanıcı oturumunuzda okunabilir. Uygulamayı kapatsanız bile, başka bir kullanıcı veya süreç anahtarlarınıza erişemez.

Uygulamayı ilk açtığınızda ⚙️ API Anahtarları butonuna tıklayın, anahtarlarınızı girin ve kaydedin. Bir daha girmeniz gerekmez.


🏗️ Uygulama Mimarisi
AtmacaIOC
│
├── IOC Motoru
│   ├── IOC Tespit (regex — IPv4, MD5, SHA1, SHA256, Domain)
│   ├── AnalysisWorker (QThread) — her servis ayrı thread'de çalışır
│   └── 9 Provider Metodu (AbuseIPDB, ARIN, Shodan, GreyNoise,
│                          OTX, VirusTotal, MalwareBazaar,
│                          HybridAnalysis, URLScan)
│
├── AI Log Analizi
│   ├── OllamaWorker (QThread) — bloklamayan async çalışma
│   ├── Prompt Motoru — 7 farklı log tipi için özelleştirilmiş prompt
│   │   ├── Fortigate / Firewall Trafik
│   │   ├── OT/ICS/SCADA
│   │   ├── EDR (CrowdStrike / Defender / SentinelOne)
│   │   ├── Windows Event / AccelOps / SIEM
│   │   ├── Firewall Policy Change
│   │   └── Genel (fallback)
│   └── Markdown → HTML renderer (_md_to_html)
│       ├── SOC BİLDİRİMİ → özel mavi kart
│       ├── Tablo → styled HTML table
│       ├── Tehdit seviyesi → renkli badge
│       └── Code block → syntax highlighted pre
│
├── SOC Referans Kütüphanesi
│   ├── 10 alt sekme (Portlar, Event ID, Komutlar, MITRE, IR, ...)
│   ├── Canlı arama filtresi
│   └── Tek tıkla kopyala
│
└── UI Katmanı (PyQt6)
    ├── QMainWindow + QTabWidget (3 ana sekme)
    ├── QThread tabanlı asenkron işlem (UI donmaz)
    ├── QTextBrowser — SVG base64 gauge grafik render
    └── keyring — OS native credential storage
Teknoloji Stack:
KatmanTeknolojiUI FrameworkPyQt6HTTP İsteklerirequestsCredential StoragekeyringAI EntegrasyonuOllama REST API (/api/chat)Grafik RenderSVG (base64, inline QTextBrowser)Çalışma ModuTek dosya, yerel

🚀 Kurulum
Gereksinimler
bashPython 3.10+
Bağımlılıkları Yükle
bashpip install PyQt6 requests keyring
Uygulamayı Çalıştır
bashpython atmacaioc_local.py
AI Log Analizi için Ollama Kurulumu (opsiyonel)
bash# 1. Ollama'yı kur: https://ollama.com

# 2. Model indir (birini seç)
ollama pull qwen2.5:14b    # Önerilen — en iyi analiz kalitesi (8GB VRAM)
ollama pull mistral         # Hızlı alternatif (4GB VRAM)
ollama pull llama3.1:8b    # Düşük kaynak alternatif

# 3. Uygulamada "Yerel AI Log" sekmesine geç, model adını gir, analiz et

📦 Bağımlılıklar
PaketKullanımZorunluPyQt6Arayüz✅requestsAPI istekleri✅keyringGüvenli anahtar saklama✅
