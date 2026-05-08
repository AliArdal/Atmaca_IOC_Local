🦅 AtmacaIOC — Yerel SOC Analiz Platformu

https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white
https://img.shields.io/badge/License-MIT-green?style=flat-square
https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square
https://img.shields.io/badge/AI-Ollama%20Local-orange?style=flat-square
https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square

Siber güvenlik analistleri için geliştirilmiş, modern ve kapsamlı IOC analiz ve AI log analizi platformu.
Tek dosya · Sıfır konfigürasyon · Lokalde çalışan · Dışarıya veri göndermeyen

💡 Neden Yaptım?
Bir SOC analisti olarak her gün onlarca IP, hash ve domain analiz etmek zorunda kalıyordum. Her seferinde farklı platformları — AbuseIPDB, VirusTotal, Shodan, MalwareBazaar — tek tek açıp manuel sorgulama yapmak zaman kaybettiriyordu. Üstelik hassas iç log verilerini kopyalayıp çevrimiçi araçlara yapıştırmak ciddi bir güvenlik riski oluşturuyordu.
AtmacaIOC bu sorunu çözmek için geliştirildi:

IOC sorgularını tek ekrandan, birden fazla servise paralel göndererek saniyeler içinde sonuç alıyorum
İç ağ loglarını, OT/ICS olaylarını ve EDR alarmlarını tamamen lokalde çalışan AI modeline (Ollama) göndererek hazır SOC bildirimine dönüştürüyorum — hiçbir veri dışarı çıkmıyor
Günlük analist iş akışında sürekli ihtiyaç duyduğum referans bilgileri (port listesi, MITRE ATT&CK teknikleri, Windows Event ID'leri, IR adımları, SOC komutları) tek uygulamada hızlıca erişilebilir hale getirdim

✨ Özellikler
🔍 IOC Analizi — 9 Farklı Servis, Tek Ekran
Bir IP, hash veya domain girildiğinde desteklenen tüm servislere eş zamanlı sorgu gönderilir. Her sonuç ayrı sekmede zengin HTML çıktısıyla gösterilir.
ServisDesteklenen TiplerÜcretsiz APIAbuseIPDBIP✅ARINIP✅ anahtar gerektirmezShodanIP, Domain✅GreyNoiseIP, Domain✅OTX AlienVaultIP, Domain, MD5, SHA1, SHA256✅VirusTotalIP, Domain, MD5, SHA1, SHA256✅MalwareBazaarMD5, SHA1, SHA256✅ anahtar opsiyonelHybridAnalysisMD5, SHA1, SHA256✅URLScan.ioDomain✅ anahtar opsiyonel
Her sorgu sonucu görsel olarak zenginleştirilmiş çıktıyla gelir:

Dairesel gauge grafikler — AbuseIPDB güven skoru, OTX pulse sayısı, VT zararlı motor oranı
Bar chart — VirusTotal motor dağılımı (zararlı / şüpheli / temiz / tespit yok)
Renkli kart tasarımı — zararlıysa kırmızı, temizse yeşil MalwareBazaar kartları
ClamAV, YARA ve sandbox sonuçları — OTX analysis endpoint'inden otomatik çekilir
Detay linkleri — her servis için doğrudan sayfa bağlantısı


🤖 Yerel AI Log Analizi — Ollama Entegrasyonu
Loglarınız dışarıya hiç çıkmaz. Ollama aracılığıyla bilgisayarınızda çalışan LLM modeline gönderilir, tüm işlem yereldir.
Desteklenen log tipleri ve özelleştirilmiş promptlar:
Analiz TipiNe Yapar🔥 Fortigate / Firewall Trafiksrcip, dstip, DNAT, honeypot/gerçek sistem ayrımı, ülke bazlı risk🏭 OT/ICS/SCADAPLC iletişimi, error code çözümleme, Siemens S7comm, MITRE ICS🦅 EDR (CrowdStrike/Defender/Sentinel)IOA analizi, davranışsal ML tespiti, karantina aksiyon raporu📋 Windows Event / AccelOps / SIEMSubject vs Target ayrımı, şifre sıfırlama, grup ekleme, brute force🔧 Firewall Policy ChangeAdd/Edit/Delete işlemi, kullanıcı, policy ID, değişen alanlar🔍 Genel GüvenlikHer türlü log için temel analiz

📋 SOC BİLDİRİMİ       — kopyalanabilir, hazır bildirim metni
🎯 ÖZET                — 2-3 cümle teknik özet
📍 Kaynak ve Hedef     — IP, MAC, hostname, DNAT detayları
📊 TESPİT EDİLEN VERİLER  — tüm log alanları tabloda
⚠️  GÜVENLİK DEĞERLENDİRMESİ — DÜŞÜK / ORTA / YÜKSEK / KRİTİK
🔍 NE OLDU?            — adım adım teknik açıklama
🛡️  ÖNERİLEN AKSIYONLAR — somut müdahale adımları

Önerilen modeller:

ollama pull qwen2.5:14b — en iyi analiz kalitesi (8GB VRAM)
ollama pull mistral — hızlı alternatif (4GB VRAM)
ollama pull llama3.1:8b — düşük kaynak alternatif

🛡️ SOC Analist Referans Kütüphanesi
Günlük iş akışında hızlı başvuru için kapsamlı referans sekmesi. Her bilgi aranabilir ve tek tıkla kopyalanabilir.
<details>
<summary><b>🔌 Portlar (35+ kayıt)</b></summary>
Renkli risk sınıflandırmasıyla kritik portlar: FTP, SSH, Telnet, SMB (EternalBlue), RDP (BlueKeep), Metasploit reverse shell portları, OT/SCADA portları (Modbus 502, S7 102, DNP3 20000, BACnet 47808) ve daha fazlası.
</details>
<details>
<summary><b>📋 Windows Event ID'leri (33 kayıt) + Linux Log Kaynakları</b></summary>
4624/4625 oturum, 4688 proses oluşturma, 4698 zamanlanmış görev, 4740 hesap kilitleme, 4768/4769 Kerberos (Kerberoasting tespiti), 4776 NTLM, 7045 yeni servis kurulumu ve daha fazlası. Linux tarafında auth.log, audit.log, .bash_history gibi kritik log kaynakları.
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
Initial Access'ten Impact'e tüm taktikler: T1190, T1566 (Phishing), T1059, T1003 (Mimikatz/LSASS), T1110 (Brute Force), T1486 (Ransomware şifreleme), T1490 (Shadow Copy silme) ve daha fazlası. Teknik ID'ye tıkla, kopyala.
</details>
<details>
<summary><b>🚨 Incident Response Adımları (NIST SP 800-61)</b></summary>
Hazırlık → Tespit ve Analiz → Kontrol Altına Alma → Temizleme → Kurtarma → Lessons Learned. Her adım için somut kontrol listesi.
</details>
<details>
<summary><b>⚠️ Severity Seviyeleri, 🔎 Google Dorks, 🧰 SOC Araçları, 🧩 Chrome Eklentileri</b></summary>

P1-P5 öncelik seviyeleri ve RFC 5424 Syslog seviyeleri
IOC hızlı kontrol checklist
50+ Google Dork: config dosyaları, dizin listeleme, admin panel, GitHub sızıntısı, subdomain keşfi
Nmap, Volatility, Autopsy, Wireshark, Burp Suite, Ghidra gibi SOC araç kütüphanesi
Wappalyzer, Shodan, Netcraft, uBlock Origin gibi Chrome güvenlik eklentileri
Kriptografik parola üretici (Password Generator)

</details>

🔐 API Anahtarları — Güvenli Saklama
API anahtarları hiçbir zaman kod içine, .env dosyasına veya harici bir sunucuya yazılmaz. İşletim sisteminin güvenli kimlik bilgisi yöneticisinde saklanır:
PlatformDepolama YeriWindowsWindows Credential ManagermacOSKeychainLinuxSecret Service (GNOME Keyring / KWallet)
keyring kütüphanesi aracılığıyla sağlanan bu yöntem sayesinde anahtarlar yalnızca sizin kullanıcı oturumunuzda okunabilir. Başka kullanıcı veya süreçler anahtarlarınıza erişemez.

Uygulamayı ilk açtığınızda ⚙️ API Anahtarları butonuna tıklayın, anahtarlarınızı girin ve kaydedin. Bir daha girmeniz gerekmez.


🏗️ Uygulama Mimarisi
AtmacaIOC
│
├── IOC Motoru
│   ├── IOC Tespit — regex (IPv4, MD5, SHA1, SHA256, Domain)
│   ├── AnalysisWorker (QThread) — her servis ayrı thread'de çalışır
│   └── 9 Provider: AbuseIPDB · ARIN · Shodan · GreyNoise · OTX
│                   VirusTotal · MalwareBazaar · HybridAnalysis · URLScan
│
├── AI Log Analizi
│   ├── OllamaWorker (QThread) — bloklamayan asenkron çalışma
│   ├── Prompt Motoru — 7 log tipi için özelleştirilmiş prompt
│   │   ├── Fortigate / Firewall Trafik
│   │   ├── OT/ICS/SCADA
│   │   ├── EDR (CrowdStrike / Defender / SentinelOne)
│   │   ├── Windows Event / AccelOps / SIEM
│   │   ├── Firewall Policy Change
│   │   └── Genel (fallback)
│   └── Markdown → HTML renderer
│       ├── SOC BİLDİRİMİ  →  özel mavi kart
│       ├── Tablo           →  styled HTML table
│       ├── Tehdit seviyesi →  renkli badge
│       └── Code block      →  syntax highlighted pre
│
├── SOC Referans Kütüphanesi
│   ├── 10 alt sekme (Portlar, Event ID, Komutlar, MITRE, IR ...)
│   ├── Canlı arama filtresi
│   └── Tek tıkla kopyala
│
└── UI Katmanı (PyQt6)
    ├── QMainWindow + QTabWidget — 3 ana sekme
    ├── QThread tabanlı asenkron işlem — UI donmaz
    ├── QTextBrowser — SVG base64 gauge grafik render
    └── keyring — OS native credential storage
KatmanTeknolojiUI FrameworkPyQt6HTTP İsteklerirequestsCredential StoragekeyringAI EntegrasyonuOllama REST API /api/chatGrafik RenderSVG inline (base64, QTextBrowser)Çalışma ModuTek dosya, tam yerel

🚀 Kurulum
1. Bağımlılıkları yükle
bashpip install PyQt6 requests keyring
2. Uygulamayı çalıştır
bashpython atmacaioc_local.py
3. AI Log Analizi için Ollama kurulumu (opsiyonel)
bash# Ollama'yı kur: https://ollama.com

# Model indir — birini seç
ollama pull qwen2.5:14b    # Önerilen (8GB VRAM)
ollama pull mistral         # Hızlı alternatif (4GB VRAM)
ollama pull llama3.1:8b    # Düşük kaynak alternatif
Kurulumdan sonra uygulamada Yerel AI Log sekmesine geç, model adını yaz ve analiz et.

📦 Bağımlılıklar
PaketKullanımZorunlu muPyQt6ArayüzEvetrequestsAPI istekleriEvetkeyringGüvenli anahtar saklamaEvet
