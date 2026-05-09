
# 🛡 CyberLogParser Pro 2026

**Siber güvenlik analistleri için geliştirilmiş, modern ve kapsamlı log analiz aracı.**  
Tek dosya, sıfır konfigürasyon — aç ve kullan.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![CustomTkinter](https://img.shields.io/badge/UI-CustomTkinter-cyan?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)

---

## Ne İşe Yarıyor?

Log dosyası açarsın, **Parse Et**'e basarsın. Tehditler zaten karşında olur.

- Brute force, SQLi, XSS, DoS, port scan → otomatik tespit
- MITRE ATT&CK tekniği eşlemesi
- IOC çıkarımı (IP, domain, hash, CVE)
- Gerçek zamanlı izleme (`tail -f` gibi)
- PDF / HTML / Excel / JSON / CSV rapor

---

## Desteklenen Log Formatları

| Format | Örnek Dosya / Kaynak |
|---|---|
| Apache Access Log | `/var/log/apache2/access.log` |
| Nginx Access Log | `/var/log/nginx/access.log` |
| Linux Syslog (RFC 3164 / 5424) | `/var/log/syslog` |
| SSH Auth Log | `/var/log/auth.log` |
| Windows Event Log | Event Viewer XML / CSV export |
| Suricata EVE JSON | `eve.json` |
| CEF (ArcSight, QRadar) | SIEM log export |
| Cisco ASA Firewall | `%ASA-6-302013:` formatı |
| AWS VPC Flow Logs | CloudWatch / S3 export |
| FortiGate Traffic Log | `sample_logs/fortigate_traffic.log` |
| Sıkıştırılmış | `.gz` / `.bz2` / `.zip` |

> Tanınamayan formatlarda da çalışır — temel IP/mesaj çıkarımı yapar.

---

## Kurulum

```bash
# 1. Repoyu klonla
git clone https://github.com/kullanicin/CyberLogParser.git
cd CyberLogParser

# 2. Bağımlılıkları kur (zorunlu)
pip install customtkinter matplotlib Pillow

# 3. Çalıştır
python CyberLogParser.py
```

İsteğe bağlı (daha fazla özellik için):

```bash
pip install openpyxl reportlab pandas
```

> Program eksik paketleri başlangıçta otomatik kurmaya çalışır.

---

## Ekran Görüntüleri

```
┌─────────────────────────────────────────────────────┐
│  🛡 CyberLogParser    PRO 2026 · SOC Edition         │
│  📂 Dosya Aç  ⚡ Parse Et  📊 Dışa Aktar  🗑 Temizle │
├────────────┬────────────┬────────────┬──────────────┤
│ 📊 Dashboard│📋 Kayıtlar │🚨 Uyarılar │🔍 IOC Intel  │
├────────────┴────────────┴────────────┴──────────────┤
│  📄 12,847    🚨 23 Uyarı    🌍 847 IP    👤 156 User │
│                                                      │
│  [SSH-001] SSH Brute Force — 192.168.1.105          │
│  [WEB-002] SQL Injection  — 45.33.32.156            │
│  [WIN-001] Log Silindi    — SUNUCU-01               │
└─────────────────────────────────────────────────────┘
```

---

## Tespit Edilen Tehditler

| Alert ID | Tehdit | Severity | MITRE |
|---|---|---|---|
| SSH-001 | SSH Brute Force (60s içinde 5+ deneme) | 🔴 HIGH | T1110 |
| SSH-002 | Password Spray (5+ farklı kullanıcı) | 🔴 HIGH | T1110 |
| WEB-001 | SQL Injection girişimi | 🔴 CRITICAL | T1190 |
| WEB-002 | XSS (Cross-Site Scripting) girişimi | 🟠 HIGH | T1190 |
| WEB-003 | Directory Traversal | 🟠 HIGH | T1083 |
| WEB-004 | Güvenlik tarayıcısı (sqlmap, nikto...) | 🟡 MEDIUM | T1046 |
| NET-001 | DoS / Flood (10s içinde 200+ istek) | 🟠 HIGH | T1498 |
| WIN-001 | Güvenlik logu silindi (Event 1102) | 🔴 CRITICAL | T1070 |
| WIN-002 | Zamanlanmış görev oluşturuldu (4698) | 🟠 HIGH | T1053 |
| WIN-003 | Yeni servis kuruldu (Event 7045) | 🟠 HIGH | T1543 |
| MAL-001 | Zararlı yazılım izi tespit edildi | 🔴 CRITICAL | T1059 |

---

## Mimari

```
CyberLogParser.py  (tek dosya, ~1700 satır)
│
├── FormatDetector     → Dosyayı okur, formatı otomatik tahmin eder
├── LogFileReader      → .gz/.bz2/.zip dahil tüm dosyaları okur
├── Parser sınıfları   → Her format için ayrı parse mantığı
│     Apache, Nginx, Syslog, SSH, CEF, JSON, Cisco ASA, AWS VPC, FortiGate...
│
├── BehavioralAnalyzer → Zaman pencereli tehdit tespiti (stateful)
├── IOCExtractor       → Regex tabanlı IOC çıkarımı
├── StatisticsEngine   → Counter ve toplamlar
│
├── ReportGenerator    → HTML / PDF / Excel / JSON / CSV üretimi
├── LogTailHandler     → Gerçek zamanlı tail -f
│
└── UI (CustomTkinter)
      DashboardPanel, LogViewPanel, AlertsPanel,
      IOCPanel, LiveMonitorPanel, ChartsPanel
```

---

## Kullanım

1. **Dosya Aç** → log dosyasını seç (sıkıştırılmış da olabilir)
2. **Parse Et** → format otomatik tespit edilir, analiz başlar
3. **🚨 Uyarılar** sekmesine bak → tehditler skor sırasıyla listelenir
4. **🔍 IOC Intel** → tüm IP/domain/hash/CVE otomatik çıkarılmış olur
5. **📡 Canlı İzleme** → dosya seç, Başlat'a bas
6. **Dışa Aktar** → HTML veya Excel raporu oluştur

---

## Gereksinimler

| Paket | Kullanım | Zorunlu mu? |
|---|---|---|
| `customtkinter` | Modern dark UI | ✅ Evet |
| `matplotlib` | Grafikler | ✅ Evet |
| `Pillow` | Görsel işleme | ✅ Evet |
| `openpyxl` | Excel export | İsteğe bağlı |
| `reportlab` | PDF export | İsteğe bağlı |
| `pandas` | Gelişmiş analiz | İsteğe bağlı |

---

## Lisans

MIT — istediğin gibi kullan, değiştir, dağıt.

---

*SOC analistleri için, SOC analistleri tarafından yapıldı.*


