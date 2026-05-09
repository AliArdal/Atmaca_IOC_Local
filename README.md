# AtmacaIOC - Yerel SOC Analiz Platformu

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)
![AI](https://img.shields.io/badge/AI-Ollama%20Local-orange?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

> Siber guvenlik analistleri icin gelistirilmis, modern ve kapsamli IOC analiz ve AI log analizi platformu.  
> Tek dosya - Sifir konfigurasyon - Lokalde calisan - Disariya veri gondermeyen

---

## Neden Yaptim?

Bir SOC analisti olarak her gun onlarca IP, hash ve domain analiz etmek zorunda kaliyordum. Her seferinde farkli platformlari AbuseIPDB, VirusTotal, Shodan, MalwareBazaar tek tek acip manuel sorgulama yapmak hem zaman kaybettiriyor hem de hassas ic log verilerini kopyalayip cevrimici araclara yapistirmak ciddi bir guvenlik riski olusturuyordu.

**AtmacaIOC** bu sorunu cozmek icin gelistirildi:

- IOC sorgularini tek ekrandan birden fazla servise paralel gondererek saniyeler icinde sonuc aliyorum
- Ic ag loglarini, OT/ICS olaylarini ve EDR alarmlarini **tamamen lokalde calisan AI modeline** (Ollama) gondererek hazir SOC bildirimine donusturuyorum, hicbir veri disari cikmiyor
- Gunluk analist is akisinda surekli ihtiyac duyugum referans bilgileri tek uygulamada hizlica erisebilir hale getirdim

---

## Ozellikler

### IOC Analizi - 9 Farkli Servis, Tek Ekran

Bir IP, hash veya domain girildiginde desteklenen tum servislere es zamanli sorgu gonderilir. Her sonuc ayri sekmede zengin HTML ciktisiyla gosterilir.

| Servis | Desteklenen Tipler | Ucretsiz API |
| --- | --- | :---: |
| AbuseIPDB | IP | Yes |
| ARIN | IP | Yes - anahtar gerektirmez |
| Shodan | IP, Domain | Yes |
| GreyNoise | IP, Domain | Yes |
| OTX AlienVault | IP, Domain, MD5, SHA1, SHA256 | Yes |
| VirusTotal | IP, Domain, MD5, SHA1, SHA256 | Yes |
| MalwareBazaar | MD5, SHA1, SHA256 | Yes - anahtar opsiyonel |
| HybridAnalysis | MD5, SHA1, SHA256 | Yes |
| URLScan.io | Domain | Yes - anahtar opsiyonel |

Her sorgu sonucu gorsel olarak zenginlestirilmis ciktiyla gelir:

- Dairesel gauge grafikler: AbuseIPDB guven skoru, OTX pulse sayisi, VT zararli motor orani
- Bar chart: VirusTotal motor dagilimi (zararli / supehli / temiz / tespit yok)
- Renkli kart tasarimi: zararli ise kirmizi, temiz ise yesil MalwareBazaar kartlari
- ClamAV, YARA ve sandbox sonuclari: OTX analysis endpoint'inden otomatik cekilir
- Detay linkleri: her servis icin dogrudan sayfa baglantisi

---

### Yerel AI Log Analizi - Ollama Entegrasyonu

Loglariniz disariya **hic cikmaz.** Ollama araciligiyla bilgisayarinizda calisan LLM modeline gonderilir, tum islem yereldir.

Desteklenen log tipleri ve ozellestirilmis promptlar:

| Analiz Tipi | Ne Yapar |
| --- | --- |
| Fortigate / Firewall Trafik | srcip, dstip, DNAT, honeypot/gercek sistem ayrimi, ulke bazli risk |
| OT/ICS/SCADA | PLC iletisimi, error code cozumleme, Siemens S7comm, MITRE ICS |
| EDR - CrowdStrike/Defender/Sentinel | IOA analizi, davranissal ML tespiti, karantina aksiyon raporu |
| Windows Event / AccelOps / SIEM | Subject vs Target ayrimi, sifre sifirlama, grup ekleme, brute force |
| Firewall Policy Change | Add/Edit/Delete islemi, kullanici, policy ID, degisen alanlar |
| Genel Guvenlik | Her turlu log icin temel analiz |

Her analiz sonucu standart yapida gelir:

```
SOC BILDIRIMI         - kopyalanabilir, hazir bildirim metni
OZET                  - 2-3 cumle teknik ozet
Kaynak ve Hedef       - IP, MAC, hostname, DNAT detaylari
TESPIT EDILEN VERILER - tum log alanlari tabloda
GUVENLIK DEGERLENDIRMESI - DUSUK / ORTA / YUKSEK / KRITIK
NE OLDU?              - adim adim teknik aciklama
ONERILEN AKSIYONLAR   - somut mudahale adimlari
```

Onerilen modeller:

```bash
ollama pull qwen2.5:14b   # en iyi analiz kalitesi (8GB VRAM)
ollama pull mistral        # hizli alternatif (4GB VRAM)
ollama pull llama3.1:8b   # dusuk kaynak alternatif
```

---

### SOC Analist Referans Kutuphanesi

Gunluk is akisinda hizli basvuru icin kapsamli referans sekmesi. Her bilgi aranabilir ve tek tikla kopyalanabilir.

<details>
<summary><b>Portlar (35+ kayit)</b></summary>

Renkli risk siniflandirmasiyla kritik portlar: FTP, SSH, Telnet, SMB (EternalBlue), RDP (BlueKeep), Metasploit default reverse shell portlari, OT/SCADA portlari (Modbus 502, S7 102, DNP3 20000, BACnet 47808) ve daha fazlasi.

</details>

<details>
<summary><b>Windows Event ID'leri (33 kayit) + Linux Log Kaynaklari</b></summary>

4624/4625 oturum, 4688 proses olusturma, 4698 zamanlanmis gorev, 4740 hesap kilitleme, 4768/4769 Kerberos (Kerberoasting tespiti), 4776 NTLM, 7045 yeni servis kurulumu ve daha fazlasi. Linux tarafinda auth.log, audit.log, .bash_history gibi kritik log kaynaklari.

</details>

<details>
<summary><b>SIEM / Platform Komutlari</b></summary>

QRadar, Splunk, Wazuh, LogSign ve Genel SSH olmak uzere 5 platform icin hazir komutlar. Servis durumu, canli log takibi, disk kullanimi, agent listesi, cluster sagligi gibi 60+ komut. Her biri tek tikla panoya kopyalanabilir.

</details>

<details>
<summary><b>Windows CMD / PowerShell Komutlari (30 kayit)</b></summary>

netstat -ano, schtasks /query, wmic startup, cmdkey /list, Get-NetTCPConnection gibi forensic ve incident response komutlari.

</details>

<details>
<summary><b>MITRE ATT&CK Teknikleri (24 teknik)</b></summary>

Initial Access'ten Impact'e tum taktikler: T1190, T1566 Phishing, T1059, T1003 Mimikatz/LSASS, T1110 Brute Force, T1486 Ransomware sifreleme, T1490 Shadow Copy silme ve daha fazlasi. Teknik ID'ye tikla, kopyala.

</details>

<details>
<summary><b>Incident Response Adimlari (NIST SP 800-61)</b></summary>

Hazirlik > Tespit ve Analiz > Kontrol Altina Alma > Temizleme > Kurtarma > Lessons Learned. Her adim icin somut kontrol listesi.

</details>

<details>
<summary><b>Severity Seviyeleri, Google Dorks, SOC Araclari, Chrome Eklentileri</b></summary>

- P1-P5 oncelik seviyeleri ve RFC 5424 Syslog seviyeleri
- IOC hizli kontrol checklist
- 50+ Google Dork: config dosyalari, dizin listeleme, admin panel, GitHub sizintisi, subdomain kesfi
- Nmap, Volatility, Autopsy, Wireshark, Burp Suite, Ghidra gibi SOC arac kutuphanesi
- Wappalyzer, Shodan, Netcraft, uBlock Origin gibi Chrome guvenlik eklentileri
- Kriptografik parola uretici (Password Generator)

</details>

---

## API Anahtarlari - Guvenli Saklama

API anahtarlari hicbir zaman kod icine, `.env` dosyasina veya harici bir sunucuya yazilmaz. Isletim sisteminin guvenli kimlik bilgisi yoneticisinde saklanir:

| Platform | Depolama Yeri |
| --- | --- |
| Windows | Windows Credential Manager |
| macOS | Keychain |
| Linux | Secret Service (GNOME Keyring / KWallet) |

`keyring` kutuphanesi araciligiyla saglanan bu yontem sayesinde anahtarlar yalnizca sizin kullanici oturumunuzda okunabilir. Baska kullanici veya surecler anahtarlariniza erisemez.

Uygulamayi ilk actiginizda **API Anahtarlari** butonuna tiklayin, anahtarlarinizi girin ve kaydedin. Bir daha girmeniz gerekmez.

---

## Uygulama Mimarisi

```
AtmacaIOC
|
|-- IOC Motoru
|   |-- IOC Tespit: regex (IPv4, MD5, SHA1, SHA256, Domain)
|   |-- AnalysisWorker (QThread): her servis ayri thread'de calisir
|   `-- 9 Provider: AbuseIPDB, ARIN, Shodan, GreyNoise, OTX,
|                   VirusTotal, MalwareBazaar, HybridAnalysis, URLScan
|
|-- AI Log Analizi
|   |-- OllamaWorker (QThread): bloklamayan asenkron calisma
|   |-- Prompt Motoru: 7 log tipi icin ozellestirilmis prompt
|   |   |-- Fortigate / Firewall Trafik
|   |   |-- OT/ICS/SCADA
|   |   |-- EDR (CrowdStrike / Defender / SentinelOne)
|   |   |-- Windows Event / AccelOps / SIEM
|   |   |-- Firewall Policy Change
|   |   `-- Genel (fallback)
|   `-- Markdown -> HTML renderer
|       |-- SOC BILDIRIMI  -> ozel mavi kart
|       |-- Tablo          -> styled HTML table
|       |-- Tehdit seviyesi -> renkli badge
|       `-- Code block     -> syntax highlighted pre
|
|-- SOC Referans Kutuphanesi
|   |-- 10 alt sekme (Portlar, Event ID, Komutlar, MITRE, IR ...)
|   |-- Canli arama filtresi
|   `-- Tek tikla kopyala
|
`-- UI Katmani (PyQt6)
    |-- QMainWindow + QTabWidget: 3 ana sekme
    |-- QThread tabanli asenkron islem: UI donmaz
    |-- QTextBrowser: SVG base64 gauge grafik render
    `-- keyring: OS native credential storage
```

| Katman | Teknoloji |
| --- | --- |
| UI Framework | PyQt6 |
| HTTP Istekleri | requests |
| Credential Storage | keyring |
| AI Entegrasyonu | Ollama REST API /api/chat |
| Grafik Render | SVG inline (base64, QTextBrowser) |
| Calisma Modu | Tek dosya, tam yerel |

---

## Kurulum

**1. Bagimliliklari yukle**

```bash
pip install PyQt6 requests keyring
```

**2. Uygulamayi calistir**

```bash
python atmacaioc_local.py
```

**3. AI Log Analizi icin Ollama kurulumu (opsiyonel)**

```bash
# Ollama'yi kur: https://ollama.com

# Model indir, birini sec
ollama pull qwen2.5:14b    # Onerilen (8GB VRAM)
ollama pull mistral         # Hizli alternatif (4GB VRAM)
ollama pull llama3.1:8b    # Dusuk kaynak alternatif
```

Kurulumdan sonra uygulamada **Yerel AI Log** sekmesine gec, model adini yaz ve analiz et.

---

## Bagimliliklar

| Paket | Kullanim | Zorunlu mu |
| --- | --- | :---: |
| PyQt6 | Arayuz | Evet |
| requests | API istekleri | Evet |
| keyring | Guvenli anahtar saklama | Evet |

---

## Yasal Uyari

Bu arac yalnizca **yetkili sistemlerin guvenlik analizi** amaciyla kullanilmak uzere gelistirilmistir. Baskalarina ait sistemlerde izinsiz kullanim yasal sonuclar dogurabilir. Sorumluluk kullaniciya aittir.

---

## Lisans

MIT License - Ozgurce kullanin, dagitin, degistirin.

---

*AtmacaIOC - Bir SOC analisti tarafindan, SOC analistleri icin.*  
*Katkilariniz icin Pull Request ve Issue acabilirsiniz.*
