🦅 AtmacaIOC - Yerel SOC Analiz Platformu


<img width="2559" height="1387" alt="1" src="https://github.com/user-attachments/assets/787ab621-e25f-4cb5-8d08-f031e411a9cc" />
<img width="2559" height="1392" alt="2" src="https://github.com/user-attachments/assets/7f24a669-001c-4a7b-9e2e-90f4ca888064" />
<img width="2559" height="1396" alt="3" src="https://github.com/user-attachments/assets/d25f51aa-a040-477e-a525-32246c1a29f2" />
<img width="2553" height="1392" alt="4" src="https://github.com/user-attachments/assets/ad0603b2-b7d5-4a82-a6f3-60b3ea42558d" />
<img width="2559" height="1394" alt="5" src="https://github.com/user-attachments/assets/cd031dd4-94d3-4bcb-83d3-3153f1ea9283" />
<img width="2559" height="1385" alt="6" src="https://github.com/user-attachments/assets/5fad266f-8528-4bcb-b145-c2d8ef1878e4" />
<img width="2559" height="1383" alt="7" src="https://github.com/user-attachments/assets/e80500dc-d972-493d-aefb-d1842b4d6953" />



Siber güvenlik analistleri için geliştirilmiş, modern ve kapsamlı IOC analiz ve AI log analizi platformu.
Tek dosya · Sıfır konfigürasyon · Lokalde çalışan · Dışarıya veri göndermeyen

💡 Neden Yaptim?
Bir SOC analisti olarak her gun onlarca IP, hash ve domain analiz etmek zorunda kaliyordum. Her seferinde farkli platformlari AbuseIPDB, VirusTotal, Shodan, MalwareBazaar tek tek acip manuel sorgulama yapmak hem zaman kaybettiriyor hem de hassas ic log verilerini kopyalayip cevrimici araclara yapistirmak ciddi bir guvenlik riski olusturuyordu.
AtmacaIOC bu sorunu cozmek icin gelistirildi:

IOC sorgularini tek ekrandan birden fazla servise paralel gondererek saniyeler icinde sonuc aliyorum
Ic ag loglarini, OT/ICS olaylarini ve EDR alarmlarini tamamen lokalde calisan AI modeline (Ollama) gondererek hazir SOC bildirimine donusturuyorum, hicbir veri disari cikmiyor
Gunluk analist is akisinda surekli ihtiyac duyugum referans bilgileri tek uygulamada hizlica erisebilir hale getirdim

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

