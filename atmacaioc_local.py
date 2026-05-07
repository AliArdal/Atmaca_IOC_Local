# atmacaioc_local.py — AtmacaIOC Local (v6.2-local)
# v6.2 Değişiklikler:
#       • Her analiz tipi için ayrı, kısa ve net prompt
#       • Fortigate: srcip/dstip/DNAT/srccountry semantiği
#       • temperature 0.3→0.1 (daha deterministik)
#       • Dış ağ ile bağlantı kurmaz yerelde kurduğunuz yapay zeka(ollama) ila çalışır.
#   - Model önerisi: qwen2.5:14b veya mistral 

import sys
import re
import secrets
import string
import requests
import keyring
import datetime

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QPushButton, QLabel, QTabWidget, QMessageBox,
    QCheckBox, QLineEdit, QDialog, QFormLayout, QDialogButtonBox,
    QScrollArea, QProgressBar, QGroupBox, QTextBrowser, QSplitter,
    QComboBox, QSpinBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QGuiApplication

# ============================================================
# IOC TESPİT PATTERN'LARI
# ============================================================
RE_IPV4   = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
RE_MD5    = re.compile(r'\b[0-9a-fA-F]{32}\b')
RE_SHA1   = re.compile(r'\b[0-9a-fA-F]{40}\b')
RE_SHA256 = re.compile(r'\b[0-9a-fA-F]{64}\b')
RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,13}\b'
)
DOMAIN_EXCLUDE = re.compile(r'^\d+\.\d+\.\d+\.\d+$')


def detect_ioc_type(value: str) -> str:
    v = value.strip()
    if RE_SHA256.fullmatch(v):   return "sha256"
    if RE_SHA1.fullmatch(v):     return "sha1"
    if RE_MD5.fullmatch(v):      return "md5"
    if RE_IPV4.fullmatch(v) and _valid_ip(v): return "ip"
    if RE_DOMAIN.fullmatch(v) and not DOMAIN_EXCLUDE.match(v): return "domain"
    return "unknown"

def _valid_ip(ip: str) -> bool:
    try:
        p = ip.split('.')
        return len(p) == 4 and all(0 <= int(x) <= 255 and x == str(int(x)) for x in p)
    except:
        return False

def extract_iocs(text: str) -> list:
    found = []
    seen  = set()
    for m in RE_SHA256.finditer(text):
        v = m.group().lower()
        if v not in seen:
            seen.add(v); found.append((v, "sha256"))
    for m in RE_SHA1.finditer(text):
        v = m.group().lower()
        if v not in seen and not any(v in s for s, t in found if t == "sha256"):
            seen.add(v); found.append((v, "sha1"))
    for m in RE_MD5.finditer(text):
        v = m.group().lower()
        if v not in seen and not any(v in s for s, t in found if t in ("sha256","sha1")):
            seen.add(v); found.append((v, "md5"))
    for m in RE_IPV4.finditer(text):
        v = m.group()
        if _valid_ip(v) and v not in seen:
            seen.add(v); found.append((v, "ip"))
    for m in RE_DOMAIN.finditer(text):
        v = m.group().lower()
        if v not in seen and not DOMAIN_EXCLUDE.match(v) and not _valid_ip(v):
            seen.add(v); found.append((v, "domain"))
    return found


# ============================================================
# PROVIDER TANIMLARI
# ============================================================
PROVIDERS = {
    "AbuseIPDB": {
        "enabled": True, "key_name": "ABUSEIPDB",
        "requires_key": True, "supports": ["ip"],
        "rate_limit": "1000/gün",
        "register_url": "https://www.abuseipdb.com/register"
    },
    "ARIN": {
        "enabled": True, "key_name": None,
        "requires_key": False, "supports": ["ip"],
        "rate_limit": "15/dakika", "register_url": None
    },
    "Shodan": {
        "enabled": True, "key_name": "SHODAN",
        "requires_key": True, "supports": ["ip", "domain"],
        "rate_limit": "100/ay",
        "register_url": "https://developer.shodan.io"
    },
    "GreyNoise": {
        "enabled": True, "key_name": "GREYNOISE",
        "requires_key": True, "supports": ["ip", "domain"],
        "rate_limit": "50/hafta",
        "register_url": "https://viz.greynoise.io/account/details"
    },
    "OTX": {
        "enabled": True, "key_name": "OTX",
        "requires_key": True, "supports": ["ip", "domain", "md5", "sha1", "sha256"],
        "rate_limit": "10,000/gün",
        "register_url": "https://otx.alienvault.com"
    },
    "VirusTotal": {
        "enabled": True, "key_name": "VIRUSTOTAL",
        "requires_key": True, "supports": ["ip", "domain", "md5", "sha1", "sha256"],
        "rate_limit": "500/gün (ücretsiz)",
        "register_url": "https://www.virustotal.com/gui/join-us"
    },
    "MalwareBazaar": {
        "enabled": True, "key_name": "MALWAREBAZAAR",
        "requires_key": False, "key_optional": True,
        "supports": ["md5", "sha1", "sha256"],
        "rate_limit": "Ücretsiz (anahtar ile daha fazla)",
        "register_url": "https://bazaar.abuse.ch/api/#anchor_api-auth"
    },
    "HybridAnalysis": {
        "enabled": True, "key_name": "HYBRIDANALYSIS",
        "requires_key": True, "supports": ["md5", "sha1", "sha256"],
        "rate_limit": "200/gün",
        "register_url": "https://www.hybrid-analysis.com/signup"
    },
    "URLScan": {
        "enabled": True, "key_name": "URLSCAN",
        "requires_key": False, "key_optional": True,
        "supports": ["domain"],
        "rate_limit": "100/gün (anahtarsız), 1000/gün (anahtarla)",
        "register_url": "https://urlscan.io/user/signup"
    },
}
SOC_PORTS = [
    ("20/21", "TCP",     "FTP",            "#ff9800", "Dosya transferi — şifresiz, MITM riski"),
    ("22",    "TCP",     "SSH",            "#66bb6a", "Güvenli uzak erişim — brute force hedefi"),
    ("23",    "TCP",     "Telnet",         "#ef5350", "Şifresiz uzak erişim — kritik risk"),
    ("25",    "TCP",     "SMTP",           "#ff9800", "E-posta gönderimi — spam/relay riski"),
    ("53",    "UDP/TCP", "DNS",            "#ff9800", "DNS — tünel/exfil riski"),
    ("67/68", "UDP",     "DHCP",           "#ff9800", "IP atama — rogue DHCP saldırıları"),
    ("80",    "TCP",     "HTTP",           "#ff9800", "Web — şifresiz, web saldırıları"),
    ("110",   "TCP",     "POP3",           "#ff9800", "E-posta alma — şifresiz"),
    ("135",   "TCP",     "RPC",            "#ef5350", "Windows RPC — lateral movement"),
    ("139",   "TCP",     "NetBIOS",        "#ef5350", "SMB/NetBIOS — EternalBlue hedefi"),
    ("143",   "TCP",     "IMAP",           "#ff9800", "E-posta — şifresiz"),
    ("161",   "UDP",     "SNMP",           "#ff9800", "Ağ yönetimi — bilgi ifşası"),
    ("389",   "TCP",     "LDAP",           "#ff9800", "Dizin servisi — credential dumping"),
    ("443",   "TCP",     "HTTPS",          "#66bb6a", "Güvenli web — C2 tüneli riski"),
    ("445",   "TCP",     "SMB",            "#ef5350", "Windows paylaşım — EternalBlue/ransomware"),
    ("500",   "UDP",     "IKE/IPSec",      "#66bb6a", "VPN — zayıf config riski"),
    ("514",   "UDP",     "Syslog",         "#ff9800", "Log iletimi — UDP spoofing riski"),
    ("636",   "TCP",     "LDAPS",          "#66bb6a", "Güvenli LDAP"),
    ("1433",  "TCP",     "MSSQL",          "#ef5350", "SQL Server — brute force/SQL injection"),
    ("1434",  "UDP",     "MSSQL Browser",  "#ef5350", "SQL Browser — bilgi ifşası"),
    ("1521",  "TCP",     "Oracle DB",      "#ef5350", "Oracle DB — brute force"),
    ("3306",  "TCP",     "MySQL",          "#ef5350", "MySQL — uzak erişim riski"),
    ("3389",  "TCP",     "RDP",            "#ef5350", "Uzak masaüstü — brute force/BlueKeep"),
    ("4444",  "TCP",     "Metasploit",     "#ef5350", "⚠ Metasploit default reverse shell"),
    ("4899",  "TCP",     "Radmin",         "#ef5350", "Uzak yönetim — saldırgan aracı"),
    ("5432",  "TCP",     "PostgreSQL",     "#ef5350", "PostgreSQL — brute force"),
    ("5900",  "TCP",     "VNC",            "#ef5350", "Ekran paylaşımı — brute force/şifresiz"),
    ("6379",  "TCP",     "Redis",          "#ef5350", "Redis — auth bypass/RCE riski"),
    ("8080",  "TCP",     "HTTP Alt.",      "#ff9800", "Alternatif HTTP — proxy/uygulama"),
    ("8443",  "TCP",     "HTTPS Alt.",     "#ff9800", "Alternatif HTTPS"),
    ("27017", "TCP",     "MongoDB",        "#ef5350", "MongoDB — auth bypass riski"),
    ("102",   "TCP",     "S7 (Siemens)",   "#ef5350", "OT/PLC — Siemens SIMATIC"),
    ("502",   "TCP",     "Modbus",         "#ef5350", "OT/ICS — internette açık olmamalı"),
    ("20000", "TCP",     "DNP3",           "#ef5350", "OT/SCADA — internette açık olmamalı"),
    ("47808", "UDP",     "BACnet",         "#ef5350", "OT/BAS protokolü — internette açık olmamalı"),
]

SOC_EVENT_IDS_WIN = [
    ("4624",  "Oturum",    "Başarılı giriş",                                    "#66bb6a"),
    ("4625",  "Oturum",    "Başarısız giriş — brute force izle",                "#ef5350"),
    ("4634",  "Oturum",    "Oturum kapanışı",                                   "#66bb6a"),
    ("4648",  "Oturum",    "Açık kimlik bilgisi ile giriş (RunAs)",             "#ff9800"),
    ("4662",  "AD",        "AD nesnesi üzerinde işlem",                         "#ff9800"),
    ("4663",  "Dosya",     "Nesneye erişim girişimi",                           "#ff9800"),
    ("4672",  "Oturum",    "Yönetici haklarıyla giriş",                         "#ef5350"),
    ("4688",  "Proses",    "Yeni proses oluşturuldu",                           "#ff9800"),
    ("4697",  "Servis",    "Sistem servis kurulumu",                            "#ef5350"),
    ("4698",  "Görev",     "Zamanlanmış görev oluşturuldu",                     "#ef5350"),
    ("4700",  "Görev",     "Zamanlanmış görev etkinleştirildi",                 "#ff9800"),
    ("4702",  "Görev",     "Zamanlanmış görev güncellendi",                     "#ff9800"),
    ("4719",  "Politika",  "Audit politikası değişti",                          "#ef5350"),
    ("4720",  "Kullanıcı", "Kullanıcı hesabı oluşturuldu",                      "#ef5350"),
    ("4722",  "Kullanıcı", "Hesap etkinleştirildi",                             "#ff9800"),
    ("4723",  "Şifre",     "Şifre değiştirme girişimi",                         "#ff9800"),
    ("4725",  "Kullanıcı", "Hesap devre dışı bırakıldı",                        "#ff9800"),
    ("4728",  "Grup",      "Güvenlik grubu üye eklendi",                        "#ef5350"),
    ("4732",  "Grup",      "Local grup üye eklendi",                            "#ef5350"),
    ("4738",  "Kullanıcı", "Hesap değiştirildi",                                "#ff9800"),
    ("4740",  "Hesap",     "Hesap kilitlendi — brute force?",                   "#ef5350"),
    ("4756",  "Grup",      "Universal grup üye eklendi",                        "#ef5350"),
    ("4768",  "Kerberos",  "TGT isteği (Kerberoasting?)",                       "#ff9800"),
    ("4769",  "Kerberos",  "Servis bileti isteği",                              "#ff9800"),
    ("4771",  "Kerberos",  "Kerberos pre-auth başarısız",                       "#ef5350"),
    ("4776",  "NTLM",      "NTLM auth girişimi",                                "#ff9800"),
    ("4798",  "Kullanıcı", "Local grup üyeliği sorgulandı",                     "#ff9800"),
    ("4799",  "Grup",      "Güvenlik grubu üyeliği sorgulandı",                 "#ff9800"),
    ("4946",  "Firewall",  "FW izin verilen kural eklendi",                     "#ff9800"),
    ("5140",  "Ağ",        "Ağ paylaşımı erişildi",                             "#ff9800"),
    ("5145",  "Ağ",        "Ağ paylaşım nesnesi erişim denetimi",               "#ff9800"),
    ("7045",  "Servis",    "Yeni servis yüklendi",                              "#ef5350"),
    ("8004",  "PS",        "PowerShell remote oturum",                          "#ef5350"),
]

SOC_EVENT_IDS_LINUX = [
    ("auth.log / secure", "SSH",     "SSH giriş denemeleri — /var/log/auth.log",             "#ff9800"),
    ("cron",              "Görev",   "Cron job aktivitesi — /var/log/cron",                  "#ff9800"),
    ("kern.log",          "Kernel",  "Kernel mesajları, modül yüklemeleri",                  "#ff9800"),
    ("syslog",            "Sistem",  "Genel sistem mesajları",                               "#66bb6a"),
    ("audit.log",         "Denetim", "Linux auditd — execve, open, connect çağrıları",       "#ef5350"),
    ("wtmp / utmp",       "Oturum",  "Son login kaydı — last komutu",                        "#ff9800"),
    ("lastb",             "Oturum",  "Başarısız SSH denemeleri",                             "#ef5350"),
    ("dmesg",             "Kernel",  "Donanım/kernel hata mesajları",                        "#ff9800"),
    ("faillog",           "Oturum",  "Başarısız giriş sayacı",                               "#ef5350"),
    (".bash_history",     "Komut",   "Bash geçmişi — şüpheli komutları kontrol et",          "#ef5350"),
]

SOC_COMMANDS = {
    "QRadar": {
        "color": "#0f62fe",
        "icon": "🔷",
        "commands": [
            ("Servis Durumu",           "systemctl status hostcontext",                                          "QRadar ana servis durumu"),
            ("Servis Yeniden Başlat",   "systemctl restart hostcontext",                                         "Tüm QRadar servislerini yeniden başlatır"),
            ("Tüm Servisleri Kontrol",  "/opt/ibm/si/console/bin/qradar_service_status.sh",                      "Konsol ve bileşen servisleri"),
            ("Disk Kullanımı",          "df -h /store",                                                          "QRadar veri depolama alanı"),
            ("EPS Değerleri",           "grep -i 'Events per Second' /var/log/qradar.log | tail -20",            "Saniyedeki olay sayısı"),
            ("Sistem Logları",          "tail -f /var/log/qradar.log",                                           "Canlı QRadar logları"),
            ("Veritabanı Durum",        "/opt/ibm/si/console/bin/qradar_db_status.sh",                           "PostgreSQL durumu"),
            ("Lisans Kontrol",          "grep -i license /var/log/qradar.log | tail -10",                        "Lisans uyarıları"),
            ("Backup Durumu",           "/opt/ibm/si/console/bin/qradar_backup_status.sh",                       "Son backup durumu"),
            ("Event Pipeline",          "grep 'Event Processor' /var/log/qradar.log | tail -20",                 "Event işleme durumu"),
        ]
    },
    "Splunk": {
        "color": "#65a637",
        "icon": "🟢",
        "commands": [
            ("Servis Durumu",           "systemctl status Splunkd",                                              "Splunk daemon durumu"),
            ("Splunk Başlat",           "/opt/splunk/bin/splunk start",                                          "Splunk başlatma"),
            ("Splunk Durdur",           "/opt/splunk/bin/splunk stop",                                           "Splunk durdurma"),
            ("Splunk Yeniden Başlat",   "/opt/splunk/bin/splunk restart",                                        "Splunk restart"),
            ("Cluster Bundle Durum",    "/opt/splunk/bin/splunk show cluster-bundle-status",                     "Indexer cluster durumu"),
            ("Index Listesi",           "/opt/splunk/bin/splunk list index",                                     "Tüm indexler ve boyutları"),
            ("Lisans Kullanımı",        "/opt/splunk/bin/splunk list licenser-localslave",                       "Günlük lisans kullanımı"),
            ("Forwarder Durumu",        "/opt/splunk/bin/splunk list forward-server",                            "Forwarder bağlantıları"),
            ("Canlı Log",               "tail -f /opt/splunk/var/log/splunk/splunkd.log",                        "Splunk daemon logları"),
            ("Search Peer Durum",       "/opt/splunk/bin/splunk show distributed-search",                        "Distributed search peers"),
            ("Input İzle",              "/opt/splunk/bin/splunk list monitor",                                   "İzlenen dosyalar"),
            ("BTool Config",            "/opt/splunk/bin/splunk btool inputs list --debug",                      "Input konfigürasyonu"),
        ]
    },
    "Wazuh": {
        "color": "#00a9e0",
        "icon": "🔵",
        "commands": [
            ("Manager Durumu",          "systemctl status wazuh-manager",                                        "Wazuh manager servisi"),
            ("Agent Durumu",            "systemctl status wazuh-agent",                                          "Wazuh agent servisi"),
            ("Manager Restart",         "systemctl restart wazuh-manager",                                       "Manager yeniden başlatma"),
            ("Tüm Agent Listesi",       "/var/ossec/bin/agent_control -l",                                       "Bağlı tüm agentlar"),
            ("Agent Detay",             "/var/ossec/bin/agent_control -i <AGENT_ID>",                            "Belirli agent bilgileri"),
            ("Aktif Agentlar",          "/var/ossec/bin/agent_control -la",                                      "Sadece aktif agentlar"),
            ("Canlı Loglar",            "tail -f /var/ossec/logs/ossec.log",                                     "Wazuh manager logları"),
            ("Canlı Alarmlar",          "tail -f /var/ossec/logs/alerts/alerts.log",                             "Tetiklenen alarmlar"),
            ("Kural Test",              "/var/ossec/bin/wazuh-logtest",                                          "Log kural test aracı"),
            ("Config Doğrula",          "/var/ossec/bin/wazuh-control configtest",                               "Konfigürasyon doğrulama"),
            ("Cluster Durumu",          "/var/ossec/bin/cluster_control -l",                                     "Cluster node listesi"),
            ("Agent İstatistik",        "/var/ossec/bin/agent_control -s",                                       "Agent istatistikleri"),
        ]
    },
    "LogSign": {
        "color": "#e84118",
        "icon": "🔴",
        "commands": [
            ("Servis Durumu",           "systemctl status logsign-server",                                       "LogSign server servisi"),
            ("Servis Başlat",           "systemctl start logsign-server",                                        "Servis başlatma"),
            ("Servis Durdur",           "systemctl stop logsign-server",                                         "Servis durdurma"),
            ("Servis Restart",          "systemctl restart logsign-server",                                      "Servis yeniden başlatma"),
            ("Canlı Log",               "tail -f /var/log/logsign/logsign.log",                                  "LogSign uygulama logları"),
            ("Disk Durumu",             "df -h /logsign",                                                        "LogSign depolama alanı"),
            ("PostgreSQL Durum",        "systemctl status postgresql",                                           "Veritabanı servisi"),
            ("Elasticsearch Durum",     "systemctl status elasticsearch",                                        "ES servis durumu"),
            ("ES Cluster Sağlık",       "curl -s localhost:9200/_cluster/health | python3 -m json.tool",         "ES cluster sağlığı"),
            ("ES Index Listesi",        "curl -s 'localhost:9200/_cat/indices?v'",                               "ES index listesi ve boyutları"),
        ]
    },
    "Genel SSH": {
        "color": "#9b59b6",
        "icon": "⚡",
        "commands": [
            ("Aktif Bağlantılar",       "ss -tnp | grep ESTABLISHED",                                           "Aktif TCP bağlantıları ve processler"),
            ("Dinleyen Portlar",        "ss -tlnp",                                                              "Açık portlar ve hangi process kullanıyor"),
            ("CPU — Top Process",       "ps aux --sort=-%cpu | head -20",                                        "En çok CPU kullanan processler"),
            ("RAM — Top Process",       "ps aux --sort=-%mem | head -20",                                        "En çok bellek kullanan processler"),
            ("Son Girişler",            "last -20",                                                              "Son 20 başarılı giriş"),
            ("Başarısız SSH",           "lastb | head -20",                                                      "Son 20 başarısız SSH girişimi"),
            ("Aktif Oturumlar",         "who -a",                                                                "Şu an bağlı kullanıcılar"),
            ("Cron Joblar",             "crontab -l && ls /etc/cron*",                                           "Zamanlanmış görevler"),
            ("SUID Dosyalar",           "find / -perm /4000 -type f 2>/dev/null",                                "SUID bit ayarlı dosyalar"),
            ("Son Yeni Dosyalar",       "find /tmp /var/tmp -mtime -1 -type f 2>/dev/null",                      "Son 24 saatte oluşturulan dosyalar"),
            ("Kernel & OS",             "uname -r && cat /etc/os-release",                                       "OS ve kernel versiyon bilgisi"),
            ("Çalışan Servisler",       "systemctl list-units --type=service --state=running",                   "Aktif servis listesi"),
            ("Firewall Kuralları",      "iptables -L -n -v --line-numbers",                                      "Firewall kural listesi"),
            ("Journal Canlı",           "journalctl -f",                                                         "Systemd journal canlı log"),
            ("Auth Log Canlı",          "tail -f /var/log/auth.log",                                             "SSH/auth canlı log izleme"),
            ("Disk Kullanımı",          "df -h && du -sh /var/log/*",                                            "Disk ve log boyutları"),
            ("Bellek Durumu",           "free -h && vmstat 1 5",                                                 "Bellek kullanım detayı"),
            ("Saldırı Araç Tespiti",    "dpkg -l | grep -iE 'netcat|nmap|hydra|john|metasploit'",               "Şüpheli araç paketleri"),
            ("ARP Tablosu",             "arp -n",                                                                "ARP cache — poisoning tespiti"),
            ("DNS Test",                "dig +short @8.8.8.8 <DOMAIN>",                                         "DNS çözümleme testi"),
            ("Traceroute",              "traceroute -n <IP>",                                                    "Ağ yolu takibi"),
            ("Paket Yakala",            "tcpdump -i eth0 -nn -w /tmp/capture.pcap -c 1000",                      "1000 paket yakala ve kaydet"),
            ("Dosya Hash",              "sha256sum <DOSYA>",                                                     "Dosya bütünlük kontrolü"),
            ("Açık Dosyalar",           "lsof -i -n -P | grep LISTEN",                                          "Dinleyen socket ve processler"),
        ]
    },
}

SOC_MITRE = [
    ("Initial Access",    "T1190", "Exploit Public-Facing App",        "Web/VPN açıklarını sömürme"),
    ("Initial Access",    "T1566", "Phishing",                         "Kötü amaçlı e-posta eki/linki"),
    ("Execution",         "T1059", "Command & Scripting Interpreter",  "PowerShell, bash, cmd"),
    ("Execution",         "T1053", "Scheduled Task/Job",               "Zamanlanmış görev — kalıcılık"),
    ("Persistence",       "T1547", "Boot/Logon Autostart Execution",   "Run key, startup folder"),
    ("Persistence",       "T1543", "Create/Modify System Process",     "Servis oluşturma"),
    ("Privilege Esc.",    "T1548", "Abuse Elevation Control",          "UAC bypass, sudo exploit"),
    ("Privilege Esc.",    "T1055", "Process Injection",                "DLL injection, shellcode"),
    ("Defense Evasion",   "T1070", "Indicator Removal",                "Log silme, geçmiş temizleme"),
    ("Defense Evasion",   "T1562", "Impair Defenses",                  "AV/EDR devre dışı bırakma"),
    ("Credential Access", "T1003", "OS Credential Dumping",            "Mimikatz, LSASS dump"),
    ("Credential Access", "T1110", "Brute Force",                      "Password spray, stuffing"),
    ("Discovery",         "T1046", "Network Service Discovery",        "Nmap, port tarama"),
    ("Discovery",         "T1082", "System Information Discovery",     "OS/donanım bilgi toplama"),
    ("Lateral Movement",  "T1021", "Remote Services",                  "RDP, SSH, WinRM, SMB"),
    ("Lateral Movement",  "T1550", "Use Alternate Auth Material",      "Pass the Hash / Ticket"),
    ("Collection",        "T1114", "Email Collection",                 "Posta kutusu erişimi"),
    ("Collection",        "T1056", "Input Capture",                    "Keylogger"),
    ("Exfiltration",      "T1048", "Exfil Over Alt Protocol",          "DNS/ICMP tünel"),
    ("Exfiltration",      "T1041", "Exfil Over C2 Channel",            "C2 üzerinden veri sızdırma"),
    ("C2",                "T1071", "Application Layer Protocol",       "HTTP/S, DNS C2"),
    ("C2",                "T1095", "Non-Application Layer Protocol",   "Raw TCP/UDP C2"),
    ("Impact",            "T1486", "Data Encrypted for Impact",        "Ransomware şifreleme"),
    ("Impact",            "T1490", "Inhibit System Recovery",          "Shadow copy silme"),
]

SOC_IR_STEPS = [
    ("1", "Hazırlık", "#1565c0", [
        "Olay müdahale planının güncel olduğunu doğrula",
        "İletişim ağacını hazır tut (CISO, IT, Hukuk, PR)",
        "Araçları hazırla: forensic toolkit, yedek erişim",
        "Olay kaydı aç (ticket / IR form numarası al)",
    ]),
    ("2", "Tespit & Analiz", "#6a1b9a", [
        "Log kaynaklarını topla ve merkezi ilet",
        "IOC'leri tespit et: IP, hash, domain, kullanıcı adı",
        "Timeline oluştur (ilk olay ne zaman başladı?)",
        "Etkilenen sistemleri belirle ve sınıflandır",
        "Tehdit seviyesini belirle: DÜŞÜK / ORTA / YÜKSEK / KRİTİK",
    ]),
    ("3", "Kontrol Altına Alma", "#e65100", [
        "Etkilenen sistemleri ağdan izole et",
        "Şüpheli hesapları kilitle / devre dışı bırak",
        "C2 IP/domain'lerini firewall'da engelle",
        "Etkilenen servisleri gerekirse durdur",
        "Forensic imaj al (containment öncesi ve sonrası)",
    ]),
    ("4", "Temizleme", "#b71c1c", [
        "Zararlı yazılımları ve backdoor'ları tespit edip kaldır",
        "Zamanlanmış görevleri, servis kayıtlarını kontrol et",
        "Değiştirilen konfigürasyonları geri yükle",
        "Etkilenen tüm hesapların şifrelerini sıfırla",
        "Yamaları uygula — exploit edilen açıkları kapat",
    ]),
    ("5", "Kurtarma", "#2e7d32", [
        "Sistemleri temiz yedekten geri yükle",
        "Aşamalı olarak sistemi production'a al",
        "İzlemeyi artır — yeniden enfeksiyon takibi yap",
        "Bütünlük doğrulaması yap (hash kontrolü)",
    ]),
    ("6", "Lessons Learned", "#455a64", [
        "Olay sonrası rapor hazırla (24-72 saat içinde)",
        "Kök neden analizini (RCA) belgele",
        "Politika ve prosedür güncellemelerini belirle",
        "Ekiple post-mortem toplantısı düzenle",
        "SIEM kurallarını ve alertleri güncelle",
    ]),
]

SOC_SEVERITY = [
    ("P1 — KRİTİK", "#ef5350", "#3a0a0a", "Aktif ihlal, veri sızdırma, ransomware. Anında müdahale — 0-15 dk"),
    ("P2 — YÜKSEK",  "#ff9800", "#3a2000", "Şüpheli lateral movement, privilege esc. — 15-60 dk müdahale"),
    ("P3 — ORTA",    "#f57f17", "#3a2d00", "Başarısız brute force, port tarama — 1-4 saat inceleme"),
    ("P4 — DÜŞÜK",   "#66bb6a", "#0a2a0a", "Politika ihlali, tek başarısız giriş — 24 saat inceleme"),
    ("P5 — BİLGİ",   "#78909c", "#1a2a2a", "İzleme, istatistik — haftalık raporlama"),
]
SOC_GOOGLE_DORKS = [
    ("🔧 Konfigürasyon Dosyaları", "#ef5350", [
        ('site:TARGET.com filetype:env', 'Ortam değişkenleri, API keyleri, sifreler'),
        ('site:TARGET.com filetype:ini', 'Uygulama konfigürasyonu'),
        ('site:TARGET.com filetype:conf', 'Sunucu/servis konfigürasyonu'),
        ('site:TARGET.com filetype:cfg', 'Konfigürasyon dosyaları'),
        ('site:TARGET.com filetype:log', 'Log dosyaları — hassas bilgi içerebilir'),
        ('site:TARGET.com filetype:xml inurl:config', 'XML konfigürasyonları'),
        ('site:TARGET.com ext:properties', 'Java properties dosyaları'),
    ]),
    ("📁 Dizin Listeleme & Yedekler", "#ff9800", [
        ('site:TARGET.com intitle:"index of"', 'Açık dizin listeleme — tüm dosyalar görünür'),
        ('site:TARGET.com intitle:"index of /" "parent directory"', 'Üst dizin erişimi'),
        ('site:TARGET.com filetype:bak', 'Yedek dosyalar'),
        ('site:TARGET.com filetype:old', 'Eski dosyalar'),
        ('site:TARGET.com filetype:backup', 'Backup dosyaları'),
        ('site:TARGET.com filetype:sql', 'SQL dump dosyaları — veritabanı'),
        ('site:TARGET.com filetype:zip OR filetype:tar OR filetype:gz', 'Sıkıştırılmış arşivler'),
    ]),
    ("🔐 Yönetim Panelleri & Giriş Sayfaları", "#ff9800", [
        ('site:TARGET.com inurl:admin', 'Admin paneli'),
        ('site:TARGET.com inurl:login', 'Giriş sayfaları'),
        ('site:TARGET.com intitle:"admin panel"', 'Admin panel başlığı'),
        ('site:TARGET.com inurl:wp-admin', 'WordPress admin'),
        ('site:TARGET.com inurl:phpmyadmin', 'phpMyAdmin — veritabanı paneli'),
        ('site:TARGET.com inurl:cpanel', 'cPanel yönetim paneli'),
        ('site:TARGET.com inurl:dashboard', 'Dashboard sayfaları'),
        ('site:TARGET.com inurl:portal', 'Portal sayfaları'),
    ]),
    ("📄 Açık Dokümanlar & Hassas Dosyalar", "#ff9800", [
        ('site:TARGET.com filetype:pdf', 'PDF belgeler'),
        ('site:TARGET.com filetype:xls OR filetype:xlsx', 'Excel dosyaları — veri sızıntısı'),
        ('site:TARGET.com filetype:doc OR filetype:docx', 'Word belgeleri'),
        ('site:TARGET.com filetype:ppt OR filetype:pptx', 'Sunum dosyaları'),
        ('site:TARGET.com filetype:csv', 'CSV veri dosyaları'),
        ("site:TARGET.com \"confidential\" OR \"internal use\"", 'Gizli olarak işaretlenen sayfalar'),
        ("site:TARGET.com \"not for public release\"", 'Kamuya açık olmayan içerik'),
    ]),
    ("🗄️ Veritabanı & Kod Bilgisi", "#9c27b0", [
        ('site:TARGET.com inurl:db OR inurl:database', 'Veritabanı URLleri'),
        ("site:TARGET.com \"mysql_connect\" OR \"mysqli_connect\"", 'PHP MySQL bağlantı kodu'),
        ("site:TARGET.com \"password\" filetype:txt", 'Şifre içerebilecek text dosyalar'),
        ('site:TARGET.com inurl:.git', 'Git repository erişimi'),
        ('site:TARGET.com filetype:php inurl:upload', 'Upload fonksiyonları olan PHP sayfaları'),
        ("site:github.com TARGET.com \"password\" OR \"secret\" OR \"api_key\"", 'GitHubda sızdırılmış kimlik bilgileri'),
    ]),
    ("📧 E-posta & Kullanıcı Bilgileri", "#1565c0", [
        ('site:TARGET.com "@TARGET.com"', "Calisan e-posta adresleri"),
        ('site:TARGET.com intext:@TARGET.com', "Sayfada gecen e-posta adresleri"),
        ("site:linkedin.com TARGET.com", 'LinkedIn calisanlar'),
        ('TARGET.com filetype:xls email', 'E-posta listesi içeren Excel dosyaları'),
    ]),
    ("🔍 Sunucu & Hizmet Tespiti", "#2e7d32", [
        ('site:TARGET.com inurl:api', 'API endpointleri'),
        ('site:TARGET.com intitle:"swagger"', 'Swagger API dokümantasyonu'),
        ('site:TARGET.com intitle:"Jenkins"', 'Jenkins CI/CD — açık portlar'),
        ('site:TARGET.com intitle:"Grafana"', 'Grafana dashboard'),
        ('site:TARGET.com intitle:"Kibana"', 'Kibana log analiz paneli'),
        ('site:TARGET.com intitle:"GitLab"', 'GitLab — kod deposu'),
        ('intitle:"Apache2 Ubuntu Default Page" site:TARGET.com', 'Varsayılan Apache sayfası'),
        ('intitle:"Welcome to nginx" site:TARGET.com', 'Varsayılan Nginx sayfası'),
    ]),
]

SOC_CMD_WINDOWS = [
    ("systeminfo",              "Sistem bilgisi — OS, patch tarihi, RAM, CPU",           "#64b5f6"),
    ("ipconfig /all",           "Tüm ağ adaptörleri, IP, MAC, DNS, DHCP bilgisi",        "#64b5f6"),
    ("ipconfig /displaydns",    "DNS önbelleği — hangi domainler sorgulandı?",            "#ff9800"),
    ("netstat -ano",            "Aktif bağlantılar + process IDleri",                    "#ef5350"),
    ("netstat -anb",            "Aktif bağlantılar + executable adı (admin gerekli)",     "#ef5350"),
    ("arp -a",                  "ARP tablosu — MAC-IP eşleşmeleri, spoofing tespiti",     "#ff9800"),
    ("net user",                "Sistemdeki tüm kullanıcıları listeler",                  "#ff9800"),
    ("net user USERNAME",       "Belirli bir kullanıcının detaylı bilgisi",               "#ff9800"),
    ("net localgroup Administrators", "Local Administrators grubundaki üyeler",           "#ef5350"),
    ("net share",               "Paylaşılan ağ kaynakları",                               "#ff9800"),
    ("net session",             "Aktif ağ oturumları",                                    "#ff9800"),
    ("query user",              "Oturum açmış kullanıcılar ve oturum süreleri",           "#66bb6a"),
    ("tasklist /v",             "Çalışan tüm prosesler ve detayları",                     "#ff9800"),
    ("tasklist /svc",           "Prosesler ve bağlı servisler",                           "#ff9800"),
    ("sc query",                "Tüm Windows servislerinin durumu",                       "#ff9800"),
    ("schtasks /query /fo LIST /v","Zamanlanmış tüm görevler — persistence tespiti",      "#ef5350"),
    ("wmic startup list full",  "Başlangıçta çalışan programlar",                         "#ef5350"),
    ("wmic process list full",  "Çalışan tüm prosesler — tam detay",                     "#ff9800"),
    ("wmic useraccount list full","Tüm kullanıcı hesapları",                              "#ff9800"),
    ("dir /s /a",               "Tüm dosya ve dizinler (gizliler dahil)",                "#ff9800"),
    ("dir %TEMP% /s",           "Temp klasörü içeriği — malware sıkça buraya düşer",     "#ef5350"),
    ("cmdkey /list",            "Kayıtlı kimlik bilgileri — credential harvesting",       "#ef5350"),
    ("whoami /priv",            "Mevcut kullanıcının ayrıcalıkları",                      "#ff9800"),
    ("whoami /groups",          "Kullanıcının ait olduğu gruplar",                        "#ff9800"),
    ("curl ifconfig.me",        "Dış IP adresini öğren",                                  "#66bb6a"),
    ("curl ifconfig.me/all",    "Tüm dış ağ bilgisi",                                     "#66bb6a"),
    ("reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                                "Başlangıç kayıt anahtarları — persistence",              "#ef5350"),
    ("Get-EventLog Security -Newest 50", "Son 50 güvenlik olayı (PowerShell)",            "#9c27b0"),
    ("Get-Process | Sort-Object CPU -Descending | Select -First 15",
                                "En çok CPU kullanan processler (PowerShell)",            "#9c27b0"),
    ("Get-NetTCPConnection | Where State -eq Established",
                                "Aktif TCP bağlantıları (PowerShell)",                    "#9c27b0"),
]
SOC_TOOLS = {
    "🔍 Tarama & Keşif": {
        "color": "#1565c0",
        "items": [
            ("Nmap","https://nmap.org","Ağ taraması, port keşfi, servis/OS tespiti","Ücretsiz / CLI"),
            ("Masscan","https://github.com/robertdavidgraham/masscan","Çok hızlı port tarayıcı, büyük ağlar için","Ücretsiz / CLI"),
            ("Shodan","https://shodan.io","İnternet bağlı cihaz arama motoru","Freemium / Web"),
            ("Censys","https://censys.io","IP/domain enumeration, sertifika analizi","Freemium / Web"),
            ("Amass","https://github.com/owasp-amass/amass","Subdomain enumeration, ASN keşfi","Ücretsiz / CLI"),
            ("TheHarvester","https://github.com/laramies/theHarvester","E-posta, subdomain, IP toplama","Ücretsiz / CLI"),
            ("Maltego","https://maltego.com","Görsel OSINT ve link analizi","Freemium / GUI"),
        ]
    },
    "🎣 Phishing & E-posta Güvenliği": {
        "color": "#e65100",
        "items": [
            ("GoPhish","https://getgophish.com","Phishing simülasyon framework","Ücretsiz / Web"),
            ("Phishtank","https://phishtank.org","Phishing URL veritabanı ve doğrulama","Ücretsiz / Web"),
            ("MXToolbox","https://mxtoolbox.com","MX kayıtları, SPF/DKIM/DMARC analizi","Ücretsiz / Web"),
            ("Have I Been Pwned","https://haveibeenpwned.com","E-posta/breach sorgulama","Ücretsiz / Web"),
            ("Email Header Analyzer","https://mxtoolbox.com/EmailHeaders.aspx","E-posta başlığı analizi","Ücretsiz / Web"),
            ("DMARC Analyzer","https://dmarcanalyzer.com","DMARC rapor analizi","Freemium / Web"),
        ]
    },
    "🦠 Malware Analysis": {
        "color": "#6a1b9a",
        "items": [
            ("VirusTotal","https://virustotal.com","70+ AV motoru ile hash/URL/domain analizi","Ücretsiz / Web"),
            ("Any.Run","https://any.run","Interaktif sandbox — canlı malware analizi","Freemium / Web"),
            ("Hybrid Analysis","https://hybrid-analysis.com","Sandbox analizi, davranış raporu","Ücretsiz / Web"),
            ("MalwareBazaar","https://bazaar.abuse.ch","Malware hash veritabanı, örnek indirme","Ücretsiz / Web"),
            ("Joe Sandbox","https://joesandbox.com","Gelişmiş statik + dinamik analiz","Freemium / Web"),
            ("Cuckoo Sandbox","https://cuckoosandbox.org","Self-hosted malware sandbox","Ücretsiz / CLI"),
            ("CAPE Sandbox","https://capesandbox.com","Gelişmiş Cuckoo fork, unpacking özelliği","Ücretsiz / Web"),
            ("Ghidra","https://ghidra-sre.org","NSA reverse engineering framework","Ücretsiz / GUI"),
            ("IDA Free","https://hex-rays.com/ida-free","Disassembler — statik analiz","Freemium / GUI"),
            ("PEStudio","https://winitor.com","PE dosya analizi, import/string inceleme","Ücretsiz / GUI"),
            ("Detect-It-Easy","https://github.com/horsicq/Detect-It-Easy","Packer/compiler tespiti","Ücretsiz / GUI"),
        ]
    },
    "🌐 Web & URL Analizi": {
        "color": "#00695c",
        "items": [
            ("URLScan.io","https://urlscan.io","URL sandbox ve screenshot analizi","Freemium / Web"),
            ("URLVoid","https://urlvoid.com","URL reputation kontrolü","Ücretsiz / Web"),
            ("Wannabrowser","https://www.wannabrowser.net","Headless browser URL analizi","Ücretsiz / Web"),
            ("WHOIS Lookup","https://who.is","Domain kayıt bilgisi","Ücretsiz / Web"),
            ("DNSdumpster","https://dnsdumpster.com","DNS keşfi, subdomain haritası","Ücretsiz / Web"),
            ("Burp Suite","https://portswigger.net/burp","Web uygulama güvenlik testi","Freemium / GUI"),
            ("OWASP ZAP","https://zaproxy.org","Web uygulama tarayıcı — otomatik test","Ücretsiz / GUI"),
        ]
    },
    "🔎 Threat Intelligence": {
        "color": "#b71c1c",
        "items": [
            ("OTX AlienVault","https://otx.alienvault.com","Threat intel paylaşım platformu","Ücretsiz / Web"),
            ("MISP","https://misp-project.org","Threat intel paylaşım ve analiz","Ücretsiz / Self-host"),
            ("GreyNoise","https://greynoise.io","IP noise/sınıflandırma, internet tarayıcıları","Freemium / Web"),
            ("Threat Crowd","https://threatcrowd.org","Domain/IP/hash ilişkilendirme","Ücretsiz / Web"),
            ("Talos Intelligence","https://talosintelligence.com","Cisco Talos IP/domain reputation","Ücretsiz / Web"),
            ("AbuseIPDB","https://abuseipdb.com","IP kötüye kullanım raporları","Freemium / Web"),
            ("Pulsedive","https://pulsedive.com","IOC enrichment ve threat intel","Freemium / Web"),
        ]
    },
    "🛠️ Forensics & IR": {
        "color": "#37474f",
        "items": [
            ("Autopsy","https://autopsy.com","Dijital forensics analiz aracı","Ücretsiz / GUI"),
            ("Volatility","https://volatilityfoundation.org","Memory forensics framework","Ücretsiz / CLI"),
            ("FTK Imager","https://exterro.com/ftk-imager","Disk imaj ve forensics aracı","Ücretsiz / GUI"),
            ("Eric Zimmerman Tools","https://ericzimmerman.github.io","Windows artifact analiz araçları","Ücretsiz / CLI"),
            ("KAPE","https://ericzimmerman.github.io/#!docs/KAPE.md","Triage ve artifact toplama","Ücretsiz / CLI"),
            ("Wireshark","https://wireshark.org","Ağ paketi yakalama ve analizi","Ücretsiz / GUI"),
            ("NetworkMiner","https://netresec.com/networkMiner","Pasif ağ forensics aracı","Freemium / GUI"),
            ("Sysinternals","https://learn.microsoft.com/sysinternals","Windows sistem araçları paketi","Ücretsiz / GUI"),
        ]
    },
}
SOC_CHROME_EXTENSIONS = [
    ("🔍 IOC & URL Analizi", "#1565c0", [
        ("Wappalyzer","Ziyaret edilen sitenin teknoloji stackini tespit eder (CMS, framework, CDN, analitik vb.)",
         "https://www.wappalyzer.com/","Ücretsiz"),
        ("Hunter.io","Bir domaine ait e-posta adreslerini arar ve doğrular",
         "https://hunter.io/chrome","Freemium"),
        ("SalesQL","LinkedIn profil e-postalarını ve telefon numaralarını çeker — OSINT için kullanışlı",
         "https://salesql.com/","Freemium"),
        ("Shodan","Ziyaret edilen sitenin IP bilgisi, açık portlar ve CVElerini gösterir",
         "https://chrome.google.com/webstore/detail/shodan/jAkieggehpkmkolAng","Freemium"),
        ("URLVoid","URLyi anında reputation servislerine gönderir",
         "https://chrome.google.com/webstore/detail/urlvoid","Ücretsiz"),
        ("Virus Total","Sayfadaki URL ve dosyaları VTye gönderip sonucu gösterir",
         "https://chrome.google.com/webstore/detail/vtchromizer","Ücretsiz"),
        ("IP Address and Domain Information","Hızlı WHOIS, DNS, IP lookup",
         "https://chrome.google.com/webstore/detail/ip-address-domain-informa","Ücretsiz"),
    ]),
    ("🎣 Phishing Tespiti", "#e65100", [
        ("Netcraft Extension","Phishing ve zararlı siteleri gerçek zamanlı engeller",
         "https://www.netcraft.com/apps/browser/","Ücretsiz"),
        ("Suspicious Site Reporter","Şüpheli siteleri Google Safe Browsinge raporlar",
         "https://chrome.google.com/webstore/detail/suspicious-site-reporter","Ücretsiz"),
        ("Email Header Analyzer","Gmail başlıklarını tek tıkla analiz eder",
         "https://chrome.google.com/webstore/detail/email-header-analyzer","Ücretsiz"),
    ]),
    ("🔐 Güvenlik & Gizlilik", "#2e7d32", [
        ("Privacy Badger","Gizli izleyicileri tespit eder ve engeller",
         "https://privacybadger.org/","Ücretsiz"),
        ("uBlock Origin","Reklam/tracker engelleme — C2 domain tespitinde yardımcı",
         "https://ublockorigin.com/","Ücretsiz"),
        ("HTTPS Everywhere","Siteleri otomatik HTTPSe yönlendirir",
         "https://eff.org/https-everywhere","Ücretsiz"),
        ("Cookie-Editor","Cookieleri incele/düzenle — session analizi",
         "https://cookie-editor.cgagnier.ca/","Ücretsiz"),
        ("EditThisCookie","Cookie yönetimi ve forensics",
         "https://chrome.google.com/webstore/detail/editthiscookie","Ücretsiz"),
    ]),
    ("🛠️ Geliştirici & Analiz", "#7b1fa2", [
        ("Builtwith Technology Profiler","Sitenin tüm teknoloji altyapısını gösterir",
         "https://builtwith.com/toolbar","Ücretsiz"),
        ("Web Developer","HTTP başlıkları, kaynaklar, cookie inceleme",
         "https://chrome.google.com/webstore/detail/web-developer","Ücretsiz"),
        ("ModHeader","HTTP istek/yanıt başlıklarını değiştir — test amaçlı",
         "https://modheader.com/","Freemium"),
        ("Requestly","Request intercept, redirect, mock — pentest yardımcısı",
         "https://requestly.io/","Freemium"),
        ("JSON Viewer","JSON yanıtlarını güzel formatlar — API analizi",
         "https://chrome.google.com/webstore/detail/json-viewer","Ücretsiz"),
        ("OpenLink Structured Data Sniffer","Sayfanın metadata ve yapılandırılmış verilerini gösterir",
         "https://chrome.google.com/webstore/detail/openlink-structured-data","Ücretsiz"),
    ]),
    ("📊 OSINT", "#37474f", [
        ("Social Analyzer","Sosyal medya profil araması — kullanıcı adı pivoting",
         "https://github.com/qeeqbox/social-analyzer","Ücretsiz"),
        ("Pipl Search","Kişi arama ve OSINT veri toplama",
         "https://pipl.com/","Freemium"),
        ("Nimbus Screenshot","Tam sayfa ekran görüntüsü — kanıt toplama",
         "https://nimbusweb.me/screenshot.php","Ücretsiz"),
        ("SingleFile","Sayfayı tek HTML dosyasına kaydet — evidence preservation",
         "https://github.com/gildas-lormeau/SingleFile","Ücretsiz"),
    ]),
]

# ============================================================
# WORKER THREAD
# ============================================================
class AnalysisWorker(QThread):
    result_ready = pyqtSignal(str, str)
    finished_one = pyqtSignal()

    def __init__(self, value: str, ioc_type: str, provider: str):
        super().__init__()
        self.value    = value
        self.ioc_type = ioc_type
        self.provider = provider

    def run(self):
        v, t, p = self.value, self.ioc_type, self.provider
        try:
            method = getattr(self, f"_{p.lower().replace('-','_')}", None)
            if method:
                title, html = method(v, t)
            else:
                title, html = f"{p} - {v[:20]}", "<i>Desteklenmeyen sağlayıcı</i>"
        except Exception as e:
            title = f"Hata - {v[:20]}"
            html  = f"<h3 style='color:red;'>Beklenmeyen Hata [{p}]</h3><pre>{e}</pre>"
        self.result_ready.emit(title, html)
        self.finished_one.emit()

    @staticmethod
    def _color_score(score, hi=50, mid=20):
        return "#ef5350" if score > hi else "#ff9800" if score > mid else "#66bb6a"

    @staticmethod
    def _ts(unix):
        if not unix: return ""
        try:
            return datetime.datetime.fromtimestamp(
                int(unix), tz=datetime.timezone.utc
            ).strftime('%Y-%m-%d')
        except:
            return ""

    @staticmethod
    def _gauge(value, max_val, col, label="", sublabel=""):
        import math as _m, base64 as _b
        R = 52; cx = cy = 72; W = H = 144
        pct = min(value / max_val, 1.0) if max_val else 0
        sa, fa = -220, 260
        ea = sa + fa * pct
        def pt(r, deg):
            rd = _m.radians(deg)
            return cx + r * _m.cos(rd), cy + r * _m.sin(rd)
        def arc(r, a1, a2, clr, sw=11):
            x1,y1 = pt(r,a1); x2,y2 = pt(r,a2)
            lg = 1 if (a2-a1)%360 > 180 else 0
            return (f'<path d="M {x1:.1f} {y1:.1f} A {r} {r} 0 {lg} 1 {x2:.1f} {y2:.1f}" '
                    f'fill="none" stroke="{clr}" stroke-width="{sw}" stroke-linecap="round"/>')
        svg  = f'<svg width="{W}" height="{H}" xmlns="http://www.w3.org/2000/svg">'
        svg += f'<rect width="{W}" height="{H}" fill="#151515" rx="10"/>'
        svg += arc(R, sa, sa+fa, "#252525")
        if pct > 0:
            svg += arc(R, sa, ea, col)
        svg += (f'<text x="{cx}" y="{cy-5}" text-anchor="middle" fill="{col}" '
                f'font-size="22" font-weight="bold" font-family="Consolas">{value}</text>')
        if label:
            svg += (f'<text x="{cx}" y="{cy+13}" text-anchor="middle" fill="#555" '
                    f'font-size="11" font-family="Consolas">{label}</text>')
        if sublabel:
            svg += (f'<text x="{cx}" y="{cy+28}" text-anchor="middle" fill="#666" '
                    f'font-size="10" font-family="sans-serif">{sublabel}</text>')
        svg += '</svg>'
        b64 = _b.b64encode(svg.encode()).decode()
        return f'<img src="data:image/svg+xml;base64,{b64}" width="{W}" height="{H}" style="vertical-align:middle;">'

    def _abuseipdb(self, value, ioc_type):
        key = keyring.get_password("atmacaioc", "ABUSEIPDB")
        if not key:
            return f"AIPDB - {value}", "<i>API anahtarı eksik</i>"
        params  = {'ipAddress': value, 'maxAgeInDays': 90, 'verbose': True}
        headers = {'Key': key, 'Accept': 'application/json'}
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers=headers, params=params, timeout=12)
        if r.status_code == 429: return f"AIPDB - {value}", "<h3 style='color:orange;'>Rate limit (429)</h3>"
        if r.status_code == 401: return f"AIPDB - {value}", "<h3 style='color:red;'>401 Unauthorized</h3>"
        if r.status_code != 200: return f"AIPDB - {value}", f"<i>HTTP {r.status_code}</i>"
        d     = r.json().get('data', {})
        score = d.get('abuseConfidenceScore', 0)
        col   = self._color_score(score)
        gauge_col = "#ef5350" if score > 50 else "#ff9800" if score > 20 else "#66bb6a"
        gauge_html = self._gauge(score, 100, gauge_col, "/ 100", "güven skoru")
        html  = f'<div style="background:#1a1a1a;border:2px solid #2a2a2a;border-radius:10px;padding:16px;margin:6px;">'
        html += f'<h2 style="color:{col};margin:0 0 10px 0;">AbuseIPDB: {value}</h2>'
        html += '<table style="width:100%;border-collapse:collapse;margin-bottom:12px;"><tr>'
        html += f'<td style="width:154px;vertical-align:middle;padding-right:16px;">{gauge_html}</td>'
        html += '<td style="vertical-align:middle;">'
        html += f'<div style="font-size:28px;font-weight:bold;color:{col};">{score}%</div>'
        html += f'<div style="color:#666;font-size:12px;">Kötüye Kullanım Güven Skoru</div>'
        html += '<br>'
        html += f'<b style="color:#aaa;">Raporlar:</b> <span style="color:#ccc;">{d.get("totalReports",0)}</span>&nbsp;&nbsp;'
        html += f'<b style="color:#aaa;">Son:</b> <span style="color:#ccc;">{(d.get("lastReportedAt","") or "")[:10] or "Yok"}</span><br>'
        html += f'<b style="color:#aaa;">Beyaz liste:</b> <span style="color:#ccc;">{"Evet" if d.get("isWhitelisted") else "Hayır"}</span>'
        html += '</td></tr></table>'
        html += "<table style='width:100%;border-collapse:collapse;margin-bottom:8px;'>"
        for lbl2, key2 in [("ISP","isp"),("Ülke","countryName"),("Şehir","city"),
                           ("Domain","domain"),("Kullanım","usageType")]:
            v2 = d.get(key2, "")
            if v2:
                html += (f"<tr><td style='color:#888;padding:3px 10px 3px 0;width:80px;'><b>{lbl2}</b></td>"
                         f"<td style='color:#ccc;'>{v2}</td></tr>")
        html += "</table>"
        reps = d.get("reports", [])[:5]
        if reps:
            html += "<br><b>Son Raporlar:</b><ul>"
            for rep in reps:
                cats = ", ".join(str(c) for c in rep.get("categories", []))
                html += f"<li>{rep.get('reportedAt','')[:10]} — {cats} — {rep.get('comment','')[:80]}</li>"
            html += "</ul>"
        html += "</div>"
        return f"AIPDB {score}% - {value}", html

    def _arin(self, value, ioc_type):
        r = requests.get(f"https://whois.arin.net/rest/ip/{value}",
                         headers={"Accept":"application/json"}, timeout=10)
        if r.status_code != 200: return f"ARIN - {value}", f"<i>HTTP {r.status_code}</i>"
        net   = r.json().get('net', {})
        org   = net.get('orgRef',{}).get('@name','')
        s     = net.get('startAddress',{}).get('$','')
        e     = net.get('endAddress',{}).get('$','')
        reg   = net.get('registrationDate',{}).get('$','')
        name_ = net.get('name',{}).get('$','')
        html  = f"<h3>ARIN: {value}</h3>"
        html += f"<b>Ağ:</b> {name_}<br><b>Org:</b> {org}<br>"
        html += f"<b>Blok:</b> {s} — {e}<br><b>Kayıt:</b> {reg[:10]}<br>"
        return f"ARIN - {value}", html

    def _shodan(self, value, ioc_type):
        key = keyring.get_password("atmacaioc", "SHODAN")
        if not key: return f"Shodan - {value}", "<i>API anahtarı eksik</i>"
        if ioc_type == "ip":
            url = f"https://api.shodan.io/shodan/host/{value}?key={key}"
            r   = requests.get(url, timeout=15)
            if r.status_code == 404:
                return f"Shodan - {value}", f"<h3>Shodan: {value}</h3><b>Kayıt yok</b>"
            if r.status_code == 401:
                return f"Shodan - {value}", "<h3 style='color:red;'>Shodan 401</h3>"
            if r.status_code == 403:
                return f"Shodan - {value}", f"<h3 style='color:orange;'>Shodan 403</h3>"
            if r.status_code == 429:
                return f"Shodan - {value}", "<h3 style='color:orange;'>Shodan 429 — Rate limit</h3>"
            if r.status_code != 200:
                try:    err = r.json().get("error", r.text[:200])
                except: err = r.text[:200]
                return f"Shodan - {value}", f"<h3 style='color:red;'>Shodan HTTP {r.status_code}</h3>{err}"
            d     = r.json()
            ports = sorted(d.get('ports', []))
            vulns = d.get('vulns', {})
            html  = f"<h3>Shodan: {value}</h3>"
            html += f"<b>Ülke:</b> {d.get('country_name','')}  <b>Şehir:</b> {d.get('city','')}<br>"
            html += f"<b>Org:</b> {d.get('org','')}  <b>ISP:</b> {d.get('isp','')}<br>"
            html += f"<b>OS:</b> {d.get('os') or 'Bilinmiyor'}<br>"
            html += f"<b>Açık Portlar ({len(ports)}):</b> {', '.join(map(str,ports[:30]))}<br>"
            if vulns:
                html += f"<br><b style='color:red;'>CVE'ler ({len(vulns)}):</b><ul>"
                for cve, info in list(vulns.items())[:10]:
                    html += f"<li>{cve} CVSS:{info.get('cvss','?')}</li>"
                html += "</ul>"
            tag = f" ⚠{len(vulns)}CVE" if vulns else ""
            return f"Shodan{tag} - {value}", html
        else:
            url = f"https://api.shodan.io/dns/resolve?hostnames={value}&key={key}"
            r   = requests.get(url, timeout=10)
            if r.status_code != 200:
                return f"Shodan - {value}", f"<i>HTTP {r.status_code}</i>"
            raw = r.json()
            resolved_ip = ""
            if isinstance(raw, dict):
                val = raw.get(value, "")
                if isinstance(val, str) and _valid_ip(val):
                    resolved_ip = val
            html = f"<h3>Shodan DNS: {value}</h3>"
            if resolved_ip:
                html += f"<b>Çözümlenen IP:</b> {resolved_ip}<br>"
            return f"Shodan - {value}", html

    def _greynoise(self, value, ioc_type):
        key = keyring.get_password("atmacaioc", "GREYNOISE")
        if not key: return f"GN - {value}", "<i>API anahtarı eksik</i>"
        headers = {"key": key, "Accept": "application/json"}
        if ioc_type == "ip":
            url = f"https://api.greynoise.io/v3/community/{value}"
            r   = requests.get(url, headers=headers, timeout=15)
            if r.status_code == 404: return f"GN - {value}", f"<h3 style='color:green;'>GreyNoise: {value}</h3><b>Kayıt yok</b>"
            if r.status_code == 401: return f"GN - {value}", "<h3 style='color:red;'>401 Unauthorized</h3>"
            if r.status_code == 429: return f"GN - {value}", "<h3 style='color:orange;'>Rate limit (429)</h3>"
            if r.status_code != 200: return f"GN - {value}", f"<i>HTTP {r.status_code}</i>"
            d   = r.json()
            clf = d.get("classification","unknown").upper()
            col = {"MALICIOUS":"#ef5350","BENIGN":"#66bb6a"}.get(clf,"#ff9800")
            html  = f'<h3 style="color:{col};">GreyNoise: {value}</h3>'
            html += f'<b>Sınıf:</b> <span style="color:{col};">{clf}</span><br>'
            html += f'<b>Noise:</b> {"Evet" if d.get("noise") else "Hayır"}&nbsp; <b>RIOT:</b> {"Evet" if d.get("riot") else "Hayır"}<br>'
            if d.get("name"):      html += f'<b>İsim:</b> {d["name"]}<br>'
            if d.get("last_seen"): html += f'<b>Son Görülme:</b> {d["last_seen"][:10]}<br>'
            return f"GN {clf} - {value}", html
        else:
            url = f"https://api.greynoise.io/v2/experimental/gnql?query=metadata.rdns:{value}&size=5"
            r   = requests.get(url, headers=headers, timeout=15)
            if r.status_code != 200: return f"GN - {value}", f"<i>HTTP {r.status_code}</i>"
            d     = r.json()
            count = d.get("count", 0)
            html  = f"<h3>GreyNoise Domain: {value}</h3>"
            html += f"<b>Eşleşen IP sayısı:</b> {count}<br>"
            return f"GN - {value}", html

    def _otx(self, value, ioc_type):
        key = keyring.get_password("atmacaioc", "OTX")
        if not key:
            return f"OTX - {value[:20]}", "<i>API anahtarı eksik</i>"
        headers = {"X-OTX-API-KEY": key}
        lbl = value[:32] + ("..." if len(value) > 32 else "")

        # ── HASH
        if ioc_type in ("md5", "sha1", "sha256"):
            base = f"https://otx.alienvault.com/api/v1/indicators/file/{value}"
            gen, anal = {}, {}
            try:
                r = requests.get(f"{base}/general", headers=headers, timeout=12)
                if r.status_code == 200: gen = r.json()
            except: pass
            try:
                r = requests.get(f"{base}/analysis", headers=headers, timeout=12)
                if r.status_code == 200: anal = r.json()
            except: pass
            pulse_info  = gen.get("pulse_info", {}) or {}
            pulse_count = pulse_info.get("count", 0)
            pulses      = (pulse_info.get("pulses") or [])[:8]
            col = "#ef5350" if pulse_count > 10 else "#ff9800" if pulse_count > 0 else "#66bb6a"
            bg  = "#2a1212" if pulse_count > 10 else "#2a1e10" if pulse_count > 0 else "#1a1a1a"
            bdr = "#5a2020" if pulse_count > 10 else "#5a3c10" if pulse_count > 0 else "#333"
            html  = f'<div style="background:{bg};border:2px solid {bdr};border-radius:10px;padding:16px;margin:6px;">'
            html += f'<h2 style="color:{col};margin:0 0 10px 0;">OTX [{ioc_type.upper()}]: {lbl}</h2>'
            pg = self._gauge(pulse_count, max(pulse_count, 50), col, "", "pulse")
            html += f'<div style="display:inline-block;margin-bottom:12px;">{pg}</div>'
            html += (f'<div style="display:inline-block;vertical-align:middle;margin-left:16px;margin-bottom:12px;">'
                     f'<div style="font-size:32px;font-weight:bold;color:{col};">{pulse_count}</div>'
                     f'<div style="color:#666;font-size:12px;">Toplam Pulse</div></div>')
            # Dosya bilgileri
            mal_fam   = gen.get("malware_families") or []
            type_title = gen.get("type_title","") or gen.get("type","")
            size_val  = gen.get("size","")
            md5_v     = gen.get("md5","")
            sha1_v    = gen.get("sha1","")
            sha256_v  = gen.get("sha256","")
            html += "<table style='width:100%;border-collapse:collapse;margin:8px 0;'>"
            for lbl2, val2 in [("Dosya Tipi",type_title),("Boyut",str(size_val)+" byte" if size_val else ""),
                               ("MD5",md5_v),("SHA1",sha1_v),("SHA256",sha256_v)]:
                if val2:
                    html += (f"<tr><td style='color:#888;padding:3px 10px 3px 0;width:90px;vertical-align:top;'>"
                             f"<b>{lbl2}</b></td>"
                             f"<td style='color:#ccc;font-family:Consolas;font-size:11px;word-break:break-all;'>{val2}</td></tr>")
            html += "</table>"
            if mal_fam:
                html += (f'<div style="background:#3a1010;border-left:4px solid #ef5350;'
                         f'padding:8px 14px;border-radius:6px;margin:8px 0;">'
                         f'<b style="color:#ef5350;">⚠ Zararlı Aile: {", ".join(str(x) for x in mal_fam[:5])}</b></div>')
            # Analysis — YARA, ClamAV, Cuckoo
            try:
                anal2   = (anal.get("analysis") or {})
                plugins = (anal2.get("plugins") or {})
                if isinstance(plugins, dict):
                    clamav_p = plugins.get("clamav") or {}
                    if isinstance(clamav_p, dict):
                        for res in (clamav_p.get("results") or []):
                            if isinstance(res, dict) and res.get("detection"):
                                html += (f'<div style="background:#3a2010;border-left:4px solid #ff9800;'
                                         f'padding:6px 12px;border-radius:6px;margin:6px 0;">'
                                         f'<span style="color:#ff9800;">🦠 ClamAV: {res["detection"]}</span></div>')
                    yara_rules = []
                    for yn in ("yarad","yara"):
                        yp = plugins.get(yn) or {}
                        if isinstance(yp, dict):
                            for yr in (yp.get("results") or []):
                                if isinstance(yr, dict):
                                    rule = yr.get("rule","") or yr.get("name","")
                                    if rule: yara_rules.append(rule)
                    if yara_rules:
                        html += f'<b style="color:#9c27b0;">YARA ({len(yara_rules)}):</b><ul>'
                        for yr in yara_rules[:6]:
                            html += f"<li style='color:#ce93d8;font-size:12px;'>{yr}</li>"
                        html += "</ul>"
                    cuckoo   = plugins.get("cuckoo") or {}
                    cuck_res = (cuckoo.get("result") or {}) if isinstance(cuckoo,dict) else {}
                    cuck_net = (cuck_res.get("network") or {}) if isinstance(cuck_res,dict) else {}
                    if isinstance(cuck_net, dict):
                        hosts = [h for h in (cuck_net.get("hosts") or []) if isinstance(h, str)]
                        doms  = [d.get("domain","") for d in (cuck_net.get("domains") or []) if isinstance(d,dict) and d.get("domain")]
                        if hosts:
                            html += '<b style="color:#ff9800;">Bağlantı Kurulan IP:</b> '
                            html += " ".join(f'<span style="color:#ffcc80;">{h}</span>' for h in hosts[:8])+"<br>"
                        if doms:
                            html += f'<b style="color:#ff9800;">Bağlantı Domainleri:</b> '
                            html += " ".join(f'<span style="color:#ffcc80;">{d}</span>' for d in doms[:8])+"<br>"
                    sigs = (cuck_res.get("signatures") or []) if isinstance(cuck_res,dict) else []
                    sig_names = [s.get("name","") for s in sigs if isinstance(s,dict) and s.get("name")]
                    if sig_names:
                        html += '<b style="color:#ff9800;">Davranış İmzaları:</b><ul>'
                        for sn in sig_names[:8]:
                            html += f"<li style='color:#ffb74d;font-size:12px;'>{sn}</li>"
                        html += "</ul>"
            except Exception: pass
            # Etiketler
            all_tags = list(set(t for p in pulses for t in (p.get("tags") or [])))[:12]
            if all_tags:
                tag_colors = {"botnet":"#b71c1c","rootkit":"#880e4f","trojan":"#b71c1c","ransomware":"#b71c1c",
                              "rat":"#6a1b9a","stealer":"#e65100","malware":"#c62828","keylogger":"#b71c1c","backdoor":"#4a0080"}
                html += "<div style='margin:8px 0;'><b style='color:#aaa;'>Etiketler: </b>"
                for tag in all_tags:
                    tc = tag_colors.get(tag.lower(), "#2a2a3a")
                    html += (f"<span style='background:{tc};color:white;padding:2px 8px;border-radius:4px;"
                             f"margin:2px;font-size:11px;display:inline-block;'>{tag}</span>")
                html += "</div>"
            if pulses:
                html += f'<b style="color:#aaa;">İlgili Pulseler ({pulse_count}):</b><ul>'
                for p in pulses:
                    pname = (p.get("name") or "")[:80]
                    pdate = (p.get("created") or "")[:10]
                    html += f"<li style='color:#bbb;'>{pname} <i style='color:#555;'>({pdate})</i></li>"
                html += "</ul>"
            html += f'<br><a href="https://otx.alienvault.com/indicator/file/{value}" style="color:#64b5f6;">🔗 OTX Detay Sayfası</a>'
            html += "</div>"
            icon = "🔴" if pulse_count > 10 else "🟡" if pulse_count > 0 else "🟢"
            return f"OTX {icon}{pulse_count}p - {lbl}", html

        # ── IP
        if ioc_type == "ip":
            data = {}
            for sec in ("general","geo","passive_dns"):
                try:
                    r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{value}/{sec}",
                                     headers=headers, timeout=12)
                    if r.status_code == 200: data[sec] = r.json()
                except: pass
            pulse_count = (data.get("general",{}).get("pulse_info") or {}).get("count", 0)
            pulses      = ((data.get("general",{}).get("pulse_info") or {}).get("pulses") or [])[:5]
            geo         = data.get("geo", {})
            col  = "#ef5350" if pulse_count > 10 else "#ff9800" if pulse_count > 0 else "#66bb6a"
            bg   = "#2a1212" if pulse_count > 10 else "#2a1e10" if pulse_count > 0 else "#1a1a1a"
            html = f'<div style="background:{bg};border:2px solid #333;border-radius:10px;padding:16px;margin:6px;">'
            html += f'<h2 style="color:{col};margin:0 0 10px 0;">OTX [IP]: {value}</h2>'
            pg = self._gauge(pulse_count, max(pulse_count, 50), col, "", "pulse")
            html += (f'<div style="display:inline-block;margin-bottom:12px;">{pg}</div>'
                     f'<div style="display:inline-block;vertical-align:middle;margin-left:16px;margin-bottom:12px;">'
                     f'<div style="font-size:32px;font-weight:bold;color:{col};">{pulse_count}</div>'
                     f'<div style="color:#666;font-size:12px;">Toplam Pulse</div></div><br>')
            html += f'<b>Ülke:</b> {geo.get("country_name","")} &nbsp; <b>Şehir:</b> {geo.get("city","")}<br>'
            html += f'<b>ASN:</b> {geo.get("asn","N/A")} {geo.get("org","")}<br>'
            pdns = (data.get("passive_dns",{}).get("passive_dns") or [])[:5]
            if pdns:
                html += "<b>Passive DNS:</b><ul>"
                for rec in pdns:
                    html += f"<li>{rec.get('hostname','')} — {rec.get('record_type','')} — {rec.get('first','')[:10]}</li>"
                html += "</ul>"
            if pulses:
                html += "<b>Pulse Adları:</b><ul>"
                for p in pulses:
                    html += f"<li>{(p.get('name') or '')[:80]} <i>({(p.get('created') or '')[:10]})</i></li>"
                html += "</ul>"
            html += f'<br><a href="https://otx.alienvault.com/indicator/ip/{value}" style="color:#64b5f6;">🔗 OTX Detay Sayfası</a>'
            html += "</div>"
            return f"OTX {pulse_count}p - {lbl}", html

        # ── Domain
        if ioc_type == "domain":
            data = {}
            for sec in ("general","geo","passive_dns","whois"):
                try:
                    r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{value}/{sec}",
                                     headers=headers, timeout=12)
                    if r.status_code == 200: data[sec] = r.json()
                except: pass
            pulse_count = (data.get("general",{}).get("pulse_info") or {}).get("count", 0)
            pulses      = ((data.get("general",{}).get("pulse_info") or {}).get("pulses") or [])[:5]
            geo         = data.get("geo", {})
            whois       = data.get("whois", {}) or {}
            col  = "#ef5350" if pulse_count > 10 else "#ff9800" if pulse_count > 0 else "#66bb6a"
            bg   = "#2a1212" if pulse_count > 10 else "#2a1e10" if pulse_count > 0 else "#1a1a1a"
            html = f'<div style="background:{bg};border:2px solid #333;border-radius:10px;padding:16px;margin:6px;">'
            html += f'<h2 style="color:{col};margin:0 0 10px 0;">OTX [Domain]: {value}</h2>'
            pg = self._gauge(pulse_count, max(pulse_count, 50), col, "", "pulse")
            html += (f'<div style="display:inline-block;margin-bottom:12px;">{pg}</div>'
                     f'<div style="display:inline-block;vertical-align:middle;margin-left:16px;margin-bottom:12px;">'
                     f'<div style="font-size:32px;font-weight:bold;color:{col};">{pulse_count}</div>'
                     f'<div style="color:#666;font-size:12px;">Toplam Pulse</div></div><br>')
            html += f'<b>Ülke:</b> {geo.get("country_name","")}<br>'
            if isinstance(whois, dict):
                html += f'<b>Registrar:</b> {whois.get("registrar","")}<br>'
                html += f'<b>Oluşturma:</b> {(whois.get("date") or "")[:10]}<br>'
            pdns = (data.get("passive_dns",{}).get("passive_dns") or [])[:5]
            if pdns:
                html += "<b>Passive DNS:</b><ul>"
                for rec in pdns:
                    html += f"<li>{rec.get('hostname','')} → {rec.get('address','')} ({rec.get('record_type','')})</li>"
                html += "</ul>"
            if pulses:
                html += "<b>Pulse Adları:</b><ul>"
                for p in pulses:
                    html += f"<li>{(p.get('name') or '')[:80]} <i>({(p.get('created') or '')[:10]})</i></li>"
                html += "</ul>"
            html += f'<br><a href="https://otx.alienvault.com/indicator/domain/{value}" style="color:#64b5f6;">🔗 OTX Detay Sayfası</a>'
            html += "</div>"
            return f"OTX {pulse_count}p - {lbl}", html

        return f"OTX - {lbl}", "<i>Desteklenmeyen IOC tipi</i>"

    def _virustotal(self, value, ioc_type):
        key = keyring.get_password("atmacaioc", "VIRUSTOTAL")
        if not key: return f"VT - {value[:20]}", "<i>API anahtarı eksik</i>"
        headers = {"x-apikey": key, "Accept": "application/json"}
        ep_map = {
            "ip":     f"https://www.virustotal.com/api/v3/ip_addresses/{value}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{value}",
            "md5":    f"https://www.virustotal.com/api/v3/files/{value}",
            "sha1":   f"https://www.virustotal.com/api/v3/files/{value}",
            "sha256": f"https://www.virustotal.com/api/v3/files/{value}",
        }
        url = ep_map.get(ioc_type, ep_map["sha256"])
        r   = requests.get(url, headers=headers, timeout=15)
        lbl = value[:32] + ("…" if len(value) > 32 else "")
        if r.status_code == 401: return f"VT - {lbl}", "<h3 style='color:#ef5350;'>401 Unauthorized</h3>"
        if r.status_code == 429: return f"VT - {lbl}", "<h3 style='color:#ff9800;'>Rate limit (429) — 4 istek/dk</h3>"
        if r.status_code == 404: return f"VT - {lbl}", f"<h3 style='color:#66bb6a;'>VirusTotal: {lbl}</h3><b>Hiç raporlanmamış — Temiz</b>"
        if r.status_code != 200: return f"VT - {lbl}", f"<i>HTTP {r.status_code}: {r.text[:200]}</i>"

        attr  = r.json().get("data",{}).get("attributes",{})
        stats = attr.get("last_analysis_stats",{})
        mal   = stats.get("malicious",0)
        sus   = stats.get("suspicious",0)
        har   = stats.get("harmless",0)
        und   = stats.get("undetected",0)
        total = mal + sus + har + und
        col   = "#ef5350" if mal > 5 else "#ff9800" if mal > 0 or sus > 0 else "#66bb6a"
        bg    = "#2a1212" if mal > 5 else "#2a1e10" if mal > 0 or sus > 0 else "#122a14"
        bdr   = "#5a2020" if mal > 5 else "#5a3c10" if mal > 0 or sus > 0 else "#1e5a22"

        def make_chart(mal, sus, har, und, total):
            if total == 0: return ""
            col_mal = "#ef5350"; col_sus = "#ff9800"; col_har = "#66bb6a"; col_und = "#555"
            gauge_col = col_mal if mal > 5 else col_sus if mal > 0 or sus > 0 else col_har
            out  = '<table style="width:100%;border-collapse:collapse;margin:8px 0;"><tr>'
            out += '<td style="width:160px;vertical-align:middle;padding-right:16px;">'
            out += self._gauge(mal, total, gauge_col, f'/ {total}', 'zararlı motor')
            out += '</td><td style="vertical-align:middle;">'
            out += f'<div style="color:#666;font-size:11px;margin-bottom:6px;">Toplam {total} motor</div>'
            for label, count, color in [
                ("Zararlı", mal, col_mal), ("Şüpheli", sus, col_sus),
                ("Temiz", har, col_har), ("Tespit Yok", und, col_und),
            ]:
                pct_w = max(int((count/total)*100), 2 if count > 0 else 0)
                out += '<table style="width:100%;border-collapse:collapse;margin:3px 0;"><tr>'
                out += f'<td style="color:#aaa;font-size:12px;width:75px;">{label}</td>'
                out += f'<td style="background:#1e1e1e;border-radius:3px;height:14px;padding:0;">'
                out += f'<div style="background:{color};width:{pct_w}%;height:14px;border-radius:3px;"></div></td>'
                out += f'<td style="color:{color};font-weight:bold;font-size:13px;width:32px;text-align:right;padding-left:4px;">{count}</td>'
                out += '</tr></table>'
            out += '</td></tr></table>'
            return out

        html = f'<div style="background:{bg};border:2px solid {bdr};border-radius:10px;padding:16px;margin:6px;">'
        html += f'<h2 style="color:{col};margin:0 0 8px 0;">VirusTotal [{ioc_type.upper()}]</h2>'

        if ioc_type in ("md5", "sha1", "sha256"):
            verdict = "ZARARLII" if mal > 5 else "ŞÜPHELİ" if mal > 0 or sus > 0 else "TEMİZ"
            threat_label = attr.get("popular_threat_classification",{}).get("suggested_threat_label","")
            name_str = attr.get("meaningful_name","") or ""
            if threat_label:
                html += (f'<div style="background:#3a1515;border-left:4px solid #ef5350;'
                         f'padding:8px 12px;border-radius:6px;margin-bottom:10px;">'
                         f'<span style="color:#ef5350;font-weight:bold;">⚠ {threat_label}</span></div>')
            if name_str:
                html += f'<p style="color:#bbb;margin:0 0 8px 0;">📄 {name_str}</p>'
            html += make_chart(mal, sus, har, und, total)
            html += f'<div style="border-left:4px solid {col};padding:8px 12px;margin:8px 0;background:#111;">'
            html += f'<span style="color:{col};font-size:15px;font-weight:bold;">{verdict}: {mal}/{total} motor zararlı buluyor</span></div>'
            html += "<table style='width:100%;border-collapse:collapse;margin:8px 0;'>"
            for rlbl, rval in [
                ("Dosya Adı", name_str),
                ("Tür", attr.get("type_description","")),
                ("Boyut", (str(attr.get("size","")) + " byte") if attr.get("size") else ""),
                ("MD5", attr.get("md5","")),
                ("SHA1", attr.get("sha1","")),
                ("SHA256", attr.get("sha256","")),
                ("İlk Gönderim", self._ts(attr.get("first_submission_date",0))),
                ("Son Analiz", self._ts(attr.get("last_analysis_date",0))),
            ]:
                if rval:
                    html += (f"<tr><td style='color:#888;padding:3px 10px 3px 0;width:100px;vertical-align:top;'><b>{rlbl}</b></td>"
                             f"<td style='color:#ccc;font-family:Consolas;font-size:12px;word-break:break-all;'>{rval}</td></tr>")
            html += "</table>"
            if attr.get("tags"):
                html += "<div style='margin:6px 0;'><b style='color:#aaa;'>Etiketler: </b>"
                for tag in attr["tags"][:10]:
                    html += f"<span style='background:#2a2a2a;color:#ccc;padding:2px 8px;border-radius:4px;margin:2px;font-size:11px;display:inline-block;'>{tag}</span>"
                html += "</div>"
            sandbox = attr.get("sandbox_verdicts",{})
            if sandbox:
                html += "<b style='color:#aaa;'>Sandbox:</b><ul>"
                for sb, sv in list(sandbox.items())[:5]:
                    sv_col = {"malicious":"#ef5350","suspicious":"#ff9800"}.get(sv.get("verdict",""),"#66bb6a")
                    html += f"<li><span style='color:{sv_col};'>{sv.get('verdict','').upper()}</span> — {sb}</li>"
                html += "</ul>"
            if mal > 0:
                html += f"<br><b style='color:#ef5350;'>Zararlı Bulan Motorlar ({mal}):</b>"
                html += "<table style='width:100%;margin:6px 0;'>"
                cnt = 0
                for eng, res in attr.get("last_analysis_results",{}).items():
                    if res.get("category") in ("malicious","suspicious"):
                        rc = "#ef5350" if res.get("category") == "malicious" else "#ff9800"
                        html += (f"<tr><td style='color:#aaa;padding:2px 10px 2px 0;width:140px;'><b>{eng}</b></td>"
                                 f"<td style='color:{rc};font-size:12px;'>{res.get('result','')}</td></tr>")
                        cnt += 1
                        if cnt >= 20: break
                html += "</table>"

        elif ioc_type == "ip":
            html += make_chart(mal, sus, har, und, total)
            html += f'<div style="border-left:4px solid {col};padding:8px 12px;margin:8px 0;background:#111;">'
            html += f'<span style="color:{col};font-size:15px;font-weight:bold;">{mal} Zararlı / {sus} Şüpheli / {har} Temiz / {und} Tespit Yok</span></div>'
            html += "<table style='width:100%;border-collapse:collapse;margin:8px 0;'>"
            for lbl2, val2 in [("AS Owner", attr.get("as_owner","")), ("ASN", str(attr.get("asn",""))),
                               ("Ülke", attr.get("country","")), ("Network", attr.get("network",""))]:
                if val2:
                    html += (f"<tr><td style='color:#888;padding:3px 10px 3px 0;width:90px;'><b>{lbl2}</b></td>"
                             f"<td style='color:#ccc;'>{val2}</td></tr>")
            html += "</table>"
            cats = list(set((attr.get("categories") or {}).values()))[:5]
            if cats: html += f'<b style="color:#aaa;">Kategoriler:</b> {", ".join(cats)}<br>'
            if mal > 0 or sus > 0:
                html += "<br><b style='color:#ef5350;'>Zararlı/Şüpheli Bulan Motorlar:</b><table style='width:100%;margin:6px 0;'>"
                cnt = 0
                for eng, res in (attr.get("last_analysis_results") or {}).items():
                    if res.get("category") in ("malicious","suspicious"):
                        rc = "#ef5350" if res.get("category") == "malicious" else "#ff9800"
                        html += (f"<tr><td style='color:#aaa;padding:2px 10px 2px 0;width:160px;'><b>{eng}</b></td>"
                                 f"<td style='color:{rc};font-size:12px;'>{res.get('result','')}</td></tr>")
                        cnt += 1
                        if cnt >= 20: break
                html += "</table>"

        elif ioc_type == "domain":
            html += make_chart(mal, sus, har, und, total)
            html += f'<div style="border-left:4px solid {col};padding:8px 12px;margin:8px 0;background:#111;">'
            html += f'<span style="color:{col};font-size:15px;font-weight:bold;">{mal} Zararlı / {sus} Şüpheli / {har} Temiz</span></div>'
            html += "<table style='width:100%;border-collapse:collapse;margin:8px 0;'>"
            for lbl2, val2 in [("Registrar", attr.get("registrar","")),
                               ("Oluşturma", self._ts(attr.get("creation_date",0))),
                               ("Güncelleme", self._ts(attr.get("last_update_date",0)))]:
                if val2:
                    html += (f"<tr><td style='color:#888;padding:3px 10px 3px 0;width:90px;'><b>{lbl2}</b></td>"
                             f"<td style='color:#ccc;'>{val2}</td></tr>")
            html += "</table>"
            dns_recs = (attr.get("last_dns_records") or [])[:5]
            if dns_recs:
                html += "<b style='color:#aaa;'>Son DNS Kayıtları:</b><ul>"
                for rec in dns_recs:
                    html += f"<li>{rec.get('type','')} → {rec.get('value','')}</li>"
                html += "</ul>"
            if mal > 0 or sus > 0:
                html += "<br><b style='color:#ef5350;'>Zararlı/Şüpheli Bulan Motorlar:</b><table style='width:100%;margin:6px 0;'>"
                cnt = 0
                for eng, res in (attr.get("last_analysis_results") or {}).items():
                    if res.get("category") in ("malicious","suspicious"):
                        rc = "#ef5350" if res.get("category") == "malicious" else "#ff9800"
                        html += (f"<tr><td style='color:#aaa;padding:2px 10px 2px 0;width:160px;'><b>{eng}</b></td>"
                                 f"<td style='color:{rc};font-size:12px;'>{res.get('result','')}</td></tr>")
                        cnt += 1
                        if cnt >= 20: break
                html += "</table>"

        html += "</div>"
        return f"VT {mal}/{total} - {lbl}", html

    def _malwarebazaar(self, value, ioc_type):
        key = keyring.get_password("atmacaioc", "MALWAREBAZAAR")
        lbl = value[:20] + "…"
        headers = {}
        if key: headers["Auth-Key"] = key
        payload = {"query": "get_info", "hash": value}
        r = requests.post("https://mb-api.abuse.ch/api/v1/",
                          data=payload, headers=headers, timeout=15)
        if r.status_code != 200:
            return f"MB - {lbl}", f"<i>HTTP {r.status_code}: {r.text[:200]}</i>"
        try: d = r.json()
        except: return f"MB - {lbl}", f"<i>JSON parse hatası: {r.text[:200]}</i>"

        status = d.get("query_status", "")
        if status == "hash_not_found":
            html = ("<div style='background:#122a14;border:2px solid #1e5a22;border-radius:10px;padding:16px;margin:6px;'>"
                    f"<h2 style='color:#66bb6a;margin:0 0 8px 0;'>✅ MalwareBazaar: Temiz</h2>"
                    f"<p style='color:#aaa;'>Bu hash MalwareBazaar veritabanında bulunamadı.</p></div>")
            return f"MB Temiz - {lbl}", html
        if status in ("unauthorized", "no_auth"):
            return f"MB - {lbl}", ("<div style='background:#2a1e10;border:2px solid #5a3c10;border-radius:10px;padding:16px;margin:6px;'>"
                                   "<h3 style='color:#ff9800;'>MalwareBazaar — API Anahtarı Gerekli</h3>"
                                   "<a href='https://bazaar.abuse.ch/api/' style='color:#64b5f6;'>bazaar.abuse.ch/api/</a></div>")
        if status != "ok":
            return f"MB - {lbl}", f"<div style='background:#1e1e1e;padding:12px;border-radius:8px;'><b style='color:#ff9800;'>Durum:</b> <code>{status}</code></div>"

        data_list = d.get("data") or []
        if not data_list:
            return f"MB - {lbl}", "<div style='background:#1e1e2a;padding:16px;border-radius:10px;'><h3 style='color:#ff9800;'>Veri Bulunamadı</h3></div>"
        info = data_list[0]

        sig    = info.get("signature") or ""
        clamav = info.get("clamav_detection") or ""
        tags   = info.get("tags") or []
        reporter = info.get("reporter") or ""
        mal_tags = {"malware","trojan","ransomware","rat","stealer","loader","dropper","botnet","backdoor","spyware","worm","virus","keylogger"}
        is_mal = bool(sig or clamav or any(t.lower() in mal_tags for t in tags))

        if is_mal:
            bg, bdr, hcol = "#2a1212", "#5a2020", "#ef5350"
            verdict_icon  = "🔴 ZARARLII"
        else:
            bg, bdr, hcol = "#122010", "#1e4a20", "#66bb6a"
            verdict_icon  = "🟡 Bilinmiyor / Temiz"

        html  = f'<div style="background:{bg};border:2px solid {bdr};border-radius:10px;padding:16px;margin:6px;">'
        html += f'<h2 style="color:{hcol};margin:0 0 10px 0;border-bottom:1px solid {bdr};padding-bottom:8px;">{verdict_icon} — MalwareBazaar</h2>'

        if sig:
            html += (f'<div style="background:#3a1010;border-left:4px solid #ef5350;padding:10px 14px;border-radius:6px;margin-bottom:10px;">'
                     f'<span style="color:#ef5350;font-size:15px;font-weight:bold;">⚠ Zararlı Yazılım Ailesi: {sig}</span></div>')
        if clamav:
            html += (f'<div style="background:#3a2010;border-left:4px solid #ff9800;padding:8px 14px;border-radius:6px;margin-bottom:10px;">'
                     f'<span style="color:#ff9800;">🦠 ClamAV: {clamav}</span></div>')

        html += "<table style='width:100%;border-collapse:collapse;margin-bottom:10px;'>"
        for hl, hv in [("SHA256", info.get("sha256_hash","")), ("SHA1", info.get("sha1_hash","")),
                       ("MD5", info.get("md5_hash","")), ("ImpHash", info.get("imphash","")),
                       ("SSDeep", (info.get("ssdeep","") or "")[:70]),
                       ("TLSH", (info.get("tlsh","") or "")[:50])]:
            if hv:
                html += (f"<tr><td style='color:#888;padding:3px 10px 3px 0;width:70px;vertical-align:top;'><b>{hl}</b></td>"
                         f"<td style='color:#ccc;font-family:Consolas;font-size:11px;word-break:break-all;'>{hv}</td></tr>")
        html += "</table>"

        file_size = info.get("file_size")
        size_str  = f"{int(file_size):,} byte" if file_size else ""
        html += "<table style='width:100%;border-collapse:collapse;margin-bottom:10px;'>"
        for fl, fv in [
            ("Dosya Adı", info.get("file_name","")),
            ("Dosya Tipi", info.get("file_type","")),
            ("MIME", info.get("mime_type","")),
            ("Boyut", size_str),
            ("İlk Görülme", (info.get("first_seen","") or "")[:16]),
            ("Son Görülme", (info.get("last_seen","") or "")[:16]),
            ("Kaynak Ülke", info.get("origin_country","")),
            ("Reporter", reporter),
        ]:
            if fv:
                html += (f"<tr><td style='color:#888;padding:3px 10px 3px 0;width:100px;'><b>{fl}</b></td>"
                         f"<td style='color:#ddd;'>{fv}</td></tr>")
        html += "</table>"

        if tags:
            tag_colors = {"exe":"#1565c0","dll":"#1565c0","ransomware":"#b71c1c","stealer":"#e65100",
                          "rat":"#6a1b9a","loader":"#e65100","botnet":"#880e4f","backdoor":"#4a0080","keylogger":"#b71c1c"}
            html += "<div style='margin:8px 0;'><b style='color:#aaa;'>Etiketler: </b>"
            for tag in tags[:15]:
                tc = tag_colors.get(tag.lower(), "#2a2a3a")
                html += (f"<span style='background:{tc};color:white;padding:2px 8px;border-radius:4px;"
                         f"margin:2px;font-size:11px;display:inline-block;'>{tag}</span>")
            html += "</div>"

        intel = info.get("intelligence") or {}
        if not isinstance(intel, dict): intel = {}
        downloads = intel.get("downloads", 0); uploads = intel.get("uploads", 0)
        if downloads or uploads:
            html += (f'<div style="background:#1a1a2a;padding:8px 12px;border-radius:6px;margin:8px 0;">'
                     f'<b style="color:#aaa;">İstihbarat:</b> '
                     f'<span style="color:#64b5f6;">⬇ {downloads} indirme</span> &nbsp; '
                     f'<span style="color:#81c784;">⬆ {uploads} yükleme</span></div>')

        sha256v = info.get("sha256_hash","")
        if sha256v:
            html += f'<br><a href="https://bazaar.abuse.ch/sample/{sha256v}/" style="color:#64b5f6;font-size:13px;">🔗 MalwareBazaar Detay Sayfası</a>'
        html += "</div>"
        return f"MB {'🔴 ' + sig[:15] if sig else '🟡?'} - {lbl}", html

    def _hybridanalysis(self, value, ioc_type):
        key = keyring.get_password("atmacaioc", "HYBRIDANALYSIS")
        if not key: return f"HA - {value[:20]}…", "<i>API anahtarı eksik</i>"
        lbl = value[:20] + "…"
        headers = {"api-key": key, "User-Agent": "Falcon Sandbox",
                   "Content-Type": "application/x-www-form-urlencoded", "accept": "application/json"}
        r = requests.get("https://www.hybrid-analysis.com/api/v2/search/hash",
                         headers=headers, params={"hash": value}, timeout=15)
        if r.status_code == 401: return f"HA - {lbl}", "<h3 style='color:#ef5350;'>401 Unauthorized</h3>"
        if r.status_code == 429: return f"HA - {lbl}", "<h3 style='color:#ff9800;'>Rate limit (429)</h3>"
        if r.status_code != 200: return f"HA - {lbl}", f"<i>HTTP {r.status_code}: {r.text[:200]}</i>"
        raw = r.json()
        best = None
        def verdict_rank(v): return {"malicious":3,"suspicious":2,"no specific threat":1}.get(v or "",0)
        if isinstance(raw, dict):
            result_val = raw.get("result") or raw.get("results")
            if isinstance(result_val, dict): best = result_val
            elif isinstance(result_val, list) and result_val:
                best = max([x for x in result_val if isinstance(x, dict)], key=lambda x: verdict_rank(x.get("verdict","")))
            elif not result_val and (raw.get("verdict") or raw.get("sha256")): best = raw
        elif isinstance(raw, list) and raw:
            best = max([x for x in raw if isinstance(x, dict)], key=lambda x: verdict_rank(x.get("verdict","")))
        if not best:
            return f"HA - {lbl}", (f"<h3 style='color:#ff9800;'>HybridAnalysis: Kayıt Bulunamadı</h3>"
                                   f"<p><a href='https://www.hybrid-analysis.com/sample/{value}' style='color:#64b5f6;'>HA'da ara →</a></p>")
        verdict = best.get("verdict","unknown")
        threat_score = best.get("threat_score") or best.get("multiscan_result","N/A")
        col = {"malicious":"#ef5350","suspicious":"#ff9800"}.get(verdict,"#66bb6a")
        bg  = "#2a1212" if verdict == "malicious" else "#2a1e10" if verdict == "suspicious" else "#1a1a1a"
        bdr = "#5a2020" if verdict == "malicious" else "#5a3c10" if verdict == "suspicious" else "#333"
        html  = f'<div style="background:{bg};border:2px solid {bdr};border-radius:10px;padding:16px;margin:6px;">'
        html += f'<h2 style="color:{col};margin:0 0 10px 0;">HybridAnalysis: {lbl}</h2>'
        html += f'<div style="border-left:4px solid {col};padding:8px 12px;border-radius:6px;margin-bottom:10px;background:#111;">'
        html += f'<span style="color:{col};font-size:15px;font-weight:bold;">{verdict.upper()}</span>'
        if threat_score and threat_score != "N/A":
            html += f' &nbsp;—&nbsp; Tehdit Skoru: {threat_score}/100'
        html += '</div>'
        html += "<table style='width:100%;border-collapse:collapse;margin:8px 0;'>"
        for fl, fv in [("Dosya Adı", best.get("last_file_name","") or best.get("submit_name","")),
                       ("SHA256", best.get("sha256","")), ("Mimari", best.get("architecture","")),
                       ("Boyut", (str(best.get("size","")) + " byte") if best.get("size") else ""),
                       ("İlk Analiz", (best.get("analysis_start_time","") or "")[:16])]:
            if fv:
                html += (f"<tr><td style='color:#888;padding:3px 10px 3px 0;width:100px;vertical-align:top;'><b>{fl}</b></td>"
                         f"<td style='color:#ccc;font-family:Consolas;font-size:12px;word-break:break-all;'>{fv}</td></tr>")
        html += "</table>"
        related = best.get("related_reports") or best.get("reports") or []
        if related:
            html += f"<b style='color:#aaa;'>Analiz Raporları ({len(related)}):</b><ul>"
            for rep in related[:5]:
                if not isinstance(rep, dict): continue
                rv = rep.get("verdict",""); renv = rep.get("environment_id",""); rjob = rep.get("job_id","")
                rsha = rep.get("sha256","") or best.get("sha256","")
                rc = {"malicious":"#ef5350","suspicious":"#ff9800","no specific threat":"#66bb6a"}.get(rv,"#aaa")
                link = f'<a href="https://www.hybrid-analysis.com/sample/{rsha}/{rjob}" style="color:#64b5f6;">Rapor</a>' if rsha else ""
                html += f"<li><span style='color:{rc};'>{rv or '?'}</span> — Env:{renv} {link}</li>"
            html += "</ul>"
        scanners = best.get("scanners") or best.get("scanners_v2") or []
        if scanners:
            detects = [(s.get("name",""), s.get("status",""), s.get("anti_virus_results",""))
                       for s in scanners if isinstance(s, dict) and s.get("status") not in ("clean","whitelisted","")]
            if detects:
                html += "<b style='color:#aaa;'>AV Sonuçları:</b><ul>"
                for name, status, avr in detects[:8]:
                    sc = "#ef5350" if status == "malicious" else "#ff9800"
                    html += f"<li><b style='color:{sc};'>{name}</b>: {status} {avr}</li>"
                html += "</ul>"
        sha256v = best.get("sha256","")
        if sha256v:
            html += f'<br><a href="https://www.hybrid-analysis.com/sample/{sha256v}" style="color:#64b5f6;">🔗 HA Detay Sayfası</a>'
        html += "</div>"
        return f"HA {verdict} - {lbl}", html

    def _urlscan(self, value, ioc_type):
        key     = keyring.get_password("atmacaioc", "URLSCAN")
        headers = {"Content-Type": "application/json"}
        if key: headers["API-Key"] = key
        r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{value}&size=5",
                         headers=headers, timeout=12)
        lbl = value
        if r.status_code == 429: return f"URLScan - {lbl}", "<h3 style='color:#ff9800;'>Rate limit (429)</h3>"
        if r.status_code != 200: return f"URLScan - {lbl}", f"<i>HTTP {r.status_code}</i>"
        results = r.json().get("results",[])
        total   = r.json().get("total", 0)
        html    = f"<h3>URLScan.io: {lbl}</h3><b>Toplam:</b> {total}<br>"
        if results:
            html += "<ul>"
            for res in results[:5]:
                html += f"<li>{res.get('task',{}).get('time','')[:10]} — {res.get('page',{}).get('url','')[:60]}</li>"
            html += "</ul>"
        return f"URLScan - {lbl}", html


# ============================================================
# YEREL LOG ANALİZİ — OllamaWorker (v6.2 — Fortigate desteği)
# ============================================================
class OllamaWorker(QThread):
    result_ready = pyqtSignal(str)
    error        = pyqtSignal(str)

    def __init__(self, base_url: str, model: str, log_text: str, analiz_tipi: str):
        super().__init__()
        self.base_url    = base_url.rstrip("/")
        self.model       = model.strip()
        self.log_text    = log_text
        self.analiz_tipi = analiz_tipi

    def run(self):
        try:
            html = self._analyze()
            self.result_ready.emit(html)
        except Exception as e:
            self.error.emit(str(e))

    # ──────────────────────────────────────────────────────
    # PROMPT MOTORU — her tip için kısa, net, yapılandırılmış
    # ──────────────────────────────────────────────────────
    def _analyze(self):
        import requests as _req

        analiz_tipi = self.analiz_tipi
        log_text    = self.log_text[:6000]

        # ── Fortigate / Firewall Trafik Logu
        if "Fortigate" in analiz_tipi or "Firewall Trafik" in analiz_tipi:
            prompt = f"""Sen kıdemli bir SOC analistisin. Aşağıdaki Fortigate firewall trafik logunu Türkçe analiz et.

=== LOG ===
{log_text}
=== LOG SONU ===

Logdaki GERÇEK alan değerlerini kullan. Hiçbir değeri uydurma.

## 📋 SOC BİLDİRİMİ
Aşağıdaki kalıbı logdaki gerçek değerlerle doldur:

Zararlı [srcip] ([srccountry]) IP adresinden [dstip] hedef IP'sine [dstport] numaralı port üzerinden gerçekleştirilen bağlantı denemesi[, DNAT ile [tranip]:[tranport] adresine yönlendirilerek kontrollü şekilde karşılanmış / direkt hedef sisteme ulaşmış] olup olay [tehdit seviyesi] riskli olarak değerlendirilmiştir. [Ek bağlam: honeypot ise "Cowrie honeypot ortamına yönlendirilmiştir", blacklist ise "Zararlı IP Blackliste eklenmiştir" gibi.] 

Servis adı "Cowrie" veya "honeypot" içeriyorsa bunu mutlaka yaz. action değerini parantez içinde belirt.

## 🎯 ÖZET
2-3 cümle teknik özet. Ülke, port, DNAT, honeypot/gerçek sistem gibi kritik detayları dahil et.

## 📍 Kaynak ve Hedef

### Kaynak (Source)
- IP: [srcip değeri]
- Port: [srcport değeri]
- Ülke: [srccountry değeri]
- Arayüz: [srcintf değeri]

### Hedef (Destination)
- IP: [dstip değeri]
- Port: [dstport değeri]
- Ülke: [dstcountry değeri]
- Arayüz: [dstintf değeri]
- DNAT Yönlendirme: [tranip]:[tranport] (varsa)
- İşletim Sistemi: [dstosname değeri]
- MAC: [dstmac değeri]

## 📊 TESPİT EDİLEN VERİLER

| Alan | Değer | Açıklama |
|------|-------|----------|
| Tarih/Saat | [date + time] | |
| Cihaz Adı | [devname] | |
| Log ID | [logid] | |
| Protokol | TCP/[proto] | |
| Aksiyon | [action] | |
| Policy ID | [policyid] | |
| Servis | [service] | |
| Süre | [duration] sn | |
| Gönderilen | [sentbyte] byte / [sentpkt] paket | |
| Alınan | [rcvdbyte] byte / [rcvdpkt] paket | |
| Hedef Vendor | [dsthwvendor] | |
| Hedef OS | [dstosname] | |
| Session ID | [sessionid] | |

## ⚠️ GÜVENLİK DEĞERLENDİRMESİ
**Tehdit Seviyesi: DÜŞÜK / ORTA / YÜKSEK / KRİTİK**
Servis adı, kaynak ülke, DNAT hedefi (honeypot mu gerçek sistem mi?), paket sayısı ve süreye göre değerlendir.

## 🔍 NE OLDU?
Adım adım: hangi IP nereden geldi, hangi porta bağlandı, DNAT ne yaptı, bağlantı başarılı mı, trafik miktarı normal mi?

## 🛡️ ÖNERİLEN AKSIYONLAR
- Kaynak IP'yi AbuseIPDB ve VirusTotal'da sorgula
- Honeypot ise: tetikleme beklenen davranıştır, logla ve izle
- Gerçek SSH ise: auth loglarını incele, başarılı giriş var mı kontrol et
- Policy ve DNAT kuralını doğrula
- Tekrar eden kaynaklardan geliyorsa Blacklist'e ekle
"""

        # ── OT / ICS / SCADA
        elif "OT" in analiz_tipi or "ICS" in analiz_tipi or "SCADA" in analiz_tipi:
            prompt = f"""Sen kıdemli bir SOC analistisin. Aşağıdaki OT/ICS güvenlik logunu Türkçe analiz et.

=== LOG ===
{log_text}
=== LOG SONU ===

Logdaki GERÇEK değerleri kullan. Uydurma yapma.

ÖNEMLİ KURALLAR:
- Kaynak cihaz adı logda "*", "* (N)" veya boş ise: "belirtilmemiş (muhtemelen istemci bilgisayar)" yaz.
- Hedef cihazda hostname varsa (örn. D181224, L021054.uludag.local) onu kullan.
- Logda "Description" veya "Marker" alanı varsa MUTLAKA oku — bu alanda olay detayı yazar (örn. error code, kural açıklaması, event türü). SOC bildiriminde protokol adından SONRA bu description'ı kullan.
- "ERROR CODE detected" yerine logdaki gerçek error kodu (örn. 52866) ve açıklamasını yaz.
- Olay tipine göre (ağ erişimi, PLC programlama, hata kodu, kural ihlali vb.) uygun cümle kur.

## 📋 SOC BİLDİRİMİ
Aşağıdaki kalıbı doldur:

**Senaryo A — PLC/cihaz arası iletişim:**
[Kaynak IP] IP'li [kaynak cihaz adı — bilinmiyorsa "kaynak cihazı belirtilmemiş (muhtemelen istemci bilgisayar)"] cihazından [Hedef IP] ([Hedef hostname]) IP'li [hedef cihaz tipi: PLC/iş istasyonu/sunucu] cihaza doğru [protokol adı] protokolü üzerinden [Description/Marker alanındaki olay detayı — örn: "Error Code 52866 tespit edilmiştir" veya "PLC program yükleme işlemi gerçekleştirilmiştir"] tespit edilmiştir. [Varsa MITRE tekniği.] İlgili işlem bilginiz dahilinde midir?

**Senaryo B — Dış ağ erişimi:**
[Kaynak IP] IP'li ([kaynak cihaz adı — bilinmiyorsa "belirtilmemiş"]) kaynağından [Hedef hostname] ([Hedef IP]) hedefine doğru [protokol] üzerinden [Description alanındaki olay] tespit edilmiştir. [Risk değerlendirmesi.] İlgili işlem bilginiz dahilinde midir?

## 🎯 ÖZET
2-3 cümle: kaynak→hedef, protokol, olay türü (Description alanından), risk.

## 📍 Kaynak ve Hedef

### Kaynak (Source)
- IP: [Source IP adresi]
- MAC: [Source MAC adresi]
- Cihaz: [Device adı — yoksa "belirtilmemiş (muhtemelen istemci bilgisayar)"]

### Hedef (Destination)
- Hostname: [Destination Host name — yoksa "belirtilmemiş"]
- IP: [Destination IP adresi]
- MAC: [Destination MAC adresi]
- Cihaz Tipi: [PLC/sunucu/iş istasyonu — logdan çıkar]

## 📊 TESPİT EDİLEN VERİLER

| Alan | Değer | Açıklama |
|------|-------|----------|
| Tarih/Saat | | |
| Olay ID | | |
| Kural/Tetikleyen | | |
| Protokol | | |
| Teknoloji | | |
| Olay Türü | | |
| Description/Marker | | logdaki tam açıklamayı yaz |
| Başlangıç | | |
| Son Görülme | | |
| Toplam Görünme | | |

## ⚠️ GÜVENLİK DEĞERLENDİRMESİ
**Tehdit Seviyesi: DÜŞÜK / ORTA / YÜKSEK / KRİTİK**
Error code mu? Dış ağa çıkış mı? Yetkisiz erişim mi? PLC programlama mı? Buna göre değerlendir.

## 🔍 NE OLDU?
Teknik açıklama: kaynak, hedef, protokol, Description alanındaki detay, risk.

## 🛡️ ÖNERİLEN AKSIYONLAR
- Kaynağı doğrula: yetkili bir istemci mi?
- Error code ise: ilgili cihaz/operatör ile teyit et
- Dış IP ise: hedef IP'yi threat intel'de sorgula
- Yetkisiz ise: kaynağı izole et, change kaydı kontrol et
- Allowlist / firewall kurallarını gözden geçir
"""

        # ── EDR
        elif "EDR" in analiz_tipi:
            prompt = f"""Sen kıdemli bir SOC analistisin. Aşağıdaki EDR olayını Türkçe analiz et.

=== LOG ===
{log_text}
=== LOG SONU ===

Logdaki GERÇEK değerleri kullan. Uydurma yapma.

## 📋 SOC BİLDİRİMİ
Aşağıdaki kalıbı doldur (tüm değerleri logdan al):

İlgili host ([External IP veya Local IP]) üzerinde gerçekleşen olayda, kullanıcı [User/username] tarafından çalıştırılan [Process adı] süreci aracılığıyla açılan "[arşiv/dosya adı — Command Line'dan al]" [arşivinden çıkarılan / dosyasından] [tetiklenen dosya adı] dosyası [EDR platformu — CrowdStrike/Defender/SentinelOne] tarafından tespit edilip karantinaya alınmıştır.
Dosya sistemine yazılan [tetiklenen dosya adı], sensör üzerinde gerçekleştirilen makine öğrenimi tabanlı davranışsal analiz sonucunda yüksek güven seviyesinde zararlı olarak değerlendirilmiştir. Dosyanın [tespit gerekçesi: yüksek entropi, paketlenmiş yapı, zararlı yazılımlarla benzerlik vb.] nedeniyle "[IOA adı] ([Teknik ID])" tekniği kapsamında IOA oluşturulmuştur.

## 🎯 ÖZET
2-3 cümle: host, kullanıcı, dosya, aksiyon, tehdit tipi.

## 📊 TESPİT EDİLEN VERİLER

| Alan | Değer |
|------|-------|
| Host Adı | [hostname] |
| Kullanıcı | [user] |
| Process | [Process adı] |
| Command Line | [tam command line] |
| Tetiklenen Dosya Yolu | [Triggering indicator dosya yolu] |
| SHA256 | [SHA256 değeri] |
| External IP | [External IP] |
| Local IP | [Local IP] |
| Severity | [Severity] |
| Aksiyon | [Actions taken] |
| Teknik ID | [CST0007 vb.] |
| IOA Adı | [IOA name] |
| Başlangıç | [Start time] |
| Bitiş | [End time] |
| OS | [OS] |
| Sensor Versiyon | [Sensor version] |

## ⚠️ GÜVENLİK DEĞERLENDİRMESİ
**Tehdit Seviyesi: DÜŞÜK / ORTA / YÜKSEK / KRİTİK**
Karantina alındı mı? Hash prevalence nedir? Unique mi? Buna göre değerlendir.

## 🔍 NE OLDU?
Adım adım: kullanıcı ne yaptı → hangi dosya çıkarıldı → neden zararlı sayıldı → EDR ne yaptı.

## 🛡️ ÖNERİLEN AKSIYONLAR
- Host'u izole et ve forensic inceleme başlat
- SHA256 hash'ini VirusTotal ve MalwareBazaar'da sorgula
- Kullanıcının diğer aktivitelerini incele (lateral movement?)
- Arşiv dosyasının kaynağını belirle (e-posta, indirme, USB?)
- Diğer hostlarda aynı hash var mı kontrol et (internal prevalence)
"""

        # ── Genel Güvenlik / Windows Event / Firewall Policy / diğer
        elif "Windows Event" in analiz_tipi or "AccelOps" in analiz_tipi or "SIEM" in analiz_tipi or \
             "Policy Change" in analiz_tipi or "Config" in analiz_tipi or \
             "Kimlik" in analiz_tipi or "Brute" in analiz_tipi or \
             "Genel" in analiz_tipi or "Windows Event Log" in analiz_tipi or \
             "Linux" in analiz_tipi or "Web Sunucusu" in analiz_tipi or \
             "Veritabanı" in analiz_tipi or "Ağ Trafiği" in analiz_tipi or "Zararlı" in analiz_tipi:
            prompt = f"""Sen kıdemli bir SOC analistisin. Aşağıdaki güvenlik logunu Türkçe analiz et.
Kategori: {analiz_tipi}

=== LOG ===
{log_text}
=== LOG SONU ===

Logdaki GERÇEK değerleri kullan. Uydurma yapma.

ÖNEMLİ KURALLAR:
1. SOC bildiriminde saat bilgisini YAZMA — sadece tabloya koy.
2. Hangi kullanıcı, hangi sunucu/kaynak üzerinde, ne işlemi yaptı — bunu net belirt.
3. İşlemi yapan kullanıcı Subject/user alanından gelir. Target Account/hedef ise işlem yapılan nesnedir.
4. Logon Type varsa (3=Network, 2=Interactive, 10=RemoteInteractive vb.) belirt.
5. Workstation Name ve sunucu/bilgisayar adı varsa SOC bildiriminde kullan.
6. Firewall Policy Change logunda: hangi kullanıcı, hangi GUI/kaynak'tan, hangi action (Add/Edit/Delete), hangi policy ID, hangi değişiklikler (srcaddr, dstaddr, service, status vb.) yaptı — hepsini açık yaz.

## 📋 SOC BİLDİRİMİ
Logdaki gerçek değerleri kullanarak olay tipine göre uygun kalıpla doldur:

**Windows Event (şifre sıfırlama, grup ekleme, hesap değişikliği vb.):**
[Subject/Account Name — işlemi yapan kullanıcı] kullanıcısı [computer/sunucu adı] sunucusu üzerinde [hedef hesap/grup/nesne] üzerinde [işlem: şifre sıfırlama / gruba ekleme / hesap oluşturma vb.] gerçekleştirmiştir. [Logon Type varsa belirt.] İlgili işlem bilginiz dahilinde midir?

**Brute Force / Failed Logon:**
[kullanıcı] kullanıcısı [sunucu adı] sunucusu [Workstation Name] hostu ile ağ üzerinden çok sayıda hatalı giriş gerçekleştirmiştir. [Logon Type N (açıklama) olarak kaydedilmiştir.] İlgili işlem bilginiz dahilinde midir?

**Firewall Policy Change (Fortigate/Palo Alto vb.):**
[user] kullanıcısı [ui/kaynak IP veya arayüz] üzerinden [devname] cihazında [action: Add/Edit/Delete] işlemi gerçekleştirmiş, [cfgpath/policy türü] [cfgobj/policy ID]'li kural [değişiklik özeti: status değişikliği, srcaddr/dstaddr güncelleme, servis ekleme vb.] şeklinde düzenlenmiştir. İlgili işlem bilginiz dahilinde midir?

## 🎯 ÖZET
2-3 cümle özet. Kim, nerede, ne yaptı, neden önemli?

## 📊 TESPİT EDİLEN VERİLER

| Alan | Değer | Açıklama |
|------|-------|----------|

Logdaki tüm önemli alanları doldur:
- Windows Event için: Event ID, işlemi yapan (Subject), hedef (Target Account/Group), sunucu, domain, Logon Type, tarih
- Firewall Policy için: user, ui, devname, action, cfgpath, cfgobj, değişen alanlar (cfgattr), tarih, msg

## ⚠️ GÜVENLİK DEĞERLENDİRMESİ
**Tehdit Seviyesi: DÜŞÜK / ORTA / YÜKSEK / KRİTİK**
Yetkisiz değişiklik mi? Ayrıcalıklı hesap işlemi mi? Policy disable mi? Buna göre değerlendir.

## 🔍 NE OLDU?
Adım adım teknik açıklama: kim, nereden, neye, ne yaptı.

## 🛡️ ÖNERİLEN AKSIYONLAR
- Windows Event ise: işlemi yapan hesabın yetkisini doğrula, change kaydı var mı kontrol et
- Firewall Policy ise: change yönetimi onaylı mı, etkiyi değerlendir, geri alma gerekli mi?
- Şüpheli ise: ilgili hesabı kilitle, CISO ve sistem yöneticisine bildir
"""

        # ── Fallback — hiçbiri eşleşmezse
        else:
            prompt = f"""Sen kıdemli bir SOC analistisin. Aşağıdaki güvenlik logunu Türkçe analiz et.
Kategori: {analiz_tipi}

=== LOG ===
{log_text}
=== LOG SONU ===

## 📋 SOC BİLDİRİMİ
Logdaki gerçek değerleri kullanarak kısa ve net bir bildirim yaz.

## 🎯 ÖZET
## 📊 TESPİT EDİLEN VERİLER
| Alan | Değer | Açıklama |
|------|-------|----------|

## ⚠️ GÜVENLİK DEĞERLENDİRMESİ
**Tehdit Seviyesi: DÜŞÜK / ORTA / YÜKSEK / KRİTİK**

## 🔍 NE OLDU?
## 🛡️ ÖNERİLEN AKSIYONLAR
"""
        url = f"{self.base_url}/api/chat"
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": 4096},
        }
        try:
            r = _req.post(url, json=payload, timeout=300)
        except _req.exceptions.RequestException as e:
            return (
                "<h3 style='color:#ff9800;'>Yerel modele bağlanılamadı</h3>"
                "<p style='color:#aaa;'>Ollama çalışıyor mu kontrol edin (<code>http://127.0.0.1:11434</code>).</p>"
                "<p style='color:#888;'><b>Önerilen modeller:</b><br>"
                "<code>ollama pull qwen2.5:14b</code> (en iyi — 14B)<br>"
                "<code>ollama pull mistral</code> (hızlı — 7B)<br>"
                "<code>ollama pull llama3.1:8b</code> (alternatif)</p>"
                f"<pre style='color:#ef5350;'>{e}</pre>"
            )

        data = r.json() if r.text else {}
        if r.status_code != 200:
            err = data.get("error") if isinstance(data, dict) else r.text
            return f"<h3 style='color:#ef5350;'>Ollama HTTP {r.status_code}</h3><pre style='color:#aaa;'>{err}</pre>"

        msg = (data.get("message") or {}) if isinstance(data, dict) else {}
        llm_text = msg.get("content")
        if not llm_text:
            return f"<h3 style='color:#ef5350;'>Yanıt boş</h3><pre>{str(data)[:800]}</pre>"

        return self._md_to_html(llm_text)

    def _md_to_html(self, text: str) -> str:
        import re as _re

        lines = text.splitlines()
        out   = "<div style='font-family:Segoe UI,sans-serif;color:#e0e0e0;padding:4px;'>"
        i     = 0

        def inline(s):
            s = _re.sub(r'\*\*(.+?)\*\*', r"<b style='color:#fff;'>\1</b>", s)
            s = _re.sub(r'`([^`]+)`', r"<code style='background:#0d0d0d;color:#a8d8a8;padding:1px 5px;border-radius:3px;font-size:12px;'>\1</code>", s)
            for word, badge in [
                ("KRİTİK", "<span style='background:#b71c1c;color:white;padding:2px 8px;border-radius:4px;font-weight:bold;'>🔴 KRİTİK</span>"),
                ("YÜKSEK", "<span style='background:#e65100;color:white;padding:2px 8px;border-radius:4px;font-weight:bold;'>🟠 YÜKSEK</span>"),
                ("ORTA",   "<span style='background:#f57f17;color:black;padding:2px 8px;border-radius:4px;font-weight:bold;'>🟡 ORTA</span>"),
                ("DÜŞÜK",  "<span style='background:#2e7d32;color:white;padding:2px 8px;border-radius:4px;font-weight:bold;'>🟢 DÜŞÜK</span>"),
            ]:
                s = s.replace(word, badge)
            return s

        in_soc_block = False
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            if not stripped:
                i += 1
                continue

            if stripped.startswith("```"):
                code_lines = []
                i += 1
                while i < len(lines) and not lines[i].strip().startswith("```"):
                    code_lines.append(lines[i].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"))
                    i += 1
                out += (f"<pre style='background:#0d0d0d;border:1px solid #2a2a2a;border-radius:6px;"
                        f"padding:10px 14px;font-size:12px;color:#a8d8a8;margin:8px 0;'>"
                        f"{''.join(l + chr(10) for l in code_lines)}</pre>")
                i += 1
                continue

            h = _re.match(r'^(#{1,4})\s+(.*)', stripped)
            if h:
                lvl  = len(h.group(1))
                txt  = inline(h.group(2))
                size = {1:"22px",2:"18px",3:"16px",4:"14px"}.get(lvl,"15px")
                col  = {1:"#ef5350",2:"#ff9800",3:"#64b5f6",4:"#81c784"}.get(lvl,"#ccc")
                if "SOC" in h.group(2) and "BİLDİRİM" in h.group(2):
                    if in_soc_block:
                        out += "</div>"
                    out += (
                        "<div style='background:#020d1a;border:2px solid #1976d2;"
                        "border-radius:10px;padding:16px 18px;margin:16px 0;"
                        "box-shadow:0 0 12px rgba(25,118,210,0.15);'>"
                        "<div style='font-size:14px;font-weight:bold;color:#64b5f6;"
                        "margin-bottom:10px;border-bottom:1px solid #1976d2;padding-bottom:8px;'>"
                        "📋 SOC BİLDİRİMİ</div>"
                    )
                    in_soc_block = True
                else:
                    if in_soc_block:
                        out += "</div>"
                        in_soc_block = False
                    out += (f"<div style='font-size:{size};font-weight:bold;color:{col};"
                            f"margin:14px 0 6px 0;border-left:3px solid {col};padding-left:10px;'>{txt}</div>")
                i += 1
                continue

            if stripped.startswith("|") and "|" in stripped[1:]:
                table_lines = []
                while i < len(lines) and lines[i].strip().startswith("|"):
                    table_lines.append(lines[i].strip())
                    i += 1
                if len(table_lines) >= 2:
                    headers = [c.strip() for c in table_lines[0].strip("|").split("|")]
                    out += "<table style='width:100%;border-collapse:collapse;margin:8px 0;'>"
                    out += "<tr>"
                    for h2 in headers:
                        out += (f"<th style='background:#1e1e2a;color:#64b5f6;padding:7px 10px;"
                                f"border-bottom:2px solid #333;text-align:left;font-size:12px;'>{inline(h2)}</th>")
                    out += "</tr>"
                    for row_line in table_lines[2:]:
                        cells = [c.strip() for c in row_line.strip("|").split("|")]
                        out += "<tr>"
                        for c in cells:
                            out += (f"<td style='padding:6px 10px;border-bottom:1px solid #222;"
                                    f"font-size:12px;color:#ccc;'>{inline(c)}</td>")
                        out += "</tr>"
                    out += "</table>"
                continue

            if _re.match(r'^[-*•\d+\.] ', stripped):
                out += "<ul style='margin:4px 0;padding-left:20px;'>"
                while i < len(lines) and _re.match(r'^\s*[-*•\d+\.] ', lines[i]):
                    item = _re.sub(r'^\s*[-*•\d+\.] ', '', lines[i].strip())
                    color = '#90caf9' if in_soc_block else '#bbb'
                    out += f"<li style='color:{color};margin:3px 0;font-size:13px;'>{inline(item)}</li>"
                    i += 1
                out += "</ul>"
                continue

            if _re.match(r'^[-_*]{3,}$', stripped):
                out += "<hr style='border:none;border-top:1px solid #2a2a2a;margin:10px 0;'/>"
                i += 1
                continue

            if in_soc_block:
                out += (
                    f"<p style='color:#bbdefb;margin:0;font-size:13px;line-height:1.9;"
                    f"font-family:Consolas,monospace;background:#041424;padding:12px 14px;"
                    f"border-radius:6px;border-left:3px solid #1976d2;word-break:break-word;'>"
                    f"{inline(stripped)}</p>"
                )
            else:
                out += f"<p style='color:#ccc;margin:5px 0;font-size:13px;line-height:1.7;'>{inline(stripped)}</p>"
            i += 1

        if in_soc_block:
            out += "</div>"
        out += "</div>"
        return out


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("API Anahtarları & Servis Ayarları")
        self.setGeometry(150, 100, 620, 780)
        self.parent_win = parent
        self._inputs = {}
        self.setStyleSheet("""
            QDialog     { background-color:#1a1a1a; color:#e0e0e0; }
            QScrollArea { background:#1a1a1a; border:none; }
            QWidget#scroll_content { background:#1a1a1a; }
            QLabel      { color:#e0e0e0; font-size:13px; }
            QGroupBox   { border:1px solid #3a3a3a; border-radius:8px;
                          margin-top:10px; padding:10px 8px 8px 8px; }
            QGroupBox::title { subcontrol-origin:margin; left:10px; padding:0 4px;
                               font-size:12px; font-weight:bold; }
            QLineEdit   { background-color:#252525; color:#e0e0e0; padding:9px 12px;
                          border-radius:6px; border:1px solid #3a3a3a; font-size:13px; }
            QLineEdit:focus { border:1px solid #c62828; }
            QPushButton { background-color:#c62828; color:white; padding:10px 20px;
                          border-radius:8px; font-weight:bold; font-size:13px; }
            QPushButton:hover { background-color:#b71c1c; }
        """)
        self._init_ui()

    def _init_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;background:#1a1a1a;}")
        content = QWidget()
        content.setObjectName("scroll_content")
        layout = QVBoxLayout(content)
        layout.setSpacing(10)
        layout.setContentsMargins(18, 18, 18, 12)

        hdr = QLabel("🔑  API Anahtarları")
        hdr.setStyleSheet("font-size:18px; font-weight:bold; color:#e0e0e0; padding-bottom:4px;")
        layout.addWidget(hdr)

        GROUPS = [
            ("🌐  IP Sağlayıcıları", "#1565c0", [
                ("AbuseIPDB",      "IP kötüye kullanım raporu, güven skoru",     True),
                ("Shodan",         "Açık portlar, banner, CVE, DNS çözümleme",   True),
                ("GreyNoise",      "IP noise/sınıflandırma, RIOT",               True),
            ]),
            ("🔀  Çok Amaçlı  (IP · Hash · Domain)", "#7b1fa2", [
                ("OTX",            "AlienVault — pulse, geo, passive DNS",        True),
                ("VirusTotal",     "70+ motor, sandbox, WHOIS, DNS kayıtları",   True),
            ]),
            ("🔑  Hash Sağlayıcıları", "#4a148c", [
                ("HybridAnalysis", "Sandbox, MITRE ATT&CK, AV oranı",           True),
                ("MalwareBazaar",  "Ücretsiz — anahtar opsiyonel",              False),
            ]),
            ("🌍  Domain Sağlayıcıları", "#1b5e20", [
                ("URLScan",        "Geçmiş taramalar — anahtar ile yeni tarama", False),
            ]),
        ]

        for group_title, color, members in GROUPS:
            grp = QGroupBox(group_title)
            grp.setStyleSheet(f"QGroupBox{{color:{color};border:1px solid #2a2a2a;border-radius:8px;"
                              f"margin-top:10px;padding:12px 8px 8px 8px;}}"
                              f"QGroupBox::title{{color:{color};subcontrol-origin:margin;left:10px;padding:0 4px;font-size:12px;font-weight:bold;}}")
            form = QFormLayout()
            form.setVerticalSpacing(8)
            form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            for name, desc, required in members:
                cfg   = PROVIDERS[name]
                kname = cfg.get("key_name")
                line  = QLineEdit()
                line.setMinimumWidth(320)
                if kname:
                    saved = keyring.get_password("atmacaioc", kname)
                    if saved:
                        line.setText(saved)
                        line.setEchoMode(QLineEdit.EchoMode.Password)
                    placeholder = "Opsiyonel — boş bırakabilirsin" if not required else "API anahtarını buraya gir…"
                    line.setPlaceholderText(placeholder)
                else:
                    line.setPlaceholderText("Anahtar gerektirmez — her zaman aktif")
                    line.setReadOnly(True)
                row_label = QLabel(f"<b>{name}</b><br><span style='color:#555;font-size:11px;'>{desc}</span>")
                row_label.setTextFormat(Qt.TextFormat.RichText)
                row_label.setMinimumWidth(160)
                form.addRow(row_label, line)
                reg  = cfg.get("register_url","")
                rate = cfg.get("rate_limit","")
                if reg:
                    link_lbl = QLabel(f'<a href="{reg}" style="color:#64b5f6;font-size:11px;">🔗 Kayıt / API key al</a>'
                                      f'<span style="color:#444;font-size:11px;">  —  {rate}</span>')
                    link_lbl.setOpenExternalLinks(True)
                    link_lbl.setTextFormat(Qt.TextFormat.RichText)
                    form.addRow("", link_lbl)
                self._inputs[name] = line
            grp.setLayout(form)
            layout.addWidget(grp)

        show_btn = QPushButton("👁  Anahtarları Göster / Gizle")
        show_btn.setFixedHeight(28)
        show_btn.setStyleSheet("QPushButton{background:transparent;color:#555;border:1px solid #333;"
                               "border-radius:6px;font-size:11px;padding:3px 10px;}"
                               "QPushButton:hover{color:#aaa;border-color:#555;}")
        show_btn.clicked.connect(self._toggle_visibility)
        layout.addWidget(show_btn, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll)

        btn_bar = QWidget()
        btn_bar.setStyleSheet("background:#1a1a1a;border-top:1px solid #2a2a2a;")
        btn_layout = QHBoxLayout(btn_bar)
        btn_layout.setContentsMargins(18, 10, 18, 12)
        btn_layout.addStretch()
        cancel_btn = QPushButton("İptal")
        cancel_btn.setStyleSheet("QPushButton{background:#2a2a2a;color:#aaa;border-radius:8px;padding:8px 20px;} QPushButton:hover{background:#3a3a3a;}")
        cancel_btn.clicked.connect(self.reject)
        save_btn = QPushButton("💾  Kaydet")
        save_btn.clicked.connect(self._save)
        btn_layout.addWidget(cancel_btn)
        btn_layout.addWidget(save_btn)
        outer.addWidget(btn_bar)

    def _toggle_visibility(self):
        for name, line in self._inputs.items():
            if line.isReadOnly(): continue
            line.setEchoMode(
                QLineEdit.EchoMode.Normal if line.echoMode() == QLineEdit.EchoMode.Password
                else QLineEdit.EchoMode.Password
            )

    def _save(self):
        saved_count = 0
        for name, line in self._inputs.items():
            cfg = PROVIDERS[name]
            kn  = cfg.get("key_name")
            if not kn:
                PROVIDERS[name]["enabled"] = True
                if name in self.parent_win.provider_checkboxes:
                    self.parent_win.provider_checkboxes[name].setChecked(True)
                continue
            val = line.text().strip()
            if val:
                keyring.set_password("atmacaioc", kn, val)
                PROVIDERS[name]["enabled"] = True
                saved_count += 1
            else:
                try: keyring.delete_password("atmacaioc", kn)
                except: pass
                PROVIDERS[name]["enabled"] = cfg.get("key_optional", False)
            if name in self.parent_win.provider_checkboxes:
                self.parent_win.provider_checkboxes[name].setChecked(PROVIDERS[name]["enabled"])
        QMessageBox.information(self, "Kaydedildi", f"{saved_count} API anahtarı kaydedildi.")
        self.accept()


class SocRefWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    @staticmethod
    def _generate_password(length, use_lower, use_upper, use_digits, use_symbols):
        pools = []; required = []
        if use_lower:   pools.append(string.ascii_lowercase); required.append(secrets.choice(string.ascii_lowercase))
        if use_upper:   pools.append(string.ascii_uppercase); required.append(secrets.choice(string.ascii_uppercase))
        if use_digits:  pools.append(string.digits);          required.append(secrets.choice(string.digits))
        if use_symbols:
            sym = "!@#$%^&*()-_=+[]{};:,.?/\\|~"
            pools.append(sym); required.append(secrets.choice(sym))
        if not pools: raise ValueError("En az 1 karakter türü seçmelisin.")
        min_len = len(required)
        if length < min_len: length = min_len
        all_chars = "".join(pools)
        rest = [secrets.choice(all_chars) for _ in range(length - len(required))]
        pwd_list = required + rest
        secrets.SystemRandom().shuffle(pwd_list)
        return "".join(pwd_list)

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        header = QWidget()
        header.setFixedHeight(54)
        header.setStyleSheet("background:#111;border-bottom:2px solid #1a1a1a;")
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(20, 0, 20, 0)
        title_lbl = QLabel("🛡️  SOC Analist Referans")
        title_lbl.setStyleSheet("font-size:20px;font-weight:bold;color:#e0e0e0;")
        h_layout.addWidget(title_lbl)
        h_layout.addStretch()

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("🔍  Ara — port, komut, event ID, MITRE...")
        self.search_box.setFixedWidth(300)
        self.search_box.setStyleSheet("""
            QLineEdit { background:#1e1e1e; color:#e0e0e0; border:1px solid #333;
                        border-radius:6px; padding:6px 12px; font-size:12px; }
            QLineEdit:focus { border:1px solid #c62828; }
        """)
        self.search_box.textChanged.connect(self._on_search)
        h_layout.addWidget(self.search_box)
        outer.addWidget(header)

        self.inner_tabs = QTabWidget()
        self.inner_tabs.setStyleSheet("""
            QTabWidget::pane { border:none; background:#141414; }
            QTabBar::tab { background:#1a1a1a; color:#888; padding:9px 18px; margin:1px;
                           border-top-left-radius:6px; border-top-right-radius:6px; font-size:12px; }
            QTabBar::tab:selected { background:#c62828; color:white; font-weight:bold; }
            QTabBar::tab:hover:!selected { background:#252525; color:#ccc; }
        """)
        self.inner_tabs.addTab(self._build_ports_tab(),    "🔌  Portlar")
        self.inner_tabs.addTab(self._build_eventids_tab(), "📋  Event ID'ler")
        self.inner_tabs.addTab(self._build_windows_tab(),  "🪟  Windows Komutları")
        self.inner_tabs.addTab(self._build_commands_tab(), "⌨️  Komutlar")
        self.inner_tabs.addTab(self._build_mitre_tab(),    "🎯  MITRE ATT&CK")
        self.inner_tabs.addTab(self._build_ir_tab(),       "🚨  IR Adımları")
        self.inner_tabs.addTab(self._build_severity_tab(), "⚠️  Severity")
        self.inner_tabs.addTab(self._build_dorks_tab(),    "🔎 Google Dorks")
        self.inner_tabs.addTab(self._build_tools_tab(),    "🧰 SOC Tools")
        self.inner_tabs.addTab(self._build_extensions_tab(),"🧩 Chrome Eklentileri")
        outer.addWidget(self.inner_tabs, 1)

        self.copy_lbl = QLabel("")
        self.copy_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.copy_lbl.setStyleSheet("color:#66bb6a;font-size:11px;padding:2px 16px;background:#111;")
        self.copy_lbl.setFixedHeight(22)
        outer.addWidget(self.copy_lbl)

    def _copy(self, text):
        QGuiApplication.clipboard().setText(text)
        self.copy_lbl.setText(f"✅ Kopyalandı: {text[:60]}{'…' if len(text)>60 else ''}")
        QTimer.singleShot(2500, lambda: self.copy_lbl.setText(""))

    def _scroll_widget(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;background:#141414;}")
        w = QWidget()
        w.setStyleSheet("background:#141414;")
        return scroll, w

    def _section_header(self, layout, title, color):
        lbl = QLabel(title)
        lbl.setStyleSheet(
            f"font-size:14px;font-weight:bold;color:{color};"
            f"margin:12px 0 6px 0;border-left:3px solid {color};padding-left:8px;"
        )
        layout.addWidget(lbl)

    def _cmd_card(self, label, cmd, desc="", accent="#c62828"):
        card = QWidget()
        card.setStyleSheet(f"""
            QWidget {{ background:#1a1a1a; border:1px solid #2a2a2a;
                       border-left:3px solid {accent}; border-radius:6px; }}
            QWidget:hover {{ background:#1e1e1e; }}
        """)
        cl = QHBoxLayout(card)
        cl.setContentsMargins(10, 7, 8, 7)
        cl.setSpacing(8)
        info = QVBoxLayout(); info.setSpacing(2)
        lbl = QLabel(f"<b style='color:#e0e0e0;font-size:12px;'>{label}</b>")
        lbl.setTextFormat(Qt.TextFormat.RichText)
        cmd_lbl = QLabel(f"<code style='color:#a8d8a8;font-size:11px;background:#0d0d0d;padding:2px 6px;border-radius:3px;'>{cmd}</code>")
        cmd_lbl.setTextFormat(Qt.TextFormat.RichText)
        cmd_lbl.setWordWrap(True)
        info.addWidget(lbl); info.addWidget(cmd_lbl)
        if desc:
            desc_lbl = QLabel(f"<span style='color:#555;font-size:10px;'>{desc}</span>")
            desc_lbl.setTextFormat(Qt.TextFormat.RichText)
            info.addWidget(desc_lbl)
        cl.addLayout(info, 1)
        copy_btn = QPushButton("📋")
        copy_btn.setFixedSize(28, 28)
        copy_btn.setStyleSheet(f"QPushButton{{background:#222;color:#888;border:1px solid #333;border-radius:5px;font-size:13px;}}"
                               f"QPushButton:hover{{background:{accent};color:white;border-color:{accent};}}")
        copy_btn.clicked.connect(lambda: self._copy(cmd))
        cl.addWidget(copy_btn)
        return card

    def _build_ports_tab(self):
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;background:#141414;}")
        w = QWidget(); w.setStyleSheet("background:#141414;")
        layout = QVBoxLayout(w); layout.setContentsMargins(16,12,16,16); layout.setSpacing(3)
        self._port_widgets = []
        for port, proto, svc, risk_col, desc in SOC_PORTS:
            row = QWidget()
            row.setStyleSheet(f"background:#1a1a1a;border-left:3px solid {risk_col};border-radius:5px;margin:1px 0;")
            rl = QHBoxLayout(row); rl.setContentsMargins(10,6,10,6); rl.setSpacing(8)
            port_lbl = QLabel(f"<b style='color:#fff;font-size:13px;font-family:Consolas;'>{port}</b>")
            port_lbl.setTextFormat(Qt.TextFormat.RichText); port_lbl.setFixedWidth(72)
            proto_lbl = QLabel(f"<span style='color:#888;font-size:11px;'>{proto}</span>")
            proto_lbl.setTextFormat(Qt.TextFormat.RichText); proto_lbl.setFixedWidth(65)
            svc_lbl = QLabel(f"<b style='color:{risk_col};font-size:12px;'>{svc}</b>")
            svc_lbl.setTextFormat(Qt.TextFormat.RichText); svc_lbl.setFixedWidth(120)
            desc_lbl = QLabel(f"<span style='color:#aaa;font-size:11px;'>{desc}</span>")
            desc_lbl.setTextFormat(Qt.TextFormat.RichText); desc_lbl.setWordWrap(True)
            copy_btn = QPushButton("📋"); copy_btn.setFixedSize(24,24)
            copy_btn.setStyleSheet(f"QPushButton{{background:#222;color:#666;border:1px solid #333;border-radius:4px;}}"
                                   f"QPushButton:hover{{background:{risk_col};color:white;}}")
            copy_btn.clicked.connect(lambda _, p=port: self._copy(p))
            rl.addWidget(port_lbl); rl.addWidget(proto_lbl); rl.addWidget(svc_lbl)
            rl.addWidget(desc_lbl, 1); rl.addWidget(copy_btn)
            layout.addWidget(row)
            self._port_widgets.append((port+proto+svc+desc, row))
        layout.addStretch(); scroll.setWidget(w); return scroll

    def _build_windows_tab(self):
        scroll, w = self._scroll_widget()
        lay = QVBoxLayout(w); lay.setContentsMargins(12,10,12,12); lay.setSpacing(3)
        self._win_cmd_widgets = []
        for cmd, desc, col in SOC_CMD_WINDOWS:
            row = QWidget()
            row.setStyleSheet(f"background:#1a1a1a;border-left:3px solid {col}55;border-radius:6px;margin:2px 0;")
            rl = QHBoxLayout(row); rl.setContentsMargins(12,7,8,7); rl.setSpacing(10)
            info = QVBoxLayout(); info.setSpacing(2)
            cl = QLabel(f"<code style='color:#a8d8a8;font-size:12px;background:#0d0d0d;padding:2px 6px;border-radius:3px;'>{cmd}</code>")
            cl.setTextFormat(Qt.TextFormat.RichText)
            dl = QLabel(f"<span style='color:#888;font-size:11px;'>{desc}</span>")
            dl.setTextFormat(Qt.TextFormat.RichText); dl.setWordWrap(True)
            info.addWidget(cl); info.addWidget(dl); rl.addLayout(info, 1)
            cp = QPushButton("📋"); cp.setFixedSize(28,28)
            cp.setStyleSheet(f"QPushButton{{background:#222;color:#888;border:1px solid #333;border-radius:5px;}}"
                             f"QPushButton:hover{{background:{col};color:white;}}")
            cp.clicked.connect(lambda _, c=cmd: self._copy(c))
            rl.addWidget(cp)
            lay.addWidget(row)
            self._win_cmd_widgets.append((cmd+desc, row))
        lay.addStretch(); scroll.setWidget(w); return scroll

    def _build_commands_tab(self):
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;background:#141414;}")
        w = QWidget(); w.setStyleSheet("background:#141414;")
        layout = QVBoxLayout(w); layout.setContentsMargins(16,12,16,16); layout.setSpacing(5)
        self._cmd_widgets = []
        for platform, info in SOC_COMMANDS.items():
            color = info["color"]; icon = info["icon"]; cmds = info["commands"]
            hdr = QLabel(f"{icon}  {platform}")
            hdr.setStyleSheet(f"font-size:16px;font-weight:bold;color:{color};"
                              f"margin:12px 0 4px 0;border-left:4px solid {color};padding-left:10px;")
            layout.addWidget(hdr)
            for lbl_text, cmd, desc in cmds:
                card = self._cmd_card(lbl_text, cmd, desc, accent=color)
                layout.addWidget(card)
                self._cmd_widgets.append((platform+lbl_text+cmd+desc, card))
        layout.addStretch(); scroll.setWidget(w); return scroll

    def _build_eventids_tab(self):
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;background:#141414;}")
        w = QWidget(); w.setStyleSheet("background:#141414;")
        layout = QVBoxLayout(w); layout.setContentsMargins(16,12,16,16); layout.setSpacing(3)
        self._evid_widgets = []
        win_hdr = QLabel("🪟  Windows Event ID'leri")
        win_hdr.setStyleSheet("font-size:15px;font-weight:bold;color:#64b5f6;margin:8px 0 4px 0;border-left:3px solid #1565c0;padding-left:8px;")
        layout.addWidget(win_hdr)
        for eid, cat, desc, col in SOC_EVENT_IDS_WIN:
            row = QWidget()
            row.setStyleSheet(f"background:#1a1a1a;border-left:3px solid {col};border-radius:5px;margin:1px 0;")
            rl = QHBoxLayout(row); rl.setContentsMargins(10,5,10,5); rl.setSpacing(8)
            id_lbl = QLabel(f"<b style='color:#fff;font-family:Consolas;font-size:13px;'>{eid}</b>")
            id_lbl.setTextFormat(Qt.TextFormat.RichText); id_lbl.setFixedWidth(50)
            cat_lbl = QLabel(f"<span style='color:{col};font-size:11px;font-weight:bold;'>{cat}</span>")
            cat_lbl.setTextFormat(Qt.TextFormat.RichText); cat_lbl.setFixedWidth(95)
            desc_lbl = QLabel(f"<span style='color:#ccc;font-size:12px;'>{desc}</span>")
            desc_lbl.setTextFormat(Qt.TextFormat.RichText); desc_lbl.setWordWrap(True)
            copy_btn = QPushButton("📋"); copy_btn.setFixedSize(24,24)
            copy_btn.setStyleSheet(f"QPushButton{{background:#222;color:#666;border:1px solid #333;border-radius:4px;}}"
                                   f"QPushButton:hover{{background:{col};color:white;}}")
            copy_btn.clicked.connect(lambda _, e=eid: self._copy(e))
            rl.addWidget(id_lbl); rl.addWidget(cat_lbl); rl.addWidget(desc_lbl, 1); rl.addWidget(copy_btn)
            layout.addWidget(row)
            self._evid_widgets.append((eid+cat+desc, row))
        linux_hdr = QLabel("🐧  Linux Log Kaynakları")
        linux_hdr.setStyleSheet("font-size:15px;font-weight:bold;color:#81c784;margin:16px 0 4px 0;border-left:3px solid #2e7d32;padding-left:8px;")
        layout.addWidget(linux_hdr)
        for log_file, cat, desc, col in SOC_EVENT_IDS_LINUX:
            row = QWidget()
            row.setStyleSheet(f"background:#1a1a1a;border-left:3px solid {col};border-radius:5px;margin:1px 0;")
            rl = QHBoxLayout(row); rl.setContentsMargins(10,5,10,5); rl.setSpacing(8)
            lf_lbl = QLabel(f"<b style='color:#a8d8a8;font-family:Consolas;font-size:11px;'>{log_file}</b>")
            lf_lbl.setTextFormat(Qt.TextFormat.RichText); lf_lbl.setFixedWidth(145)
            cat_lbl = QLabel(f"<span style='color:{col};font-size:11px;font-weight:bold;'>{cat}</span>")
            cat_lbl.setTextFormat(Qt.TextFormat.RichText); cat_lbl.setFixedWidth(75)
            desc_lbl = QLabel(f"<span style='color:#ccc;font-size:12px;'>{desc}</span>")
            desc_lbl.setTextFormat(Qt.TextFormat.RichText); desc_lbl.setWordWrap(True)
            rl.addWidget(lf_lbl); rl.addWidget(cat_lbl); rl.addWidget(desc_lbl, 1)
            layout.addWidget(row)
            self._evid_widgets.append((log_file+cat+desc, row))
        layout.addStretch(); scroll.setWidget(w); return scroll

    def _build_mitre_tab(self):
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;background:#141414;}")
        w = QWidget(); w.setStyleSheet("background:#141414;")
        layout = QVBoxLayout(w); layout.setContentsMargins(16,12,16,16); layout.setSpacing(3)
        TACTIC_COLORS = {
            "Initial Access":"#ef5350","Execution":"#ff9800","Persistence":"#ff7043",
            "Privilege Esc.":"#ab47bc","Defense Evasion":"#7e57c2","Credential Access":"#42a5f5",
            "Discovery":"#26c6da","Lateral Movement":"#66bb6a","Collection":"#d4e157",
            "Exfiltration":"#ffa726","C2":"#ef5350","Impact":"#b71c1c",
        }
        current_tactic = None
        self._mitre_widgets = []
        for tactic, tid, tname, example in SOC_MITRE:
            if tactic != current_tactic:
                current_tactic = tactic
                col = TACTIC_COLORS.get(tactic, "#888")
                tac_hdr = QLabel(f"  {tactic}")
                tac_hdr.setStyleSheet(f"font-size:13px;font-weight:bold;color:{col};"
                                      f"background:{col}22;border-left:3px solid {col};"
                                      f"padding:5px 10px;border-radius:4px;margin:8px 0 2px 0;")
                layout.addWidget(tac_hdr)
            col = TACTIC_COLORS.get(tactic, "#888")
            row = QWidget()
            row.setStyleSheet(f"background:#1a1a1a;border-left:3px solid {col}33;border-radius:5px;margin:1px 0;")
            rl = QHBoxLayout(row); rl.setContentsMargins(10,6,10,6); rl.setSpacing(8)
            id_btn = QPushButton(tid); id_btn.setFixedWidth(68); id_btn.setFixedHeight(24)
            id_btn.setStyleSheet(f"QPushButton{{background:{col}22;color:{col};border:1px solid {col}55;"
                                 f"border-radius:4px;font-size:11px;font-family:Consolas;font-weight:bold;}}"
                                 f"QPushButton:hover{{background:{col};color:white;}}")
            id_btn.clicked.connect(lambda _, t=tid: self._copy(t))
            name_lbl = QLabel(f"<b style='color:#e0e0e0;font-size:12px;'>{tname}</b>")
            name_lbl.setTextFormat(Qt.TextFormat.RichText); name_lbl.setFixedWidth(220)
            ex_lbl = QLabel(f"<span style='color:#777;font-size:11px;'>{example}</span>")
            ex_lbl.setTextFormat(Qt.TextFormat.RichText); ex_lbl.setWordWrap(True)
            rl.addWidget(id_btn); rl.addWidget(name_lbl); rl.addWidget(ex_lbl, 1)
            layout.addWidget(row)
            self._mitre_widgets.append((tactic+tid+tname+example, row))
        layout.addStretch(); scroll.setWidget(w); return scroll

    def _build_ir_tab(self):
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;background:#141414;}")
        w = QWidget(); w.setStyleSheet("background:#141414;")
        layout = QVBoxLayout(w); layout.setContentsMargins(16,12,16,20); layout.setSpacing(10)
        for step_no, step_name, color, items in SOC_IR_STEPS:
            card = QWidget()
            card.setStyleSheet(f"background:#1a1a1a;border:1px solid #2a2a2a;border-left:4px solid {color};border-radius:8px;")
            cl = QVBoxLayout(card); cl.setContentsMargins(14,12,14,12); cl.setSpacing(4)
            hdr_lbl = QLabel(f"<b style='color:{color};font-size:14px;'>ADIM {step_no} — {step_name}</b>")
            hdr_lbl.setTextFormat(Qt.TextFormat.RichText); cl.addWidget(hdr_lbl)
            for item in items:
                item_lbl = QLabel(f"<span style='color:#a8d8a8;font-size:11px;'>▶</span>&nbsp;"
                                  f"<span style='color:#ccc;font-size:12px;'>{item}</span>")
                item_lbl.setTextFormat(Qt.TextFormat.RichText); item_lbl.setWordWrap(True)
                cl.addWidget(item_lbl)
            layout.addWidget(card)
        layout.addStretch(); scroll.setWidget(w); return scroll

    def _build_severity_tab(self):
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;background:#141414;}")
        w = QWidget(); w.setStyleSheet("background:#141414;")
        layout = QVBoxLayout(w); layout.setContentsMargins(16,12,16,20); layout.setSpacing(10)
        for label, text_col, bg_col, desc in SOC_SEVERITY:
            card = QWidget()
            card.setStyleSheet(f"background:{bg_col};border:1px solid {text_col}44;border-left:5px solid {text_col};border-radius:8px;")
            cl = QHBoxLayout(card); cl.setContentsMargins(14,12,14,12); cl.setSpacing(12)
            sev_lbl = QLabel(f"<b style='color:{text_col};font-size:14px;'>{label}</b>")
            sev_lbl.setTextFormat(Qt.TextFormat.RichText); sev_lbl.setFixedWidth(180)
            desc_lbl = QLabel(f"<span style='color:#ccc;font-size:12px;'>{desc}</span>")
            desc_lbl.setTextFormat(Qt.TextFormat.RichText); desc_lbl.setWordWrap(True)
            cl.addWidget(sev_lbl); cl.addWidget(desc_lbl, 1)
            layout.addWidget(card)
        layout.addStretch(); scroll.setWidget(w); return scroll

    def _build_tools_tab(self):
        scroll, w = self._scroll_widget()
        lay = QVBoxLayout(w); lay.setContentsMargins(12,10,12,12); lay.setSpacing(4)
        self._tool_widgets = []

        # Password Generator
        pw_box = QGroupBox("🔐 Password Generator")
        pw_box.setStyleSheet("QGroupBox{border:1px solid #2a2a2a;border-radius:8px;margin-top:8px;padding:8px;}"
                             "QGroupBox::title{color:#777;left:10px;subcontrol-origin:margin;}")
        pw_lay = QVBoxLayout(pw_box); pw_lay.setContentsMargins(10,10,10,10); pw_lay.setSpacing(6)
        top_row = QHBoxLayout(); top_row.setSpacing(8)
        len_lbl = QLabel("Uzunluk"); len_lbl.setStyleSheet("color:#888;font-size:11px;")
        self.pw_len = QSpinBox(); self.pw_len.setRange(4,64); self.pw_len.setValue(16); self.pw_len.setFixedWidth(70)
        self.pw_len.setStyleSheet("QSpinBox{background:#1e1e1e;color:#e0e0e0;border:1px solid #333;border-radius:6px;padding:4px 8px;font-size:12px;}")
        self.pw_out = QLineEdit(); self.pw_out.setReadOnly(True); self.pw_out.setPlaceholderText("Parola üret…")
        self.pw_out.setStyleSheet("QLineEdit{background:#121212;color:#e0e0e0;border:1px solid #333;border-radius:6px;padding:6px 10px;font-size:12px;}")
        gen_btn = QPushButton("Üret"); gen_btn.setFixedHeight(28)
        gen_btn.setStyleSheet("QPushButton{background:#c62828;color:white;border:none;border-radius:6px;padding:0 12px;font-weight:bold;}QPushButton:hover{background:#ef5350;}")
        copy_btn2 = QPushButton("📋"); copy_btn2.setFixedSize(34,28)
        copy_btn2.setStyleSheet("QPushButton{background:#222;color:#888;border:1px solid #333;border-radius:6px;font-size:13px;}QPushButton:hover{background:#1565c0;color:white;}")
        reset_btn = QPushButton("Reset"); reset_btn.setFixedHeight(28)
        reset_btn.setStyleSheet("QPushButton{background:#222;color:#aaa;border:1px solid #333;border-radius:6px;padding:0 10px;}QPushButton:hover{background:#333;color:white;}")
        top_row.addWidget(len_lbl); top_row.addWidget(self.pw_len); top_row.addWidget(self.pw_out,1)
        top_row.addWidget(gen_btn); top_row.addWidget(copy_btn2); top_row.addWidget(reset_btn)
        pw_lay.addLayout(top_row)
        opt_row = QHBoxLayout(); opt_row.setSpacing(10)
        self.pw_lower = QCheckBox("a-z"); self.pw_upper = QCheckBox("A-Z")
        self.pw_digits = QCheckBox("0-9"); self.pw_symbols = QCheckBox("!@#")
        for cb in (self.pw_lower, self.pw_upper, self.pw_digits, self.pw_symbols):
            cb.setChecked(True); cb.setStyleSheet("QCheckBox{color:#aaa;font-size:11px;}"); opt_row.addWidget(cb)
        opt_row.addStretch(); pw_lay.addLayout(opt_row)
        def do_generate():
            try:
                pwd = self._generate_password(int(self.pw_len.value()),
                    self.pw_lower.isChecked(), self.pw_upper.isChecked(),
                    self.pw_digits.isChecked(), self.pw_symbols.isChecked())
                self.pw_out.setText(pwd)
            except Exception as e: QMessageBox.warning(self, "Hata", str(e))
        gen_btn.clicked.connect(do_generate)
        copy_btn2.clicked.connect(lambda: self._copy(self.pw_out.text().strip()) if self.pw_out.text().strip() else None)
        reset_btn.clicked.connect(lambda: (self.pw_len.setValue(16),
            [cb.setChecked(True) for cb in (self.pw_lower,self.pw_upper,self.pw_digits,self.pw_symbols)],
            self.pw_out.clear()))
        self._tool_widgets.append(("password generator parola şifre", pw_box))
        lay.addWidget(pw_box)

        for category, cdata in SOC_TOOLS.items():
            col = cdata["color"]
            self._section_header(lay, category, col)
            for name, url, desc, pricing in cdata["items"]:
                row = QWidget()
                row.setStyleSheet(f"background:#1a1a1a;border-left:3px solid {col}55;border-radius:6px;margin:2px 0;")
                rl = QHBoxLayout(row); rl.setContentsMargins(12,7,8,7); rl.setSpacing(10)
                info_lay = QVBoxLayout(); info_lay.setSpacing(2)
                name_lbl = QLabel(f"<a href='{url}' style='color:{col};font-size:13px;font-weight:bold;text-decoration:none;'>{name}</a>  "
                                  f"<span style='color:#444;font-size:10px;background:#1e1e1e;padding:1px 6px;border-radius:3px;'>{pricing}</span>")
                name_lbl.setTextFormat(Qt.TextFormat.RichText); name_lbl.setOpenExternalLinks(True)
                desc_lbl = QLabel(f"<span style='color:#888;font-size:11px;'>{desc}</span>")
                desc_lbl.setTextFormat(Qt.TextFormat.RichText); desc_lbl.setWordWrap(True)
                info_lay.addWidget(name_lbl); info_lay.addWidget(desc_lbl); rl.addLayout(info_lay,1)
                cp = QPushButton("🔗"); cp.setFixedSize(28,28)
                cp.setStyleSheet(f"QPushButton{{background:#222;color:#888;border:1px solid #333;border-radius:5px;}}"
                                 f"QPushButton:hover{{background:{col};color:white;}}")
                cp.clicked.connect(lambda _, u=url: self._copy(u))
                rl.addWidget(cp); lay.addWidget(row)
                self._tool_widgets.append((category+name+desc, row))
        lay.addStretch(); scroll.setWidget(w); return scroll

    def _build_dorks_tab(self):
        scroll, w = self._scroll_widget()
        lay = QVBoxLayout(w); lay.setContentsMargins(12,10,12,12); lay.setSpacing(4)
        self._dork_widgets = []
        for category, col, dorks in SOC_GOOGLE_DORKS:
            self._section_header(lay, category, col)
            for dork, desc in dorks:
                row = QWidget()
                row.setStyleSheet(f"background:#1a1a1a;border-left:3px solid {col}55;border-radius:6px;margin:2px 0;")
                rl = QHBoxLayout(row); rl.setContentsMargins(12,7,8,7); rl.setSpacing(10)
                info_lay = QVBoxLayout(); info_lay.setSpacing(2)
                dork_lbl = QLabel(f"<code style='color:#a8d8a8;font-size:12px;background:#0d0d0d;padding:2px 8px;border-radius:3px;'>{dork}</code>")
                dork_lbl.setTextFormat(Qt.TextFormat.RichText)
                desc_lbl = QLabel(f"<span style='color:#888;font-size:11px;'>{desc}</span>")
                desc_lbl.setTextFormat(Qt.TextFormat.RichText)
                info_lay.addWidget(dork_lbl); info_lay.addWidget(desc_lbl); rl.addLayout(info_lay,1)
                search_url = f"https://www.google.com/search?q={dork.replace(' ', '+')}"
                ob = QPushButton("🔍"); ob.setFixedSize(28,28)
                ob.setStyleSheet(f"QPushButton{{background:#222;color:#888;border:1px solid #333;border-radius:5px;}}"
                                 f"QPushButton:hover{{background:#1565c0;color:white;}}")
                ob.clicked.connect(lambda _, u=search_url: __import__('webbrowser').open(u))
                cp = QPushButton("📋"); cp.setFixedSize(28,28)
                cp.setStyleSheet(f"QPushButton{{background:#222;color:#888;border:1px solid #333;border-radius:5px;}}"
                                 f"QPushButton:hover{{background:{col};color:white;}}")
                cp.clicked.connect(lambda _, d=dork: self._copy(d))
                rl.addWidget(ob); rl.addWidget(cp); lay.addWidget(row)
                self._dork_widgets.append((category+dork+desc, row))
        lay.addStretch(); scroll.setWidget(w); return scroll

    def _build_extensions_tab(self):
        scroll, w = self._scroll_widget()
        lay = QVBoxLayout(w); lay.setContentsMargins(12,10,12,12); lay.setSpacing(4)
        self._ext_widgets = []
        for category, col, items in SOC_CHROME_EXTENSIONS:
            self._section_header(lay, category, col)
            for name, desc, url, pricing in items:
                row = QWidget()
                row.setStyleSheet(f"background:#1a1a1a;border-left:3px solid {col}66;border-radius:6px;margin:2px 0;")
                rl = QHBoxLayout(row); rl.setContentsMargins(12,8,8,8); rl.setSpacing(10)
                info_lay = QVBoxLayout(); info_lay.setSpacing(2)
                name_lbl = QLabel(f"<a href='{url}' style='color:{col};font-size:13px;font-weight:bold;text-decoration:none;'>{name}</a>  "
                                  f"<span style='color:#444;font-size:10px;background:#1e1e1e;padding:1px 6px;border-radius:3px;'>{pricing}</span>")
                name_lbl.setTextFormat(Qt.TextFormat.RichText); name_lbl.setOpenExternalLinks(True)
                desc_lbl = QLabel(f"<span style='color:#888;font-size:11px;'>{desc}</span>")
                desc_lbl.setTextFormat(Qt.TextFormat.RichText); desc_lbl.setWordWrap(True)
                info_lay.addWidget(name_lbl); info_lay.addWidget(desc_lbl); rl.addLayout(info_lay,1); lay.addWidget(row)
                self._ext_widgets.append((category+name+desc, row))
        lay.addStretch(); scroll.setWidget(w); return scroll

    def _on_search(self, text):
        text_l = text.lower().strip()
        for src in (
            getattr(self, "_port_widgets", []),
            getattr(self, "_win_cmd_widgets", []),
            getattr(self, "_evid_widgets", []),
            getattr(self, "_cmd_widgets", []),
            getattr(self, "_mitre_widgets", []),
            getattr(self, "_dork_widgets", []),
            getattr(self, "_tool_widgets", []),
            getattr(self, "_ext_widgets", []),
        ):
            for key, widget in src:
                widget.setVisible(not text_l or text_l in key.lower())


# ============================================================
# ANA PENCERE
# ============================================================
class AtmacaIOC(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AtmacaIOC Yerel v6.2 — IP · Hash · Domain · Yerel AI Log")
        self.setGeometry(100, 100, 1280, 820)
        self._active_workers     = []
        self._total_tasks        = 0
        self._done_tasks         = 0
        self.provider_checkboxes = {}
        self.setStyleSheet("""
            QMainWindow   { background-color:#1a1a1a; }
            QWidget       { background-color:#1a1a1a; }
            QLabel        { color:#e0e0e0; font-size:13px; }
            QTextEdit     { background-color:#252525; color:#e0e0e0; border:1px solid #3a3a3a;
                            border-radius:10px; padding:12px; font-family:Consolas; font-size:14px; }
            QTextBrowser  { background-color:#1e1e1e; color:#e0e0e0; border:none;
                            font-size:13px; padding:12px; }
            QCheckBox     { color:#ccc; font-size:12px; }
            QCheckBox::indicator { width:18px; height:18px; border-radius:5px;
                                   background:#2a2a2a; border:2px solid #555; }
            QCheckBox::indicator:checked { background:#c62828; border:2px solid #ef5350; }
            QTabWidget::pane { border:1px solid #3a3a3a; background:#1e1e1e; }
            QTabBar::tab     { background:#2a2a2a; color:#aaa; padding:10px 18px; margin:2px;
                               border-top-left-radius:8px; border-top-right-radius:8px; font-size:12px; }
            QTabBar::tab:selected     { background:#c62828; color:white; font-weight:bold; }
            QTabBar::tab:hover:!selected { background:#3a3a3a; }
            QProgressBar  { background:#2a2a2a; border:1px solid #3a3a3a; border-radius:5px;
                            text-align:center; color:white; font-size:11px; }
            QProgressBar::chunk { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
                                  stop:0 #c62828,stop:1 #ef5350); border-radius:5px; }
            QGroupBox     { color:#555; border:1px solid #333; border-radius:8px;
                            margin-top:6px; padding:6px; font-size:11px; }
            QGroupBox::title { color:#777; subcontrol-origin:margin; left:8px; }
        """)
        self._init_ui()

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout()
        root.setSpacing(12)
        root.setContentsMargins(20, 20, 20, 20)

        hdr = QHBoxLayout()
        title = QLabel("ATMACA<span style='color:#ef5350;'>IOC</span> <span style='font-size:16px;color:#555;'>Yerel v6.2</span>")
        title.setStyleSheet("font-size:28px; font-weight:bold; color:#e0e0e0;")
        title.setTextFormat(Qt.TextFormat.RichText)
        for txt, col in [("IP","#1565c0"),("HASH","#6a1b9a"),("DOMAIN","#1b5e20")]:
            badge = QLabel(txt)
            badge.setStyleSheet(f"background:{col};color:white;border-radius:4px;padding:2px 8px;font-size:11px;font-weight:bold;")
            hdr.addWidget(badge)
        hdr.insertWidget(0, title)
        hdr.addStretch()
        root.addLayout(hdr)

        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText(
            "IP, Hash (MD5/SHA1/SHA256) veya Domain — karışık girebilirsin:\n\n"
            "192.168.1.100\n"
            "d41d8cd98f00b204e9800998ecf8427e\n"
            "example.com"
        )
        self.input_text.setFixedHeight(120)
        root.addWidget(self.input_text)

        prov_outer = QHBoxLayout()
        prov_outer.setSpacing(12)
        for group_label, members, color in [
            ("🌐  IP",         ["AbuseIPDB","ARIN","Shodan","GreyNoise"], "#1565c0"),
            ("🔀  Çok Amaçlı", ["OTX","VirusTotal"],                     "#6a1b9a"),
            ("🔑  Hash",        ["MalwareBazaar","HybridAnalysis"],        "#4a148c"),
            ("🌍  Domain",      ["URLScan"],                               "#1b5e20"),
        ]:
            grp = QGroupBox(group_label)
            grp.setStyleSheet(f"QGroupBox{{color:{color};border:1px solid #333;border-radius:8px;margin-top:6px;padding:6px 10px;}}")
            gl = QHBoxLayout(); gl.setSpacing(6)
            for name in members:
                cfg = PROVIDERS[name]
                cb  = QCheckBox(name)
                if cfg["requires_key"]:
                    has = bool(keyring.get_password("atmacaioc", cfg["key_name"]))
                    cb.setChecked(cfg["enabled"] and has)
                else:
                    cb.setChecked(cfg["enabled"])
                cb.stateChanged.connect(lambda state, n=name: self._toggle(n, state))
                self.provider_checkboxes[name] = cb
                gl.addWidget(cb)
            grp.setLayout(gl)
            prov_outer.addWidget(grp)
        prov_outer.addStretch()
        root.addLayout(prov_outer)

        btn_row = QHBoxLayout()
        self.btn_analyze = QPushButton("⚡  ANALİZ ET")
        self.btn_analyze.setFixedHeight(58)
        self.btn_analyze.setStyleSheet("""
            QPushButton{background-color:#c62828;color:white;font-weight:bold;font-size:18px;border-radius:10px;}
            QPushButton:hover{background-color:#b71c1c;}
            QPushButton:disabled{background-color:#3a3a3a;color:#666;}
        """)
        self.btn_analyze.clicked.connect(self._start)
        self.btn_clear = QPushButton("🗑  Temizle")
        self.btn_clear.setFixedHeight(42)
        self.btn_clear.setStyleSheet("QPushButton{background:#2a2a2a;color:#ccc;border-radius:8px;padding:8px 14px;}QPushButton:hover{background:#3a3a3a;}")
        self.btn_clear.clicked.connect(self._clear)
        self.btn_settings = QPushButton("⚙  API Anahtarları")
        self.btn_settings.setFixedHeight(42)
        self.btn_settings.setStyleSheet("QPushButton{background:#2a2a2a;color:#ccc;border-radius:8px;padding:8px 14px;}QPushButton:hover{background:#3a3a3a;}")
        self.btn_settings.clicked.connect(lambda: SettingsDialog(self).exec())
        btn_row.addWidget(self.btn_analyze)
        btn_row.addWidget(self.btn_clear)
        btn_row.addWidget(self.btn_settings)
        btn_row.addStretch()
        root.addLayout(btn_row)

        self.progress = QProgressBar()
        self.progress.setFixedHeight(16)
        self.progress.setVisible(False)
        root.addWidget(self.progress)
        self.status_lbl = QLabel("")
        self.status_lbl.setStyleSheet("color:#666; font-size:11px;")
        root.addWidget(self.status_lbl)
        self.tabs = QTabWidget()
        self.tabs.setFont(QFont("Segoe UI", 11))
        root.addWidget(self.tabs, 1)
        central.setLayout(root)

        main_widget = QWidget()
        main_widget.setLayout(root)

        self.main_tabs = QTabWidget()
        self.main_tabs.setFont(QFont("Segoe UI", 12))
        self.main_tabs.setStyleSheet("""
            QTabBar::tab { padding:12px 24px; font-size:13px; }
            QTabBar::tab:selected { background:#c62828; }
        """)
        self.main_tabs.addTab(main_widget, "🔍  IOC Analizi")
        ai_widget = self._build_ai_tab()
        self.main_tabs.addTab(ai_widget, "🖥  Yerel AI Log")
        soc_ref_widget = SocRefWidget()
        self.main_tabs.addTab(soc_ref_widget, "🛡️  SOC Referans")

        outer_widget = QWidget()
        outer_layout  = QVBoxLayout()
        outer_layout.setContentsMargins(0,0,0,0)
        outer_layout.addWidget(self.main_tabs)
        outer_widget.setLayout(outer_layout)
        self.setCentralWidget(outer_widget)

    def _toggle(self, name, state):
        PROVIDERS[name]["enabled"] = (state == Qt.CheckState.Checked.value)

    def _clear(self):
        self.tabs.clear()
        self.input_text.clear()
        self.status_lbl.setText("")
        self.progress.setVisible(False)

    def _start(self):
        text = self.input_text.toPlainText().strip()
        if not text:
            QMessageBox.critical(self, "Hata", "IOC girin!")
            return
        self.tabs.clear()
        self._active_workers.clear()
        iocs = extract_iocs(text)
        if not iocs:
            browser = QTextBrowser()
            browser.setHtml("<h3 style='color:red;'>Geçerli IOC bulunamadı!</h3>")
            self.tabs.addTab(browser, "Hata")
            return
        enabled = [n for n, c in PROVIDERS.items() if c["enabled"]]
        if not enabled:
            QMessageBox.warning(self, "Hata", "En az bir servis seçin!")
            return
        type_icons = {"ip":"🌐","md5":"🔑","sha1":"🔑","sha256":"🔑","domain":"🌍"}
        summary  = "<h2 style='color:#ef5350;'>Tespit Edilen IOC'ler</h2>"
        summary += "<table style='border-collapse:collapse;width:100%;'>"
        for v, t in iocs:
            summary += f"<tr><td style='padding:4px 8px;font-family:Consolas;'>{v}</td><td style='padding:4px 8px;color:#aaa;'>{type_icons.get(t,'❓')} {t.upper()}</td></tr>"
        summary += "</table>"
        self._add_tab(f"IOC'ler ({len(iocs)})", summary)
        tasks = []
        for value, ioc_type in iocs:
            hash_types = {"md5","sha1","sha256"}
            for pname in enabled:
                supported = PROVIDERS[pname].get("supports",[])
                if ioc_type in hash_types:
                    if not any(h in supported for h in hash_types): continue
                elif ioc_type not in supported:
                    continue
                tasks.append((value, ioc_type, pname))
        if not tasks:
            self._add_tab("Uyarı", "<h3 style='color:#ff9800;'>Seçili servisler bu IOC tipini desteklemiyor.</h3>")
            return
        self._total_tasks = len(tasks)
        self._done_tasks  = 0
        self.progress.setMaximum(self._total_tasks)
        self.progress.setValue(0)
        self.progress.setVisible(True)
        self.status_lbl.setText(f"0 / {self._total_tasks} sorgu başlatıldı…")
        self.btn_analyze.setEnabled(False)
        for value, ioc_type, pname in tasks:
            w = AnalysisWorker(value, ioc_type, pname)
            w.result_ready.connect(self._on_result)
            w.finished_one.connect(self._on_progress)
            w.start()
            self._active_workers.append(w)

    def _on_result(self, title, html):
        self._add_tab(title, html)

    def _on_progress(self):
        self._done_tasks += 1
        self.progress.setValue(self._done_tasks)
        self.status_lbl.setText(f"{self._done_tasks} / {self._total_tasks} tamamlandı…")
        if self._done_tasks >= self._total_tasks:
            self.status_lbl.setText(f"✅ Bitti — {self._total_tasks} sorgu tamamlandı")
            self.btn_analyze.setEnabled(True)
            self._active_workers = [w for w in self._active_workers if w.isRunning()]

    def _add_tab(self, title, html):
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == title:
                w = self.tabs.widget(i)
                tb = w.findChild(QTextBrowser)
                if tb: tb.setHtml(html)
                return
        tb = QTextBrowser()
        tb.setHtml(html)
        tb.setOpenExternalLinks(True)
        tb.setStyleSheet("QTextBrowser{background:#1e1e1e;color:#e0e0e0;border:none;padding:14px;font-size:13px;}")
        self.tabs.addTab(tb, title)
        self.tabs.setCurrentIndex(self.tabs.count() - 1)

    def _build_ai_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        hdr = QLabel("🖥  Yerel AI Log Analizi  —  <span style='color:#555;font-size:13px;'>Ollama (tamamen lokal)</span>")
        hdr.setStyleSheet("font-size:20px; font-weight:bold; color:#e0e0e0;")
        hdr.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(hdr)

        # Model öneri notu
        tip = QLabel(
            "💡 <b style='color:#ff9800;'>Model Önerisi:</b> "
            "<code style='color:#a8d8a8;'>ollama pull qwen2.5:14b</code> (en iyi) &nbsp;|&nbsp; "
            "<code style='color:#a8d8a8;'>ollama pull mistral</code> (hızlı) &nbsp;|&nbsp; "
            "<code style='color:#a8d8a8;'>ollama pull llama3.1:8b</code> — llama3.2 yetersiz kalabilir."
        )
        tip.setStyleSheet("color:#888; font-size:12px; background:#1a1a1a;")
        tip.setTextFormat(Qt.TextFormat.RichText)
        tip.setWordWrap(True)
        layout.addWidget(tip)

        ollama_row = QHBoxLayout()
        ollama_lbl = QLabel("Ollama URL:"); ollama_lbl.setStyleSheet("color:#aaa;")
        self.ai_ollama_url = QLineEdit("http://127.0.0.1:11434")
        self.ai_ollama_url.setStyleSheet("QLineEdit{background:#252525;color:#e0e0e0;border:1px solid #3a3a3a;border-radius:6px;padding:6px 10px;}")
        model_lbl = QLabel("Model:"); model_lbl.setStyleSheet("color:#aaa;")
        self.ai_ollama_model = QLineEdit("qwen2.5:14b")
        self.ai_ollama_model.setPlaceholderText("qwen2.5:14b / mistral / llama3.1:8b")
        self.ai_ollama_model.setStyleSheet(self.ai_ollama_url.styleSheet())
        self.ai_ollama_model.setFixedWidth(220)
        ollama_row.addWidget(ollama_lbl); ollama_row.addWidget(self.ai_ollama_url, 1)
        ollama_row.addWidget(model_lbl); ollama_row.addWidget(self.ai_ollama_model)
        layout.addLayout(ollama_row)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background:#2a2a2a; width:4px; }")

        left = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0,0,8,0)

        log_label = QLabel("📋  Ham Log / Olay Verisi:")
        log_label.setStyleSheet("color:#aaa; font-size:12px; font-weight:bold;")
        left_layout.addWidget(log_label)

        self.ai_input = QTextEdit()
        self.ai_input.setPlaceholderText(
            "Buraya log yapıştırın. Örnek Fortigate:\n\n"
            "<45>date=2026-03-28 time=18:16:29 devname=\"FGT200F\" srcip=27.128.170.160 "
            "srcport=34454 dstip=176.236.116.122 dstport=22 action=\"accept\" "
            "service=\"Cowrie-Port\" tranip=100.100.100.10 tranport=2222 ...\n\n"
            "Fortigate, Windows Event, Syslog, EDR, OT/ICS desteklenir."
        )
        self.ai_input.setFont(QFont("Consolas", 12))
        self.ai_input.setStyleSheet("""
            QTextEdit { background:#1a1a1a; color:#e0e0e0;
                        border:1px solid #3a3a3a; border-radius:8px; padding:12px; }
        """)
        left_layout.addWidget(self.ai_input)

        type_row = QHBoxLayout()
        type_lbl = QLabel("Analiz Tipi:"); type_lbl.setStyleSheet("color:#aaa;")
        self.ai_type_combo = QComboBox()
        # ── v6.2: Fortigate sekmesi eklendi, liste düzenlendi
        self.ai_type_combo.addItems([
            "🔥 Fortigate / Firewall Trafik Logu",
            "📋 Windows Event / AccelOps / SIEM Logu",
            "🔧 Firewall Policy Change (Config Değişikliği)",
            "🔍 Genel Güvenlik Analizi",
            "🏭 OT/ICS/SCADA Güvenliği",
            "🦅 EDR Olay Analizi (CrowdStrike/Defender/SentinelOne)",
            "🔐 Kimlik Doğrulama / Brute Force",
            "🌐 Ağ Trafiği / Firewall",
            "⚠️  Zararlı Yazılım / EDR",
            "📊 Windows Event Log",
            "🐧 Linux Syslog",
            "🌍 Web Sunucusu (Apache/Nginx)",
            "🗄️  Veritabanı Logu",
        ])
        self.ai_type_combo.setStyleSheet("""
            QComboBox { background:#252525; color:#e0e0e0; border:1px solid #3a3a3a;
                        border-radius:6px; padding:6px 12px; font-size:12px; min-width:220px; }
            QComboBox::drop-down { border:none; }
            QComboBox QAbstractItemView { background:#252525; color:#e0e0e0; border:1px solid #444; }
        """)
        type_row.addWidget(type_lbl); type_row.addWidget(self.ai_type_combo); type_row.addStretch()
        left_layout.addLayout(type_row)

        self.ai_btn = QPushButton("🖥  YEREL ANALİZ")
        self.ai_btn.setFixedHeight(50)
        self.ai_btn.setStyleSheet("""
            QPushButton { background:#00695c; color:white; font-weight:bold;
                          font-size:16px; border-radius:10px; }
            QPushButton:hover    { background:#00796b; }
            QPushButton:disabled { background:#2a2a2a; color:#555; }
        """)
        self.ai_btn.clicked.connect(self._run_ai_analysis)
        left_layout.addWidget(self.ai_btn)

        self.ai_status = QLabel("")
        self.ai_status.setStyleSheet("color:#666; font-size:11px;")
        left_layout.addWidget(self.ai_status)
        left.setLayout(left_layout)
        splitter.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(8,0,0,0)
        out_label = QLabel("📊  AI Analiz Sonucu:")
        out_label.setStyleSheet("color:#aaa; font-size:12px; font-weight:bold;")
        right_layout.addWidget(out_label)

        self.ai_output = QTextBrowser()
        self.ai_output.setOpenExternalLinks(True)
        self.ai_output.setStyleSheet("""
            QTextBrowser { background:#111; color:#e0e0e0;
                           border:1px solid #2a2a2a; border-radius:8px;
                           padding:14px; font-size:13px; }
        """)
        self.ai_output.setHtml("""
            <div style='color:#333;text-align:center;padding:60px 20px;'>
                <div style='font-size:48px;'>🤖</div>
                <div style='font-size:18px;margin-top:16px;color:#444;'>Analiz Bekleniyor</div>
                <div style='font-size:12px;margin-top:8px;color:#333;'>
                    Sol tarafa log yapıştırın, "Fortigate / Firewall" tipini seçin ve analiz edin.
                </div>
            </div>
        """)
        right_layout.addWidget(self.ai_output)

        btn_row2 = QHBoxLayout()
        clear_btn = QPushButton("🗑  Temizle")
        clear_btn.setStyleSheet("QPushButton{background:#2a2a2a;color:#aaa;border-radius:6px;padding:6px 14px;}QPushButton:hover{background:#333;}")
        clear_btn.clicked.connect(lambda: (self.ai_input.clear(), self.ai_output.setHtml(
            "<div style='color:#333;text-align:center;padding:60px 20px;'>🤖<br>Temizlendi</div>"
        )))
        btn_row2.addStretch(); btn_row2.addWidget(clear_btn)
        right_layout.addLayout(btn_row2)
        right.setLayout(right_layout)
        splitter.addWidget(right)
        splitter.setSizes([500, 700])
        layout.addWidget(splitter, 1)
        widget.setLayout(layout)
        return widget

    def _run_ai_analysis(self):
        log_text = self.ai_input.toPlainText().strip()
        if not log_text:
            self.ai_output.setHtml("<h3 style='color:#ff9800;'>Log boş!</h3>")
            return
        base_url = (self.ai_ollama_url.text() or "").strip() or "http://127.0.0.1:11434"
        model = (self.ai_ollama_model.text() or "").strip() or "qwen2.5:14b"
        analiz_tipi = self.ai_type_combo.currentText()
        self.ai_btn.setEnabled(False)
        self.ai_status.setText(f"🔄 Ollama ({model}) analiz ediyor…")
        self.ai_output.setHtml(
            "<div style='color:#aaa;padding:20px;'>⏳ Yerel model çalışıyor…</div>"
        )
        worker = OllamaWorker(base_url, model, log_text, analiz_tipi)
        worker.result_ready.connect(self._on_ai_result)
        worker.error.connect(self._on_ai_error)
        worker.start()
        self._ai_worker = worker

    def _on_ai_result(self, html):
        self.ai_output.setHtml(html)
        self.ai_btn.setEnabled(True)
        self.ai_status.setText("✅ Analiz tamamlandı")

    def _on_ai_error(self, msg):
        self.ai_output.setHtml(f"<h3 style='color:#ef5350;'>Hata</h3><p style='color:#aaa;'>{msg}</p>")
        self.ai_btn.setEnabled(True)
        self.ai_status.setText("❌ Hata oluştu")


# ============================================================
# DARK MESAJ KUTULARI
# ============================================================
_DARK = """
    QMessageBox { background:#1e1e1e; color:#e0e0e0; }
    QMessageBox QLabel { color:#e0e0e0; }
    QMessageBox QPushButton { background:#c62828; color:white; padding:8px 16px;
        border-radius:6px; min-width:70px; font-weight:bold; }
    QMessageBox QPushButton:hover { background:#b71c1c; }
"""
def _dmsg(icon, parent, title, text):
    b = QMessageBox(icon, title, text, QMessageBox.StandardButton.Ok, parent)
    b.setStyleSheet(_DARK); b.exec()

QMessageBox.information = lambda p,t,m,*a,**k: _dmsg(QMessageBox.Icon.Information, p, t, m)
QMessageBox.critical    = lambda p,t,m,*a,**k: _dmsg(QMessageBox.Icon.Critical,    p, t, m)
QMessageBox.warning     = lambda p,t,m,*a,**k: _dmsg(QMessageBox.Icon.Warning,     p, t, m)


# ============================================================
# BAŞLAT
# ============================================================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = AtmacaIOC()
    window.show()
    sys.exit(app.exec())
