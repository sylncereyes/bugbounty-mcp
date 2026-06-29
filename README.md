# StealthVision-MCP

> **Stealth Bug Bounty Hunting Assistant berbasis Model Context Protocol (MCP)**  
> Mengintegrasikan analisis otomatis terhadap kerentanan **OWASP Top 10 2025** langsung ke asisten AI Anda.

---

## 🎯 Gambaran Umum

**StealthVision-MCP** adalah platform asisten keamanan yang dirancang khusus untuk mempermudah alur kerja bug bounty hunting dan penetration testing. Dengan protokol MCP, asisten AI Anda dapat mengeksekusi **31 modul uji keamanan** secara dinamis, menyimpan hasilnya ke database SQLite lokal, dan mengekspor laporan profesional dalam format HTML, Markdown, atau CSV.

---

## 🧠 Hunter Mindset Framework (NEW)

Berbeda dari scanner generik yang mengikuti checklist OWASP secara linear, StealthVision mengadopsi **kerangka hunting berbasis intuisi** yang ditanamkan ke setiap interaksi melalui *Universal System Prompt* (23K+ karakter). Framework ini terdiri dari **13 strategi hunting** yang saling melengkapi.

---

## 🛰️ Intelligence Layer (NEW)

StealthVision terintegrasi dengan **CVE + exploit intelligence** untuk mengkayakan setiap finding dengan data actionable dari sumber eksternal. Modul `tools/intelligence.py` menyediakan:

- **CVE Enrichment** via `vulnx_enrich_finding`
- **Exploitability Filtering** via `vulnx_exploitable`
- **Metasploit Search** via `msf_module_search`
- **Exploit-DB Search** via `searchsploit_query`

---

## 🛠️ Instalasi & Setup Cepat

```bash
# 1. Masuk ke direktori proyek
cd stealthvision-mcp

# 2. Buat dan aktifkan virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Pasang dependensi
pip install -r requirements.txt

# 4. Konfigurasi Environment Variables
cp .env.example .env
# Edit .env sesuai kebutuhan

# 5. Clone Knowledge Base (required)
git clone --depth 1 https://github.com/HackTricks-wiki/hacktricks knowledge_base/hacktricks
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates knowledge_base/nuclei-templates

# 6. Jalankan server
python server.py
# Output sukses: [AGY] Loaded 31/31 tool modules
```

---

## 🧰 Modules Inventory (31 Modules)

### OWASP Top 10 Modules
- `a01_access_control`, `a02_misconfiguration`, `a03_supply_chain`
- `a04_cryptography`, `a05_injection`, `a06_insecure_design`
- `a07_authentication`, `a08_integrity`, `a09_logging`, `a10_exceptions`

### Core Modules
- `recon`, `reporting`, `intelligence`, `hunter`, `knowledge_base`

### Knowledge Base Modules
- `attck_capec_kb` - MITRE ATT&CK + CAPEC (1,190 entries)
- `owasp_api_top10` - OWASP API Security (10 entries)
- `owasp_wstg` - OWASP Testing Guide
- `cve_kb` - CVE database (1,629 entries)
- `cwe_kb` - CWE database (35 entries)
- `htb_kb` - HackTheBox machines (522 entries)
- `thm_kb` - TryHackMe rooms (1,053 entries)
- `exploitdb_kb` - ExploitDB (8,982 entries)
- `hacktricks_kb` - Hacktricks methodology
- `nuclei_kb` - Nuclei templates
- `lolbins_kb` - GTFOBins + LOLBAS (1,259 entries)
- `patt_kb` - PayloadAllTheThings
- `seclists_kb` - SecLists wordlists
- `portswigger_kb` - PortSwigger Web Security Academy
- `rfc_kb` - RFC documents (HTTP, DNS, JWT, OAuth)

---

## ⚠️ Legal & Ethical Disclaimer

**🚨 PERINGATAN KERAS: Tool ini melakukan REAL network requests.**

Gunakan HANYA pada target yang in-scope program bug bounty resmi. Segala konsekuensi hukum atas penyalahgunaan bukan tanggung jawab pembuat tool ini.