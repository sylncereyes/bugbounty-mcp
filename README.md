# AGY Bug Bounty MCP Server

> **Asisten Bug Bounty Hunting Elite berbasis Model Context Protocol (MCP) untuk Antigravity (AGY)**
> Mengintegrasikan analisis otomatis terhadap kerentanan **OWASP Top 10 2025** langsung ke asisten AI Anda.

---

## 🎯 Gambaran Umum

**AGY Bug Bounty MCP Server** adalah platform asisten keamanan yang dirancang khusus untuk mempermudah alur kerja bug bounty hunting dan penetration testing. Dengan protokol MCP, asisten AI Anda (AGY/Claude) dapat mengeksekusi **86 modul uji keamanan** secara dinamis, menyimpan hasilnya ke database SQLite lokal, dan mengekspor laporan profesional dalam format HTML, Markdown, atau CSV.

MCP ini mencakup kerentanan web apps dan API berdasarkan klasifikasi **OWASP Top 10 2025**:
1. **A01:2025 — Broken Access Control** (IDOR, Path Traversal, CORS, Privilege Escalation)
2. **A02:2025 — Security Misconfiguration** (Exposed Files, Directory Listing, TLS Weakness, Default Credentials)
3. **A03:2025 — Software Supply Chain Failures** (Outdated Libraries, Manifest Exposure, Dependency Confusion)
4. **A04:2025 — Cryptographic Failures** (JWT weaknesses, Plaintext Transmission, Weak Ciphers, Sensitive Data Exposure)
5. **A05:2025 — Injection** (SQLi, XSS, SSRF, SSTI, XXE, Host Header, CRLF, NoSQL)
6. **A06:2025 — Insecure Design** (Rate Limit Checks, Price Manipulation, Captcha Bypass, Race Condition)
7. **A07:2025 — Authentication Failures** (Brute Force Checks, Session Fixation, JWT Attack Bypass, OAuth Misconfigs)
8. **A08:2025 — Software & Data Integrity Failures** (Insecure Deserialization, Cache Poisoning, Request Smuggling, Mass Assignment)
9. **A09:2025 — Security Logging Failures** (Log Injection, Error Disclosure, Sensitive Parameters in URLs, Debug Endpoints)
10. **A10:2025 — Mishandling of Exceptional Conditions** (Verbose Exception Leakage, Timing Attacks, Fail-Open Authentication)

---

## 🧠 Hunter Mindset Framework (NEW)

Berbeda dari scanner generik yang mengikuti checklist OWASP secara linear, AGY mengadopsi **kerangka hunting berbasis intuisi** yang ditanamkan ke setiap interaksi melalui *Universal System Prompt* (23K+ karakter). Framework ini terdiri dari **13 strategi hunting** yang saling melengkapi:

| # | Strategi | Filosofi Singkat |
|---|---|---|
| 1 | **Goal-First Hunting** | Tentukan objective (data breach, ATO, RCE, fraud) sebelum scanning |
| 2 | **Instinct Over Methodology** | Ikuti anomali, bukan checklist kaku |
| 3 | **Crown Jewels First** | Auth, payment, admin, OAuth > halaman informasional |
| 4 | **Escalation Before Submission** | Self-XSS → Stored via CSRF, IDOR read → write/delete |
| 5 | **Bug vs Feature Verification** | Cek changelog/docs; tolak self-XSS, missing header tanpa impact |
| 6 | **False Positive Prevention** | Reproducible? in-scope? real impact? |
| 7 | **Target Flexibility** | Adaptasi ke program apapun (web/API/mobile/cloud) |
| 8 | **Strict Guardrails** | Hard-block DoS, data wipe, ransomware, scope violation |
| 9 | **Tool-First Execution** | "Run the tool first, explain after." |
| 10 | **Hunter Mindset Pre-Engagement** | Goal → Industry → Hypothesis → Targeted tools |
| 11 | **Logic Over Automation** | Model business flow, identifikasi trust boundaries |
| 12 | **Industry-Specific Crown Jewels** | Fintech=payment, SaaS=billing, Healthtech=PHI |
| 13 | **OWASP as Safety Net** | Jalankan A01–A10 sweep TERAKHIR, bukan pertama |

Detail setiap strategi ada di `mcp_instance.py::_SYSTEM_PROMPT`. System prompt ini otomatis ter-inject ke **setiap klien MCP** yang terhubung (Claude Desktop, Claude Code, dll).

---

## 🛰️ Intelligence Layer (NEW)

AGY terintegrasi dengan **CVE + exploit intelligence** untuk mengkayakan setiap finding dengan data actionable dari sumber eksternal. Modul `tools/intelligence.py` menyediakan:

- **CVE Enrichment** via `vulnx_enrich_finding` — tarik deskripsi, CVSS vector, referensi, dan exploit publik untuk sebuah CVE.
- **Exploitability Filtering** via `vulnx_exploitable` — filter CVE berdasarkan kriteria **is_poc** (ada proof-of-concept publik), **is_kev** (masuk CISA Known Exploited Vulnerabilities), dan **is_remote** (exploitable tanpa local access). Fokus ke real-world risk, bukan CVE teoritis.
- **Metasploit Search** via `msf_module_search` — cari module Metasploit (`exploit/*`, `auxiliary/*`) yang relevan dengan CVE atau service tertentu untuk validasi eksploitability.
- **Exploit-DB Search** via `searchsploit_query` — query searchsploit (offline database Exploit-DB) untuk software, versi, atau keyword tertentu.

**Prasyarat eksternal** (instalasi manual di host, opsional tapi direkomendasikan):
```bash
# vulnx (ProjectDiscovery Cloud Platform CLI)
go install -v github.com/projectdiscovery/vulnx/cmd/vulnx@latest
vulnx auth --api-key <PDCP_API_KEY dari .env>

# searchsploit (Exploit-DB, biasanya sudah ada di Kali Linux)
sudo apt install exploitdb

# Metasploit Framework (opsional, untuk msf_module_search)
# Ikuti instalasi resmi di https://docs.metasploit.com/
```

Tools akan otomatis mendeteksi apakah CLI tersedia dan skip gracefully jika tidak ada, sehingga server tetap berjalan tanpa prerequisite eksternal.

---

## 🗺️ Roadmap / Planned

Fitur-fitur berikut **belum diimplementasikan** di source code ter-track saat ini, tapi direncanakan untuk rilis berikutnya:

- **Program-Specific Custom Headers** — dukungan env var `BUGBOUNTY_PROGRAM_HEADER_NAME` dan `BUGBOUNTY_PROGRAM_HEADER_VALUE` untuk program bug bounty yang mensyaratkan custom HTTP header (misalnya `X-Dashverse-BugBounty: <email>` atau program VDP spesifik lainnya). Saat ini `tools/http_utils.py` hanya mengirim `User-Agent` default; kontribusi untuk patch ini welcome.

---

## 🚀 Persyaratan Sistem

- **Python**: Versi 3.10 atau lebih tinggi.
- **Database**: SQLite3 (Dibuat otomatis saat inisialisasi).
- **Client**: Claude Desktop atau aplikasi lain yang mendukung Model Context Protocol.

---

## 🛠️ Instalasi & Setup Cepat

Ikuti langkah-langkah di bawah ini untuk memasang dan menjalankan server MCP di lingkungan lokal Anda:

### 1. Masuk ke direktori proyek
```bash
cd bugbounty-mcp
```

### 2. Buat dan aktifkan virtual environment (venv)
```bash
# Membuat virtual environment
python3 -m venv venv

# Mengaktifkan venv (Linux / macOS)
source venv/bin/activate

# Mengaktifkan venv (Windows)
# venv\Scripts\activate
```

### 3. Pasang dependensi
```bash
pip install -r requirements.txt
```

### 4. Konfigurasi Environment Variables
Salin berkas konfigurasi template `.env.example` menjadi `.env` lalu sesuaikan isinya:
```bash
cp .env.example .env
```
Isi konfigurasi dalam berkas `.env` mencakup:
```env
# API Keys (Opsional)
SHODAN_API_KEY=your_shodan_key
GITHUB_TOKEN=your_github_personal_access_token
PDCP_API_KEY=your_projectdiscovery_api_key

# Konfigurasi Network/HTTP
REQUEST_TIMEOUT=30
REQUEST_DELAY=0.5
USER_AGENT=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AGY/1.0
```

### 5. (Opsional) Pasang CLI untuk Intelligence Layer
Lihat section [Intelligence Layer](#-intelligence-layer-new) di atas untuk `vulnx`, `searchsploit`, dan `msfconsole`. Tanpa ini, tools CVE/exploit akan skip gracefully.

### 6. Jalankan Pengujian Server
Jalankan server untuk memverifikasi seluruh modul ter-load dengan benar:
```bash
python server.py
```
*Output sukses:* `[AGY] Loaded 14/14 tool modules` dan `[AGY] Starting stdio server...`

---

## ⚙️ Integrasi dengan Claude Desktop

Tambahkan konfigurasi server MCP ini ke pengaturan Claude Desktop Anda agar AI dapat mengenali dan mengeksekusi perkakas uji.

Buka berkas konfigurasi Claude Desktop Anda:
- **Linux/macOS**: `~/.config/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Tambahkan blok berikut di bawah bagian `"mcpServers"`:

```json
{
  "mcpServers": {
    "agy-bugbounty": {
      "command": "/absolute/path/to/bugbounty-mcp/venv/bin/python",
      "args": ["/absolute/path/to/bugbounty-mcp/server.py"],
      "env": {
        "SHODAN_API_KEY": "ISI_SHODAN_API_KEY_DISINI",
        "GITHUB_TOKEN": "ISI_GITHUB_TOKEN_DISINI"
      }
    }
  }
}
```
> ⚠️ **Catatan**: Ganti `/absolute/path/to/` dengan path lengkap lokasi direktori proyek di komputer Anda. Pastikan menunjuk ke executable `python` di dalam folder `venv`.

---

## 🔄 Alur Kerja Pengujian (Typical Workflow)

Berikut adalah contoh skenario penggunaan terpadu yang dapat dijalankan melalui interaksi dengan AGY:

```
1. Daftarkan Target Program baru
   → add_target(program_name="HackerOne - TargetCorp", domain="targetcorp.com", scope=["*.targetcorp.com"])

2. Jalankan Rekon Dasar
   → recon_domain(domain="targetcorp.com")
   → dns_lookup(domain="targetcorp.com", record_type="MX")

3. Discovery Aset & Endpoint Sensitif
   → forced_browsing_scan(base_url="https://targetcorp.com", wordlist_type="common")
   → admin_panel_discovery(base_url="https://targetcorp.com")
   → exposed_files_check(base_url="https://targetcorp.com")

4. Pemeriksaan baseline Keamanan Web
   → security_headers_check(url="https://targetcorp.com")
   → tls_ssl_check(hostname="targetcorp.com")
   → cookie_security_check(url="https://targetcorp.com")

5. Pengujian Kerentanan Spesifik (Contoh: SQLi, XSS, SSRF)
   → sqli_test(url="https://targetcorp.com/search.php", params={"q": "test"}, method="GET")
   → xss_test(url="https://targetcorp.com/profile.php", params={"user": "test"}, method="POST")

6. Penyimpanan & Pembuatan Laporan
   Semua temuan (findings) disimpan secara otomatis ke database lokal jika `target_id` disertakan saat menjalankan tools.
   → generate_report(target_id=1, format="html")
   → export_findings_csv(target_id=1)
```

---

## 🗄️ Manajemen Database Lokal

Proyek ini menggunakan database **SQLite** (`database/bugbounty.db`) untuk mencatat kemajuan pengujian Anda secara persisten.

### Tabel Utama:
1. **`targets`**: Menyimpan program bug bounty, ruang lingkup (scope), notes, dan bounty range.
2. **`findings`**: Daftar kelemahan/celah keamanan yang berhasil dikonfirmasi. Setiap celah dikategorikan berdasarkan kelas keparahan (Critical, High, Medium, Low) dan referensi kategori OWASP Top 10.
3. **`assets`**: Domain, subdomain, port terbuka, dan teknologi web yang teridentifikasi selama masa pengintaian (recon).
4. **`scan_logs`**: Catatan riwayat eksekusi perkakas (tools) untuk keperluan audit pengujian.

---

## 📁 Struktur Direktori Proyek

```
bugbounty-mcp/
├── server.py                   # Entry point utama MCP server
├── mcp_instance.py             # Instansiasi FastMCP & 23K-char system prompt
├── audit_hunter_tools.py       # Skrip audit konsistensi tools vs system prompt
├── config.py                   # Konfigurasi terpusat (env, timeout, UA, keys)
├── requirements.txt            # Dependensi paket Python
├── .env.example                # Template environment variables
├── .env                        # Konfigurasi aktif (DIABAIKAN OLEH GIT)
├── .gitignore
├── vulnerability_taxonomy_webapp_api.json # Taksonomi VRT khusus Web & API
├── database/                   # SQLite lokal (DIABAIKAN OLEH GIT)
├── templates/
│   └── report.html             # Template HTML laporan (Jinja2)
├── reports/                    # Output scan (DIABAIKAN OLEH GIT)
└── tools/
    ├── __init__.py
    ├── db.py                   # Layer interaksi SQLite
    ├── http_utils.py           # Shared httpx client + TLS helper
    ├── validators.py           # Validasi URL/domain/scope
    ├── a01_access_control.py   # IDOR, path traversal, privilege escalation
    ├── a02_misconfiguration.py # security misconfiguration tools
    ├── a03_supply_chain.py     # software supply chain tools
    ├── a04_cryptography.py     # cryptography failure tools
    ├── a05_injection.py        # injection vulnerability tools
    ├── a06_insecure_design.py  # insecure design verification
    ├── a07_authentication.py   # authentication bypass tests
    ├── a08_integrity.py        # integrity/deserialization verification
    ├── a09_logging.py          # logging & info disclosure tests
    ├── a10_exceptions.py       # exception mishandling verification
    ├── recon.py                # CRUD target & DNS/WHOIS recon
    ├── reporting.py            # Modul eksportir laporan
    ├── intelligence.py         # CVE/exploit intel (vulnx, msf, searchsploit)
    └── hunter.py               # 86 tools registered (A01–A10 + intel + recon)
```

---

## 🧰 Tools Inventory (86 Tools)

Total **86 modul uji keamanan** yang ter-register via FastMCP, diorganisir per kategori:

| Kategori | Modul | Tools Unggulan |
|---|---|---|
| **A01 Access Control** | `a01_access_control.py` | `idor_test`, `path_traversal_test`, `privilege_escalation_test`, `parameter_tampering_test`, `access_control_bypass_test`, `forced_browsing_scan` |
| **A02 Misconfiguration** | `a02_misconfiguration.py` | `security_headers_check`, `cookie_security_check`, `directory_listing_check`, `default_credentials_check`, `exposed_files_check`, `admin_panel_discovery`, `tls_ssl_check`, `subdomain_takeover_check`, `http_methods_check`, `check_https_redirect` |
| **A03 Supply Chain** | `a03_supply_chain.py` | `detect_vulnerable_js_libs`, `check_package_json_exposure`, `scan_github_secrets`, `check_dependency_confusion`, `check_sensitive_data_exposure`, `check_plaintext_credentials`, `check_cdn_integrity` |
| **A04 Cryptography** | `a04_cryptography.py` | `jwt_analyze`, `jwt_attack_test`, `ssl_cipher_check`, `detect_weak_hashing`, `padding_oracle_check`, `check_saml_vulnerabilities` |
| **A05 Injection** | `a05_injection.py` | `sqli_test`, `xss_test`, `ssti_test`, `xxe_test`, `command_injection_test`, `ssrf_test`, `nosql_injection_test`, `host_header_injection_test`, `crlf_injection_test` |
| **A06 Insecure Design** | `a06_insecure_design.py` | `business_logic_price_test`, `captcha_bypass_check`, `race_condition_test`, `mass_assignment_test`, `rate_limit_check` |
| **A07 Authentication** | `a07_authentication.py` | `account_enumeration_test`, `brute_force_protection_check`, `credential_stuffing_simulation`, `mfa_bypass_check`, `oauth_misconfiguration_check`, `password_policy_check`, `password_reset_test`, `session_management_check` |
| **A08 Integrity** | `a08_integrity.py` | `check_insecure_deserialization`, `cache_poisoning_test`, `http_request_smuggling_check` |
| **A09 Logging** | `a09_logging.py` | `log_injection_test`, `sensitive_data_in_logs_check`, `check_debug_endpoints` |
| **A10 Exceptions** | `a10_exceptions.py` | `check_fail_open`, `error_disclosure_check`, `error_handling_analysis`, `exception_information_disclosure`, `timing_attack_check` |
| **Recon** | `recon.py` | `add_target`, `delete_target`, `list_targets`, `dns_lookup`, `whois_lookup`, `recon_domain` |
| **Reporting** | `reporting.py` | `save_finding_tool`, `list_findings`, `update_finding_status_tool`, `generate_report`, `generate_executive_summary`, `export_findings_csv`, `cvss_calculator` |
| **Intelligence** | `intelligence.py` | `osint_recon`, `vulnx_enrich_finding`, `vulnx_exploitable`, `msf_module_search`, `searchsploit_query` |\n| **Hunter** | `hunter.py` | `define_hunt_goal`, `exploit_chain`, `escalation_advisor`, `hidden_endpoint_discovery`, `logic_flow_mapper` |\n\n| **ATT&CK+CAPEC** | `attck_capec_kb.py` | `search_attck`, `get_attck_technique`, `search_capec`, `get_capec_by_technique`, `get_attck_tactics` |\n| **OWASP API Security** | `owasp_api_top10.py` | `api_top10_search`, `api_top10_get`, `api_top10_list`, `api_top10_sync` |\n| **ExploitDB** | `exploitdb_kb.py` | `search_exploits`, `get_exploit`, `list_platforms`, `sync_exploitdb` |\n| **Hacktricks** | `hacktricks_kb.py` | `search_hacktricks`, `get_hacktricks_by_path`, `sync_hacktricks` |\n| **Nuclei** | `nuclei_kb.py` | `search_nuclei_templates`, `get_nuclei_template`, `sync_nuclei`, `list_nuclei_severities` |\n\n## 🗂️ Knowledge Base Modules (NEW)

---

## ⚠️ Pernyataan Hukum & Etika (Legal & Ethical Disclaimer)

> **🚨 PERINGATAN KERAS: Tool ini melakukan REAL network requests.**

AGY Bug Bounty MCP menjalankan request HTTP/TLS/DNS **langsung ke target yang Anda tentukan**. Setiap kali Anda memanggil `sqli_test`, `xss_test`, `port_scan`, `recon_domain`, atau hampir semua tool lainnya, request aktual terkirim ke server target. Artinya:

- **Gunakan HANYA pada target yang in-scope** program bug bounty resmi dan sesuai *rules of engagement* masing-masing program.
- **Selalu cek scope dan prohibited activities** sebelum testing — banyak program melarang testing pada subdomain tertentu, melarang automated scanning, melarang password spraying pada akun produksi, dll.
- **JANGAN PERNAH menjalankan tool ini terhadap** sistem milik sendiri yang tidak Anda izinkan, target out-of-scope, sistem pihak ketiga tanpa otorisasi tertulis, atau infrastruktur pemerintah/kritikal.
- **Rate limiting** di-config via `REQUEST_DELAY` di `.env` — turunkan nilai (atau naikkan delay) jika program target Anda mensyaratkan polite scanning.
- **Logging** request muncul di stderr server; waspadalah saat share output di publik — bisa saja URL lengkap ikut terexpos.

**PERINGATAN: Server MCP ini dikembangkan hanya untuk tujuan pengujian penetrasi resmi dan partisipasi program Bug Bounty yang sah secara hukum.**

1. Selalu lakukan pengujian di bawah batas ruang lingkup (*in-scope*) yang telah ditentukan secara tertulis oleh pemilik program.
2. Jangan pernah melakukan tindakan yang dapat menyebabkan kegagalan sistem layanan (*Denial of Service*), perusakan data, atau modifikasi data yang tidak sah.
3. Segala konsekuensi hukum atas penyalahgunaan perkakas ini di luar hak akses yang diizinkan sepenuhnya merupakan tanggung jawab pengguna masing-masing.
