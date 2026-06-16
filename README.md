# AGY Bug Bounty MCP Server

> **Asisten Bug Bounty Hunting Elite berbasis Model Context Protocol (MCP) untuk Antigravity (AGY)**
> Mengintegrasikan analisis otomatis terhadap kerentanan **OWASP Top 10 2025** langsung ke asisten AI Anda.

---

## 🎯 Gambaran Umum

**AGY Bug Bounty MCP Server** adalah platform asisten keamanan yang dirancang khusus untuk mempermudah alur kerja bug bounty hunting dan penetration testing. Dengan protokol MCP, asisten AI Anda (AGY/Claude) dapat mengeksekusi lebih dari 40+ modul uji keamanan secara dinamis, menyimpan hasilnya ke database SQLite lokal, dan mengekspor laporan profesional dalam format HTML, Markdown, atau CSV.

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

# Konfigurasi Network/HTTP
REQUEST_TIMEOUT=30
REQUEST_DELAY=0.5
USER_AGENT=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AGY/1.0
```

### 5. Jalankan Pengujian Server
Jalankan server untuk memverifikasi seluruh modul ter-load dengan benar:
```bash
python server.py
```
*Output sukses:* `[AGY] Loaded 12/12 tool modules` dan `[AGY] Starting stdio server...`

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
├── mcp_instance.py             # Instansiasi FastMCP & petunjuk sistem
├── requirements.txt            # Dependensi paket Python
├── .env.example                # Template berkas environment variables
├── .env                        # Konfigurasi aktif (DIABAIKAN OLEH GIT)
├── .gitignore
├── vulnerability_taxonomy_webapp_api.json # Taksonomi VRT khusus Web & API
├── database/
│   └── bugbounty.db            # Database SQLite lokal (dibuat otomatis)
├── templates/
│   └── report.html             # Template HTML laporan hasil uji
├── reports/                    # Direktori output laporan (HTML/Markdown/CSV)
└── tools/
    ├── __init__.py
    ├── db.py                   # Modul interaksi dengan SQLite
    ├── a01_access_control.py   # broken access control tools
    ├── a02_misconfiguration.py # security misconfiguration tools
    ├── a03_supply_chain.py     # software supply chain tools
    ├── a04_cryptography.py     # cryptography failure tools
    ├── a05_injection.py        # injection vulnerability tools
    ├── a06_insecure_design.py  # insecure design verification
    ├── a07_authentication.py   # authentication bypass tests
    ├── a08_integrity.py        # integrity/deserialization verification
    ├── a09_logging.py          # logging & info disclosure tests
    ├── a10_exceptions.py       # exception mishandling verification
    ├── recon.py                # CRUD target & tools rekon DNS/WHOIS
    └── reporting.py            # Modul eksportir laporan
```

---

## ⚠️ Pernyataan Hukum & Etika (Legal & Ethical Disclaimer)

**PERINGATAN: Server MCP ini dikembangkan hanya untuk tujuan pengujian penetrasi resmi dan partisipasi program Bug Bounty yang sah secara hukum.**

1. Selalu lakukan pengujian di bawah batas ruang lingkup (*in-scope*) yang telah ditentukan secara tertulis oleh pemilik program.
2. Jangan pernah melakukan tindakan yang dapat menyebabkan kegagalan sistem layanan (*Denial of Service*), perusakan data, atau modifikasi data yang tidak sah.
3. Segala konsekuensi hukum atas penyalahgunaan perkakas ini di luar hak akses yang diizinkan sepenuhnya merupakan tanggung jawab pengguna masing-masing.
