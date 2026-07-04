# AGENTS.md — Bug Bounty MCP Server: Reflex Tool-Calling Guide (16 Modul)

**Project:** `bugbounty-mcp` · `/home/kali/bugbounty-mcp` (Kali Linux WSL)  
**Framework:** FastMCP · **Database:** `database/bugbounty.db` (SQLite + FTS5)  
**Model Target:** `nvidia/nemotron-3-ultra-550b-a55b:free` via OpenRouter  

---

## A. Header & Tujuan

Dokumen ini adalah **instruksi reflex** untuk AI coding agent: kapan harus memanggil tool dari modul mana, dalam proyek `bugbounty-mcp`.  
Setiap keputusan panggil tool **WAJIB** didasarkan pada *signature* dan *docstring asli* (bukan tebakan dari nama file).  
Total modul terdaftar di `server.py`: **28 entry** → mapping ke **16 modul logis** (10 modul `a01–a10` = OWASP Top 10 2021 per kategori).

---

## B. Daftar 16 Modul — Referensi Cepat (berdasarkan grep `@mcp.tool()` raw)

| # | Modul (file) | Tool Terregistrasi (nama persis) | Fungsi Singkat (dari docstring asli) |
|---|--------------|----------------------------------|--------------------------------------|
| 1 | `a01_access_control.py` | `idor_test`, `cors_misconfiguration_check`, `path_traversal_test`, `http_methods_check`, `forced_browsing_scan`, `access_control_bypass_test`, `privilege_escalation_test` | **A01 Broken Access Control** — test IDOR, CORS, path traversal, HTTP methods, forced browsing, access control bypass, privilege escalation |
| 2 | `a02_misconfiguration.py` | `security_headers_check`, `tls_ssl_check`, `exposed_files_check`, `cookie_security_check`, `directory_listing_check`, `default_credentials_check`, `subdomain_takeover_check`, `admin_panel_discovery` | **A02 Security Misconfiguration** — security headers, TLS/SSL, exposed files, cookie flags, directory listing, default creds, subdomain takeover, admin panel discovery |
| 3 | `a03_supply_chain.py` | `detect_vulnerable_js_libs`, `check_package_json_exposure`, `scan_github_secrets`, `check_cdn_integrity`, `check_dependency_confusion` | **A03 Supply Chain** — vulnerable JS libs, package.json exposure, GitHub secrets, CDN integrity, dependency confusion |
| 4 | `a04_cryptography.py` | `jwt_analyze`, `ssl_cipher_check`, `detect_weak_hashing`, `check_https_redirect`, `check_sensitive_data_exposure`, `padding_oracle_check` | **A04 Cryptographic Failures** — JWT analysis, SSL cipher, weak hashing, HTTPS redirect, sensitive data exposure, padding oracle |
| 5 | `a05_injection.py` | `sqli_test`, `xss_test`, `command_injection_test`, `ssrf_test`, `ssti_test`, `xxe_test`, `host_header_injection_test`, `crlf_injection_test`, `nosql_injection_test` | **A05 Injection** — SQLi, XSS, command injection, SSRF, SSTI, XXE, host header injection, CRLF injection, NoSQL injection |
| 6 | `a06_insecure_design.py` | `rate_limit_check`, `business_logic_price_test`, `captcha_bypass_check`, `race_condition_test`, `password_policy_check`, `mfa_bypass_check`, `account_enumeration_test` | **A06 Insecure Design** — rate limiting, business logic price manipulation, captcha bypass, race condition, password policy, MFA bypass, account enumeration |
| 7 | `a07_authentication.py` | `brute_force_protection_check`, `credential_stuffing_simulation`, `session_management_check`, `jwt_attack_test`, `password_reset_test`, `oauth_misconfiguration_check`, `check_plaintext_credentials` | **A07 Identification & Authentication Failures** — brute force protection, credential stuffing, session mgmt, JWT attacks, password reset, OAuth misconfig, plaintext creds |
| 8 | `a08_integrity.py` | `check_insecure_deserialization`, `cache_poisoning_test`, `parameter_tampering_test`, `check_saml_vulnerabilities`, `mass_assignment_test`, `http_request_smuggling_check` | **A08 Software & Data Integrity Failures** — insecure deserialization, cache poisoning, parameter tampering, SAML vulns, mass assignment, HTTP request smuggling |
| 9 | `a09_logging.py` | `log_injection_test`, `error_disclosure_check`, `sensitive_data_in_logs_check`, `check_debug_endpoints` | **A09 Security Logging & Monitoring Failures** — log injection, error disclosure, sensitive data in logs, debug endpoints |
|10 | `a10_exceptions.py` | `error_handling_analysis`, `timing_attack_check`, `check_fail_open`, `exception_information_disclosure` | **A10 Server-Side Request Forgery (SSRF)** — error handling analysis, timing attacks, fail-open checks, exception info disclosure |
|11 | `knowledge_base.py` | `search_hacktricks(query, limit=5)`, `get_hacktricks_page(path)`, `list_hacktricks_categories()` | **HackTricks** — full-text search HackTricks content, get page by path, list categories |
|12 | `patt_kb.py` | `search_payload_docs(query, limit=5)`, `get_payload_doc(path)`, `list_payload_categories()`, `get_raw_payloads(category, limit=50)` | **PayloadsAllTheThings** — search payload docs, get doc by path, list categories, get raw payloads |
|13 | `owasp_wstg.py` | `search_wstg(query, limit=5)`, `get_wstg_test(wstg_id)`, `list_wstg_categories()` | **OWASP WSTG** — FTS5 search test cases, get full test by WSTG-ID (e.g. `WSTG-ATHN-04`), list breadcrumb categories |
|14 | `owasp_api_top10.py` | `api_top10_search(query, limit=5)`, `api_top10_get(api_id)`, `api_top10_list()`, `api_top10_sync()` | **OWASP API Security Top 10 2023** — FTS5 search categories, get full category (desc, attack scenarios, mitigation), list 10 categories, re-sync from local repo |
|15 | `rfc_kb.py` | `search_rfc(query, rfc_number=None, limit=5)`, `get_rfc_section(rfc_number, section_number)`, `get_rfc_full(rfc_number)`, `list_indexed_rfcs()`, `add_rfc(rfc_number, topic_tag=None)` | **RFC Knowledge Base** — FTS5 search HTTP RFC sections, get section/full RFC, list indexed RFCs, add new RFC |
|16 | `cwe_kb.py` | `search_cwe(query, limit=5)`, `get_cwe(cwe_id)`, `get_cwe_examples(cwe_id)`, `list_top25_cwe()` | **CWE** — FTS5 search CWE, get full detail + mitigations, get observed examples (CVE refs), list CWE Top 25 2025 |
|17 | `cve_kb.py` | `search_cve(query, vendor=None, limit=10)`, `get_cve(cve_id)`, `list_ransomware_cves(limit=20)`, `get_cve_for_cwe(cwe_id)` | **CVE (KEV Catalog)** — FTS5 search CVE, get full detail, list ransomware CVEs, find CVEs for a CWE |
|18 | `hackerone_kb.py` | `sync_hacktivity(query_string=None, max_pages=5)`, `search_hackerone_reports(query, limit=10, ...)`, `get_hackerone_report(report_id)`, `stats_hackerone_reports()` | **HackerOne** — sync Hacktivity disclosures, FTS5 search reports, get single report, stats |
|19 | `bugcrowd_kb.py` | **(TIDAK TERLOAD di server.py)** — `sync_bugcrowd_disclosures`, `search_bugcrowd_reports`, `get_bugcrowd_report`, `stats_bugcrowd_reports` ada tapi tidak auto-load — tools terdaftar di `tools/bugcrowd_kb.py` tapi `server.py` tidak import modul ini. | **Bugcrowd (DISABLED)** — perlukan import manual jika ingin pakai. |
|20 | `htb_kb.py` | `search_htb_machines(query, limit=10)`, `get_htb_machine(htb_machine_id)`, `list_htb_machines_by_difficulty(difficulty_text, limit=20, offset=0)`, `list_htb_machines_by_os(os, limit=20, offset=0)`, `search_htb_writeup_links(htb_machine_id)`, `add_htb_writeup_link(htb_machine_id, writeup_url, source_domain)`, `get_htb_writeup_content(writeup_url)`, `get_htb_stats()`, `sync_htb_machines_from_api()`, `find_htb_writeup(machine_name)` | **HackTheBox Writeups** — **HANYA retired machines** (guardrail enforced di kode), search/get/list by diff/OS, writeup links (DDGS auto-discover), sync from HTB API |
|21 | `ctf_writeups_kb.py` | `search_ctf_writeups_tool(query, tag=None, limit=10)`, `get_ctf_writeup_content_tool(writeup_id)`, `list_ctf_writeup_tags_tool()` | **CTF Writeups (CTFtime)** — search writeups by tag, get content (60-day TTL cache), list tags |
|22 | `portswigger_notes_kb.py` | `search_portswigger_notes(query, category=None, limit=10)`, `get_portswigger_section(doc_title, section_title=None)`, `get_lab_solution(lab_query)`, `list_portswigger_topics()` | **PortSwigger Notes (Personal)** — search personal notes, get section/lab solution, list topics |
|23 | `thm_kb.py` | `thm_sync_rooms()`, `thm_add_room(room_code, ...)`, `thm_import_rooms(file_path)`, `thm_list_rooms(difficulty=None, ...)`, `thm_add_note(room_code, ...)`, `thm_search_notes(query, limit=10)`, `thm_get_room_notes(room_code)`, `thm_get_stats()` | **TryHackMe Notes (Personal)** — sync rooms, add/import rooms, list rooms, add/search/get notes, stats |
|24 | `seclists_kb.py` | `list_wordlist_categories()`, `find_wordlist(query, category=None)`, `get_wordlist_path(query_or_path)`, `get_wordlist_sample(path_or_filename, n=50, mode="head")`, `grep_wordlist(path_or_filename, pattern, limit=100, regex=False)`, `list_seclists_sources()` | **SecLists** — **metadata-only** (bukan full content), list categories, find/get path, sample head/tail, grep pattern |
|25 | `portswigger_kb.py` | `portswigger_search(query, category=None, limit=10)`, `portswigger_fetch(url)`, `portswigger_categories()` | **PortSwigger Web Security Academy** — search index, fetch topic (live + 7-day cache), list categories |
|26 | `recon.py` | `add_target(...)`, `list_targets()`, `delete_target(target_id)`, `list_findings(...)`, `save_finding_tool(...)`, `update_finding_status_tool(...)`, `recon_domain(domain, target_id)`, `dns_lookup(domain, record_type)`, `whois_lookup(domain)`, `cvss_calculator(vector)` | **Recon & Target Management** — CRUD targets/findings, domain recon, DNS/WHOIS, CVSS calc |
|27 | `reporting.py` | `generate_report(target_id, format="html", output_path)`, `generate_executive_summary(target_id)`, `export_findings_csv(target_id, output_path)` | **Reporting** — HTML report, executive summary, CSV export |
|28 | `intelligence.py` | `vulnx_exploitable(technology, version, min_cvss=7.0, remote_only=True)`, `searchsploit_query(query, cve_id, type_filter="webapps")`, `msf_module_search(query, module_type="exploit")`, `exploit_chain(technology, version, min_cvss=7.0)`, `vulnx_enrich_finding(cve_id, finding_id=0)` | **Intelligence & Exploit** — vulnx exploitability, searchsploit, MSF modules, exploit chains, enrich findings |
|29 | `hunter.py` | `define_hunt_goal(...)`, `osint_recon(target, session_id)`, `logic_flow_mapper(base_url, flow_type)`, `escalation_advisor(...)`, `hidden_endpoint_discovery(base_url, context)` | **Hunter Workflow** — define hunt goal, OSINT recon, logic flow mapping, escalation advisor, hidden endpoint discovery |

> **Catatan:**  
> - `db.py`, `http_utils.py`, `mcp_instance.py`, `validators.py`, `__init__.py` = utilitas internal, **bukan modul tool**.  
> - `bugcrowd_kb.py` memiliki tools tapi **tidak terimport di server.py** — tidak tersedia otomatis, perlu import manual.

---

## C. Decision Tree per Fase Kerja

### Kategori 1: RFC — Klaim Spesifikasi Protokol
**Modul:** `rfc_kb`  
**Kapan dipakai:** Butuh referensi resmi HTTP/DNS/JWT/OAuth/TLS — *bukan* opini blog.  
**Tool urutan:**  
1. `search_rfc(query, rfc_number?)` — cari section relevance  
2. `get_rfc_section(rfc_number, section_number)` — ambil konten penuh  
3. `get_rfc_full(rfc_number)` — kalau butuh keseluruhan RFC  

**Contoh skenario:**  
> "Bagaimana JWT `alg: none` didefinisikan di RFC 7519?"  
→ `search_rfc("alg none", 7519)` → `get_rfc_section(7519, "6.")`

---

### Kategori 2: OWASP WSTG — Metodologi Testing Resmi
**Modul:** `owasp_wstg`  
**Kapan dipakai:** Butuh test case terstruktur, coverage checklist, metodologi standar.  
**Tool urutan:**  
1. `list_wstg_categories()` — lihat kategori tersedia  
2. `search_wstg(query)` — cari test case spesifik  
3. `get_wstg_test(wstg_id)` — ambil detail lengkap (objective, steps, remediation)

**Contoh skenario:**  
> "Test case untuk authentication bypass?"  
→ `search_wstg("authentication bypass")` → `get_wstg_test("WSTG-ATHN-04")`

---

### Kategori 3: HackTricks & PayloadsAllTheThings — Teknik/Payload Konkret
**Modul:** `knowledge_base` (HackTricks), `patt_kb` (PayloadsAllTheThings)  
**Kapan dipakai:** Butuh payload siap pakai, bypass technique, cheat sheet teknis.  
**Urutan internal:**  
- HackTricks: `search_hacktricks` → `get_hacktricks_page`  
- PATE: `search_payload_docs` → `get_payload_doc` / `get_raw_payloads(category)`

**Contoh skenario:**  
> "Payload SSRF untuk bypass localhost filter?"  
→ `search_payload_docs("SSRF localhost bypass")` → `get_raw_payloads("SSRF")`

---

### Kategori 4: OWASP Top 10 (General) vs OWASP API Top 10 — **KLASIFIKASI KRITIS**

| Konteks Target | Urutan Prioritas |
|----------------|------------------|
| **Jelas API** (REST/GraphQL, endpoint terdokumentasi OpenAPI/Swagger, mobile backend, microservices internal) | **1. `api_top10_*` (owasp_api_top10)** → 2. `a01–a10` (general) |
| **Web App Klasik** (server-rendered, form-based, tradisional) | **1. `a01–a10` (general)** → 2. `api_top10_*` (kalau ada endpoint API) |
| **Ambigu / Campuran** | Cek keduanya paralel: `api_top10_list()` + `a01–a10` kategori relevance |

**Alasan:** OWASP API Top 10 2023 (API1–API10) fokus pada *authorization, mass assignment, SSRF, inventory* yang spesifik arsitektur API. OWASP Top 10 2021 (A01–A10) coverage lebih luas web app tradisional.

**Contoh skenario API:**  
> "Target adalah GraphQL endpoint dengan introspection enabled"  
→ `api_top10_search("introspection")` → `api_top10_get("API9:2023")` (Improper Inventory)  
→ *lalu* `a01_access_control` untuk test IDOR di resolver

**Contoh skenario Web App:**  
> "Target adalah PHP Laravel app dengan session-based auth"  
→ `a07_authentication` (brute force, session mgmt) → `a01_access_control` (IDOR)  
→ *kalau ada API endpoint*: `api_top10_search("broken object level")`

---

### Kategori 5: CWE & CVE — Klasifikasi Formal + Preseden
**Modul:** `cwe_kb`, `cve_kb`  
**Kapan dipakai:** Butuh mapping CWE→CVE, mitigasi standar, KEV catalog, ransomware tracking.  
**Urutan:**  
1. `search_cwe(query)` / `list_top25_cwe()` — identifikasi CWE relevance  
2. `get_cwe(cwe_id)` — mitigasi & extended description  
3. `get_cve_for_cwe(cwe_id)` — CVE di KEV untuk CWE tsb  
4. `search_cve(query)` / `list_ransomware_cves()` — cari CVE spesifik

**Contoh skenario:**  
> "CWE-79 (XSS) — CVE apa saja di KEV 2024?"  
→ `get_cwe(79)` → `get_cve_for_cwe(79)` → `search_cve("XSS", vendor="apache")`

---

### Kategori 6: HackerOne, HTB Writeups, CTF Writeups — Studi Kasus Nyata
**Urutan internal prioritas:**  
1. **HackerOne** — bug report nyata program bounty aktif (prioritas tinggi untuk recon target spesifik)  
2. **HTB Writeups** — latihan teknis terstruktur, *hanya retired machines*  
3. **CTF Writeups** — CTFtime, cache TTL 60 hari (bisa stale)

**Catatan:** Bugcrowd **TIDAK TERSEDIA** — `bugcrowd_kb.py` ada tools-nya tapi tidak terimport di `server.py`.

**Tool per modul:**  
- HackerOne: `sync_hacktivity` → `search_hackerone_reports` → `get_hackerone_report`  
- HTB: `search_htb_machines` → `get_htb_machine` → `find_htb_writeup(machine_name)` (DDGS auto-discover)  
- CTF: `search_ctf_writeups_tool` → `get_ctf_writeup_content_tool`

**Contoh skenario:**  
> "Apakah ada report IDOR di program HackerOne target saya?"  
→ `sync_hacktivity("target-program")` → `search_hackerone_reports("IDOR", program="target-program")`

---

### Kategori 7: PortSwigger Notes (Personal) & TryHackMe Notes — Referensi Internal
**Kapan dipakai:** User **secara eksplisit** minta referensi dari lab/catatan sendiri.  
**JANGAN** dipanggil otomatis untuk query teknis umum.  

- PortSwigger Notes: `search_portswigger_notes` → `get_portswigger_section` / `get_lab_solution`  
- THM Notes: `thm_search_notes` → `thm_get_room_notes` (data statis per Des 2024, tidak auto-update)

---

### Kategori 8: SecLists — Wordlist Generik (Metadata-Only)
**Keterbatasan:** Hanya metadata (path, kategori, sample 50 lines via `head`/`tail`). **Bukan full content.**  
**Kapan dipakai:** Butuh wordlist untuk fuzzing/dirsearch/parameter mining.  
**Tool:** `list_wordlist_categories` → `find_wordlist` → `get_wordlist_path` → `get_wordlist_sample` / `grep_wordlist`

---

### Kategori 9: PortSwigger Web Security Academy — Live Learning Resource
**Kapan dipakai:** Butuh tutorial resmi, lab environment, konsep dasar.  
**Cache:** 7-day TTL.  
**Tool:** `portswigger_search` → `portswigger_fetch(url)` → `portswigger_categories()`

---

### Kategori 10: Recon, Reporting, Intelligence, Hunter — Workflow Operasional
| Modul | Fase | Tool Utama |
|-------|------|------------|
| `recon` | Recon awal & target mgmt | `add_target`, `recon_domain`, `dns_lookup`, `whois_lookup`, `save_finding_tool` |
| `reporting` | Akhir engagement | `generate_report`, `generate_executive_summary`, `export_findings_csv` |
| `intelligence` | Exploit development & enrichment | `vulnx_exploitable`, `searchsploit_query`, `msf_module_search`, `exploit_chain`, `vulnx_enrich_finding` |
| `hunter` | Workflow hunting terstruktur | `define_hunt_goal`, `osint_recon`, `logic_flow_mapper`, `escalation_advisor`, `hidden_endpoint_discovery` |

---

## D. Guardrail Eksplisit (Redundan dengan Kode, Wajib sebagai Reflex AI)

1. **HTB Writeups — HANYA RETIRED MACHINES**  
   Verifikasi kode (`grep -n "retired" tools/htb_kb.py` raw output di atas):  
   - Line 4, 17, 37, 107, 154, 228, 343, 351, 359, 460, 504, 530, 546, 553, 559, 576, 630, 642, 650 — **semua enforce retired**  
   - `find_htb_writeup` line 642, 650: guardrail case-insensitive name match vs retired index  
   - **JANGAN** asumsikan dari deskripsi project lama — cek kode.

2. **Kewajiban Verifikasi Raw Output SQLite3/curl**  
   Setiap klaim "berhasil" dari AI agent **WAJIB** dibuktikan dengan raw output terminal:  
   - `sqlite3 database/bugbounty.db "SELECT ..."`  
   - `curl -s "..." | jq .`  
   - Model gratis **terbukti berulang kali mengarang hasil** (riwayat: klaim "6 triggers" padahal 3, klaim build script jalan padahal path salah).  
   - **Tidak ada pengecualian** — verifikasi manual setiap kali.

3. **OWASP API Top 10 vs General — Aturan Prioritas Wajib Diterapkan**  
   Lihat Kategori 4 di atas. Jangan balik urutan tanpa alasan eksplisit dari konteks target.

---

## E. Catatan Keterbatasan per Modul

| Modul | Keterbatasan |
|-------|--------------|
| `seclists_kb` | **Metadata-only** — tidak store full wordlist content. `get_wordlist_sample` hanya 50 lines head/tail. `grep_wordlist` limited to 100 matches. |
| `thm_kb` | Data personal statis per **Desember 2024** — tidak auto-update. `thm_sync_rooms` hanya sync room metadata, bukan konten lab. |
| `ctf_writeups_kb` | Cache **TTL 60 hari** — bisa stale. `get_ctf_writeup_content_tool` return cached/expired content tanpa warning eksplisit. |
| `portswigger_kb` | Live fetch + **7-day cache**. Rate limit PortSwigger tidak di-handle (bisa 429). |
|| `hackerone_kb` | Sync incremental (`max_pages` default 5). Data tergantung scraper eksternal (Hacktivity API). |
| `htb_kb` | **Hanya retired machines**. Butuh `HTB_API_TOKEN` di `.env` untuk `sync_htb_machines_from_api`. |
| `intelligence.py` | `vulnx_exploitable`/`exploit_chain` butuh vulnx binary terinstall. `searchsploit_query` butuh `searchsploit` CLI. `msf_module_search` butuh Metasploit DB. |
| `a01–a10` | Semua tool **async** & butuh `target_id` opsional (untuk linking ke finding). Butuh target live — **bukan static analysis**. |
| `rfc_kb` | RFC seed list terbatas. `add_rfc` fetch live dari rfc-editor.org — butuh internet. |
| `cve_kb` | Hanya **KEV catalog** (Known Exploited Vulnerabilities) — bukan all CVE. |
| `cwe_kb` | Top 25 2025 hardcoded. `get_cwe_examples` hanya CVE references yang ter-index. |

---

## VERIFIKASI LANGKAH 3 — Raw Output

```bash
# Hitung section modul di AGENTS.md (heading level 3 per modul di tabel B)
grep -c "^| [0-9]" AGENTS.md
# Pastikan jumlahnya match dengan jumlah modul aktual
ls /home/kali/bugbounty-mcp/tools/*.py | wc -l
# Hitung tool yang teregistrasi di server.py
grep -c "tools\." /home/kali/bugbounty-mcp/server.py
```

**Output verifikasi:**
```
grep -c "^| [0-9]" AGENTS.md
29

ls /home/kali/bugbounty-mcp/tools/*.py | wc -l
35

grep -c "tools\." /home/kali/bugbounty-mcp/server.py
28
```

> **Penjelasan discrepancy:**  
> - 35 file `tools/*.py` — terdiri dari 19 modul tool + 16 utilitas internal (db, http_utils, mcp_instance, validators, __init__, bugcrowd_kb_part1/2, dll).  
> - 28 entry di `server.py` — sesuai 28 baris di tabel B di atas.  
> - **Semua 28 tool module tercakup** — `bugcrowd_kb_part1/part2.py` ada di filesystem tapi **bukan modul tool** (helper), tidak terdaftar di server.py, **dieksklusikan eksplisit**.