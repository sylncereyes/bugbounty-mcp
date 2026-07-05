"""
StealthVision-MCP Server - OWASP Top 10 2021 Vulnerability Assessment Platform

A modular MCP server for bug bounty hunting, providing professional security testing
capabilities aligned with the OWASP Top 10 2021.

## 🛠️ Features
- **Modular Testing**: Organized by OWASP categories (A01-A10).
- **Scope Enforcement**: Mandatory scope validation using `target_id`.
- **Security First**: SSRF protection via DNS pinning and custom transport.
- **Professional Workflow**: Integrated with SQLite for targets and findings.
- **Knowledge Base**: RAG-enhanced access to CVE, CWE, PortSwigger, and HackTricks.

## 🚀 Setup
1. Install dependencies: `pip install -r requirements.txt`
2. Configure `.env` (see `.env.example`)
3. Run the server: `python server.py`

## 🗂️ Tool Categories
### Live Active Testing (OWASP Top 10)
- a01_access_control, a02_misconfiguration, a03_supply_chain, a04_cryptography,
  a05_injection, a06_insecure_design, a07_authentication, a08_integrity,
  a09_logging, a10_exceptions.

### Static Knowledge & Reference
- knowledge_base, owasp_wstg, owasp_api_top10, cve_kb, cwe_kb, htb_kb, thm_kb,
  patt_kb, lolbins_kb, attck_capec_kb, exploitdb_kb, nuclei_kb, hacktricks_kb,
  seclists_kb, portswigger_kb, portswigger_notes_kb, rfc_kb.

## ⚖️ Attribution
StealthVision-MCP evolved from an early prototype framework. We acknowledge the original 
architectural concepts and have refactored the system to ensure strict security 
and scope enforcement.

## ⚠️ Legal Disclaimer
This tool is for authorized security testing only. Unauthorized use is illegal.
"""