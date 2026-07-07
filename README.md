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

This project's HTTP tooling framework originated from an early prototype
named "StealthVision". It has since been substantially refactored, hardened
(SSRF protection, mandatory scope validation, redirect guard), and rebranded
as AGY. We acknowledge the earlier framework as the foundation this project
built upon.

## Attribution

This project's HTTP tooling framework originated from an early prototype
named "StealthVision". It has since been substantially refactored, hardened
(SSRF protection, mandatory scope validation, redirect guard), and rebranded
as AGY. We acknowledge the earlier framework as the foundation this project
built upon.

## Tool Categories

Tools in this project fall into two categories:

**Live Active Testing** — makes real HTTP requests against the target you
specify, subject to mandatory scope validation and SSRF protection:
- a01_access_control, a02_misconfiguration, a03_supply_chain,
  a04_cryptography, a05_injection, a06_insecure_design, a07_authentication,
  a08_integrity, a09_logging, a10_exceptions
- recon, reporting, intelligence, hunter, subdomain_brute, port_scanner,
  browser_analysis

**Static Knowledge / Reference** — returns cheat-sheets, lookup data, or
generated templates; does NOT make network requests:
- *_kb.py modules (cve_kb, cwe_kb, htb_kb, thm_kb, hacktricks_kb,
  portswigger_kb, seclists_kb, rfc_kb, etc.)
- knowledge_base, rag_engine, mode_selector

⚠️ Only "Live Active Testing" tools require a registered `target_id` and are
bound by scope enforcement. Always verify you have written authorization
before running these against any target.
"""