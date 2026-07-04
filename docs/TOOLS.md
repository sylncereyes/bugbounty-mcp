# StealthVision-MCP API Reference

Complete documentation of all MCP tools available in the StealthVision platform.

Last updated: Auto-generated from tool docstrings.

## Table of Contents

- [OWASP Top 10 Tools](#owasp-top-10-tools)
- [Core Tools](#core-tools)
- [Knowledge Base Tools](#knowledge-base-tools)
- [Advanced Testing Tools](#advanced-testing-tools)
- [Internal Pentest Tools](#internal-pentest-tools)

---

## OWASP Top 10 Tools

### A01 - Broken Access Control (`tools/a01_access_control.py`)

Tools for testing access control vulnerabilities including IDOR, path traversal, and privilege escalation.

| Tool | Parameters | Description |
|------|------------|-------------|
| `idor_test` | `url`, `params`, `method`, `target_id` | Tests for Insecure Direct Object Reference vulnerabilities |
| `path_traversal_test` | `url`, `param`, `target_id` | Tests for path traversal in file path parameters |
| `privilege_escalation_test` | `url`, `user_id`, `target_id` | Tests for privilege escalation vectors |
| `access_control_bypass_test` | `url`, `bypass_headers`, `target_id` | Tests access control header manipulation |

### A02 - Cryptographic Failures (`tools/a02_misconfiguration.py`)

Tools for TLS/SSL, weak cryptography, and certificate validation.

| Tool | Parameters | Description |
|------|------------|-------------|
| `tls_ssl_check` | `hostname`, `port` | Tests TLS/SSL configuration |
| `ssl_cipher_check` | `hostname`, `port` | Checks for weak cipher suites |
| `detect_weak_hashing` | `url`, `target_id` | Detects weak hashing algorithms in use |

### A03 - Injection (`tools/a03_supply_chain.py`)

Supply chain and CI/CD security tools.

### A04 - Insecure Design (`tools/a04_cryptography.py`)

Cryptographic implementation and JWT security tools.

### A05 - Injection (`tools/a05_injection.py`)

Core injection testing tools.

| Tool | Parameters | Description |
|------|-|-------------|
| `sqli_test` | `url`, `params`, `method`, `target_id` | Tests parameters for SQL Injection vulnerabilities |
| `xss_test` | `url`, `params`, `method`, `target_id` | Tests parameters for Reflected XSS vulnerabilities |
| `command_injection_test` | `url`, `params`, `method`, `target_id` | Tests parameters for OS Command Injection |
| `ssrf_test` | `url`, `params`, `ssrf_payload`, `method`, `target_id` | Tests parameters for SSRF vulnerabilities |
| `ssti_test` | `url`, `params`, `method`, `target_id` | Tests parameters for Server-Side Template Injection |
| `xxe_test` | `url`, `content_type`, `target_id` | Tests if XML parsers handle external entities |
| `crlf_injection_test` | `url`, `params`, `target_id` | Checks for CRLF injection |
| `nosql_injection_test` | `url`, `params`, `target_id` | Tests parameters for NoSQL Injection |

### A06 - Vulnerable Components (`tools/a06_insecure_design.py`)

Business logic and insecure design testing.

| Tool | Parameters | Description |
|------|------------|-------------|
| `business_logic_price_test` | `url`, `price_params`, `target_id` | Tests for price manipulation vulnerabilities |
| `race_condition_test` | `url`, `requests_count`, `target_id` | Tests for race condition vulnerabilities |
| `mass_assignment_test` | `url`, `restricted_params`, `target_id` | Tests for mass assignment vulnerabilities |

### A07 - Authentication (`tools/a07_authentication.py`)

Authentication security testing tools.

| Tool | Parameters | Description |
|------|------------|-------------|
| `account_enumeration_test` | `url`, `username_param` | Tests for username/email enumeration |
| `brute_force_protection_check` | `url`, `max_attempts` | Checks brute force protection |
| `mfa_bypass_check` | `url`, `target_id` | Tests MFA implementation bypass |
| `password_reset_test` | `url`, `email_param` | Tests password reset security |

### A08 - Integrity Failures (`tools/a08_integrity.py`)

Data integrity and deserialization tools.

### A09 - Logging Failures (`tools/a09_logging.py`)

Security misconfiguration and logging tools.

### A10 - SSRF (`tools/a10_exceptions.py`)

Exception handling and SSRF follow-up tools.

---

## Core Tools

### Recon (`tools/recon.py`)

| Tool | Parameters | Description |
|------|------------|-------------|
| `recon_domain` | `domain`, `target_id` | Performs subdomain and asset discovery |
| `dns_lookup` | `domain`, `record_type` | DNS record lookup |
| `whois_lookup` | `domain` | WHOIS information lookup |
| `port_scan` | `host`, `ports`, `target_id` | TCP port scanning |

### Reporting (`tools/reporting.py`)

| Tool | Parameters | Description |
|------|------------|-------------|
| `generate_report` | `target_id`, `format` | Generates HTML/Markdown/CSV report |
| `list_findings` | `target_id`, `severity`, `status` | Lists findings with filters |
| `update_finding_status` | `finding_id`, `status` | Updates finding status |

### Intelligence (`tools/intelligence.py`)

| Tool | Parameters | Description |
|------|------------|-------------|
| `searchsploit_query` | `software`, `version` | Searches ExploitDB via searchsploit |
| `msf_module_search` | `cve_id` | Searches Metasploit modules |
| `vulnx_enrich_finding` | `finding_data` | Enriches finding with CVE intel |

---

## Knowledge Base Tools

| Tool | Module | Description |
|------|--------|-------------|
| `search_attck` | `attck_capec_kb` | MITRE ATT&CK search |
| `search_cve` | `cve_kb` | CVE database search |
| `search_cwe` | `cwe_kb` | CWE database search |
| `rag_search` | `rag_engine` | RAG KB search |
| `search_exploits` | `exploitdb_kb` | ExploitDB search |

---

## Advanced Testing Tools

| Tool | Module | Description |
|------|--------|-------------|
| `csti_fuzz` | `csti_chains` | CSTI fuzzing |
| `waf_detect` | `waf_bypass` | WAF detection |
| `waf_bypass_payload` | `waf_bypass` | WAF bypass payload generation |
| `graphql_introspect` | `graphql_introspect` | GraphQL schema introspection |
| `graphql_mutation_test` | `graphql_mutation` | GraphQL mutation privilege test |

---

## Scope Enforcement

**IMPORTANT**: All vulnerability testing tools accept an optional `target_id` parameter. When provided:
- The tool validates the URL against declared scope in the `targets` table
- Out-of-scope URLs raise `ValueError` with clear error message
- Always run `add_target()` before testing to define scope

Example:
```python
# Add target with scope
target_id = add_target(
    program_name="HackerOne - Acme",
    domain="acme.com",
    scope=["*.acme.com", "api.acme.com"]
)

# Test - will fail if URL not in scope
result = sqli_test(
    url="https://api.acme.com/search",
    params={"q": "test"},
    target_id=target_id
)
```

---

## Configuration

Environment variables (set in `.env`):

| Variable | Default | Description |
|----------|---------|-------------|
| `VERIFY_SSL` | `true` | SSL certificate verification |
| `DRY_RUN` | `true` | Return payloads without execution |
| `REQUEST_DELAY` | `0.5` | Delay between HTTP requests (seconds) |
| `MCP_API_KEY` | `` | API key for SSE authentication |
| `ENCRYPTION_KEY` | `` | Fernet key for findings encryption |

---

## Error Codes

| Error Prefix | Meaning |
|--------------|---------|
| `OUT_OF_SCOPE:` | URL not in declared scope |
| `INVALID_TARGET:` | Target ID not found in database |
| `RATE LIMIT/WAF:` | Target blocking detected, backoff applied |