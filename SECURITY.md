# Security Policy

## Scope
This tool is designed for authorized bug bounty hunting and penetration testing only. Any misuse against systems without explicit written authorization is the sole responsibility of the user.

## Reporting a Vulnerability in This Tool Itself
If you discover a security issue in AGY's own code (e.g. an SSRF bypass, scope validation bypass, or credential handling issue), please report it privately rather than opening a public issue. We aim to respond within 5 business days.

## Known Limitations
- Redirect-scope-guard re-validates scope at every hop but is opt-in (`manual_follow_redirects=True`); tools not using this flag rely on `follow_redirects=False` alone.
- SSRF protection validates DNS resolution before each request/redirect hop, but a small TOCTOU window remains within a single attempt (see docstring in `tools/http_utils.py::secure_request`).