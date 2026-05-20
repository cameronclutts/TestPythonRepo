# TestPythonRepo — Vulnerability Testing Corpus

A collection of intentionally vulnerable Python files covering a wide range of vulnerability categories and severity levels. **None of this code should ever be used in production.**

---

## Purpose

This repo serves as a test corpus for:

- Validating static analysis rule coverage and detection accuracy
- Benchmarking true-positive rates across vulnerability categories
- Training and demonstration of SAST tooling
- Security education — understanding what vulnerable code looks like before writing it

---

## File Inventory

| File | Description | Vulns |
|---|---|---|
| `main.py` | Foundational examples — RCE, deserialization, weak hashing | 3 |
| `sql_injection.py` | SQL injection via string concat, f-strings, `%` formatting | 6 |
| `path_traversal.py` | Directory traversal via `open()`, `send_file()`, `os.path.join()` | 5 |
| `hardcoded_secrets.py` | AWS keys, DB passwords, JWT secrets, API keys, RSA private key | 11 |
| `ssrf_and_xss.py` | SSRF via user-controlled URLs, reflected XSS, open redirect | 9 |
| `insecure_deserialization.py` | `pickle`, `yaml.load`, `jsonpickle`, `marshal`, `shelve` | 8 |
| `command_injection.py` | `os.system`, `subprocess` with `shell=True`, `os.popen` | 8 |
| `crypto_weaknesses.py` | MD5/SHA1 passwords, insecure random, DES/RC4/AES-ECB, `verify=False` | 12 |
| `xxe_and_template_injection.py` | XXE via lxml, SSTI via Jinja2, LDAP injection | 8 |
| `insecure_flask_django.py` | Hardcoded secrets, debug mode, CSRF missing, insecure cookies, CORS | 14 |
| `massive_vulns.py` | High-density corpus — 11 sections, 240+ distinct vulnerability instances | 240 |
| **Total** | | **~324** |

---

## Total Vulnerability Count

| Metric | Count |
|---|---|
| **Total vulnerabilities** | **~324** |
| Files | 11 |
| Vulnerability categories | 12 |

---

## Breakdown by Severity

Severity assignments follow Semgrep's standard classification (ERROR → CRITICAL, WARNING → HIGH, INFO → MEDIUM, NOTE → LOW).

| Severity | Count | % of Total |
|---|---|---|
| Critical | ~91 | 28% |
| High | ~164 | 51% |
| Medium | ~53 | 16% |
| Low | ~16 | 5% |
| **Total** | **~324** | **100%** |

### Critical (~91)
Remote code execution, arbitrary command injection, insecure deserialization leading to RCE, server-side template injection, and live payment/cloud credentials.

- Command injection (`os.system`, `subprocess shell=True`, `os.popen`) — 34 instances
- Insecure deserialization (`pickle.loads`, `marshal.loads` on untrusted input) — 15 instances
- Arbitrary code execution (`eval()`, `exec()`, `__import__()` on user input) — 15 instances
- Server-side template injection (Jinja2 `Template(user_input)`, `render_template_string`) — 11 instances
- Hardcoded cloud/payment credentials (AWS keys, Stripe live key, RSA private key) — 11 instances
- RCE via deserialization in primary examples — 5 instances

### High (~164)
Injection flaws, unvalidated redirects, path traversal, SSRF, XSS, and strong-but-not-immediately-exploitable credential exposure.

- SQL injection (string concat, f-string, `%` format) — 41 instances
- SSRF (user-controlled `requests.get`, `urllib.urlopen`, raw sockets) — 24 instances
- Path traversal (`open()`, `send_file()`, `os.path.join()` with user input) — 25 instances
- Hardcoded secrets (DB passwords, JWT secrets, API keys, tokens) — 30 instances
- Insecure deserialization (`yaml.load` without Loader, `jsonpickle.decode`) — 13 instances
- XSS — reflected user input in HTML responses — 16 instances
- XXE — lxml with entity resolution enabled — 7 instances
- Insecure random for security tokens (`random.randint`, `random.choice`) — 8 instances

### Medium (~53)
Weak algorithms, insecure TLS configuration, broken session security, and misconfigured framework defaults.

- Weak hashing for passwords (MD5, SHA1) — 15 instances
- Broken/weak ciphers (DES, RC4, AES in ECB mode) — 10 instances
- SSL certificate verification disabled (`verify=False`, `CERT_NONE`) — 7 instances
- Insecure Flask/Django configuration (debug mode, insecure cookies, wildcard CORS) — 13 instances
- Open redirect — 5 instances
- XXE via `xml.etree` — 3 instances

### Low (~16)
Defense-in-depth issues and informational findings that reduce security posture but are not directly exploitable.

- Django security settings disabled (`SECURE_HSTS_SECONDS=0`, `SECURE_SSL_REDIRECT=False`, etc.) — 7 instances
- Hardcoded IV / static salt — 3 instances
- Base64 used as encryption — 2 instances
- Timing-attack-vulnerable comparisons — 2 instances
- Verbose error messages (stack traces exposed) — 2 instances

---

## Breakdown by Vulnerability Category

| Category | CWE | Instances | Severity |
|---|---|---|---|
| SQL Injection | CWE-89 | ~41 | High |
| Command Injection / RCE | CWE-78 | ~34 | Critical |
| Hardcoded Secrets | CWE-798 | ~41 | Critical / High |
| Path Traversal | CWE-22 | ~25 | High |
| Insecure Deserialization | CWE-502 | ~28 | Critical / High |
| SSRF | CWE-918 | ~24 | High |
| XSS (Reflected) | CWE-79 | ~16 | High |
| Weak Cryptography | CWE-327 | ~22 | High / Medium |
| Server-Side Template Injection | CWE-94 | ~15 | Critical |
| Arbitrary Code Execution | CWE-95 | ~15 | Critical |
| XXE | CWE-611 | ~13 | High / Medium |
| Insecure Configuration | CWE-16 | ~10 | Medium / Low |

---

## Notes

- Vulnerability counts are based on manual review. Actual scanner findings will vary depending on which rule packs are active and the tool version used.
- Some instances are intentionally redundant across files to validate that rules fire consistently across different code patterns (e.g., f-string vs. string concatenation SQL injection).
- `massive_vulns.py` is structured in labeled sections to make it easy to isolate specific vulnerability families during testing.

---

> **Warning:** This repository contains code that deliberately demonstrates serious security vulnerabilities. It is intended solely for SAST testing and security education. Do not deploy, execute against live infrastructure, or use any patterns shown here in real applications.
