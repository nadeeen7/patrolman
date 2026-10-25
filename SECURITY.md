# PATROLMAN — Security Policy and Safe Assessment Guide

This document defines the security architecture, authorization controls, operational boundaries, and vulnerability disclosure policies for the PATROLMAN Automated Vulnerability Assessment Framework.

---

## 1. Authorized-Target Requirements

PATROLMAN is designed solely for defensive, authorized assessments of applications and systems under the operator's direct ownership or explicit written authorization.

- **Explicit Authorization Mandatory**: By default (`AVA_REQUIRE_AUTHORIZED_TARGET=true`), PATROLMAN strictly refuses to dispatch any network scan unless an active, unexpired target authorization record exists in the database.
- **Strict Scope Boundaries**: Scan targets must match configured hostnames or IPv4/IPv6 CIDR ranges exactly. Wildcard patterns are prohibited to prevent accidental out-of-scope scanning.
- **Private & Loopback Safeguards**: Private network ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and loopback addresses (`127.0.0.0/8`) are locked down by default. Assessing loopback targets (such as local OWASP Juice Shop testbeds) requires explicit operator opt-in (`AVA_ALLOW_PRIVATE_TARGETS=true`).

---

## 2. Target Scope Validation & Runtime Defense

To prevent scope escape, SSRF, and DNS-rebinding attacks, PATROLMAN enforces multi-layer scope validation:

1. **Pre-flight Normalization**: Input target strings are sanitized, normalized to canonical IP or lowercase FQDN formats, and verified against internationalized domain name (IDN) standards.
2. **DNS Resolution Verification**: Before executing any network tool, the backend resolves the target host via an isolated subprocess. If the target resolves to more than 4 IP addresses, or if any resolved address falls outside the authorized CIDR boundaries, the scan terminates immediately.
3. **Literal IP Passing**: Scanners that support direct IP targets are passed literal canonical IP addresses rather than hostnames to ensure tools cannot be tricked by dynamic DNS changes during an assessment.
4. **Local Directory Traversal Defense**: For local source-code assessments (`Local` profile), targets are validated against `AVA_ALLOWED_LOCAL_ROOTS`. Symlinks, junctions, hardlinks, reparse points, and parent directory traversal (`../`) are rejected. Files are copied to a bounded, link-free temporary snapshot (maximum 10,000 files, 100 MB total, 10 MB per file).

---

## 3. Prohibited Assessment Methods

PATROLMAN enforces a non-destructive assessment baseline. The following attack categories are prohibited and rejected at both the configuration and engine layers:

- **No Denial of Service (`dos`)**: High-rate packet flooding, UDP amplification, stress testing, and resource-exhaustion tests are blocked. Rate limits default to 10 requests per second.
- **No Exploit Execution (`exploit`)**: Scanners must only verify vulnerability indicators; executing exploit payloads, reverse shells, or weaponized binary code is prohibited.
- **No Credential Attacks (`credential_attack`)**: Automated password brute-forcing, credential stuffing, and dictionary attacks are strictly disallowed.
- **Nikto Permanent Retirement**: Nikto was removed from PATROLMAN due to aggressive, unthrottled brute-forcing and denial-of-service risks. No configuration or API call can launch it.

---

## 4. Authentication and Authorization Safeguards

- **Single Trusted Administrator Model**: Designed for local execution by authorized security administrators.
- **Password Protection**: Passwords (minimum 8 characters, maximum 1024) are hashed using Argon2id or bcrypt (via Werkzeug security helpers). Plaintext passwords and hashes are never returned in API responses or logged.
- **Cookie & Session Security**:
  - Web sessions use server-side session stores with SHA-256 token hashing.
  - Session cookies are marked `HttpOnly` and `SameSite=Strict`.
  - The `Secure` flag is automatically applied when accessed over HTTPS.
  - Idle sessions expire after 30 minutes; absolute session lifetime is 8 hours.
- **CSRF Defense**: Pre-session CSRF tokens protect login and registration (`GET /api/auth/csrf`). Per-session CSRF tokens (`X-CSRF-Token`) protect all state-changing authenticated requests.
- **Brute-Force Throttling**: Client IP and per-account rate limits restrict login and registration to 5 attempts per 15-minute window with a 15-minute lockout.
- **Multi-Tenant / User Isolation**: Scans and evidence items are attributed to the creating user (`created_by`). Cross-user direct object access (IDOR) is blocked.
- **Tamper-Proof Audit Logging**: The `audit_events` table contains an append-only SQLite trigger preventing `UPDATE` and `DELETE` operations.

---

## 5. Secret and Environment-Variable Handling

- **Never Commit Secrets**: Never commit `.env` files, API keys, passwords, or tokens to version control. Keep `.env` listed in `.gitignore`.
- **API Token Requirements**: If external Bearer authentication is configured (`AVA_API_TOKEN`), the token must contain at least 32 characters of high-entropy data. Placeholder tokens (e.g. `REPLACE_WITH_...`) prevent server startup.
- **Automated Evidence Redaction**: `backend/services/results.py` automatically scrubs credentials, passwords, Bearer tokens, cookies, Basic authentication headers, and private keys from scanner output before storage or display.

---

## 6. Safe Report and Evidence Handling

- Generated HTML and JSON reports contain redacted evidence and are accessible only to authenticated administrators.
- Report downloads are protected by session authentication and explicit confirmation headers.
- Untrusted finding descriptions and HTTP request/response payloads are sanitized and rendered using safe text elements in the web UI, preventing Cross-Site Scripting (XSS).

---

## 7. Known Security Limitations

- **Not an OS Sandbox**: PATROLMAN relies on Windows Job Objects and native process controls for execution boundaries. It does not provide full virtual machine or container isolation.
- **Unauthenticated Web Crawling**: Web assessment tools evaluate surface endpoints; deep crawling behind complex Single-Sign-On (SSO) or multi-factor authentication (MFA) is not supported.
- **Offline Scanner Rules**: Trivy and Nuclei operate in offline mode by default to prevent unexpected network egress during scans.

---

## 8. Responsible Vulnerability Reporting

If you discover a security vulnerability or safety flaw within PATROLMAN, please practice responsible disclosure:
1. Do not open public GitHub issues for security vulnerabilities.
2. Submit a private security advisory or contact the project maintainers directly.
3. Provide a detailed reproduction guide including affected versions and proof-of-concept steps.
4. Maintainers will investigate and provide remediation patches promptly.

---

## 9. Disclaimer of Warranty

> **Important Assessment Disclaimer:** PATROLMAN is an automated assessment tool. Automated vulnerability scanners produce preliminary potential findings and technical observations. A scan reporting zero findings **does not prove that a target is secure or defect-free**. All results require human expert review and manual validation. The authors and maintainers accept no liability for damage resulting from authorized or unauthorized use of this software.
