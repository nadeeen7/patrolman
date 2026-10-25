# PATROLMAN — Automated Vulnerability Assessment Framework

PATROLMAN is an automated, defensive vulnerability assessment orchestration platform engineered for native Windows environments. Developed as an academic software engineering and cybersecurity project, PATROLMAN enables security administrators to conduct authorized, multi-tool security assessments across web applications, network endpoints, and local codebases through an intuitive dashboard.

> **Important Assessment Disclaimer:** Automated vulnerability scanners produce preliminary observations and potential findings. A scan reporting zero findings **does not prove that a target is secure or defect-free**. All scanner-generated results require human review and manual validation before remediation.

---

## 1. Project Overview

Running individual security scanners typically produces fragmented outputs, noisy false positives, and operational hazards. PATROLMAN coordinates leading open-source security tools into structured, non-destructive workflows by:

- **Enforcing strict scope boundaries**: Preventing out-of-scope scanning via host and CIDR validation.
- **Normalizing disparate outputs**: Converting diverse tool outputs into a standardized schema with severity, confidence, provenance, and automatically redacted evidence.
- **Guarding against destructive behavior**: Actively blocking denial-of-service (`dos`), weaponized exploit payloads (`exploit`), and credential attacks (`credential_attack`).
- **Providing full operational transparency**: Explicitly reporting the real-time execution state of every scanner (`COMPLETED_WITH_FINDINGS`, `COMPLETED_WITHOUT_FINDINGS`, `SKIPPED`, `FAILED`, etc.) so operators know exactly what ran and what was skipped.

---

## 2. Key Features

- **Strict Authorization Engine**: Enforces explicit database-backed target authorizations, CIDR network validation, DNS revalidation subprocesses, and prohibited-method restrictions.
- **Nine Integrated Security Scanners**: Automated port discovery, passive DNS enumeration, HTTP probing, technology fingerprinting, template-based vulnerability assessment, TLS auditing, web header analysis, secret leak detection, and dependency vulnerability scanning.
- **Automated Evidence Redaction**: Built-in scrubbing engine masks sensitive passwords, Bearer tokens, cookies, API keys, and Authorization headers in all logs, database records, and reports.
- **Native Windows Operation**: Runs directly on Windows 10 and 11 without requiring WSL, Docker, or Linux dependencies.
- **Single-Page Dashboard**: Modern React interface supporting dark and light themes, real-time scan progress polling, finding inspection modals, and multi-format report exports.

---

## 3. Technology Stack

- **Frontend**: React 19, Vite 6, Tailwind CSS v4, Lucide React icons.
- **Backend**: Python 3.11–3.13, Flask 3.1, SQLAlchemy 2.0+, Werkzeug 3.1.
- **Database**: SQLite 3 with Write-Ahead Logging (WAL) mode, foreign key constraints, and append-only audit trail triggers.
- **Authentication**: Argon2id / bcrypt password hashing, HttpOnly `SameSite=Strict` session cookies, pre-session CSRF tokens, and client rate limiting.

---

## 4. Architecture Overview

PATROLMAN follows a decoupled, service-oriented architecture:

```
[ React 19 Single-Page App ] ──(REST API + CSRF)──> [ Flask Backend Service (Port 5055) ]
                                                            │
                 ┌──────────────────────────────────────────┴──────────────────────────────────────────┐
                 ▼                                                                                     ▼
      [ SQLite WAL Database ]                                                              [ Scan Orchestration Engine ]
   - Administrator accounts & sessions                                                     - Single-worker FIFO queue
   - Target authorizations & audit trail                                                   - Windows Job Object containment
   - Scans, findings, assets, evidence                                                     - DNS revalidation & literal IP binding
                                                                                                       │
                                                 ┌─────────────────────────────────────────────────────┴──────────────────┐
                                                 ▼                                                                        ▼
                                     [ Network Assessment Tools ]                                             [ Local Assessment Tools ]
                              (Nmap, Subfinder, HTTPX, WhatWeb, Nuclei, SSLyze, Wapiti)                          (Gitleaks, Trivy)
```

1. **Client Layer**: The browser communicates with Flask over JSON REST endpoints (`/api/*`). State-changing requests require a validated CSRF token (`X-CSRF-Token`).
2. **Execution & Containment**: Assessments execute asynchronously in a background worker thread. Subprocesses are placed inside a Windows Job Object configured to terminate child processes cleanly on timeout or cancellation.
3. **Evidence Normalization & Deduplication**: Raw outputs are parsed by dedicated adapters, sanitized by the redaction engine, deduplicated by canonical endpoint and issue fingerprint, and persisted to SQLite.

---

## 5. Supported Assessment Tools

PATROLMAN integrates **exactly nine tools**. Each tool operates only within its designated profile, target type, and authorization gate.

| Tool | Simple purpose |
| :--- | :--- |
| **Nmap** | Discovers open TCP ports and determines active service version banners. |
| **Subfinder** | Passively enumerates valid subdomains using external DNS sources without active querying. |
| **HTTPX** | Probes discovered ports for active HTTP/HTTPS web services, status codes, and titles. |
| **WhatWeb** | Identifies website technologies, CMS platforms, web servers, and embedded libraries. |
| **Nuclei** | Scans web applications for security misconfigurations and CVEs using vetted, safe templates. |
| **SSLyze** | Analyzes TLS/SSL cipher suites, protocols, and certificate validity on HTTPS endpoints. |
| **Wapiti** | Audits web applications for missing security headers, cookie flags, and CSP gaps (opt-in safety gate). |
| **Gitleaks** | Scans local source code directories for hardcoded secrets, private keys, and credentials. |
| **Trivy** | Scans local filesystem dependencies and configuration files for known package vulnerabilities. |

> **Operational Note on Skipped Tools**: Tools are automatically marked `SKIPPED` when not applicable to the target type. For example, Subfinder is skipped when scanning a literal IP address (such as `127.0.0.1`), SSLyze is skipped for plain HTTP ports, and Gitleaks only executes during local directory scans.

### Retired Tool: Nikto
Nikto is deliberately and permanently excluded from PATROLMAN. It was retired due to unthrottled brute-force testing and high denial-of-service risks. No configuration or API route can launch it.

---

## 6. Supported Assessment Profiles

PATROLMAN organizes tool execution into four structured profiles:

- **Quick**: Bounded network scan targeting four core web ports (80, 443, 8000, 8443) using Nmap, HTTPX, and WhatWeb. Fast service discovery and passive technology identification.
- **Standard**: Common web and infrastructure ports using Nmap, Subfinder, HTTPX, WhatWeb, Nuclei, and SSLyze. Includes passive subdomain discovery, bundled safe Nuclei template checks, and TLS analysis.
- **Comprehensive**: Expanded fixed port list using all enabled network tools (Nmap, Subfinder, HTTPX, WhatWeb, Nuclei, SSLyze, and Wapiti). Wapiti requires explicit operator opt-in (`AVA_WAPITI_ENABLED=true`).
- **Local**: Filesystem source-code scan for approved local directories using Gitleaks and Trivy. Audits working-tree secrets, dependencies, and configuration files. Requires explicit path approval in `AVA_ALLOWED_LOCAL_ROOTS`.

---

## 7. Prerequisites and Supported Operating System

- **Operating System**: Windows 10 (64-bit) or Windows 11. (WSL and Docker are not required).
- **Python**: Python 3.11 to 3.13 (Verified on Python 3.13.14).
- **Node.js**: Node.js 18+ (Verified on Node.js v24.22.1) and npm 9+.
- **Database**: SQLite 3.35+ (Included natively with Python; WAL mode enabled).
- **External Scanner Binaries**:
  - `nmap.exe`: Official Windows installation from nmap.org.
  - `subfinder.exe`: ProjectDiscovery Windows AMD64 binary.
  - `httpx.exe`: ProjectDiscovery Windows AMD64 binary.
  - `whatweb`: Ruby script with native Ruby 3.x in `PATH`.
  - `nuclei.exe`: ProjectDiscovery Windows AMD64 binary with bundled templates.
  - `sslyze`: Python library installed in the virtual environment.
  - `wapiti3`: Python library installed in the virtual environment.
  - `gitleaks.exe`: Official Windows AMD64 binary.
  - `trivy.exe`: Official Windows AMD64 binary.

---

## 8. Installation and Setup Instructions for Windows

Open a PowerShell terminal and navigate to the project directory:

### Step 1: Create and Activate Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 2: Install Python Dependencies
Install the verified dependencies from the project requirement manifest:
```powershell
.\.venv\Scripts\python.exe -m pip install -r python-dependencies.txt
```
*(Alternatively, for core server dependencies only, use `requirements-lock.txt`).*

### Step 3: Install Frontend Dependencies
```powershell
npm --prefix frontend install
```

### Step 4: Initialize the Administrator Account
Set up the first administrator account via the CLI management tool:
```powershell
.\.venv\Scripts\python.exe -m backend.admin setup
```
Follow the hidden prompts to enter an administrator username (3–64 characters) and password (minimum 8 characters).

---

## 9. Environment Configuration

Create a `.env` file in the project root with the following safe default settings:

```powershell
Set-Content -LiteralPath '.env' -Encoding utf8 -Value @(
    "AVA_ALLOWED_TARGETS=127.0.0.1",
    "AVA_ALLOW_PRIVATE_TARGETS=true",
    "AVA_ALLOWED_LOCAL_ROOTS=C:\Projects\SampleApp",
    "AVA_WAPITI_ENABLED=false",
    "AVA_REGISTRATION_ENABLED=true",
    "AVA_REQUIRE_AUTHORIZED_TARGET=true"
)
```

> **Security Note**: Never commit real credentials, passwords, or tokens to version control. The `.env` file is git-ignored by default. If configuring an optional external API Bearer token via `AVA_API_TOKEN`, the token must be at least 32 characters long.

---

## 10. Starting PATROLMAN

### Method 1: Automated PowerShell Startup Script (Recommended)
```powershell
.\Start-Patrolman.ps1 -LoopbackTesting
```
This script launches the backend, checks prerequisites, sets up process isolation, and restricts scope to loopback testing (`127.0.0.1`).

### Method 2: Manual Terminal Execution

**Terminal 1 — Backend API Service:**
```powershell
.\.venv\Scripts\python.exe -m backend
```

**Terminal 2 — Frontend Development Server:**
```powershell
npm --prefix frontend run dev
```

---

## 11. Application URLs and Health Check

- **Frontend Web UI**: `http://127.0.0.1:5173/`
- **Backend API Base**: `http://127.0.0.1:5055/`
- **Health Check Endpoint**: `http://127.0.0.1:5055/api/health`

**Health Check Verification Command**:
```powershell
curl http://127.0.0.1:5055/api/health
```
**Expected Response**:
```json
{
  "data": {
    "phase": "integrated",
    "scanning_enabled": true,
    "status": "ok"
  }
}
```

---

## 12. Assessment Workflow

1. **Log In**: Open `http://127.0.0.1:5173/` in your browser and sign in with your administrator credentials.
2. **Authorize Target**: In the **Targets** tab, select or register an authorized scope (e.g., `127.0.0.1` for local OWASP Juice Shop).
3. **Verify Target Scope**: Confirm target hostnames and CIDRs. Verify that prohibited methods (`dos`, `exploit`, `credential_attack`) remain blocked.
4. **Launch Assessment**: In **New Assessment**, choose a profile (`Quick`, `Standard`, `Comprehensive`, or `Local`), select tools, and click **Start Assessment**.
5. **Monitor Progress**: Watch real-time execution states and stage progress on the scan details page.
6. **Inspect Findings**: Review discovered findings, confidence levels, and sanitized HTTP request/response evidence.
7. **Export Reports**: Generate compliance reports in HTML, JSON, or PDF format.

---

## 13. Findings, Evidence, and Report Exports

- **Finding Inspector**: Displays severity, status (`potential`, `confirmed`, `informational`, `inconclusive`), confidence (`scanner-reported`, `verified`), affected URL, and source provenance.
- **Evidence Inspector**: Shows sanitized HTTP request and response pairs captured during scanning.
- **Audit History**: Complete historical records stored in SQLite, surviving page refreshes and backend restarts.
- **Supported Export Formats**:
  - `GET /api/scans/:id/report?format=html`: Standalone HTML assessment report.
  - `GET /api/scans/:id/report?format=json`: Machine-readable assessment data export.
  - `GET /api/scans/:id/report?format=vulnerabilities`: Normalized vulnerability findings list.
  - `GET /api/scans/:id/report?format=pdf`: Formatted PDF executive report.

---

## 14. Verification and Automated Testing

### Backend Automated Test Suite (pytest)
```powershell
.\.venv\Scripts\python.exe -m pytest
```
*Verification status: 654 passed, 2 skipped across all test modules (Verified October 2026).*

### Frontend Unit & Component Tests (Vitest)
```powershell
npm --prefix frontend test
```
*Verification status: 87 passed across 5 test suites (Verified October 2026).*

### Frontend Production Build (Vite)
```powershell
npm --prefix frontend run build
```
Generates production assets in `frontend/dist/`, which are served directly by Flask via `backend/app.py`.

---

## 15. Security Controls and Safe-Use Guidance

- **Explicit Authorization Only**: Scans require an active, unexpired target authorization.
- **Scope Enforcement**: Enforces CIDR boundaries and revalidates DNS records immediately before each tool invocation.
- **Prohibited Methods Enforced**: Denial of service, exploit payloads, and credential attacks are rejected at both API and orchestrator levels.
- **Credential Protection**: Redaction engine sanitizes secrets, tokens, passwords, and cookies before storage or export.
- **Detailed Security Policy**: For full details on authentication safeguards, CSRF tokens, session handling, and responsible disclosure, see [SECURITY.md](SECURITY.md).

---

## 16. Limitations and Troubleshooting

### Common Troubleshooting Solutions
| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| **Port 5055 in use** | An earlier backend process is still running. | Run `Get-Process python` or `netstat -ano \| findstr :5055` and terminate the orphaned process. |
| **Port 5173 in use** | An earlier Vite server is running. | Close conflicting terminal or run `npm --prefix frontend run dev -- --port 5174`. |
| **Backend Network Error** | Backend is stopped, initializing, or CORS origin is blocked. | Verify backend at `http://127.0.0.1:5055/api/health` and verify `AVA_TRUSTED_ORIGINS`. |
| **Tool marked `SKIPPED`** | Incompatible target type. | Subfinder skips literal IP addresses; SSLyze skips plain HTTP endpoints. |
| **Tool marked `BLOCKED_BY_POLICY`** | Windows AppLocker or WDAC blocked execution. | Consult your administrator to approve binary hash. **Never disable Windows Defender or execution policies.** |
| **Local scan fails** | Target directory is not allowlisted. | Add exact folder path to `AVA_ALLOWED_LOCAL_ROOTS` in `.env`. |

### Important System Limitations
- **Single-Administrator Deployment**: Designed for local use by trusted administrators, not as a public multi-tenant SaaS.
- **Unauthenticated Crawling**: Assesses accessible endpoints; deep crawling behind complex Single-Sign-On (SSO) or multi-factor authentication (MFA) is not supported.
- **Passive Subdomain Enumeration**: Subfinder relies on external passive intelligence and does not perform active brute-force DNS resolution.
- **Trivy Offline Mode**: Vulnerability scanning requires an offline vulnerability database pre-cached on the system.

---

## 17. Project Status and Disclaimer

This project is developed for academic evaluation and authorized vulnerability assessment research.

> **Disclaimer**: PATROLMAN is provided "as is" without warranty of any kind. Finding zero vulnerabilities does not guarantee that a target is secure. All automated observations require human verification.
