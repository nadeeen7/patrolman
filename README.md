# PATROLMAN — Automated Vulnerability Assessment Framework

PATROLMAN is an automated, defensive vulnerability assessment orchestration platform engineered for native Windows environments. Developed for academic software engineering and cybersecurity research, PATROLMAN enables security administrators to conduct authorized, multi-tool assessments across web applications, network endpoints, and local codebases through a unified, intuitive dashboard.

> **Important Assessment Disclaimer:** Automated vulnerability scanners produce preliminary observations and potential findings. A scan reporting zero findings **does not prove that a target is secure or defect-free**. All scanner-generated results require human review and manual validation before remediation.

---

## 1. Project Overview

Running individual security scanners typically produces fragmented outputs, noisy false positives, and operational hazards. PATROLMAN coordinates leading open-source security tools into structured, non-destructive workflows by:

- **Enforcing strict scope boundaries**: Preventing out-of-scope scanning via host and CIDR validation.
- **Normalizing disparate outputs**: Converting diverse tool outputs into a standardized schema with severity, confidence, provenance, and automatically redacted evidence.
- **Guarding against destructive behavior**: Actively blocking denial-of-service (`dos`), weaponized exploit payloads (`exploit`), and credential attacks (`credential_attack`).
- **Providing full operational transparency**: Explicitly reporting the real-time execution state of every scanner (`COMPLETED_WITH_FINDINGS`, `COMPLETED_WITHOUT_FINDINGS`, `SKIPPED`, `FAILED`, etc.) so operators know exactly what ran and what was skipped.

---

## 2. Integrated Assessment Tools

PATROLMAN implements integrations for **exactly nine tools**. Each tool operates only within its designated profile, target type, and authorization gate.

| Tool | Simple purpose | Status |
| :--- | :--- | :--- |
| **Nmap** | Discovers open TCP ports and determines active service version banners. | Core Network Tool |
| **Subfinder** | Passively enumerates valid subdomains using external DNS sources without active querying. | Passive Reconnaissance |
| **HTTPX** | Probes discovered ports for active HTTP/HTTPS web services, status codes, and titles. | Core Web Tool |
| **WhatWeb** | Identifies website technologies, CMS platforms, web servers, and embedded libraries. | Technology Fingerprinting |
| **Nuclei** | Scans web applications for security misconfigurations and CVEs using vetted, safe templates. | Vulnerability Scanner |
| **SSLyze** | Analyzes TLS/SSL cipher suites, protocols, and certificate validity on HTTPS endpoints. | Cryptographic Auditor |
| **Wapiti** | Audits web applications for missing security headers, cookie flags, and CSP gaps. | Gated Auditor (Opt-in) |
| **Gitleaks** | Scans local source code directories for hardcoded secrets, private keys, and credentials. | Local Secret Scanner |
| **Trivy** | Scans local filesystem dependencies and configuration files for known package vulnerabilities. | Local Dependency Scanner |

> **Operational Note on Skipped Tools**: Tools are automatically marked `SKIPPED` when not applicable to the target type. For example, Subfinder is skipped when scanning a literal IP address (such as `127.0.0.1`), SSLyze is skipped for plain HTTP ports, and Gitleaks only executes during local directory scans.

### Retired Tool: Nikto
Nikto is deliberately and permanently excluded from PATROLMAN. It was retired due to unthrottled brute-force testing and high denial-of-service risks. No configuration or API route can launch it.

---

## 3. Supported Operating System & Prerequisites

### Supported Environment
- **Operating System**: Native Windows 10 (64-bit) or Windows 11. (WSL and Docker are not required).

### Core Runtime Dependencies
- **Python**: Python 3.11 to 3.13 (Verified on Python 3.13.14).
- **Node.js**: Node.js 18+ (Verified on Node.js v24.22.1) and npm 9+.
- **Database**: SQLite 3.35+ (Included natively with Python; WAL mode enabled).

### External Scanner Binaries (Optional / Tool-Specific)
PATROLMAN automatically detects available tools on your system `PATH` or configured paths:
- `nmap.exe`: Official Windows installation from [nmap.org](https://nmap.org/).
- `subfinder.exe`: ProjectDiscovery Windows AMD64 binary.
- `httpx.exe`: ProjectDiscovery Windows AMD64 binary.
- `whatweb`: Ruby script with native Ruby 3.x installed in `PATH`.
- `nuclei.exe`: ProjectDiscovery Windows AMD64 binary with bundled templates.
- `sslyze`: Python library installed in `.venv`.
- `wapiti3`: Python library installed in `.venv`.
- `gitleaks.exe`: Official Windows AMD64 binary.
- `trivy.exe`: Official Windows AMD64 binary.

---

## 4. First-Time Installation and Setup

Follow these step-by-step commands in a PowerShell terminal:

### Step 1: Clone the GitHub Repository
```powershell
git clone https://github.com/nadeeen7/patrolman.git
cd patrolman
```

### Step 2: Create and Activate Python Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 3: Install Python Dependencies
Install all required packages from the project manifest:
```powershell
.\.venv\Scripts\python.exe -m pip install -r python-dependencies.txt
```
*(For minimal server-only dependencies, you can alternatively use `requirements-lock.txt`).*

### Step 4: Install Frontend Dependencies
```powershell
npm --prefix frontend install
```

### Step 5: Configure Environment Variables
Create your local `.env` configuration file from the template:
```powershell
Copy-Item .env.example .env
```

The default `.env` includes safe settings for local development and testing:
```ini
AVA_ALLOWED_TARGETS=127.0.0.1
AVA_ALLOW_PRIVATE_TARGETS=true
AVA_REQUIRE_AUTHORIZED_TARGET=true
AVA_PORT=5055
AVA_DATA_DIR=data
AVA_ALLOWED_LOCAL_ROOTS=C:\Projects\SampleApp
AVA_WAPITI_ENABLED=false
AVA_REGISTRATION_ENABLED=true
AVA_TRUSTED_ORIGINS=http://127.0.0.1:5173
```

---

## 5. Administrator Setup and Authentication

PATROLMAN provides two straightforward ways to set up administrator accounts:

### Method A: Command-Line Setup (Recommended for Initial Setup)
You can create the primary administrator account while the backend is stopped:
```powershell
.\.venv\Scripts\python.exe -m backend.admin setup
```
- Enter an administrator username (3–64 characters; lowercase letters, numbers, hyphens, dots).
- Enter a secure password (minimum 8 characters, maximum 1024).
- Confirm the password.

To recover or reset an administrator password in the future:
```powershell
.\.venv\Scripts\python.exe -m backend.admin recover
```

### Method B: Web UI Admin Sign Up
If you start the backend before running the CLI setup, open `http://127.0.0.1:5173/` in your browser. The login screen will display **Admin Sign Up**. Enter your desired administrator credentials to create the account.

### Registration Behavior & Controls
- **Default State**: Self-registration is enabled (`AVA_REGISTRATION_ENABLED=true`), allowing initial administrator setup and additional administrators to register.
- **Closing Registration**: In production or restricted lab environments, set `AVA_REGISTRATION_ENABLED=false` in `.env`. The backend rejects new registration attempts (`HTTP 403 registration_disabled`). Existing accounts and CLI recovery remain functional.
- **Brute-Force Protection**: Login and registration are throttled to 5 attempts per 15-minute window per client IP and account, with a 15-minute lockout on exceeding.
- **Session Security**: Sessions use server-side tokens, `HttpOnly` `SameSite=Strict` cookies, 30-minute idle expiration, 8-hour maximum lifetime, and pre-session CSRF tokens (`X-CSRF-Token`).

---

## 6. Starting PATROLMAN

### Method 1: Using the PowerShell Startup Script (Recommended)
```powershell
.\Start-Patrolman.ps1 -LoopbackTesting
```
This script launches the backend, sets up process containment, verifies environment variables, and restricts targets to loopback testing (`127.0.0.1`).

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

## 7. Application URLs and Health Check

- **Frontend Web UI**: `http://127.0.0.1:5173/`
- **Backend API Base**: `http://127.0.0.1:5055/`
- **Health Check Endpoint**: `http://127.0.0.1:5055/api/health`

### Health Check Verification
Verify that the backend is running and database connectivity is healthy:
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

## 8. Target Registration & Scope Management

PATROLMAN strictly requires an active, unexpired target authorization before dispatching network scans. Adding a target in the UI establishes an audit trail of documented permission.

> **Legal & Ethical Notice:** You must obtain explicit, written authorization from system owners before assessing any target. Adding a target into PATROLMAN does not grant legal authorization to scan it.

### How to Register an Authorized Target
1. Log in to the web interface at `http://127.0.0.1:5173/`.
2. Click **Targets** in the top navigation bar.
3. Click the **Register Target** button to open the modal.
4. Fill in the authorization fields:
   - **Target Name**: Descriptive label (e.g., `OWASP Juice Shop Local Lab`).
   - **Target Type**: Select `lab`, `organization`, `client`, or `bug_bounty`.
   - **Owner / Organization**: System owner (e.g., `Local Security Lab`).
   - **In-Scope Domains / Canonical IPs**: Target host or CIDR (e.g., `127.0.0.1` or `127.0.0.1/32`). Multiple entries can be entered one per line.
   - **Permitted Methods**: Select allowed testing methods (e.g., `port_scan`, `web_audit`, `tls_audit`).
   - **Prohibited Methods**: Keep `dos`, `exploit`, and `credential_attack` strictly checked as prohibited.
   - **Authorization Validity**: Set the `Valid From` and `Valid To` dates.
   - **Authorization Reference**: Provide an authorization tracking reference (e.g., `Lab Authorization Ref #JUICE-SHOP-2026`).
5. Click **Save Authorization Profile**.

---

## 9. Running a Test Assessment (OWASP Juice Shop)

Follow this walkthrough to run a safe, bounded test assessment against a local OWASP Juice Shop instance:

### Step 1: Start OWASP Juice Shop Locally
Run Juice Shop on port 3000 using Docker or native Node.js:
```powershell
docker run --rm -p 3000:3000 bkimminich/juice-shop
```
Confirm Juice Shop is responding at `http://127.0.0.1:3000`.

### Step 2: Launch the Assessment in PATROLMAN
1. Navigate to **New Assessment** in PATROLMAN (`http://127.0.0.1:5173/`).
2. Set **Target**: `http://127.0.0.1:3000` (or `127.0.0.1` with port 3000).
   - PATROLMAN parses port `3000` and automatically appends it to Nmap's scan ports and designates it as a web service for HTTPX, WhatWeb, and Nuclei.
3. Select an **Assessment Profile**:
   - `Quick`: Fast TCP discovery and passive technology identification.
   - `Standard` *(Recommended)*: Adds Nuclei template checks and TLS analysis.
   - `Comprehensive`: Extended port checks and deep web auditing.
   - `Local`: For filesystem scanning of local code directories (Gitleaks/Trivy).
4. Select your desired tools (e.g., Nmap, HTTPX, WhatWeb, Nuclei).
5. Check the required authorization confirmation checkbox: *"I confirm this assessment is strictly authorized."*
6. Click **Start Assessment**.

---

## 10. Reviewing Findings, Evidence, History, and Reports

- **Execution Monitor**: Real-time progress cards show tool status (`RUNNING`, `COMPLETED_WITH_FINDINGS`, `COMPLETED_WITHOUT_FINDINGS`, `SKIPPED`, `FAILED`).
- **Findings Inspector**: Click on any finding to open the details modal. Inspect severity, confidence (`scanner-reported`, `verified`), CVSS vectors, remediation advice, and source tool.
- **Evidence Inspector**: View sanitized HTTP request/response evidence pairs captured during scanning. Sensitive cookies, passwords, and tokens are automatically redacted.
- **Scan History**: The **History** view persists past scans with search, filtering, and cross-scan comparisons.
- **Exporting Reports**:
  - `HTML Report`: Interactive standalone web report (`/api/scans/:id/report?format=html`).
  - `JSON Report`: Machine-readable scan data export (`/api/scans/:id/report?format=json`).
  - `Vulnerabilities JSON`: Dedicated findings list (`/api/scans/:id/report?format=vulnerabilities`).
  - `PDF Report`: Formatted executive summary (`/api/scans/:id/report?format=pdf`).

---

## 11. Testing and Verification

PATROLMAN maintains extensive automated test suites for both backend and frontend.

### Backend Automated Test Suite (pytest)
```powershell
.\.venv\Scripts\python.exe -m pytest
```
*Verified Status: 654 passed, 2 skipped (offline DB / TLS loopback fixture) — October 2026.*

### Frontend Unit & Component Tests (Vitest)
```powershell
npm --prefix frontend test
```
*Verified Status: 87 passed across 5 test suites — October 2026.*

### Frontend Production Build (Vite)
```powershell
npm --prefix frontend run build
```
Generates production assets in `frontend/dist/`, which are served directly by Flask.

---

## 12. Troubleshooting Common Issues

| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| **Port 5055 in use** | A previous PATROLMAN backend process is still running. | Run `Get-Process python` or `netstat -ano \| findstr :5055` and terminate the orphaned process. |
| **Port 5173 in use** | An earlier Vite dev server is running. | Close conflicting terminal or run `npm --prefix frontend run dev -- --port 5174`. |
| **Backend "Network Error"** | Backend stopped, initializing, or CORS origin blocked. | Check backend status at `http://127.0.0.1:5055/api/health` and verify `AVA_TRUSTED_ORIGINS`. |
| **Tool marked `SKIPPED`** | Tool is not applicable to target type. | Subfinder skips literal IP targets; SSLyze skips plain HTTP endpoints. This is normal behavior. |
| **Tool marked `BLOCKED_BY_POLICY`** | Windows AppLocker or WDAC blocked binary. | Consult your administrator to approve binary hash. **Never disable Windows Defender or execution policies.** |
| **Out-of-Scope error (403)** | Target is not in authorized target database or `.env`. | Add target to `.env` (`AVA_ALLOWED_TARGETS`) and create an authorized target profile in the **Targets** tab. |
| **Local scan fails** | Target directory is not in allowed roots. | Add exact folder path to `AVA_ALLOWED_LOCAL_ROOTS` in `.env`. |

---

## 13. Security Boundaries & Limitations

- **Single-Administrator Deployment**: Designed for local execution by trusted security administrators. Not architected as a multi-tenant public SaaS.
- **Unauthenticated Web Crawling**: Assesses accessible endpoints; deep crawling behind complex Single-Sign-On (SSO) or multi-factor authentication (MFA) is not supported.
- **Passive Subdomain Enumeration**: Subfinder relies on external passive intelligence and does not perform active brute-force DNS resolution.
- **Trivy Offline Mode**: Vulnerability scanning requires an offline vulnerability database pre-cached on the system.
- **Detailed Security Policy**: For full details on authentication safeguards, CSRF tokens, session handling, and responsible disclosure, see [SECURITY.md](SECURITY.md).

---

## 14. Project Status and Disclaimer

This project is developed for academic evaluation and authorized vulnerability assessment research.

> **Disclaimer**: PATROLMAN is provided "as is" without warranty of any kind. Finding zero vulnerabilities does not guarantee that a target is secure. All automated observations require human verification.
