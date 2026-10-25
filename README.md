# PATROLMAN — Automated Vulnerability Assessment Framework

PATROLMAN is an automated, defensive vulnerability assessment orchestration platform engineered for native Windows environments. Developed for academic software engineering and cybersecurity research, PATROLMAN enables security administrators to conduct authorized, multi-tool assessments across web applications, network endpoints, and local codebases through an intuitive, modern dashboard.

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

| Tool | Purpose in Simple English | When It Runs | When It May Be Skipped | Installation Source |
| :--- | :--- | :--- | :--- | :--- |
| **Nmap** | Discovers open TCP ports and determines active service version banners. | `Quick`, `Standard`, and `Comprehensive` network profiles. | Skipped during `Local` filesystem scans, or if target is unreachable. | External Windows binary from [nmap.org](https://nmap.org/). |
| **Subfinder** | Passively enumerates valid subdomains using external DNS sources. | `Standard` and `Comprehensive` profiles against domain targets. | Skipped on literal IP targets (e.g. `127.0.0.1`), `Quick`, or `Local` scans. | External AMD64 binary from [ProjectDiscovery](https://github.com/projectdiscovery/subfinder/releases). |
| **HTTPX** | Probes discovered ports for active HTTP/HTTPS web services, status codes, and titles. | `Quick`, `Standard`, and `Comprehensive` profiles on open web ports. | Skipped if Nmap finds no open web ports, or during `Local` scans. | External AMD64 binary from [ProjectDiscovery](https://github.com/projectdiscovery/httpx/releases). |
| **WhatWeb** | Identifies website technologies, CMS platforms, web servers, and embedded libraries. | `Quick`, `Standard`, and `Comprehensive` profiles on live web URLs. | Skipped if no HTTP services are live, or during `Local` scans. | Ruby script ([WhatWeb](https://github.com/urbanadventurer/WhatWeb)); requires native Ruby in `PATH`. |
| **Nuclei** | Scans web applications for security misconfigurations and CVEs using vetted, safe templates. | `Standard` and `Comprehensive` profiles on live web endpoints. | Skipped during `Quick` scans, `Local` scans, or if no HTTP services exist. | External AMD64 binary from [ProjectDiscovery](https://github.com/projectdiscovery/nuclei/releases); safe templates bundled. |
| **SSLyze** | Analyzes TLS/SSL cipher suites, protocols, and certificate validity on HTTPS endpoints. | `Standard` and `Comprehensive` profiles against HTTPS endpoints. | Skipped on plain HTTP endpoints (e.g., port 80 or plain HTTP 3000), `Quick`, or `Local` scans. | Python library installed directly in `.venv` (`sslyze==6.3.1`). |
| **Wapiti** | Audits web applications for missing security headers, cookie flags, and CSP gaps. | `Comprehensive` profile only when explicitly opted in by operator. | Skipped by default (`DISABLED_FOR_SAFETY`) unless `AVA_WAPITI_ENABLED=true` is set. | Python package installed directly in `.venv` (`wapiti3==3.3.2`). |
| **Gitleaks** | Scans local source code directories for hardcoded secrets, private keys, and credentials. | `Local` filesystem profile against authorized local directories. | Skipped during all network profiles (`Quick`, `Standard`, `Comprehensive`). | External AMD64 binary from [Gitleaks](https://github.com/gitleaks/gitleaks/releases). |
| **Trivy** | Scans local filesystem dependencies and configuration files for known package vulnerabilities. | `Local` filesystem profile on authorized local working trees. | Skipped during all network profiles; vulnerability checks skipped if DB not cached. | External AMD64 binary from [Aqua Security](https://github.com/aquasecurity/trivy/releases). |

> **Operational Note on Skipped Tools**: A tool marked `SKIPPED` represents normal, expected behavior when a tool is not applicable to the target type (e.g. Subfinder on an IP address, or SSLyze on plain HTTP). A scan resulting in zero findings does not prove that a target is secure.

### Retired Tool: Nikto
Nikto is deliberately and permanently excluded from PATROLMAN. It was retired due to unthrottled brute-force testing and high denial-of-service risks. No configuration or API route can launch it. For the complete architectural decision record, see [docs/NIKTO_SAFETY_INVESTIGATION.md](docs/NIKTO_SAFETY_INVESTIGATION.md).

---

## 3. Assessment Profiles

PATROLMAN organizes tool execution into four structured profiles:

- **Quick**: Bounded network scan targeting four core web ports (80, 443, 8000, 8443) using Nmap, HTTPX, and WhatWeb. Fast service discovery and passive technology identification without deep checks.
- **Standard**: Common infrastructure and web ports using Nmap, Subfinder, HTTPX, WhatWeb, Nuclei, and SSLyze. Includes passive subdomain discovery, bundled safe Nuclei template checks, and TLS certificate analysis.
- **Comprehensive**: Expanded fixed port list using all enabled network tools (Nmap, Subfinder, HTTPX, WhatWeb, Nuclei, SSLyze, and Wapiti). Wapiti requires explicit operator opt-in (`AVA_WAPITI_ENABLED=true`).
- **Local**: Filesystem source-code scan for approved local directories using Gitleaks and Trivy. Audits working-tree secrets, dependencies, and configuration files. Requires explicit path approval in `AVA_ALLOWED_LOCAL_ROOTS`.

---

## 4. Supported Operating System & Prerequisites

### Supported Environment
- **Operating System**: Native Windows 10 (64-bit) or Windows 11. (WSL and Docker are not required to run PATROLMAN).

### Core Runtime Dependencies (Required)
- **Python**: Python 3.11 to 3.13 (Verified on Python 3.13.14).
- **Node.js**: Node.js 18+ (Verified on Node.js v24.22.1) and npm 9+.
- **Database**: SQLite 3.35+ (Included natively with Python; WAL mode enabled).

### Scanner Tool Distribution Model
- **Bundled / Python Packages**: SSLyze (`sslyze==6.3.1`) and Wapiti (`wapiti3==3.3.2`) are Python libraries installed directly into `.venv`. Nuclei templates are bundled in `backend/nuclei_templates/`.
- **System Binaries**: External scanner executables (`nmap.exe`, `subfinder.exe`, `httpx.exe`, `whatweb`, `nuclei.exe`, `gitleaks.exe`, `trivy.exe`) are detected automatically from system `PATH` or configured paths. Tools that are not installed report as `NOT_INSTALLED` or `SKIPPED` without crashing the platform.

---

## 5. Windows Installation and Setup

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
Install the locked dependencies from the project manifest:
```powershell
.\.venv\Scripts\python.exe -m pip install -r python-dependencies.txt
```
*(For minimal server-only dependencies without optional tools, you can use `requirements-lock.txt`).*

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

## 6. Administrator Setup and Authentication

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

## 7. Starting and Stopping PATROLMAN

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

### Stopping the Application Safely
- If using `Start-Patrolman.ps1`, press `Ctrl+C` in the terminal. The script's cleanup routine automatically terminates backend background processes, unbinds port 5055, and restores environment settings.
- If using manual terminals, press `Ctrl+C` in the backend PowerShell window and `Ctrl+C` in the frontend Vite terminal.

---

## 8. Application URLs and Health Check

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

## 9. Normal Assessment Workflow

1. **Start PATROLMAN**: Launch backend and frontend as described in Section 7.
2. **Log In**: Open `http://127.0.0.1:5173/` and sign in with your administrator credentials.
3. **Register Target**: In the **Targets** tab, register your authorized IP or domain.
4. **Set Scope & Permissions**: Set authorized hostnames/CIDRs, validity dates, and confirm prohibited methods remain checked.
5. **Select Profile & Launch**: In **New Assessment**, pick a profile (`Quick`, `Standard`, `Comprehensive`, or `Local`), check the authorization checkbox, and click **Start Assessment**.
6. **Review Progress**: Monitor real-time tool execution states on the scan details page.
7. **Inspect Findings & Evidence**: Review findings, confidence ratings, and sanitized HTTP request/response evidence.
8. **Export Reports**: Download compliance reports in HTML, JSON, or PDF format.

---

## 10. Local Testing Walkthrough (OWASP Juice Shop)

Follow this walkthrough to run a safe, bounded test assessment against a local OWASP Juice Shop instance:

### Step 1: Start OWASP Juice Shop Locally
Run Juice Shop on port 3000 using Docker or native Node.js (in a separate terminal):
```powershell
docker run --rm -p 3000:3000 bkimminich/juice-shop
```
Confirm Juice Shop is responding at `http://127.0.0.1:3000`.

### Step 2: Register the Juice Shop Target in PATROLMAN
1. Log in to PATROLMAN at `http://127.0.0.1:5173/`.
2. Click **Targets** in the top navigation bar.
3. Click the **Register Target** button to open the modal.
4. Fill in the authorization fields:
   - **Target Name**: `OWASP Juice Shop Local Lab`
   - **Target Type**: `lab`
   - **Owner / Organization**: `Local Security Lab`
   - **In-Scope Domains / Canonical IPs**: `127.0.0.1` (or `127.0.0.1/32`)
   - **Permitted Methods**: `port_scan`, `web_audit`, `tls_audit`
   - **Prohibited Methods**: Keep `dos`, `exploit`, and `credential_attack` checked as prohibited.
   - **Authorization Validity**: Set `Valid From` and `Valid To` dates.
   - **Authorization Reference**: `Lab Authorization Ref #JUICE-SHOP-2026`
5. Click **Save Authorization Profile**.

> **Important Scope Notice:** Adding a target into PATROLMAN documents authorization within the application, but does not grant legal permission to scan it. Users must always obtain written authorization from system owners before assessing any target.

### Step 3: Launch the Assessment in PATROLMAN
1. Navigate to **New Assessment** in PATROLMAN (`http://127.0.0.1:5173/`).
2. Set **Target**: `http://127.0.0.1:3000` (or `127.0.0.1` with port 3000).
   - PATROLMAN parses port `3000` and automatically appends it to Nmap's scan ports and designates it as a web service for HTTPX, WhatWeb, and Nuclei.
3. Select an **Assessment Profile**:
   - `Standard` *(Recommended)*: Adds Nuclei template checks and technology detection.
4. Select your desired tools (e.g., Nmap, HTTPX, WhatWeb, Nuclei).
5. Check the required authorization confirmation checkbox: *"I confirm this assessment is strictly authorized."*
6. Click **Start Assessment**.

---

## 11. Understanding Findings, Evidence, and Statuses

### Tool Execution Statuses
- `COMPLETED_WITH_FINDINGS`: Tool executed successfully and reported one or more findings.
- `COMPLETED_WITHOUT_FINDINGS`: Tool executed successfully and found zero security issues.
- `SKIPPED`: Tool was omitted because it was not applicable to the target type (e.g., Subfinder on an IP address) or was not selected. Normal, non-error behavior.
- `FAILED`: Tool process crashed, timed out (exceeded deadline), or exited with an unhandled error.

### Finding Severities and Statuses
- **Severity Levels**:
  - `Critical`: Severe vulnerabilities with direct compromise potential (CVSS ≥ 9.0).
  - `High`: Significant vulnerabilities allowing privilege escalation or data exposure (CVSS 7.0–8.9).
  - `Medium`: Configuration or logic weaknesses requiring specific conditions (CVSS 4.0–6.9).
  - `Low`: Minor misconfigurations with minimal direct impact (CVSS 0.1–3.9).
  - `Informational`: Technical observations, open ports, server banners, or cryptographic capabilities (not vulnerabilities).
- **Finding Statuses**:
  - `potential`: Preliminary scanner detection requiring manual operator verification.
  - `confirmed`: Verified finding backed by unambiguous evidence (e.g., matched response payloads or confirmed CVE vectors).
  - `informational`: Expected technical observations (e.g., HTTP headers present, open ports).
  - `inconclusive`: Scanner encountered ambiguous responses or execution limits.
- **Confidence Ratings**:
  - `scanner-reported`: Direct observation reported by the tool adapter.
  - `verified`: Confirmed by multiple tools or matching CVE signatures.

### Exporting Reports
- `HTML Report`: Interactive standalone web report (`/api/scans/:id/report?format=html`).
- `JSON Report`: Machine-readable scan data export (`/api/scans/:id/report?format=json`).
- `Vulnerabilities JSON`: Dedicated findings list (`/api/scans/:id/report?format=vulnerabilities`).
- `PDF Report`: Formatted executive summary (`/api/scans/:id/report?format=pdf`).

---

## 12. Verification and Automated Testing

PATROLMAN maintains extensive automated test suites for both backend and frontend.

### Backend Automated Test Suite (pytest)
```powershell
.\.venv\Scripts\python.exe -m pytest
```
*Verified Status: 654 passed, 2 skipped across all test modules (Verified October 2026).*

### Frontend Unit & Component Tests (Vitest)
```powershell
npm --prefix frontend test
```
*Verified Status: 87 passed across 5 test suites (Verified October 2026).*

### Frontend Production Build (Vite)
```powershell
npm --prefix frontend run build
```
Generates production assets in `frontend/dist/`, which are served directly by Flask via `backend/app.py`.

---

## 13. Troubleshooting Common Issues

| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| **Port 5055 in use** | A previous PATROLMAN backend process is still running. | Run `Get-NetTCPConnection -LocalPort 5055` to find the owning PID, then terminate it with `Stop-Process -Id <PID>`. |
| **Port 5173 in use** | An earlier Vite dev server is running. | Close the conflicting terminal or run `npm --prefix frontend run dev -- --port 5174`. |
| **Backend "Network Error"** | Backend stopped, initializing, or CORS origin blocked. | Check backend status at `http://127.0.0.1:5055/api/health` and verify `AVA_TRUSTED_ORIGINS=http://127.0.0.1:5173`. |
| **Auth lockout / registration disabled** | Too many failed attempts, or registration is turned off. | Wait 15 minutes for lockout expiry, recover credentials with `python -m backend.admin recover`, or set `AVA_REGISTRATION_ENABLED=true`. |
| **Tool marked `SKIPPED`** | Tool is not applicable to target type. | Subfinder skips literal IP targets; SSLyze skips plain HTTP endpoints. This is normal, expected behavior. |
| **Tool marked `BLOCKED_BY_POLICY`** | Windows AppLocker or WDAC blocked binary execution. | Consult your administrator to allow the binary hash. **Never disable Windows Defender or system execution policies.** |
| **Out-of-Scope error (403)** | Target is not in authorized target database or `.env`. | Add target to `.env` (`AVA_ALLOWED_TARGETS`) and create an authorized target profile in the **Targets** tab. |
| **Local scan fails** | Target directory is not in allowed roots. | Add exact folder path to `AVA_ALLOWED_LOCAL_ROOTS` in `.env`. |

---

## 14. Security Controls and Boundaries

- **Explicit Authorization Only**: Assessments are restricted to authorized scopes.
- **Non-Destructive Baseline**: Prohibited methods (`dos`, `exploit`, `credential_attack`) are actively rejected.
- **Credential Protection**: Redaction masks sensitive tokens, Authorization headers, and cookies across all logs, reports, and UI views.
- **Single-Administrator Deployment**: Designed for local execution by trusted administrators; not architected as a public multi-tenant SaaS.
- **Unauthenticated Web Crawling**: Assesses accessible endpoints; deep crawling behind complex Single-Sign-On (SSO) or multi-factor authentication (MFA) is not supported.
- **Detailed Security Policy**: For full details on authentication safeguards, CSRF tokens, session handling, and responsible disclosure, see [SECURITY.md](SECURITY.md).

---

## 15. Project Status and Disclaimer

This project is developed for academic evaluation and authorized vulnerability assessment research.

> **Disclaimer**: PATROLMAN is provided "as is" without warranty of any kind. Finding zero vulnerabilities does not guarantee that a target is secure. All automated observations require human verification.
