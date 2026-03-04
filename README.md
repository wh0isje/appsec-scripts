![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

# 🔐 AppSec Scripts

Collection of **small, focused Python scripts** used to support **application security testing** and manual security assessments.

These scripts are designed as **helpers**, not full scanners — they assist in validating controls, simulating abuse scenarios and speeding up common AppSec checks.

> ⚠️ **Use only against systems you own or have explicit authorization to test.**

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/whoisje/appsec-scripts.git
cd appsec-scripts
pip install -r requirements.txt
```
```
# Check security headers
python check_headers.py -u https://example.com

# Test rate limiting
python multithread_rate_limit.py -u https://example.com/login

# Scan common ports
python portscan.py -H 192.168.1.1 -p 1-1000

# API input testing
python apitest.py -u https://api.example.com/v1/user
```

---

## 📂 Available Scripts

| Script | Purpose | Category | Status |
|--------|---------|----------|--------|
| [`check_headers.py`](#-check_headerspy) | HTTP security headers check | Web | ✅ Stable |
| [`multithread_rate_limit.py`](#-multithread_rate_limitpy) | Rate limiting assessment | API | ✅ Stable |
| [`apitest.py`](#-apitestpy) | Basic API input testing | API | 🧪 Beta |
| [`portscan.py`](#-portscanpy) | Network port scanning | Network | ✅ Stable |

---

### 🚦 `multithread_rate_limit.py`

Sends **concurrent HTTP requests** to an endpoint in order to evaluate basic rate limiting behavior.

**What it helps assess**

- Absence of rate limiting
- Feasibility of brute-force attacks
- Server behavior under concurrent load

**Typical targets**

- Login endpoints
- OTP / MFA validation
- Password reset APIs
- Public endpoints without authentication

---

### 🔍 `check_headers.py`

Checks for the presence of common **HTTP security headers** in server responses.

**Headers verified**

- Strict-Transport-Security
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection

**Use cases**

- Quick security posture validation
- Supporting security reviews
- Identifying missing baseline protections

---

### 🌐 `apitest.py`

Helper script for **basic API input testing**, simulating simple injection payloads.

**What it does**

- Sends crafted input payloads (e.g. SQL injection strings)
- Observes HTTP response behavior

**Important note**

> This script **does not confirm vulnerabilities**. It is intended to support **manual testing and analysis**, not automated detection.

---

### 🔌 `portscan.py`

Lightweight port scanning utility to identify **open network services** on common ports.

**Features**

- Scans common service ports
- Highlights known risks associated with exposed services
- Uses multithreading for faster execution

**Use cases**

- Initial attack surface mapping
- Infrastructure security reviews
- Supporting AppSec and cloud assessments

---

## 🛠️ Tech Stack

| Aspect | Details |
|--------|---------|
| **Language** | Python 3.8+ |
| **Libraries** | Requests, Socket, Threading |
| **Execution** | CLI-based |
| **Platform** | Cross-platform (Linux, macOS, Windows) |

---

## 📈 Roadmap

- [ ] Improved rate limit testing with RPS control and metrics
- [ ] Authorization testing helpers (IDOR / BOLA scenarios)
- [ ] JWT structure and claim analysis utilities
- [ ] Exportable results for reporting and evidence (JSON/CSV)
- [ ] Custom payload support for apitest.py

---

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
