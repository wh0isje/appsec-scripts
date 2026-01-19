# 🔐 AppSec Scripts

Collection of **small, focused Python scripts** used to support **application security testing** and manual security assessments.

These scripts are designed as **helpers**, not full scanners — they assist in validating controls, simulating abuse scenarios and speeding up common AppSec checks.

> ⚠️ **Use only against systems you own or have explicit authorization to test.**

---

## 🧠 Purpose

This repository centralizes lightweight scripts commonly used during:

* Web & API security testing
* Initial attack surface analysis
* Validation of security controls
* Manual vulnerability assessment workflows

The focus is on **practical AppSec support**, not automated exploitation frameworks.

---

## 📂 Available Scripts

### 🚦 `multithread_rate_limit.py`

Sends **concurrent HTTP requests** to an endpoint in order to evaluate basic rate limiting behavior.

**What it helps assess**

* Absence of rate limiting
* Feasibility of brute-force attacks
* Server behavior under concurrent load

**Typical targets**

* Login endpoints
* OTP / MFA validation
* Password reset APIs
* Public endpoints without authentication

---

### 🔍 `check_headers.py`

Checks for the presence of common **HTTP security headers** in server responses.

**Headers verified**

* Strict-Transport-Security
* Content-Security-Policy
* X-Content-Type-Options
* X-Frame-Options
* X-XSS-Protection

**Use cases**

* Quick security posture validation
* Supporting security reviews
* Identifying missing baseline protections

---

### 🌐 `apitest.py`

Helper script for **basic API input testing**, simulating simple injection payloads.

**What it does**

* Sends crafted input payloads (e.g. SQL injection strings)
* Observes HTTP response behavior

**Important note**
This script **does not confirm vulnerabilities**.
It is intended to support **manual testing and analysis**, not automated detection.

---

### 🔌 `portscan.py`

Lightweight port scanning utility to identify **open network services** on common ports.

**Features**

* Scans common service ports
* Highlights known risks associated with exposed services
* Uses multithreading for faster execution

**Use cases**

* Initial attack surface mapping
* Infrastructure security reviews
* Supporting AppSec and cloud assessments

---

## 🛠️ Tech Stack

* Python
* Requests
* Threading / concurrency
* Socket programming
* CLI-based execution

---

## 📈 Roadmap

* Improved rate limit testing with RPS control and metrics
* Authorization testing helpers (IDOR / BOLA scenarios)
* JWT structure and claim analysis utilities
* Exportable results for reporting and evidence

---

## 📚 References

* OWASP Top 10
* OWASP API Security Top 10
* OWASP ASVS

---

## 📎 Notes

This repository consolidates scripts that were previously maintained separately.
Archived repositories remain available for historical reference.
