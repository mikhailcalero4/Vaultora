# 🔒 Vaultora — Secure File Vault

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-green)
![Security](https://img.shields.io/badge/AES--256-Encrypted-red)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Tests](https://img.shields.io/badge/Tests-Pytest-orange)
![Compliance](https://img.shields.io/badge/Compliance-HIPAA%20%7C%20GDPR%20%7C%20ISO27001-blueviolet)

A cybersecurity-focused encrypted file storage and transfer web application
built with Flask. Developed as a capstone project at Florida International
University (KFSCIS) demonstrating the CIA triad through real-world security
controls.

---

## 🔐 Security Features

| Feature | Implementation |
|---|---|
| AES-256 Encryption | Files encrypted at rest using PyCryptodome (EAX mode) |
| Two-Factor Auth | TOTP via pyotp — compatible with Google Authenticator |
| Role-Based Access Control | Admin and user roles enforced at the route level |
| Rate Limiting | flask-limiter on login, upload, and MFA routes |
| CSRF Protection | flask-wtf tokens on all POST forms |
| Security Headers | flask-talisman (CSP, X-Frame-Options, HSTS) |
| File Integrity Verification | SHA-256 hash stored at upload, verified on every download |
| Malware Scanning | ClamAV integration via pyclamd |
| Geofencing | Country-based access control via ipapi.co |
| Zero Trust | Device ID and IP allowlist enforcement |
| Audit Logging | Every action logged with username, IP, and timestamp |
| SIEM Export | Audit logs downloadable in CEF format (Splunk / QRadar) |
| File Versioning | Automatic snapshots on re-upload with rollback |
| AES Key Rotation | Admin-triggered re-encryption of all files with new key |
| Auto File Expiry | APScheduler removes files past retention date nightly |
| Secure Sharing | Password-protected, time-limited one-use download links |
| Compliance Dashboard | Live GDPR, HIPAA, and ISO 27001 control mapping |
| Performance Metrics | Encryption/decryption latency and integrity pass rate tracking |

---

## 📊 Performance Metrics

Measured on Apple M-series, local SQLite:

| Operation | Average | Min | Max |
|---|---|---|---|
| AES-256 Encryption | ~2ms | ~1ms | ~8ms |
| AES-256 Decryption | ~1ms | ~0.5ms | ~5ms |
| SHA-256 Integrity Check | ~0.3ms | ~0.1ms | ~1ms |
| Malware Scan (ClamAV) | ~120ms | ~80ms | ~300ms |
| Rate Limit Trigger | 10 attempts | — | — |
| Integrity Pass Rate | 100% | — | — |

Live metrics visible at `/admin/metrics` after login.

---

## 🛡️ CIA Triad Mapping

| Principle | Controls Implemented |
|---|---|
| **Confidentiality** | AES-256 encryption, MFA, RBAC, geofencing, zero trust, CSRF, secure sharing |
| **Integrity** | SHA-256 on every download, file versioning, AES key rotation, security headers |
| **Availability** | Auto expiry cleanup, file retention policies, Waitress WSGI server, Docker |

---

## ⚠️ Threat Model (STRIDE Summary)

Full analysis in [`THREAT_MODEL.md`](THREAT_MODEL.md)

| Threat | Category | Mitigation |
|---|---|---|
| Credential brute force | Spoofing | Rate limiting, TOTP MFA |
| Session hijacking | Spoofing | Secure cookies, HSTS, 2hr expiry |
| Malicious file upload | Tampering | ClamAV scan, file type allowlist |
| File tampering at rest | Tampering | AES-256 EAX authenticated mode + SHA-256 |
| Unauthorized route access | Elevation of Privilege | RBAC, @login_required, @role_required |
| Sensitive data exposure | Info Disclosure | AES-256 at rest, TLS in transit, env-var key |
| Audit log repudiation | Repudiation | Append-only DB log, admin-only view |
| Upload flood / DoS | Denial of Service | Rate limiting, 50MB file size cap |

---

## 🏗️ Security Architecture

```
Browser → Waitress (production WSGI)
              ↓
        flask-talisman (CSP, X-Frame-Options, HSTS)
              ↓
        flask-wtf (CSRF token check)
              ↓
        flask-limiter (rate limiting — 10 req/min on auth routes)
              ↓
        blueprints/auth.py (login + TOTP MFA)
              ↓
        RBAC (@login_required + @role_required)
              ↓
        blueprints/security.py (ClamAV scan + geofence + zero trust)
              ↓
        AES-256 EAX encrypt → uploads/filename.enc
              ↓
        SHA-256 hash → SQLite (verified on every download)
              ↓
        AuditLog + Metric → SQLite (every action recorded)
```

---

## 📁 Project Structure

```
Vaultora/
├── blueprints/
│   ├── __init__.py
│   ├── admin.py         # Audit log, compliance, SIEM export, metrics
│   ├── auth.py          # Login, logout, TOTP, register, decorators
│   ├── files.py         # Upload, download, delete, versioning, key rotation
│   ├── security.py      # Malware scan, geofencing, zero trust
│   └── sharing.py       # Password-protected time-limited share links
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── two_factor.html
│   ├── admin.html
│   ├── compliance.html
│   ├── metrics.html
│   ├── 403.html
│   ├── 404.html
│   └── 429.html
├── uploads/             # AES-256 encrypted files (.enc)
├── versions/            # Versioned file snapshots
├── backups/             # Reserved for key rotation backups
├── sensitive_files/     # Zero-trust protected files
├── app.py               # App factory, scheduler, error handlers
├── extensions.py        # Shared db, limiter, csrf, talisman
├── models.py            # SQLAlchemy models
├── serve.py             # Waitress production server entry point
├── TestVaultora.py      # Pytest security test suite
├── THREAT_MODEL.md      # Full STRIDE threat model
├── Dockerfile
├── .env.example
├── .gitignore
└── requirements.txt
```

---

## ⚙️ Local Setup

```bash
git clone https://github.com/mikhailcalero4/Vaultora.git
cd Vaultora

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
# Generate your AES key and paste it into .env:
python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"

python app.py
```

Visit `http://127.0.0.1:5000`
Default login: `admin` / password `yourpassword` from `.env`

---

## 🚀 Production Server

```bash
python serve.py
```

---

## 🐳 Docker

```bash
docker build -t vaultora .
docker run -p 8000:8000 --env-file .env vaultora
```

Visit `http://127.0.0.1:8000`

---

## 🧪 Run Tests

```bash
pytest TestVaultora.py -v
```

Expected output:
```
PASSED TestVaultora.py::test_file_encryption_and_decryption
PASSED TestVaultora.py::test_file_integrity_verification
PASSED TestVaultora.py::test_upload_without_login
PASSED TestVaultora.py::test_login_wrong_password
PASSED TestVaultora.py::test_rate_limiting_login
PASSED TestVaultora.py::test_admin_route_blocked_for_non_admin
PASSED TestVaultora.py::test_encryption_round_trip
PASSED TestVaultora.py::test_integrity_hash_mismatch
PASSED TestVaultora.py::test_security_txt_route
PASSED TestVaultora.py::test_role_audit
```

---

## 🔧 Environment Variables

| Variable | Description |
|---|---|
| `FLASK_SECRET_KEY` | Long random string for session signing |
| `ADMIN_PASS` | Password for the default admin account |
| `AES_KEY_B64` | Base64-encoded 32-byte AES-256 encryption key |
| `FLASK_DEBUG` | Set `false` in production |
| `RATELIMIT_STORAGE_URI` | Use `memory://` for local dev |
| `KEY_FILE_PATH` | Fallback key file path (default: `secret.key`) |

---

## 📋 Compliance Mapping

| Framework | Controls Covered |
|---|---|
| **GDPR** | Encryption at rest, audit logging, data retention/expiry, access control |
| **HIPAA** | AES-256, MFA, audit trails, integrity verification, breach detection |
| **ISO 27001** | RBAC, incident logging, key management, secure coding |

Live compliance dashboard at `/admin/compliance`.

---

## 🔍 Security Disclosure

See [`/.well-known/security.txt`](http://127.0.0.1:8000/.well-known/security.txt)

---

## 👥 Team

Built by FIU KFSCIS Capstone II — 2025/2026
Florida International University
Instructor: Prof. Masoud Sadjadi
