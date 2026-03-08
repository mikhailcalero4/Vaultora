# 🔒 Vaultora — Secure File Vault

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-green)
![Security](https://img.shields.io/badge/AES--256-Encrypted-red)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Tests](https://img.shields.io/badge/Tests-Pytest-orange)

A cybersecurity-focused encrypted file storage and transfer web application
built with Flask. Developed as a capstone project demonstrating the CIA triad
through real-world security controls.

---

## Features

| Feature | Implementation |
|---|---|
| AES-256 Encryption | Files encrypted at rest using PyCryptodome (EAX mode) |
| Two-Factor Auth | TOTP via pyotp — compatible with Google Authenticator |
| Role-Based Access | Admin and user roles enforced at the route level |
| Rate Limiting | flask-limiter on login, upload, and MFA routes |
| CSRF Protection | flask-wtf tokens on all POST forms |
| Security Headers | flask-talisman (CSP, X-Frame-Options, HSTS) |
| File Integrity | SHA-256 hash verification on every download |
| Malware Scanning | ClamAV integration via pyclamd |
| Geofencing | Country-based access control via ipapi.co |
| Zero Trust | Device ID and IP allowlist enforcement |
| Audit Logging | Every action logged with username, IP, and timestamp |
| SIEM Export | Audit logs downloadable in CEF format (Splunk / QRadar) |
| File Versioning | Automatic snapshots on re-upload with rollback |
| Key Rotation | Admin-triggered AES key rotation re-encrypts all files |
| Auto Expiry | APScheduler removes files past retention date nightly |
| Secure Sharing | Password-protected, time-limited one-use download links |
| Compliance Dashboard | GDPR, HIPAA, and ISO 27001 control mapping |

---

## CIA Triad Mapping

| Principle | Controls Implemented |
|---|---|
| **Confidentiality** | AES-256 encryption, MFA, RBAC, geofencing, zero trust, secure sharing |
| **Integrity** | SHA-256 hashing on every download, file versioning, key rotation |
| **Availability** | Auto expiry cleanup, file retention policies, production server (Waitress) |

---

## Security Architecture

```
Browser → Waitress (production WSGI)
              ↓
        flask-talisman (security headers)
              ↓
        flask-wtf (CSRF check)
              ↓
        flask-limiter (rate limiting)
              ↓
        blueprints/auth.py (login + TOTP)
              ↓
        RBAC (admin / user role check)
              ↓
        blueprints/security.py (malware scan + geofence)
              ↓
        AES-256 encrypt → uploads/filename.enc
              ↓
        SHA-256 hash → SQLite (models.py)
              ↓
        AuditLog → SQLite (every action)
```

---

## Project Structure

```
Vaultora/
├── blueprints/
│   ├── __init__.py
│   ├── admin.py       # Audit log, compliance, SIEM export, user management
│   ├── auth.py        # Login, logout, TOTP, register, decorators
│   ├── files.py       # Upload, download, delete, versioning, key rotation
│   ├── security.py    # Malware scan, geofencing, zero trust
│   └── sharing.py     # Password-protected links, one-use download tokens
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── two_factor.html
│   ├── admin.html
│   ├── compliance.html
│   ├── 403.html
│   ├── 404.html
│   └── 429.html
├── uploads/           # Encrypted files at rest (.enc)
├── versions/          # Versioned file snapshots
├── backups/           # Reserved for backup logic
├── sensitive_files/   # Zero-trust protected files
├── app.py             # App factory, scheduler, error handlers
├── extensions.py      # Shared db, limiter, csrf, talisman
├── models.py          # SQLAlchemy models (User, File, AuditLog, ShareLink)
├── serve.py           # Waitress production server entry point
├── TestVaultora.py    # Pytest test suite
├── Dockerfile
├── .env.example
├── .gitignore
└── requirements.txt
```

---

## Local Setup

```bash
git clone https://github.com/yourname/vaultora.git
cd vaultora

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
# Open .env and fill in your values
# Generate AES key:
python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"

python app.py
```

Visit `http://127.0.0.1:5000`

Default login: `admin` / the password: `yourpassword` 

---

## Production Server (Waitress)

```bash
python serve.py
```

Visit the URL printed in the terminal.

---

## Docker

```bash
# Build
docker build -t vaultora .

# Run
docker run -p 8000:8000 --env-file .env vaultora
```

Visit `http://127.0.0.1:8000`

---

## Run Tests

```bash
pytest TestVaultora.py -v
```

Expected output:
```
PASSED TestVaultora.py::test_file_encryption_and_decryption
PASSED TestVaultora.py::test_file_integrity_verification
PASSED TestVaultora.py::test_upload_without_login
PASSED TestVaultora.py::test_login_wrong_password
PASSED TestVaultora.py::test_admin_route_blocked_for_non_admin
PASSED TestVaultora.py::test_encryption_round_trip
PASSED TestVaultora.py::test_integrity_hash_mismatch
PASSED TestVaultora.py::test_security_txt_route
PASSED TestVaultora.py::test_role_audit
```

---

## Environment Variables

See `.env.example` for all required variables. Key ones:

| Variable | Description |
|---|---|
| `FLASK_SECRET_KEY` | Long random string for session signing |
| `ADMIN_PASS` | Password for the default admin account |
| `AES_KEY_B64` | Base64-encoded 32-byte AES encryption key |
| `FLASK_DEBUG` | Set `false` in production |
| `RATELIMIT_STORAGE_URI` | Set `memory://` for local dev |

---

## Security Disclosure

See [`/.well-known/security.txt`](http://127.0.0.1:8000/.well-known/security.txt)
for the full list of implemented security controls.

---

## Tech Stack

- **Backend:** Python 3.11, Flask 3.x, Flask-SQLAlchemy, Flask-Limiter, Flask-WTF, Flask-Talisman
- **Encryption:** PyCryptodome (AES-256 EAX), pyotp (TOTP/RFC 6238)
- **Database:** SQLite via SQLAlchemy ORM
- **Malware:** ClamAV via pyclamd
- **Server:** Waitress (production WSGI)
- **Frontend:** Bootstrap 5, Jinja2
- **Testing:** Pytest
- **Scheduler:** APScheduler
- **Deployment:** Docker
